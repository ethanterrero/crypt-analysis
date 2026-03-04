#include "chacha_cipher.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <cstring>
#include <iostream>

ChaChaCipher::ChaChaCipher() {
}

ChaChaCipher::~ChaChaCipher() {
}

bool ChaChaCipher::encrypt(const std::vector<uint8_t> &input, const std::string &key, std::vector<uint8_t> &output) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    // Generate Salt
    unsigned char salt[SALT_SIZE];
    if (RAND_bytes(salt, SALT_SIZE) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Derive Key/IV using PBKDF2
    unsigned char chachaKey[KEY_SIZE];
    unsigned char chachaIv[IV_SIZE];
    KeyDerivation::deriveKeyAndIV(key, salt, SALT_SIZE, chachaKey, KEY_SIZE, chachaIv, IV_SIZE);

    // Build file header: [FC magic][algo][mode][salt][iv]
    auto header = FileFormat::buildHeader(FileFormat::ALGO_CHACHA20, FileFormat::MODE_NONE,
                                           salt, SALT_SIZE, chachaIv, IV_SIZE);
    output.clear();
    output.insert(output.end(), header.begin(), header.end());

    // Init ChaCha20
    if (1 != EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, chachaKey, chachaIv)) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Encrypt
    int len;
    int ciphertext_len;
    size_t header_size = output.size();
    output.resize(header_size + input.size() + 16);

    if (1 != EVP_EncryptUpdate(ctx, &output[header_size], &len, input.data(), input.size())) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, &output[header_size + len], &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext_len += len;

    output.resize(header_size + ciphertext_len);
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool ChaChaCipher::decrypt(const std::vector<uint8_t> &input, const std::string &key, std::vector<uint8_t> &output) {
    // Parse the file header
    FileFormat::AlgorithmID algo;
    FileFormat::ModeID mode;
    std::vector<uint8_t> salt, iv;
    size_t headerSize;

    try {
        headerSize = FileFormat::parseHeader(input, algo, mode, salt, iv);
    } catch (const std::exception &e) {
        std::cerr << "Header parse error: " << e.what() << std::endl;
        return false;
    }

    // Derive Key using PBKDF2 with salt from header, use IV from header
    unsigned char chachaKey[KEY_SIZE];
    unsigned char chachaIv[IV_SIZE];
    KeyDerivation::deriveKeyAndIV(key, salt.data(), static_cast<int>(salt.size()),
                                  chachaKey, KEY_SIZE, chachaIv, 1);
    // Use the IV stored in the header
    memcpy(chachaIv, iv.data(), iv.size());

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    // Init Decrypt
    if (1 != EVP_DecryptInit_ex(ctx, EVP_chacha20(), NULL, chachaKey, chachaIv)) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Decrypt
    int len;
    int plaintext_len;
    output.resize(input.size());

    if (1 != EVP_DecryptUpdate(ctx, output.data(), &len,
                                input.data() + headerSize, input.size() - headerSize)) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, output.data() + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    plaintext_len += len;

    output.resize(plaintext_len);
    EVP_CIPHER_CTX_free(ctx);
    return true;
}
