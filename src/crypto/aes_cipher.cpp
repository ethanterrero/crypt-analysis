#include "aes_cipher.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <cstring>
#include <iostream>
#include <stdexcept>

AesCipher::AesCipher(const std::string &mode) : m_mode(mode) {
    getCipher(); // validate mode at construction
}

AesCipher::~AesCipher() {
}

const EVP_CIPHER* AesCipher::getCipher() const {
    if (m_mode == "cbc") return EVP_aes_256_cbc();
    if (m_mode == "ecb") return EVP_aes_256_ecb();
    if (m_mode == "gcm") return EVP_aes_256_gcm();
    throw std::runtime_error("Unknown AES mode: " + m_mode + " (supported: cbc, ecb, gcm)");
}

int AesCipher::getIVSize() const {
    if (m_mode == "ecb") return 0;
    if (m_mode == "gcm") return GCM_IV_SIZE;
    return IV_SIZE;
}

bool AesCipher::encrypt(const std::vector<uint8_t> &input, const std::string &key, std::vector<uint8_t> &output) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    // Generate a random salt
    unsigned char salt[SALT_SIZE];
    if (RAND_bytes(salt, SALT_SIZE) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Derive Key and IV using PBKDF2
    int ivSize = getIVSize();
    unsigned char aesKey[KEY_SIZE];
    unsigned char aesIv[IV_SIZE];
    KeyDerivation::deriveKeyAndIV(key, salt, SALT_SIZE, aesKey, KEY_SIZE,
                                  aesIv, ivSize > 0 ? ivSize : 1);

    // Build file header: [FC magic][algo][mode][salt][iv]
    auto algoId = FileFormat::ALGO_AES256;
    auto modeId = FileFormat::modeFromString(m_mode);
    auto header = FileFormat::buildHeader(algoId, modeId, salt, SALT_SIZE, aesIv, ivSize);

    output.clear();
    output.insert(output.end(), header.begin(), header.end());

    // Initialize Encryption
    const EVP_CIPHER *cipher = getCipher();
    if (m_mode == "gcm") {
        if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL)) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_SIZE, NULL)) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, aesKey, aesIv)) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
    } else {
        unsigned char *ivPtr = (ivSize > 0) ? aesIv : NULL;
        if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, aesKey, ivPtr)) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
    }

    // Encrypt Data
    int len;
    int ciphertext_len;
    size_t header_size = output.size();
    output.resize(header_size + input.size() + AES_BLOCK_SIZE);

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

    // For GCM, append the 16-byte authentication tag
    if (m_mode == "gcm") {
        unsigned char tag[GCM_TAG_SIZE];
        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_SIZE, tag)) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        output.insert(output.end(), tag, tag + GCM_TAG_SIZE);
    }

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool AesCipher::decrypt(const std::vector<uint8_t> &input, const std::string &key, std::vector<uint8_t> &output) {
    // Parse the file header to extract salt, IV, algo, mode
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

    // Derive Key and IV using PBKDF2 with salt from header
    int ivSize = static_cast<int>(iv.size());
    unsigned char aesKey[KEY_SIZE];
    unsigned char aesIv[IV_SIZE];

    if (ivSize > 0) {
        memcpy(aesIv, iv.data(), ivSize);
    }
    // We only need to derive the key since IV is stored in header
    // But we derive both for consistency and use the stored IV
    KeyDerivation::deriveKeyAndIV(key, salt.data(), static_cast<int>(salt.size()),
                                  aesKey, KEY_SIZE, aesIv, 1); // derive key only (1 dummy IV byte)
    // Overwrite with the actual IV from the header
    if (ivSize > 0) {
        memcpy(aesIv, iv.data(), ivSize);
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    size_t dataStart = headerSize;
    size_t dataLen = input.size() - headerSize;

    // Resolve mode string from header
    std::string modeStr = FileFormat::modeToString(mode);

    // For GCM, extract the auth tag from the end
    unsigned char tag[GCM_TAG_SIZE];
    if (modeStr == "gcm") {
        if (dataLen < static_cast<size_t>(GCM_TAG_SIZE)) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        dataLen -= GCM_TAG_SIZE;
        memcpy(tag, input.data() + dataStart + dataLen, GCM_TAG_SIZE);
    }

    // Initialize Decryption using mode from file header, not constructor
    const EVP_CIPHER *cipher;
    if (modeStr == "cbc") cipher = EVP_aes_256_cbc();
    else if (modeStr == "ecb") cipher = EVP_aes_256_ecb();
    else if (modeStr == "gcm") cipher = EVP_aes_256_gcm();
    else { EVP_CIPHER_CTX_free(ctx); return false; }
    if (modeStr == "gcm") {
        if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL)) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ivSize, NULL)) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, aesKey, aesIv)) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_SIZE, tag)) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
    } else {
        unsigned char *ivPtr = (ivSize > 0) ? aesIv : NULL;
        if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, aesKey, ivPtr)) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
    }

    // Decrypt
    int len;
    int plaintext_len;
    output.resize(input.size());

    if (1 != EVP_DecryptUpdate(ctx, output.data(), &len, input.data() + dataStart, dataLen)) {
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
