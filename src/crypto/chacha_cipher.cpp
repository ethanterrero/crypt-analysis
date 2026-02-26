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

    // Write Salt to output
    output.clear();
    output.insert(output.end(), salt, salt + SALT_SIZE);

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
    if (input.size() < SALT_SIZE) return false;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    // Extract Salt
    unsigned char salt[SALT_SIZE];
    memcpy(salt, input.data(), SALT_SIZE);

    // Derive Key/IV using PBKDF2
    unsigned char chachaKey[KEY_SIZE];
    unsigned char chachaIv[IV_SIZE];
    KeyDerivation::deriveKeyAndIV(key, salt, SALT_SIZE, chachaKey, KEY_SIZE, chachaIv, IV_SIZE);

    // Init Decrypt
    if (1 != EVP_DecryptInit_ex(ctx, EVP_chacha20(), NULL, chachaKey, chachaIv)) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Decrypt
    int len;
    int plaintext_len;
    output.resize(input.size());

    if (1 != EVP_DecryptUpdate(ctx, output.data(), &len, input.data() + SALT_SIZE, input.size() - SALT_SIZE)) {
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
