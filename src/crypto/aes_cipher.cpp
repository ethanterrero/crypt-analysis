#include "aes_cipher.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <cstring>
#include <iostream>
#include <stdexcept>

AesCipher::AesCipher(const std::string &mode) : m_mode(mode) {
    // Validate mode at construction time
    getCipher();
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
    if (m_mode == "ecb") return 0;   // ECB has no IV
    if (m_mode == "gcm") return GCM_IV_SIZE; // 12 bytes for GCM
    return IV_SIZE; // 16 bytes for CBC
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

    // Derive the actual AES Key and IV from user's password using PBKDF2
    int ivSize = getIVSize();
    unsigned char aesKey[KEY_SIZE];
    unsigned char aesIv[IV_SIZE]; // allocate max size
    KeyDerivation::deriveKeyAndIV(key, salt, SALT_SIZE, aesKey, KEY_SIZE,
                                  aesIv, ivSize > 0 ? ivSize : 1);

    // Write Salt to the beginning of output
    output.clear();
    output.insert(output.end(), salt, salt + SALT_SIZE);

    // Initialize Encryption
    const EVP_CIPHER *cipher = getCipher();
    if (m_mode == "gcm") {
        if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL)) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        // Set IV length for GCM
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
    if (input.size() < static_cast<size_t>(SALT_SIZE)) return false;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    // Extract Salt from the beginning
    unsigned char salt[SALT_SIZE];
    memcpy(salt, input.data(), SALT_SIZE);

    // Derive Key and IV using PBKDF2
    int ivSize = getIVSize();
    unsigned char aesKey[KEY_SIZE];
    unsigned char aesIv[IV_SIZE];
    KeyDerivation::deriveKeyAndIV(key, salt, SALT_SIZE, aesKey, KEY_SIZE,
                                  aesIv, ivSize > 0 ? ivSize : 1);

    size_t dataStart = SALT_SIZE;
    size_t dataLen = input.size() - SALT_SIZE;

    // For GCM, extract the auth tag from the end
    unsigned char tag[GCM_TAG_SIZE];
    if (m_mode == "gcm") {
        if (dataLen < static_cast<size_t>(GCM_TAG_SIZE)) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        dataLen -= GCM_TAG_SIZE;
        memcpy(tag, input.data() + dataStart + dataLen, GCM_TAG_SIZE);
    }

    // Initialize Decryption
    const EVP_CIPHER *cipher = getCipher();
    if (m_mode == "gcm") {
        if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL)) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_SIZE, NULL)) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, aesKey, aesIv)) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        // Set expected tag
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

    // Decrypt Data
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
