#include "chacha_cipher.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <cstring>
#include <iostream>

ChaChaCipher::ChaChaCipher() {
    // OpenSSL init is handled automatically
}

ChaChaCipher::~ChaChaCipher() {
}

// Helper: Uses EVP_Digest 
void ChaChaCipher::deriveKeyAndIV(const std::string &phrase, const unsigned char *salt, unsigned char *key, unsigned char *iv) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned int hashLen;
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    // Generate Key
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, phrase.c_str(), phrase.length());
    EVP_DigestUpdate(ctx, salt, SALT_SIZE);
    EVP_DigestFinal_ex(ctx, hash, &hashLen);
    memcpy(key, hash, KEY_SIZE);

    // Generate IV (ChaCha uses 16 bytes: 4 byte counter + 12 byte nonce)
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, hash, SHA256_DIGEST_LENGTH);
    EVP_DigestFinal_ex(ctx, hash, &hashLen);
    memcpy(iv, hash, IV_SIZE);

    EVP_MD_CTX_free(ctx);
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

    // Derive Key/IV
    unsigned char chachaKey[KEY_SIZE];
    unsigned char chachaIv[IV_SIZE];
    deriveKeyAndIV(key, salt, chachaKey, chachaIv);

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

    //  Derive Key/IV
    unsigned char chachaKey[KEY_SIZE];
    unsigned char chachaIv[IV_SIZE];
    deriveKeyAndIV(key, salt, chachaKey, chachaIv);

    //  Init Decrypt
    if (1 != EVP_DecryptInit_ex(ctx, EVP_chacha20(), NULL, chachaKey, chachaIv)) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    //  Decrypt
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