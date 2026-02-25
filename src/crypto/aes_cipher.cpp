#include "aes_cipher.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <cstring>
#include <iostream>

AesCipher::AesCipher() {
}

AesCipher::~AesCipher() {
}

// Helper: Turn string password into 32-byte Key and 16-byte IV using SHA256
void AesCipher::deriveKeyAndIV(const std::string &phrase, const unsigned char *salt, unsigned char *key, unsigned char *iv) {
    unsigned char hash[SHA256_DIGEST_LENGTH]; // 32 bytes
    unsigned int hashLen;
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    // Generate Key: Hash(Pass + Salt)
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, phrase.c_str(), phrase.length());
    EVP_DigestUpdate(ctx, salt, SALT_SIZE);
    EVP_DigestFinal_ex(ctx, hash, &hashLen);
    memcpy(key, hash, KEY_SIZE);

    // Generate IV: Hash(Key)
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, hash, SHA256_DIGEST_LENGTH);
    EVP_DigestFinal_ex(ctx, hash, &hashLen);
    memcpy(iv, hash, IV_SIZE);

    EVP_MD_CTX_free(ctx);
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

    // Derive the actual AES Key and IV from user's string
    unsigned char aesKey[KEY_SIZE];
    unsigned char aesIv[IV_SIZE];
    deriveKeyAndIV(key, salt, aesKey, aesIv);

    // Write Salt to the beginning of output 
    output.clear();
    output.insert(output.end(), salt, salt + SALT_SIZE);

    // Initialize Encryption
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aesKey, aesIv)) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Encrypt Data
    int len;
    int ciphertext_len;
    
    // Resize output to fit input + potential padding
    size_t header_size = output.size();
    output.resize(header_size + input.size() + AES_BLOCK_SIZE);

    // Encrypt the main body
    // &output[header_size] points to the space AFTER the salt
    if (1 != EVP_EncryptUpdate(ctx, &output[header_size], &len, input.data(), input.size())) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext_len = len;

    // Finalize (Add Padding)
    if (1 != EVP_EncryptFinal_ex(ctx, &output[header_size + len], &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext_len += len;

    // Shrink vector to match actual size
    output.resize(header_size + ciphertext_len);

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool AesCipher::decrypt(const std::vector<uint8_t> &input, const std::string &key, std::vector<uint8_t> &output) {
    if (input.size() < SALT_SIZE) return false;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    // Extract Salt from the beginning of the file
    unsigned char salt[SALT_SIZE];
    memcpy(salt, input.data(), SALT_SIZE);

    // Derive Key and IV (Using same logic as encrypt)
    unsigned char aesKey[KEY_SIZE];
    unsigned char aesIv[IV_SIZE];
    deriveKeyAndIV(key, salt, aesKey, aesIv);

    // Initialize Decryption
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aesKey, aesIv)) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Decrypt Data
    int len;
    int plaintext_len;
    output.resize(input.size());

    // Decrypt everything AFTER the salt
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