#pragma once

#include "encryptor.h"
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <string>
#include <vector>

class AesCipher : public Encryptor {
public:
    AesCipher();
    ~AesCipher();

    bool encrypt(const std::vector<uint8_t> &input, 
                 const std::string &key, 
                 std::vector<uint8_t> &output) override;

    bool decrypt(const std::vector<uint8_t> &input, 
                 const std::string &key, 
                 std::vector<uint8_t> &output) override;

private:

    static const int KEY_SIZE = 32; // 256 bits
    static const int IV_SIZE = 16;  // 128 bits 
    static const int SALT_SIZE = 8; 


    void deriveKeyAndIV(const std::string &phrase, 
                        const unsigned char *salt, 
                        unsigned char *key, 
                        unsigned char *iv);
};