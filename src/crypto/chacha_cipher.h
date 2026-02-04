#pragma once

#include "encryptor.h"
#include <openssl/evp.h>
#include <string>
#include <vector>

class ChaChaCipher : public Encryptor {
public:
    ChaChaCipher();
    ~ChaChaCipher();

    bool encrypt(const std::vector<uint8_t> &input, 
                 const std::string &key, 
                 std::vector<uint8_t> &output) override;

    bool decrypt(const std::vector<uint8_t> &input, 
                 const std::string &key, 
                 std::vector<uint8_t> &output) override;

private:
    static const int KEY_SIZE = 32;
    static const int IV_SIZE = 16;    
    static const int SALT_SIZE = 8; 

    void deriveKeyAndIV(const std::string &phrase, 
                        const unsigned char *salt, 
                        unsigned char *key, 
                        unsigned char *iv);
};