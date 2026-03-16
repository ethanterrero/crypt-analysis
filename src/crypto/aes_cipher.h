#pragma once

#include "encryptor.h"
#include "key_derivation.h"
#include "file_format.h"
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <string>
#include <vector>

class AesCipher : public Encryptor {
public:
    explicit AesCipher(const std::string &mode = "cbc");
    ~AesCipher();

    bool encrypt(const std::vector<uint8_t> &input,
                 const std::string &key,
                 std::vector<uint8_t> &output) override;

    bool decrypt(const std::vector<uint8_t> &input,
                 const std::string &key,
                 std::vector<uint8_t> &output) override;

private:
    std::string m_mode;
    static const int KEY_SIZE = 32;  // 256 bits
    static const int IV_SIZE = 16;   // 128 bits
    static const int SALT_SIZE = KeyDerivation::SALT_SIZE;
    const EVP_CIPHER* getCipher() const;
    int getIVSize() const;
};
