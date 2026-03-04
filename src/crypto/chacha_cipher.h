#pragma once

#include "encryptor.h"
#include "key_derivation.h"
#include "file_format.h"
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
    static const int IV_SIZE = 16;   // 4-byte counter + 12-byte nonce
    static const int SALT_SIZE = KeyDerivation::SALT_SIZE;
};
