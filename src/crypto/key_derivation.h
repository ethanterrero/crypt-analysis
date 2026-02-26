#pragma once

#include <openssl/evp.h>
#include <string>

// Shared PBKDF2 key derivation for all cipher implementations
namespace KeyDerivation {

static const int SALT_SIZE = 16;       // 128-bit salt
static const int PBKDF2_ITERATIONS = 100000;

// Derive a key and IV from a password + salt using PBKDF2-HMAC-SHA256
void deriveKeyAndIV(const std::string &password,
                    const unsigned char *salt,
                    int saltLen,
                    unsigned char *key, int keyLen,
                    unsigned char *iv, int ivLen);

} // namespace KeyDerivation
