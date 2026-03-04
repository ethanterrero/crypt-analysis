#include "key_derivation.h"
#include <openssl/evp.h>
#include <stdexcept>
#include <vector>

namespace KeyDerivation {

void deriveKeyAndIV(const std::string &password,
                    const unsigned char *salt,
                    int saltLen,
                    unsigned char *key, int keyLen,
                    unsigned char *iv, int ivLen) {
    // Derive (keyLen + ivLen) bytes in a single PBKDF2 call
    int totalLen = keyLen + ivLen;
    std::vector<unsigned char> derived(totalLen);

    if (1 != PKCS5_PBKDF2_HMAC(password.c_str(),
                                 static_cast<int>(password.length()),
                                 salt, saltLen,
                                 PBKDF2_ITERATIONS,
                                 EVP_sha256(),
                                 totalLen,
                                 derived.data())) {
        throw std::runtime_error("PBKDF2 key derivation failed");
    }

    // First keyLen bytes → key, remaining ivLen bytes → IV
    memcpy(key, derived.data(), keyLen);
    memcpy(iv, derived.data() + keyLen, ivLen);
}

} // namespace KeyDerivation
