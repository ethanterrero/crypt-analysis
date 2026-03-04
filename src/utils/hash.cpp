#include "hash.h"
#include <openssl/evp.h>
#include <fstream>
#include <stdexcept>
#include <sstream>
#include <iomanip>

namespace HashUtil {

std::vector<uint8_t> hash_buffer(const std::vector<uint8_t> &data) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create hash context");

    std::vector<uint8_t> digest(EVP_MD_size(EVP_sha256()));
    unsigned int len = 0;

    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data.data(), data.size());
    EVP_DigestFinal_ex(ctx, digest.data(), &len);
    EVP_MD_CTX_free(ctx);

    digest.resize(len);
    return digest;
}

std::vector<uint8_t> hash_file(const std::string &path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) throw std::runtime_error("Cannot open file for hashing: " + path);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create hash context");

    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);

    char buf[8192];
    while (file.read(buf, sizeof(buf))) {
        EVP_DigestUpdate(ctx, buf, file.gcount());
    }
    // Process any remaining bytes
    if (file.gcount() > 0) {
        EVP_DigestUpdate(ctx, buf, file.gcount());
    }

    std::vector<uint8_t> digest(EVP_MD_size(EVP_sha256()));
    unsigned int len = 0;
    EVP_DigestFinal_ex(ctx, digest.data(), &len);
    EVP_MD_CTX_free(ctx);

    digest.resize(len);
    return digest;
}

bool hashes_match(const std::vector<uint8_t> &a, const std::vector<uint8_t> &b) {
    return a == b;
}

std::string to_hex_string(const std::vector<uint8_t> &hash) {
    std::ostringstream ss;
    for (auto byte : hash) {
        ss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

} // namespace HashUtil
