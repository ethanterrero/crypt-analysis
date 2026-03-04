#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace HashUtil {

// SHA-256 hash of a byte buffer
std::vector<uint8_t> hash_buffer(const std::vector<uint8_t> &data);

// SHA-256 hash of a file (streaming, memory-efficient)
std::vector<uint8_t> hash_file(const std::string &path);

// Compare two hash digests
bool hashes_match(const std::vector<uint8_t> &a, const std::vector<uint8_t> &b);

// Convert a hash digest to a hex string
std::string to_hex_string(const std::vector<uint8_t> &hash);

} // namespace HashUtil
