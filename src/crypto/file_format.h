#pragma once

#include <cstdint>
#include <string>
#include <vector>

// File header layout:
// [2B magic "FC"] [1B algorithm] [1B mode] [16B salt] [IV...] [ciphertext...]

namespace FileFormat {

static const uint8_t MAGIC[2] = {'F', 'C'};
static const size_t MAGIC_SIZE = 2;

// Algorithm IDs
enum AlgorithmID : uint8_t {
    ALGO_AES256   = 0x01,
    ALGO_CHACHA20 = 0x02,
};

// Mode IDs
enum ModeID : uint8_t {
    MODE_CBC = 0x01,
    MODE_ECB = 0x02,
    MODE_NONE = 0x00,  // for stream ciphers like ChaCha20
};

// Convert algorithm string to ID
AlgorithmID algorithmFromString(const std::string &name);

// Convert algorithm ID to string
std::string algorithmToString(AlgorithmID id);

// Convert mode string to ID
ModeID modeFromString(const std::string &name);

// Convert mode ID to string
std::string modeToString(ModeID id);

// Get IV size for a given algorithm/mode combination
int getIVSize(AlgorithmID algo, ModeID mode);

// Build the header bytes (magic + algo + mode + salt + iv)
std::vector<uint8_t> buildHeader(AlgorithmID algo, ModeID mode,
                                  const uint8_t *salt, int saltLen,
                                  const uint8_t *iv, int ivLen);

// Parse header from encrypted data. Returns offset where ciphertext begins.
// Fills out algo, mode, salt, iv from the header.
size_t parseHeader(const std::vector<uint8_t> &data,
                   AlgorithmID &algo, ModeID &mode,
                   std::vector<uint8_t> &salt,
                   std::vector<uint8_t> &iv);

} // namespace FileFormat
