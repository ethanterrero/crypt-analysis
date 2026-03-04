#include "file_format.h"
#include "key_derivation.h"
#include <stdexcept>
#include <cstring>

namespace FileFormat {

AlgorithmID algorithmFromString(const std::string &name) {
    if (name == "aes256") return ALGO_AES256;
    if (name == "chacha20") return ALGO_CHACHA20;
    throw std::runtime_error("Unknown algorithm: " + name);
}

std::string algorithmToString(AlgorithmID id) {
    switch (id) {
        case ALGO_AES256:   return "aes256";
        case ALGO_CHACHA20: return "chacha20";
        default: throw std::runtime_error("Unknown algorithm ID");
    }
}

ModeID modeFromString(const std::string &name) {
    if (name == "cbc")  return MODE_CBC;
    if (name == "ecb")  return MODE_ECB;
    if (name == "gcm")  return MODE_GCM;
    if (name == "none") return MODE_NONE;
    throw std::runtime_error("Unknown mode: " + name);
}

std::string modeToString(ModeID id) {
    switch (id) {
        case MODE_CBC:  return "cbc";
        case MODE_ECB:  return "ecb";
        case MODE_GCM:  return "gcm";
        case MODE_NONE: return "none";
        default: throw std::runtime_error("Unknown mode ID");
    }
}

int getIVSize(AlgorithmID algo, ModeID mode) {
    if (algo == ALGO_CHACHA20) return 16;  // 4-byte counter + 12-byte nonce
    // AES modes
    if (mode == MODE_ECB) return 0;
    if (mode == MODE_GCM) return 12;
    return 16; // CBC default
}

std::vector<uint8_t> buildHeader(AlgorithmID algo, ModeID mode,
                                  const uint8_t *salt, int saltLen,
                                  const uint8_t *iv, int ivLen) {
    std::vector<uint8_t> header;
    header.push_back(MAGIC[0]);
    header.push_back(MAGIC[1]);
    header.push_back(static_cast<uint8_t>(algo));
    header.push_back(static_cast<uint8_t>(mode));
    header.insert(header.end(), salt, salt + saltLen);
    header.insert(header.end(), iv, iv + ivLen);
    return header;
}

size_t parseHeader(const std::vector<uint8_t> &data,
                   AlgorithmID &algo, ModeID &mode,
                   std::vector<uint8_t> &salt,
                   std::vector<uint8_t> &iv) {
    // Minimum header: 2 (magic) + 1 (algo) + 1 (mode) + salt_size
    const int saltSize = KeyDerivation::SALT_SIZE;
    size_t minSize = MAGIC_SIZE + 2 + saltSize;
    if (data.size() < minSize) {
        throw std::runtime_error("File too small to contain a valid header");
    }

    // Check magic bytes
    if (data[0] != MAGIC[0] || data[1] != MAGIC[1]) {
        throw std::runtime_error("Invalid file format (missing FC magic bytes)");
    }

    algo = static_cast<AlgorithmID>(data[2]);
    mode = static_cast<ModeID>(data[3]);

    // Validate known values
    algorithmToString(algo); // throws if unknown
    modeToString(mode);      // throws if unknown

    int ivSize = getIVSize(algo, mode);

    size_t headerSize = MAGIC_SIZE + 2 + saltSize + ivSize;
    if (data.size() < headerSize) {
        throw std::runtime_error("File too small for header with IV");
    }

    salt.assign(data.begin() + 4, data.begin() + 4 + saltSize);
    iv.assign(data.begin() + 4 + saltSize, data.begin() + 4 + saltSize + ivSize);

    return headerSize;
}

} // namespace FileFormat
