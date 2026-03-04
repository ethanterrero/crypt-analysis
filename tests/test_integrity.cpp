#include <gtest/gtest.h>
#include "utils/hash.h"
#include <vector>
#include <string>
#include <fstream>
#include <cstdio>

// ========================
// Hash Buffer Tests
// ========================

TEST(HashUtil, BufferHashConsistency) {
    std::vector<uint8_t> data = {0x48, 0x65, 0x6C, 0x6C, 0x6F}; // "Hello"
    auto hash1 = HashUtil::hash_buffer(data);
    auto hash2 = HashUtil::hash_buffer(data);
    EXPECT_EQ(hash1, hash2);
    EXPECT_EQ(hash1.size(), 32u); // SHA-256 = 32 bytes
}

TEST(HashUtil, DifferentDataDifferentHash) {
    std::vector<uint8_t> data1 = {0x01, 0x02, 0x03};
    std::vector<uint8_t> data2 = {0x01, 0x02, 0x04};
    auto hash1 = HashUtil::hash_buffer(data1);
    auto hash2 = HashUtil::hash_buffer(data2);
    EXPECT_NE(hash1, hash2);
}

TEST(HashUtil, EmptyBufferHash) {
    std::vector<uint8_t> data;
    auto hash = HashUtil::hash_buffer(data);
    EXPECT_EQ(hash.size(), 32u);
    // SHA-256 of empty string is well-known
    std::string hex = HashUtil::to_hex_string(hash);
    EXPECT_EQ(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

// ========================
// Hash Match Tests
// ========================

TEST(HashUtil, HashesMatch) {
    std::vector<uint8_t> data = {0x41, 0x42, 0x43};
    auto hash1 = HashUtil::hash_buffer(data);
    auto hash2 = HashUtil::hash_buffer(data);
    EXPECT_TRUE(HashUtil::hashes_match(hash1, hash2));
}

TEST(HashUtil, HashesDontMatch) {
    std::vector<uint8_t> data1 = {0x41};
    std::vector<uint8_t> data2 = {0x42};
    EXPECT_FALSE(HashUtil::hashes_match(
        HashUtil::hash_buffer(data1),
        HashUtil::hash_buffer(data2)));
}

// ========================
// Hex String Tests
// ========================

TEST(HashUtil, HexStringLength) {
    std::vector<uint8_t> data = {0xDE, 0xAD};
    auto hash = HashUtil::hash_buffer(data);
    std::string hex = HashUtil::to_hex_string(hash);
    EXPECT_EQ(hex.size(), 64u); // 32 bytes * 2 hex chars
}

TEST(HashUtil, HexStringFormat) {
    std::vector<uint8_t> hash = {0x00, 0xFF, 0x0A, 0xBC};
    std::string hex = HashUtil::to_hex_string(hash);
    EXPECT_EQ(hex, "00ff0abc");
}

// ========================
// File Hash Tests
// ========================

TEST(HashUtil, FileHashMatchesBufferHash) {
    // Write temp file
    std::string tmpPath = "/tmp/test_hash_file.bin";
    std::vector<uint8_t> data = {0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64};
    {
        std::ofstream out(tmpPath, std::ios::binary);
        out.write(reinterpret_cast<const char*>(data.data()), data.size());
    }

    auto fileHash = HashUtil::hash_file(tmpPath);
    auto bufHash = HashUtil::hash_buffer(data);
    EXPECT_TRUE(HashUtil::hashes_match(fileHash, bufHash));

    std::remove(tmpPath.c_str());
}

TEST(HashUtil, FileHashDetectsCorruption) {
    std::string tmpPath = "/tmp/test_hash_corrupt.bin";
    std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04, 0x05};
    {
        std::ofstream out(tmpPath, std::ios::binary);
        out.write(reinterpret_cast<const char*>(data.data()), data.size());
    }
    auto originalHash = HashUtil::hash_file(tmpPath);

    // Corrupt the file
    data[2] = 0xFF;
    {
        std::ofstream out(tmpPath, std::ios::binary);
        out.write(reinterpret_cast<const char*>(data.data()), data.size());
    }
    auto corruptHash = HashUtil::hash_file(tmpPath);

    EXPECT_FALSE(HashUtil::hashes_match(originalHash, corruptHash));

    std::remove(tmpPath.c_str());
}

TEST(HashUtil, NonExistentFileThrows) {
    EXPECT_THROW(HashUtil::hash_file("/tmp/nonexistent_file_12345.bin"), std::runtime_error);
}
