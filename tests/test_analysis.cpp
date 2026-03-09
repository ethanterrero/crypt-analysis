#include <gtest/gtest.h>
#include "analysis/entropy.h"
#include "analysis/frequency.h"
#include "analysis/avalanche.h"
#include <vector>
#include <cmath>

// Helper: buffer of `count` bytes all set to `value`
static std::vector<uint8_t> uniform_buffer(size_t count, uint8_t value) {
    return std::vector<uint8_t>(count, value);
}

// Helper: buffer containing each byte value exactly `reps` times, in order
static std::vector<uint8_t> all_bytes_buffer(size_t reps = 1) {
    std::vector<uint8_t> buf(256 * reps);
    for (size_t i = 0; i < buf.size(); ++i) {
        buf[i] = static_cast<uint8_t>(i % 256);
    }
    return buf;
}

// Helper: pseudo-random buffer using Numerical Recipes LCG (period 2^32).
// Taking bits 16-23 produces 8-bit values that are well-distributed over
// the full period, so large samples give a flat byte histogram.
static std::vector<uint8_t> pseudo_random_buffer(size_t n, uint32_t seed = 42) {
    std::vector<uint8_t> buf(n);
    uint32_t x = seed;
    for (size_t i = 0; i < n; ++i) {
        x = x * 1664525u + 1013904223u;
        buf[i] = static_cast<uint8_t>((x >> 16) & 0xFF);
    }
    return buf;
}

// ========================
// Shannon Entropy Tests
// ========================

TEST(Entropy, EmptyInputReturnsZeroTotalBytes) {
    auto result = measure_entropy({});
    EXPECT_EQ(result.total_bytes, 0u);
    EXPECT_DOUBLE_EQ(result.entropy, 0.0);
}

TEST(Entropy, AllSameByteHasZeroEntropy) {
    // Only one byte value present → only one probability term → H = 0
    auto result = measure_entropy(uniform_buffer(1024, 0xAB));
    EXPECT_NEAR(result.entropy, 0.0, 1e-9);
    EXPECT_EQ(result.total_bytes, 1024u);
}

TEST(Entropy, MaxEntropyWhenAllBytesEquallyRepresented) {
    // 256 distinct values each appearing once → H = -256*(1/256 * log2(1/256)) = 8.0
    auto result = measure_entropy(all_bytes_buffer(1));
    EXPECT_NEAR(result.entropy, 8.0, 1e-9);
}

TEST(Entropy, TotalBytesMatchesInput) {
    auto buf = all_bytes_buffer(4);
    auto result = measure_entropy(buf);
    EXPECT_EQ(result.total_bytes, buf.size());
}

TEST(Entropy, MostCommonByteTrackedCorrectly) {
    // All 256 values once, then 0x42 again — 0x42 should be most common
    auto buf = all_bytes_buffer(1);
    buf.push_back(0x42);
    auto result = measure_entropy(buf);
    EXPECT_EQ(result.most_common_byte, 0x42);
}

TEST(Entropy, FreqBoundsAreValid) {
    auto result = measure_entropy(all_bytes_buffer(40)); // 10240 bytes, perfectly uniform
    EXPECT_GE(result.min_byte_freq, 0.0);
    EXPECT_LE(result.max_byte_freq, 1.0);
    EXPECT_LE(result.min_byte_freq, result.max_byte_freq);
}

TEST(Entropy, HighEntropyForPseudoRandomData) {
    // 64 KB of LCG output should have entropy well above 7.5
    auto result = measure_entropy(pseudo_random_buffer(64 * 1024));
    EXPECT_GT(result.entropy, 7.5);
}

// ========================
// Chi-Squared Frequency Tests
// ========================

TEST(Frequency, EmptyInputReturnsZeroTotalBytes) {
    auto result = run_frequency_test({});
    EXPECT_EQ(result.total_bytes, 0u);
}

TEST(Frequency, DegreesOfFreedomIsAlways255) {
    auto result = run_frequency_test(all_bytes_buffer(4));
    EXPECT_EQ(result.degrees_of_freedom, 255);
}

TEST(Frequency, TotalBytesMatchesInput) {
    auto buf = all_bytes_buffer(8);
    auto result = run_frequency_test(buf);
    EXPECT_EQ(result.total_bytes, buf.size());
}

TEST(Frequency, NonUniformDataHasLowPValue) {
    // All same byte → extreme skew → chi_squared is enormous → p_value ≈ 0
    auto result = run_frequency_test(uniform_buffer(4096, 0x00));
    EXPECT_LT(result.p_value, 0.05);
}

TEST(Frequency, PerfectlyUniformDataHasSuspiciouslyHighPValue) {
    // chi_squared = 0 (all counts equal expected) → p_value = 1.0 → NOTE band
    auto result = run_frequency_test(all_bytes_buffer(1));
    EXPECT_NEAR(result.chi_squared, 0.0, 1e-9);
    EXPECT_GT(result.p_value, 0.95);
}

TEST(Frequency, PseudoRandomDataPassesUniformityTest) {
    // 51200 bytes: expected count per byte = 200; LCG is well-distributed enough
    // to land p_value in the PASS band [0.05, 0.95]
    auto result = run_frequency_test(pseudo_random_buffer(256 * 200));
    EXPECT_GE(result.p_value, 0.05);
    EXPECT_LE(result.p_value, 0.95);
}

TEST(Frequency, CountsAreConsistentForSingleByteBuffer) {
    // All 0xFF → most_common_byte = 0xFF, most_common_count = total
    auto buf = uniform_buffer(256, 0xFF);
    auto result = run_frequency_test(buf);
    EXPECT_EQ(result.most_common_byte, 0xFF);
    EXPECT_EQ(result.most_common_count, 256u);
}

// ========================
// Avalanche Effect Tests
// ========================

TEST(Avalanche, BitsTested) {
    // max_bits_to_test=32 with a 32-byte plaintext — should test exactly 32 positions
    std::vector<uint8_t> pt(32, 0xAA);
    auto result = run_avalanche_test(CipherType::AES256_CBC, pt, 32);
    EXPECT_EQ(result.bits_tested, 32u);
}

TEST(Avalanche, CiphertextBitsPositive) {
    std::vector<uint8_t> pt(64, 0x55);
    auto result = run_avalanche_test(CipherType::AES256_CBC, pt, 8);
    EXPECT_GT(result.ciphertext_bits, 0u);
}

TEST(Avalanche, AesCbcAverageChangeNearFiftyPercent) {
    // Block cipher ideal: ~50% output bits change per 1-bit input flip.
    // 128 bit positions on 64-byte input gives enough samples for a stable mean.
    std::vector<uint8_t> pt(64, 0xAA);
    auto result = run_avalanche_test(CipherType::AES256_CBC, pt, 128);
    EXPECT_GT(result.avg_bit_change_pct, 25.0);
    EXPECT_LT(result.avg_bit_change_pct, 75.0);
}

TEST(Avalanche, ChaCha20AverageChangeIsNearZero) {
    // Stream cipher: C = P XOR keystream → exactly 1 ciphertext bit changes per flip.
    // For 64-byte (512-bit) ciphertext: 1/512 * 100 ≈ 0.2% — far below 5%.
    std::vector<uint8_t> pt(64, 0xBB);
    auto result = run_avalanche_test(CipherType::CHACHA20, pt, 64);
    EXPECT_LT(result.avg_bit_change_pct, 5.0);
}

TEST(Avalanche, AesEcbProducesNonZeroResult) {
    // ECB encrypts blocks independently — some diffusion within affected blocks
    std::vector<uint8_t> pt(64, 0x00);
    auto result = run_avalanche_test(CipherType::AES256_ECB, pt, 32);
    EXPECT_GT(result.bits_tested, 0u);
    EXPECT_GT(result.avg_bit_change_pct, 0.0);
}

TEST(Avalanche, MinLeqAvgLeqMax) {
    std::vector<uint8_t> pt(32, 0x5A);
    auto result = run_avalanche_test(CipherType::AES256_CBC, pt, 32);
    EXPECT_LE(result.min_bit_change_pct, result.avg_bit_change_pct);
    EXPECT_GE(result.max_bit_change_pct, result.avg_bit_change_pct);
}
