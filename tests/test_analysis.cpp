#include <gtest/gtest.h>
#include "analysis/entropy.h"
#include "analysis/frequency.h"
#include "analysis/avalanche.h"
#include "crypto/aes_cipher.h"
#include "crypto/chacha_cipher.h"
#include <vector>
#include <cmath>
#include <iostream>
#include <string>

static std::vector<uint8_t> uniform_buffer(size_t count, uint8_t value) {
    return std::vector<uint8_t>(count, value);
}

static std::vector<uint8_t> all_bytes_buffer(size_t reps = 1) {
    std::vector<uint8_t> buf(256 * reps);
    for (size_t i = 0; i < buf.size(); ++i) {
        buf[i] = static_cast<uint8_t>(i % 256);
    }
    return buf;
}

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

TEST(Entropy, HighEntropyForPseudoRandomData) {
    auto result = measure_entropy(pseudo_random_buffer(64 * 1024));
    std::cout << "\n[ DATA ] Entropy Analysis (Pseudo-Random Calibration):\n";
    std::cout << "  Bytes Analyzed: " << result.total_bytes << "\n";
    std::cout << "  Calculated Entropy: " << result.entropy << " bits/byte\n";
    EXPECT_GT(result.entropy, 7.5);
}

TEST(Entropy, RealAes256CbcHasMaxEntropy) {
    std::vector<uint8_t> pt(64 * 1024, 0x00);
    std::vector<uint8_t> ct;
    AesCipher aes("cbc");
    ASSERT_TRUE(aes.encrypt(pt, "pass", ct));
    auto result = measure_entropy(ct);
    std::cout << "\n========================================\n";
    std::cout << "[ DATA ] Shannon Entropy (AES-256-CBC):\n";
    std::cout << "  Bytes Analyzed: " << result.total_bytes << "\n";
    std::cout << "  Calculated Entropy: " << result.entropy << " bits/byte (Ideal: ~8.0)\n";
    std::cout << "========================================\n";
    EXPECT_GT(result.entropy, 7.95);
}

TEST(Entropy, RealAes256GcmHasMaxEntropy) {
    std::vector<uint8_t> pt(64 * 1024, 0x00);
    std::vector<uint8_t> ct;
    AesCipher aes("gcm");
    ASSERT_TRUE(aes.encrypt(pt, "pass", ct));
    auto result = measure_entropy(ct);
    std::cout << "\n========================================\n";
    std::cout << "[ DATA ] Shannon Entropy (AES-256-GCM):\n";
    std::cout << "  Bytes Analyzed: " << result.total_bytes << "\n";
    std::cout << "  Calculated Entropy: " << result.entropy << " bits/byte (Ideal: ~8.0)\n";
    std::cout << "========================================\n";
    EXPECT_GT(result.entropy, 7.95);
}

TEST(Entropy, RealAes256EcbRevealsStructure) {
    std::vector<uint8_t> pt(64 * 1024, 0x00);
    std::vector<uint8_t> ct;
    AesCipher aes("ecb");
    ASSERT_TRUE(aes.encrypt(pt, "pass", ct));
    auto result = measure_entropy(ct);
    std::cout << "\n========================================\n";
    std::cout << "[ DATA ] Shannon Entropy (AES-256-ECB):\n";
    std::cout << "  Bytes Analyzed: " << result.total_bytes << "\n";
    std::cout << "  Calculated Entropy: " << result.entropy << " bits/byte (WARNING: LOW)\n";
    std::cout << "========================================\n";
    EXPECT_LT(result.entropy, 5.0);
}

TEST(Entropy, RealChaCha20HasMaxEntropy) {
    std::vector<uint8_t> pt(64 * 1024, 0x00);
    std::vector<uint8_t> ct;
    ChaChaCipher chacha;
    ASSERT_TRUE(chacha.encrypt(pt, "pass", ct));
    auto result = measure_entropy(ct);
    std::cout << "\n========================================\n";
    std::cout << "[ DATA ] Shannon Entropy (ChaCha20):\n";
    std::cout << "  Bytes Analyzed: " << result.total_bytes << "\n";
    std::cout << "  Calculated Entropy: " << result.entropy << " bits/byte (Ideal: ~8.0)\n";
    std::cout << "========================================\n";
    EXPECT_GT(result.entropy, 7.95);
}

// ========================
// Chi-Squared Frequency Tests
// ========================

TEST(Frequency, RealAes256CbcIsUniform) {
    std::vector<uint8_t> pt(64 * 1024, 0x00);
    std::vector<uint8_t> ct;
    AesCipher aes("cbc");
    ASSERT_TRUE(aes.encrypt(pt, "pass", ct));
    auto result = run_frequency_test(ct);
    std::cout << "\n========================================\n";
    std::cout << "[ DATA ] Chi-Squared Analysis (AES-256-CBC):\n";
    std::cout << "  Chi-Squared Stat (X^2): " << result.chi_squared << "\n";
    std::cout << "  P-Value: " << result.p_value << " (PASS: 0.05-0.95)\n";
    std::cout << "========================================\n";
    EXPECT_GE(result.p_value, 0.05);
}

TEST(Frequency, RealAes256GcmIsUniform) {
    std::vector<uint8_t> pt(64 * 1024, 0x00);
    std::vector<uint8_t> ct;
    AesCipher aes("gcm");
    ASSERT_TRUE(aes.encrypt(pt, "pass", ct));
    auto result = run_frequency_test(ct);
    std::cout << "\n========================================\n";
    std::cout << "[ DATA ] Chi-Squared Analysis (AES-256-GCM):\n";
    std::cout << "  Chi-Squared Stat (X^2): " << result.chi_squared << "\n";
    std::cout << "  P-Value: " << result.p_value << " (PASS: 0.05-0.95)\n";
    std::cout << "========================================\n";
    EXPECT_GE(result.p_value, 0.05);
}

TEST(Frequency, RealAes256EcbRevealsStructure) {
    std::vector<uint8_t> pt(64 * 1024, 0x00);
    std::vector<uint8_t> ct;
    AesCipher aes("ecb");
    ASSERT_TRUE(aes.encrypt(pt, "pass", ct));
    auto result = run_frequency_test(ct);
    std::cout << "\n========================================\n";
    std::cout << "[ DATA ] Chi-Squared Analysis (AES-256-ECB):\n";
    std::cout << "  Chi-Squared Stat (X^2): " << result.chi_squared << "\n";
    std::cout << "  P-Value: " << result.p_value << " (FAIL: < 0.05)\n";
    std::cout << "========================================\n";
    EXPECT_LT(result.p_value, 0.05);
}

TEST(Frequency, RealChaCha20IsUniform) {
    std::vector<uint8_t> pt(64 * 1024, 0x00);
    std::vector<uint8_t> ct;
    ChaChaCipher chacha;
    ASSERT_TRUE(chacha.encrypt(pt, "pass", ct));
    auto result = run_frequency_test(ct);
    std::cout << "\n========================================\n";
    std::cout << "[ DATA ] Chi-Squared Analysis (ChaCha20):\n";
    std::cout << "  Chi-Squared Stat (X^2): " << result.chi_squared << "\n";
    std::cout << "  P-Value: " << result.p_value << " (PASS: 0.05-0.95)\n";
    std::cout << "========================================\n";
    EXPECT_GE(result.p_value, 0.05);
}

// ========================
// Avalanche Effect Tests
// ========================

TEST(Avalanche, AesCbcAverageChangeNearFiftyPercent) {
    std::vector<uint8_t> pt(64, 0xAA);
    auto result = run_avalanche_test(CipherType::AES256_CBC, pt, 128);
    std::cout << "\n========================================\n";
    std::cout << "[ DATA ] Avalanche Effect (AES-256-CBC):\n";
    std::cout << "  Bits Tested: " << result.bits_tested << "\n";
    std::cout << "  Avg Bit Change: " << result.avg_bit_change_pct << "% (~50% IDEAL)\n";
    std::cout << "========================================\n";
    EXPECT_GT(result.avg_bit_change_pct, 40.0);
}

TEST(Avalanche, ChaCha20AverageChangeIsNearZero) {
    std::vector<uint8_t> pt(64, 0xBB);
    auto result = run_avalanche_test(CipherType::CHACHA20, pt, 64);
    std::cout << "\n========================================\n";
    std::cout << "[ DATA ] Avalanche Effect (ChaCha20):\n";
    std::cout << "  Bits Tested: " << result.bits_tested << "\n";
    std::cout << "  Avg Bit Change: " << result.avg_bit_change_pct << "%\n";
    std::cout << "========================================\n";
    EXPECT_LT(result.avg_bit_change_pct, 5.0);
}