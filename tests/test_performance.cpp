#include <gtest/gtest.h>
#include "metrics/performance.h"
#include "crypto/aes_cipher.h"
#include "crypto/chacha_cipher.h"
#include <vector>
#include <thread>
#include <chrono>

static std::vector<uint8_t> makeTestData(size_t size) {
    std::vector<uint8_t> data(size);
    for (size_t i = 0; i < size; ++i) {
        data[i] = static_cast<uint8_t>(i % 256);
    }
    return data;
}

// ========================
// Timer Tests
// ========================

TEST(PerformanceTracker, TimerMeasuresPositive) {
    PerformanceTracker tracker;
    tracker.startTimer();
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    tracker.stopTimer();
    EXPECT_GT(tracker.getElapsedSeconds(), 0.0);
}

TEST(PerformanceTracker, ThroughputCalculation) {
    PerformanceTracker tracker;
    tracker.startTimer();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    tracker.stopTimer();

    size_t bytes = 1024 * 1024; // 1 MB
    double throughput = tracker.getThroughputMBps(bytes);
    // Should be ~10 MB/s (1MB / 0.1s) give or take timing variance
    EXPECT_GT(throughput, 0.0);
}

// ========================
// Overhead Calculation Tests
// ========================

TEST(PerformanceTracker, OverheadCalculation) {
    double overhead = PerformanceTracker::computeOverhead(1000, 1100);
    EXPECT_NEAR(overhead, 10.0, 0.01);
}

TEST(PerformanceTracker, OverheadZero) {
    double overhead = PerformanceTracker::computeOverhead(1000, 1000);
    EXPECT_NEAR(overhead, 0.0, 0.01);
}

TEST(PerformanceTracker, OverheadEmptyInput) {
    double overhead = PerformanceTracker::computeOverhead(0, 100);
    EXPECT_NEAR(overhead, 0.0, 0.01);
}

// ========================
// Memory Usage Test
// ========================

TEST(PerformanceTracker, MemoryUsageNonZero) {
    size_t mem = PerformanceTracker::getCurrentMemoryUsage();
    EXPECT_GT(mem, 0u);
}

// ========================
// Build Report Test
// ========================

TEST(PerformanceTracker, BuildReport) {
    auto m = PerformanceTracker::buildReport("aes256", "cbc", 1024, 1040, 0.001, 0.002);
    EXPECT_EQ(m.algorithm, "aes256");
    EXPECT_EQ(m.mode, "cbc");
    EXPECT_EQ(m.inputSize, 1024u);
    EXPECT_EQ(m.encryptedSize, 1040u);
    EXPECT_GT(m.encryptThroughputMBps, 0.0);
    EXPECT_GT(m.decryptThroughputMBps, 0.0);
    EXPECT_GT(m.overheadPercent, 0.0);
}

// ========================
// Throughput Sanity Checks
// ========================

TEST(ThroughputSanity, AesCBCThroughputReasonable) {
    AesCipher cipher("cbc");
    auto input = makeTestData(256 * 1024); // 256 KB
    std::vector<uint8_t> encrypted;

    PerformanceTracker tracker;
    tracker.startTimer();
    ASSERT_TRUE(cipher.encrypt(input, "benchpass", encrypted));
    tracker.stopTimer();

    double mbps = tracker.getThroughputMBps(input.size());
    // Encryption should achieve at least 1 MB/s on any modern hardware
    EXPECT_GT(mbps, 1.0);
}

TEST(ThroughputSanity, ChaCha20ThroughputReasonable) {
    ChaChaCipher cipher;
    auto input = makeTestData(256 * 1024); // 256 KB
    std::vector<uint8_t> encrypted;

    PerformanceTracker tracker;
    tracker.startTimer();
    ASSERT_TRUE(cipher.encrypt(input, "benchpass", encrypted));
    tracker.stopTimer();

    double mbps = tracker.getThroughputMBps(input.size());
    EXPECT_GT(mbps, 1.0);
}
