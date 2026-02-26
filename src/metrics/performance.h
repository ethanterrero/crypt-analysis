#pragma once

#include <chrono>
#include <cstdint>
#include <string>

struct PerformanceMetrics {
    double encryptTimeSeconds = 0.0;
    double decryptTimeSeconds = 0.0;
    double encryptThroughputMBps = 0.0;
    double decryptThroughputMBps = 0.0;
    size_t inputSize = 0;
    size_t encryptedSize = 0;
    double overheadPercent = 0.0;
    size_t peakMemoryBytes = 0;
    std::string algorithm;
    std::string mode;
};

class PerformanceTracker {
public:
    void startTimer();
    void stopTimer();

    double getElapsedSeconds() const;
    double getThroughputMBps(size_t bytes) const;
    static double computeOverhead(size_t inputSize, size_t outputSize);
    static size_t getCurrentMemoryUsage();

    // Fill a metrics struct with results from an encrypt+decrypt cycle
    static PerformanceMetrics buildReport(const std::string &algorithm,
                                          const std::string &mode,
                                          size_t inputSize,
                                          size_t encryptedSize,
                                          double encryptSec,
                                          double decryptSec);

    static void printReport(const PerformanceMetrics &m);

private:
    std::chrono::time_point<std::chrono::high_resolution_clock> m_start;
    std::chrono::time_point<std::chrono::high_resolution_clock> m_end;
};
