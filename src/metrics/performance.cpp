#include "performance.h"
#include <iostream>
#include <iomanip>

#ifdef __APPLE__
#include <mach/mach.h>
#elif defined(__linux__)
#include <fstream>
#include <string>
#endif

void PerformanceTracker::startTimer() {
    m_start = std::chrono::high_resolution_clock::now();
}

void PerformanceTracker::stopTimer() {
    m_end = std::chrono::high_resolution_clock::now();
}

double PerformanceTracker::getElapsedSeconds() const {
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(m_end - m_start);
    return duration.count() / 1e6;
}

double PerformanceTracker::getThroughputMBps(size_t bytes) const {
    double sec = getElapsedSeconds();
    if (sec <= 0.0) return 0.0;
    return (static_cast<double>(bytes) / (1024.0 * 1024.0)) / sec;
}

double PerformanceTracker::computeOverhead(size_t inputSize, size_t outputSize) {
    if (inputSize == 0) return 0.0;
    return (static_cast<double>(outputSize) - static_cast<double>(inputSize))
           / static_cast<double>(inputSize) * 100.0;
}

size_t PerformanceTracker::getCurrentMemoryUsage() {
#ifdef __APPLE__
    mach_task_basic_info_data_t info;
    mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
    if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO,
                  reinterpret_cast<task_info_t>(&info), &count) == KERN_SUCCESS) {
        return info.resident_size;
    }
#elif defined(__linux__)
    std::ifstream statm("/proc/self/statm");
    if (statm) {
        size_t pages;
        statm >> pages; // total program size
        return pages * 4096;
    }
#endif
    return 0;
}

PerformanceMetrics PerformanceTracker::buildReport(const std::string &algorithm,
                                                    const std::string &mode,
                                                    size_t inputSize,
                                                    size_t encryptedSize,
                                                    double encryptSec,
                                                    double decryptSec) {
    PerformanceMetrics m;
    m.algorithm = algorithm;
    m.mode = mode;
    m.inputSize = inputSize;
    m.encryptedSize = encryptedSize;
    m.encryptTimeSeconds = encryptSec;
    m.decryptTimeSeconds = decryptSec;

    double mb = static_cast<double>(inputSize) / (1024.0 * 1024.0);
    m.encryptThroughputMBps = (encryptSec > 0) ? mb / encryptSec : 0.0;
    m.decryptThroughputMBps = (decryptSec > 0) ? mb / decryptSec : 0.0;
    m.overheadPercent = computeOverhead(inputSize, encryptedSize);
    m.peakMemoryBytes = getCurrentMemoryUsage();
    return m;
}

void PerformanceTracker::printReport(const PerformanceMetrics &m) {
    std::cout << std::fixed << std::setprecision(4);
    std::cout << "--- Performance Report ---\n";
    std::cout << "Algorithm:           " << m.algorithm << "\n";
    std::cout << "Mode:                " << m.mode << "\n";
    std::cout << "Input size:          " << m.inputSize << " bytes\n";
    std::cout << "Encrypted size:      " << m.encryptedSize << " bytes\n";
    std::cout << "Overhead:            " << std::setprecision(2) << m.overheadPercent << "%\n";
    std::cout << "Encrypt time:        " << std::setprecision(6) << m.encryptTimeSeconds << " s\n";
    std::cout << "Decrypt time:        " << m.decryptTimeSeconds << " s\n";
    std::cout << "Encrypt throughput:  " << std::setprecision(2) << m.encryptThroughputMBps << " MB/s\n";
    std::cout << "Decrypt throughput:  " << m.decryptThroughputMBps << " MB/s\n";
    std::cout << "Memory usage:        " << (m.peakMemoryBytes / 1024) << " KB\n";
    std::cout << "--------------------------\n";
}
