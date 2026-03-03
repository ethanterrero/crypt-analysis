#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct FrequencyResult {
    double chi_squared;         // Raw chi-squared statistic — lower means more uniform
    double p_value;             // 0.0–1.0. Good ciphertext lands between 0.05 and 0.95
    int degrees_of_freedom;     // Always 255 (256 byte values minus 1)
    size_t total_bytes;
    uint8_t most_common_byte;
    uint8_t least_common_byte;
    size_t most_common_count;
    size_t least_common_count;
};

// Chi-squared test for byte frequency uniformity.
//
// Counts how often each of the 256 possible byte values appears in the
// ciphertext and compares that distribution against a perfectly uniform one
// (expected count = total_bytes / 256 per value).
//
// A strong cipher should produce ciphertext where every byte value appears
// with roughly equal frequency. The chi-squared statistic measures the total
// deviation from that ideal; the p-value expresses how likely a truly random
// source would produce a deviation at least this large.
//
// p-value interpretation:
//   < 0.05  — distribution is non-uniform, detectable patterns (FAIL)
//   0.05–0.95 — looks random (PASS)
//   > 0.95  — suspiciously too uniform (NOTE)
FrequencyResult run_frequency_test(const std::vector<uint8_t>& data);

void print_frequency_result(const std::string& label, const FrequencyResult& result);
