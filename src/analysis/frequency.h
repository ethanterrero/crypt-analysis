#pragma once

#include <cstdint>
#include <string>
#include <vector>

// storign the chi-squared frequency test results 
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

/*

IDEA: Chi-square is measuring oru expectations against whats actually observed. 
I always think about a simple example with a coin toss. We expect 50% heads, 50% tails, but if we were to get an observed result of 90% heads and 10% tails, how would we interpret that? Is it too extreme to be random or is it realistic enough of a real world observation. 

What Chi-squared is doing in the context of cryptography is measuring our expected value of an even appearance of every possible byte. If we get a good enough distribution, it means we have good confusion since there is no identifiable pattern or hints about internal structure in the ciphertext that an attacker can exploit. 

*/

// p-value interpretation:
//   < 0.05  — distribution is non-uniform, detectable patterns (FAIL)
//   0.05–0.95 — looks random (PASS)
//   > 0.95  — suspiciously too uniform (NOTE)
FrequencyResult run_frequency_test(const std::vector<uint8_t>& data);

void print_frequency_result(const std::string& label, const FrequencyResult& result);
