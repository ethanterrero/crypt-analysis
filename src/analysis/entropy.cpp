#include "entropy.h"
#include <cmath>
#include <iomanip>
#include <iostream>

/*
Shannon Entropy measures how random a byte sequence looks.

There are 256 possible byte values (0x00 – 0xFF). For each value x, we
compute how often it appears as a fraction p(x) of the total bytes. 

H = -Σ p(x) * log_2(p(x)) summed over all 256 possible byte values

The log_2 maps probabilities to bits. The idea is we log_2(1/p). The rarer the value, the more information it carries. Lets say p = 1/2 => log_2(2) = 1 bit. 
*/

EntropyResult measure_entropy(const std::vector<uint8_t>& data) {
    if (data.empty()) return {};
    // taking in the ciphertext vector

    // does the same thing as frequency.cpp where each byte occurance indexes into the array and we increment it
    size_t counts[256] = {};
    for (uint8_t b : data) {
        counts[b]++;
    }

    const double n = static_cast<double>(data.size()); // size of data vector
    double entropy = 0.0;
    double min_freq = 1.0;
    double max_freq = 0.0;
    uint8_t min_byte = 0;
    uint8_t max_byte = 0;
    for (int i = 0; i < 256; ++i) {
        if (counts[i] == 0) continue; // if reads 0, just skip it 
        double p = static_cast<double>(counts[i]) / n; // probability of that byte value appearing 
        entropy -= p * std::log2(p); // subtracting a negative makes this positive

        // by the end of the lop, we have the least and most common byte values and their frequencies 
        if (p < min_freq) { min_freq = p; min_byte = static_cast<uint8_t>(i); }
        if (p > max_freq) { max_freq = p; max_byte = static_cast<uint8_t>(i); }
    }
    // creating the EntropyResult object to store this information 
    EntropyResult result{};
    result.entropy = entropy;
    result.min_byte_freq = min_freq;
    result.max_byte_freq = max_freq;
    result.most_common_byte = max_byte;
    result.least_common_byte = min_byte;
    result.total_bytes = data.size();
    return result;
}

void print_entropy_result(const std::string& label, const EntropyResult& result) {
    constexpr double MAX_ENTROPY = 8.0;
    constexpr double PASS_THRESHOLD = 7.9;
    constexpr double WARN_THRESHOLD = 7.5;
    constexpr int BAR_WIDTH = 24;
    int filled = static_cast<int>((result.entropy / MAX_ENTROPY) * BAR_WIDTH);
    std::string bar(filled, '#');
    bar += std::string(BAR_WIDTH - filled, '.');
    double ideal_freq = 1.0 / 256.0;
    std::cout << "\n=== Shannon Entropy Test: " << label << " ===\n"
              << std::fixed << std::setprecision(4)
              << "  Bytes analysed:     " << result.total_bytes << "\n"
              << "  Entropy:            " << result.entropy << " / 8.0000 bits/byte\n"
              << "  Progress:           [" << bar << "]\n"
              << std::setprecision(6)
              << "  Ideal byte freq:    " << ideal_freq << "  (1/256)\n"
              << "  Min byte freq:      " << result.min_byte_freq
              << "  (byte 0x" << std::hex << std::setw(2) << std::setfill('0')
              << static_cast<int>(result.least_common_byte) << std::dec << ")\n"
              << "  Max byte freq:      " << result.max_byte_freq
              << "  (byte 0x" << std::hex << std::setw(2) << std::setfill('0')
              << static_cast<int>(result.most_common_byte) << std::dec << ")\n";
    if (result.total_bytes < 1024) {
        std::cout << "  Note:               Input < 1 KB — some byte values may be\n"
                  << "                      absent by chance, not due to the cipher.\n";
    }
    std::string assessment;
    if (result.entropy >= PASS_THRESHOLD) assessment = "PASS  (looks random)";
    else if (result.entropy >= WARN_THRESHOLD) assessment = "WARN  (slight non-uniformity)";
    else assessment = "FAIL  (detectable patterns)";
    std::cout << "  Assessment:         " << assessment << "\n";
}
