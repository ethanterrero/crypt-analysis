#include "frequency.h"
#include <cmath>
#include <iomanip>
#include <iostream>

/*
Chi-squared test for byte frequency uniformity.

There are 256 possible byte values. For a perfectly random source each value
should appear with equal probability (1/256). The chi-squared statistic sums
up how far the actual counts deviate from that expectation:

    chi2 = sum over all 256 values of: (observed - expected)^2 / expected

where expected = total_bytes / 256.0 for every value.

A large chi2 means some byte values appear far more or less often than chance
would predict — a sign of patterns in the ciphertext.

The p-value turns chi2 into a probability: "if this data were truly random,
how likely would we be to see a chi2 this large or larger?" A low p-value
means the observed deviation is unlikely to be random chance.

For 255 degrees of freedom an exact p-value requires the incomplete gamma
function. We use the Wilson-Hilferty normal approximation instead, which is
accurate to ~3 decimal places at df=255:

    h = 2 / (9 * df)
    z = ((chi2 / df)^(1/3) - (1 - h)) / sqrt(h)
    p = 0.5 * erfc(z / sqrt(2))
*/

// Approximate p-value for chi-squared using Wilson-Hilferty normal approximation.
static double chi2_p_value(double chi2, int df) {
    double h = 2.0 / (9.0 * df);
    double z = (std::pow(chi2 / df, 1.0 / 3.0) - (1.0 - h)) / std::sqrt(h);
    return 0.5 * std::erfc(z / std::sqrt(2.0));
}

FrequencyResult run_frequency_test(const std::vector<uint8_t>& data) {
    if (data.empty()) return {};
    size_t counts[256] = {};
    for (uint8_t b : data) {
        counts[b]++;
    }
    double expected = static_cast<double>(data.size()) / 256.0;
    double chi2 = 0.0;
    size_t min_count = counts[0];
    size_t max_count = counts[0];
    uint8_t min_byte = 0;
    uint8_t max_byte = 0;
    for (int i = 0; i < 256; ++i) {
        double diff = static_cast<double>(counts[i]) - expected;
        chi2 += (diff * diff) / expected;
        if (counts[i] < min_count) { min_count = counts[i]; min_byte = static_cast<uint8_t>(i); }
        if (counts[i] > max_count) { max_count = counts[i]; max_byte = static_cast<uint8_t>(i); }
    }
    FrequencyResult result{};
    result.chi_squared = chi2;
    result.p_value = chi2_p_value(chi2, 255);
    result.degrees_of_freedom = 255;
    result.total_bytes = data.size();
    result.most_common_byte = max_byte;
    result.least_common_byte = min_byte;
    result.most_common_count = max_count;
    result.least_common_count = min_count;
    return result;
}

void print_frequency_result(const std::string& label, const FrequencyResult& result) {
    double expected = static_cast<double>(result.total_bytes) / 256.0;
    std::cout << "\n=== Byte Frequency (Chi-Squared) Test: " << label << " ===\n"
              << std::fixed << std::setprecision(4)
              << "  Bytes analysed:     " << result.total_bytes << "\n"
              << "  Expected per value: " << expected << "\n"
              << "  Chi-squared:        " << result.chi_squared
              << "  (df=" << result.degrees_of_freedom << ")\n"
              << "  P-value:            " << result.p_value << "\n"
              << "  Most common byte:   0x" << std::hex << std::setw(2) << std::setfill('0')
              << static_cast<int>(result.most_common_byte) << std::dec
              << "  (count=" << result.most_common_count << ")\n"
              << "  Least common byte:  0x" << std::hex << std::setw(2) << std::setfill('0')
              << static_cast<int>(result.least_common_byte) << std::dec
              << "  (count=" << result.least_common_count << ")\n";
    if (result.total_bytes < 1024) {
        std::cout << "  Note:               Input < 1 KB — small samples produce unreliable p-values.\n";
    }
    std::string assessment;
    if (result.p_value < 0.05) assessment = "FAIL  (non-uniform distribution, detectable patterns)";
    else if (result.p_value > 0.95) assessment = "NOTE  (suspiciously uniform — verify sample size)";
    else assessment = "PASS  (distribution looks random)";
    std::cout << "  Assessment:         " << assessment << "\n";
}
