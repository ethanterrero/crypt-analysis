#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct EntropyResult {
    double   entropy;           // Shannon entropy in bits/byte — ideal ciphertext: ~8.0
    double   min_byte_freq;     // Fraction of total bytes for the least common byte value
    double   max_byte_freq;     // Fraction of total bytes for the most common byte value
    uint8_t  most_common_byte;  // Byte value that appeared most often
    uint8_t  least_common_byte; // Byte value that appeared least often
    size_t   total_bytes;       // How many bytes were analysed
};

/* Shannon Entropy
IDEA: If one byte value dominates, you ask "Is it that byte?" first and win quickly. 
This is because the attacker has more knowledge

If all 256 values are equally likely, no strategy can help you narrow down your guesses. You always need ~8 yes/no quesitons -> entropy = 8.0 bits/byte

Shannon Entropy and the Chi-squared measurements measure similar things but from different angles. Chi-squared is asking if the distribution is statistically uniform while Shannon entropy is asking how much info a single byte is carrying. Chi-squared can catch changes in the distribution even if a single byte doesn't blatantly dominate. Strong ciphers should score well for both of these tests. 
*/
// Reliability note: with fewer than ~1 KB of data some byte values will
// be missing purely by chance, which artificially lowers entropy. Results
// are most meaningful on inputs of 1 KB or more.
EntropyResult measure_entropy(const std::vector<uint8_t>& data);

void print_entropy_result(const std::string& label, const EntropyResult& result);
