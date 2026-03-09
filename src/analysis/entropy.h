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

// Compute Shannon entropy of a byte sequence.
//
// Works directly on any buffer — pass raw ciphertext output from the cipher.
// No key or encryption needed; this just analyses the byte distribution.
//
// Reliability note: with fewer than ~1 KB of data some byte values will
// be missing purely by chance, which artificially lowers entropy. Results
// are most meaningful on inputs of 1 KB or more.
EntropyResult measure_entropy(const std::vector<uint8_t>& data);

void print_entropy_result(const std::string& label, const EntropyResult& result);
