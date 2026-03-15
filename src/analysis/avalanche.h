#pragma once

#include <cstdint>
#include <string>
#include <vector>

enum class CipherType { AES256_CBC, AES256_ECB, CHACHA20 };

struct AvalancheResult {
    double avg_bit_change_pct;  // How many output bits changed on average — ideal: ~50%
    double min_bit_change_pct;  // Worst-case single bit flip
    double max_bit_change_pct;  // Best-case single bit flip
    double std_dev;             // How consistent the diffusion is across bit positions
    size_t bits_tested;         // Number of input bit positions sampled
    size_t ciphertext_bits;     // Total bits in the ciphertext (comparison window)
};


AvalancheResult run_avalanche_test(CipherType cipher,
                                   const std::vector<uint8_t>& plaintext,
                                   size_t max_bits_to_test = 256);

void print_avalanche_result(const std::string& cipher_name,
                            const AvalancheResult& result);
