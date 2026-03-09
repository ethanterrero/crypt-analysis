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

// Tests the avalanche effect: for each sampled input bit position, flip that
// bit and measure what percentage of ciphertext bits change.
//
// Uses a single fixed random key and IV for the entire run so that the only
// variable between encryptions is the one flipped bit. max_bits_to_test=0
// tests every bit in the input.
//
// NOTE: Stream ciphers (ChaCha20) do NOT have the avalanche property by
// design — C = P XOR Keystream, so a 1-bit flip in P flips exactly 1 bit in
// C. A result near 0% is correct and expected, not a weakness.
AvalancheResult run_avalanche_test(CipherType cipher,
                                   const std::vector<uint8_t>& plaintext,
                                   size_t max_bits_to_test = 256);

void print_avalanche_result(const std::string& cipher_name,
                            const AvalancheResult& result);
