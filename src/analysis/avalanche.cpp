#include "avalanche.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <numeric>

/*
The idea behind this test, is 1 bit changed in the plaintext should result in a 50% change in the outgoing ciphertext. This is a benchmark for good use of diffusion and confusion. Doesn't work on ChaCha20 since its a stream cipher.

Literally looking at the ASCII code for a character, looking at its binary representation. Then flipping one of those bits. 

* bit / 8 - selects which byte (character) in the input 
* bit % 8 - selectes which bit position within that byte (0 through 7)
* 1u << (bit % 8) - creates a mask with exactly that one bit set
* ^= - COR flipts that single bit, leaving all the others untouched

Goal: Make smallest possible change and ask if it scrambles the output completely
*/

// does the encryption for CBC
static bool encrypt_aes256_cbc(const std::vector<uint8_t>& plaintext,
                                const uint8_t* key, const uint8_t* iv,
                                std::vector<uint8_t>& output) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new(); // creating the context here
    if (!ctx) return false; 
    // a heap allocated struct holding the internal state, check if its allocated properly 

    // AES-CBC pads to the next 16-byte boundary, so allocate input + one block
    output.resize(plaintext.size() + 16);
    int len = 0, total = 0;

    // EVP_EncryptInit_ex loads teh encryption parameters into the context so its ready to encrypt, returns 1 if failed, 0 if succesfull 

    // EVP_EncryptUpdate, the .data() is for vectors, returns a raw pointer to that array (also returns 1 if failed, 0 if successful)
    // Since OpenSSL is a C library, it doesn't know what a vector is so we have to give it the raw pointer
    // the .size() returs a size_t which is unsigned and the OpenSSL function is expecting an int so we cast it to an int. 
    // EVP_
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1 ||
        EVP_EncryptUpdate(ctx, output.data(), &len,
                          plaintext.data(), static_cast<int>(plaintext.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx); // if it failes, just free it and indicate failure
        return false;
    }
    
    total = len;

    // EVP_EncryptUpdate() only works on 16 byte blocks, so if we have leftover bytes, EVP_EncryptFinal_ex will take those, extend it to 16 bytes, then process it 
    if (EVP_EncryptFinal_ex(ctx, output.data() + total, &len) != 1) {
        // output.data() + total tells Final where to write 
        // &len tells Final how many bytes we've written so far 
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    output.resize(total + len); // trim to actual ciphertext size 
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

// we repeat what we just did above, but with ecb instead
// only real difference is ECB doesn't take an IV so we just pass in nullptr instead
static bool encrypt_aes256_ecb(const std::vector<uint8_t>& plaintext,
                                const uint8_t* key,
                                std::vector<uint8_t>& output) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    // ECB takes no IV — each block is encrypted independently.
    output.resize(plaintext.size() + 16);
    int len = 0, total = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), nullptr, key, nullptr) != 1 ||
        EVP_EncryptUpdate(ctx, output.data(), &len,
                          plaintext.data(), static_cast<int>(plaintext.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    total = len; 

    if (EVP_EncryptFinal_ex(ctx, output.data() + total, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    output.resize(total + len);
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

static bool encrypt_chacha20(const std::vector<uint8_t>& plaintext,
                              const uint8_t* key, const uint8_t* iv,
                              std::vector<uint8_t>& output) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    // ChaCha20 is a stream cipher — output is always the same length as input.
    // OpenSSL EVP_chacha20 expects a 16-byte IV: 4-byte counter + 12-byte nonce
    output.resize(plaintext.size());
    int len = 0, total = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_chacha20(), nullptr, key, iv) != 1 ||
        EVP_EncryptUpdate(ctx, output.data(), &len,
                          plaintext.data(), static_cast<int>(plaintext.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false; 
    }
    total = len;

    // Stream ciphers produce no extra bytes in Final, but we still call it
    if (EVP_EncryptFinal_ex(ctx, output.data() + total, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    output.resize(total + len); // this is always eqaul to plaintext.size() 
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

// the CipherType is defined in the avalanche.h so we can select 
// this is just a dispatcher function, the goal is to just run_avalanche_test 
// without needing to know which cipher is being tested
static bool encrypt_fixed(CipherType cipher,
                           const std::vector<uint8_t>& plaintext,
                           const uint8_t* key, const uint8_t* iv,
                           std::vector<uint8_t>& output) {
    switch (cipher) {
        case CipherType::AES256_CBC: return encrypt_aes256_cbc(plaintext, key, iv, output);
        case CipherType::AES256_ECB: return encrypt_aes256_ecb(plaintext, key, output);
        case CipherType::CHACHA20:   return encrypt_chacha20(plaintext, key, iv, output);
    }
    return false;
}

// Count the number of bits that differ between two byte sequences
// both a and b are ciphertexts
// a: baseline ciphertext 
// b: the new ciphertext generated from the 1 bit flip in plaintext
static size_t count_differing_bits(const std::vector<uint8_t>& a,
                                   const std::vector<uint8_t>& b,
                                   size_t len) {
    size_t count = 0;
    for (size_t i = 0; i < len; ++i) {
        count += __builtin_popcount(a[i] ^ b[i]);
        // using XOR here, any bit that is different between two bytes becomes a 1
        // we loop over each bit and do this! If they are 0, we just add 0, if its 1, we just add 1 to the count and return that 
    }
    return count;
}

AvalancheResult run_avalanche_test(CipherType cipher,
                                   const std::vector<uint8_t>& plaintext,
                                   size_t max_bits_to_test) {
    // RAND_bytes is from OpenSSL from the #include <openssl/rand.h> 
    // it fills the array with cryptographically secure random bytes (not safe to just use rand() from C standard library)
    uint8_t key[32], iv[16];
    RAND_bytes(key, sizeof(key));
    RAND_bytes(iv, sizeof(iv));

    // getting our global baseline here
    std::vector<uint8_t> baseline;
    // we use the dispatching function encrypt_fixed()
    // at first I thought if we called ECB, which doesn't take an iv this would cause an error
    // the iv will just get ignored anyways so it works fine 
    if (!encrypt_fixed(cipher, plaintext, key, iv, baseline)) {
        return {}; // this returns a blank AvalancheResult struct 
    }

    // Determine how many bit positions to sample
    size_t total_bits = plaintext.size() * 8; // each position, 8 bits
    size_t bits_to_test = (max_bits_to_test == 0 || max_bits_to_test > total_bits)
                          ? total_bits
                          : max_bits_to_test;

    std::vector<double> change_pcts; // storing result from every bit flip 
    change_pcts.reserve(bits_to_test); 

    for (size_t bit = 0; bit < bits_to_test; ++bit) {
        // Flip exactly one bit in a copy of the plaintext
        std::vector<uint8_t> flipped = plaintext;
        flipped[bit / 8] ^= static_cast<uint8_t>(1u << (bit % 8)); // this line does the flip for every bit in the plaintext 

        /* IMPORTANT: 
        bit / 8 -> selects which byte to modify 
        bit % 8 -> selects which bit position to modify within that byte
        1u << (bit % 8) -> creates a mask with exactly that one bit set 
        ^= -> XOR flips the one bit leaving everythign else untouched 
        we cast that result back to a byte since the operations above produce an unsigned int
        */

        // Encrypt with the same key/IV
        std::vector<uint8_t> flipped_out; // calling encrypt_fixed(), passing flipped_out to it
        if (!encrypt_fixed(cipher, flipped, key, iv, flipped_out)) continue;

        // XOR the outputs and count the set bits.
        size_t compare_len = std::min(baseline.size(), flipped_out.size());
        size_t diff_bits = count_differing_bits(baseline, flipped_out, compare_len);

        double pct = 100.0 * static_cast<double>(diff_bits)
                           / static_cast<double>(compare_len * 8);
        change_pcts.push_back(pct);
    }

    // here is what happens at the end of all our iterations 
    // setup
    AvalancheResult result{};
    result.bits_tested    = change_pcts.size();
    result.ciphertext_bits = baseline.size() * 8;

    // early exit 
    if (change_pcts.empty()) return result;

    // getting the average with std::acumulate
    double sum = std::accumulate(change_pcts.begin(), change_pcts.end(), 0.0);
    result.avg_bit_change_pct = sum / static_cast<double>(change_pcts.size());

    // min_element and max_element return iterators so dereferencing give the actual value 
    result.min_bit_change_pct = *std::min_element(change_pcts.begin(), change_pcts.end());
    result.max_bit_change_pct = *std::max_element(change_pcts.begin(), change_pcts.end());

    // calculating the standard deviaiton here 
    double sq_sum = 0.0;
    for (double v : change_pcts) {
        double d = v - result.avg_bit_change_pct;
        sq_sum += d * d;
    }
    result.std_dev = std::sqrt(sq_sum / static_cast<double>(change_pcts.size()));

    return result; // all gets stored in the AvalancheResult object and we return it 
}

// What matters here is we pass in the reference to the AvalancheResult object returned from the function above
// it contains all the info (passing references prevents copying, not really a big deal here but good practice)

void print_avalanche_result(const std::string& cipher_name,
                            const AvalancheResult& result) {
    constexpr double IDEAL          = 50.0;
    constexpr double PASS_THRESHOLD =  5.0;  // ±5% of ideal passes for block ciphers
    constexpr double STREAM_THRESHOLD = 1.0; // stream ciphers expect ~0%

    std::cout << "\n=== Avalanche Effect Test: " << cipher_name << " ===\n"
              << std::fixed << std::setprecision(2)
              << "  Input bits tested:  " << result.bits_tested        << "\n"
              << "  Ciphertext size:    " << result.ciphertext_bits    << " bits\n"
              << "  Avg bit change:     " << result.avg_bit_change_pct << "%  (block cipher ideal: 50.00%)\n"
              << "  Min bit change:     " << result.min_bit_change_pct << "%\n"
              << "  Max bit change:     " << result.max_bit_change_pct << "%\n"
              << "  Std deviation:      " << result.std_dev             << "%\n";

    // Stream ciphers (e.g. ChaCha20) produce C = P XOR Keystream.
    // A 1-bit plaintext flip flips exactly 1 ciphertext bit — ~0% change is
    // correct by design, not a defect. Assess differently from block ciphers.
    // ECB encrypts each block independently so only the affected block changes —
    // a low score is expected and demonstrates ECB's weakness, not a bug.
    bool is_stream_behavior = result.avg_bit_change_pct < STREAM_THRESHOLD;
    if (is_stream_behavior) {
        std::cout << "  Assessment:         N/A (stream cipher — no avalanche property by design)\n";
    } else if (cipher_name == "AES-256-ECB") {
        std::cout << "  Assessment:         NOTE (ECB — avalanche is block-local only, "
                  << "no propagation across blocks — this is a known weakness)\n";
    } else {
        bool pass = std::abs(result.avg_bit_change_pct - IDEAL) <= PASS_THRESHOLD;
        std::cout << "  Assessment:         " << (pass ? "PASS" : "FAIL")
                  << " (" << (pass ? "within" : "outside") << " "
                  << PASS_THRESHOLD << "% of ideal)\n";
    }
}
