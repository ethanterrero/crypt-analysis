#include <gtest/gtest.h>
#include "crypto/aes_cipher.h"
#include "crypto/chacha_cipher.h"
#include "test_helpers.h"
#include <vector>
#include <string>

// Helper: create test data of given size
static std::vector<uint8_t> makeTestData(size_t size) {
    std::vector<uint8_t> data(size);
    for (size_t i = 0; i < size; ++i) {
        data[i] = static_cast<uint8_t>(i % 256);
    }
    return data;
}

// --- AES-CBC round-trip ---
TEST(AesCBC, RoundTrip) {
    AesCipher cipher("cbc");
    auto input = makeTestData(1024);
    std::vector<uint8_t> encrypted, decrypted;

    ASSERT_TRUE(cipher.encrypt(input, "testpassword", encrypted));
    ASSERT_TRUE(cipher.decrypt(encrypted, "testpassword", decrypted));
    EXPECT_EQ(input, decrypted);
}

// --- AES-CBC wrong password ---
TEST(AesCBC, WrongPasswordFails) {
    AesCipher cipher("cbc");
    auto input = makeTestData(256);
    std::vector<uint8_t> encrypted, decrypted;

    ASSERT_TRUE(cipher.encrypt(input, "correctpass", encrypted));
    // Decrypting with wrong password should fail (padding check)
    EXPECT_FALSE(cipher.decrypt(encrypted, "wrongpass", decrypted));
}

// --- ChaCha20 round-trip ---
TEST(ChaCha20, RoundTrip) {
    ChaChaCipher cipher;
    auto input = makeTestData(1024);
    std::vector<uint8_t> encrypted, decrypted;

    ASSERT_TRUE(cipher.encrypt(input, "testpassword", encrypted));
    ASSERT_TRUE(cipher.decrypt(encrypted, "testpassword", decrypted));
    EXPECT_EQ(input, decrypted);
}

// --- ChaCha20 wrong password produces different output ---
TEST(ChaCha20, WrongPasswordProducesDifferentOutput) {
    ChaChaCipher cipher;
    auto input = makeTestData(256);
    std::vector<uint8_t> encrypted, decrypted;

    ASSERT_TRUE(cipher.encrypt(input, "correctpass", encrypted));
    // ChaCha20 is a stream cipher, so decrypt won't "fail" but output will differ
    ASSERT_TRUE(cipher.decrypt(encrypted, "wrongpass", decrypted));
    EXPECT_NE(input, decrypted);
}

// --- Mock encryptor round-trip ---
TEST(MockEncryptor, RoundTrip) {
    MockEncryptor mock;
    auto input = makeTestData(100);
    std::vector<uint8_t> encrypted, decrypted;

    ASSERT_TRUE(mock.encrypt(input, "key", encrypted));
    EXPECT_EQ(encrypted.size(), input.size() + 1);
    ASSERT_TRUE(mock.decrypt(encrypted, "key", decrypted));
    EXPECT_EQ(input, decrypted);
}

// --- Empty input ---
TEST(AesCBC, EmptyInput) {
    AesCipher cipher("cbc");
    std::vector<uint8_t> input;
    std::vector<uint8_t> encrypted, decrypted;

    ASSERT_TRUE(cipher.encrypt(input, "password", encrypted));
    ASSERT_TRUE(cipher.decrypt(encrypted, "password", decrypted));
    EXPECT_EQ(input, decrypted);
}
