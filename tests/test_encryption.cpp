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

// ========================
// AES-CBC Tests
// ========================

TEST(AesCBC, RoundTrip) {
    AesCipher cipher("cbc");
    auto input = makeTestData(1024);
    std::vector<uint8_t> encrypted, decrypted;

    ASSERT_TRUE(cipher.encrypt(input, "testpassword", encrypted));
    ASSERT_TRUE(cipher.decrypt(encrypted, "testpassword", decrypted));
    EXPECT_EQ(input, decrypted);
}

TEST(AesCBC, WrongPasswordFails) {
    AesCipher cipher("cbc");
    auto input = makeTestData(256);
    std::vector<uint8_t> encrypted, decrypted;

    ASSERT_TRUE(cipher.encrypt(input, "correctpass", encrypted));
    EXPECT_FALSE(cipher.decrypt(encrypted, "wrongpass", decrypted));
}

TEST(AesCBC, EmptyInput) {
    AesCipher cipher("cbc");
    std::vector<uint8_t> input;
    std::vector<uint8_t> encrypted, decrypted;

    ASSERT_TRUE(cipher.encrypt(input, "password", encrypted));
    ASSERT_TRUE(cipher.decrypt(encrypted, "password", decrypted));
    EXPECT_EQ(input, decrypted);
}

TEST(AesCBC, LargeFile) {
    AesCipher cipher("cbc");
    auto input = makeTestData(1024 * 1024); // 1 MB
    std::vector<uint8_t> encrypted, decrypted;

    ASSERT_TRUE(cipher.encrypt(input, "largefile_pass", encrypted));
    ASSERT_TRUE(cipher.decrypt(encrypted, "largefile_pass", decrypted));
    EXPECT_EQ(input, decrypted);
}

TEST(AesCBC, EncryptedDiffersFromPlaintext) {
    AesCipher cipher("cbc");
    auto input = makeTestData(512);
    std::vector<uint8_t> encrypted;

    ASSERT_TRUE(cipher.encrypt(input, "password", encrypted));
    // Encrypted output (minus header) should differ from input
    EXPECT_NE(input, std::vector<uint8_t>(encrypted.begin(), encrypted.end()));
}

// ========================
// AES-ECB Tests
// ========================

TEST(AesECB, RoundTrip) {
    AesCipher cipher("ecb");
    auto input = makeTestData(1024);
    std::vector<uint8_t> encrypted, decrypted;

    ASSERT_TRUE(cipher.encrypt(input, "testpassword", encrypted));
    ASSERT_TRUE(cipher.decrypt(encrypted, "testpassword", decrypted));
    EXPECT_EQ(input, decrypted);
}

TEST(AesECB, WrongPasswordFails) {
    AesCipher cipher("ecb");
    auto input = makeTestData(256);
    std::vector<uint8_t> encrypted, decrypted;

    ASSERT_TRUE(cipher.encrypt(input, "correctpass", encrypted));
    EXPECT_FALSE(cipher.decrypt(encrypted, "wrongpass", decrypted));
}

TEST(AesECB, EmptyInput) {
    AesCipher cipher("ecb");
    std::vector<uint8_t> input;
    std::vector<uint8_t> encrypted, decrypted;

    ASSERT_TRUE(cipher.encrypt(input, "password", encrypted));
    ASSERT_TRUE(cipher.decrypt(encrypted, "password", decrypted));
    EXPECT_EQ(input, decrypted);
}

// ========================
// ChaCha20 Tests
// ========================

TEST(ChaCha20, RoundTrip) {
    ChaChaCipher cipher;
    auto input = makeTestData(1024);
    std::vector<uint8_t> encrypted, decrypted;

    ASSERT_TRUE(cipher.encrypt(input, "testpassword", encrypted));
    ASSERT_TRUE(cipher.decrypt(encrypted, "testpassword", decrypted));
    EXPECT_EQ(input, decrypted);
}

TEST(ChaCha20, WrongPasswordProducesDifferentOutput) {
    ChaChaCipher cipher;
    auto input = makeTestData(256);
    std::vector<uint8_t> encrypted, decrypted;

    ASSERT_TRUE(cipher.encrypt(input, "correctpass", encrypted));
    ASSERT_TRUE(cipher.decrypt(encrypted, "wrongpass", decrypted));
    EXPECT_NE(input, decrypted);
}

TEST(ChaCha20, LargeFile) {
    ChaChaCipher cipher;
    auto input = makeTestData(1024 * 1024); // 1 MB
    std::vector<uint8_t> encrypted, decrypted;

    ASSERT_TRUE(cipher.encrypt(input, "largefile_pass", encrypted));
    ASSERT_TRUE(cipher.decrypt(encrypted, "largefile_pass", decrypted));
    EXPECT_EQ(input, decrypted);
}

TEST(ChaCha20, EmptyInput) {
    ChaChaCipher cipher;
    std::vector<uint8_t> input;
    std::vector<uint8_t> encrypted, decrypted;

    ASSERT_TRUE(cipher.encrypt(input, "password", encrypted));
    ASSERT_TRUE(cipher.decrypt(encrypted, "password", decrypted));
    EXPECT_EQ(input, decrypted);
}

// ========================
// Invalid Mode Test
// ========================

TEST(AesCipher, InvalidModeThrows) {
    EXPECT_THROW(AesCipher("invalid_mode"), std::runtime_error);
}

// ========================
// Mock Encryptor Tests
// ========================

TEST(MockEncryptor, RoundTrip) {
    MockEncryptor mock;
    auto input = makeTestData(100);
    std::vector<uint8_t> encrypted, decrypted;

    ASSERT_TRUE(mock.encrypt(input, "key", encrypted));
    EXPECT_EQ(encrypted.size(), input.size() + 1);
    ASSERT_TRUE(mock.decrypt(encrypted, "key", decrypted));
    EXPECT_EQ(input, decrypted);
}
