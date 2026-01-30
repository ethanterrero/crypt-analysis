#pragma once

#include <cstdint>
#include <string>
#include <vector>

/**
 * @brief Abstract base class for encryption algorithms
 */
class Encryptor {
public:
  virtual ~Encryptor() = default;

  /**
   * @brief Encrypt data
   * @param input Raw input data
   * @param key Encryption key (raw bytes or password, depending on
   * implementation)
   * @param output Vector to store encrypted data
   * @return true if successful, false otherwise
   */
  virtual bool encrypt(const std::vector<uint8_t> &input,
                       const std::string &key,
                       std::vector<uint8_t> &output) = 0;

  /**
   * @brief Decrypt data
   * @param input Encrypted data
   * @param key Decryption key
   * @param output Vector to store decrypted data
   * @return true if successful, false otherwise
   */
  virtual bool decrypt(const std::vector<uint8_t> &input,
                       const std::string &key,
                       std::vector<uint8_t> &output) = 0;
};
