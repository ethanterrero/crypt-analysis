#pragma once

#include <cstdint>
#include <string>
#include <vector>

/**
 * @brief Handles file I/O operations
 */
class FileHandler {
public:
  /**
   * @brief Read a file completely into a byte vector
   * @param path File path
   * @return Vector containing file bytes. Throws runtime_error on failure.
   */
  static std::vector<uint8_t> read_file(const std::string &path);

  /**
   * @brief Write a byte vector to a file
   * @param path File path
   * @param data Data to write
   * @return true if successful
   */
  static bool write_file(const std::string &path,
                         const std::vector<uint8_t> &data);
};
