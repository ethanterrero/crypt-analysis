#include "file_handler.h"
#include <fstream>
#include <iostream>
#include <stdexcept>

std::vector<uint8_t> FileHandler::read_file(const std::string &path) {
  // Open file at end to get size
  std::ifstream file(path, std::ios::binary | std::ios::ate);
  if (!file) {
    throw std::runtime_error("Could not open input file: " + path);
  }

  // Get size and allocate buffer
  std::streamsize size = file.tellg();
  file.seekg(0, std::ios::beg);

  std::vector<uint8_t> buffer(size);
  if (file.read(reinterpret_cast<char *>(buffer.data()), size)) {
    return buffer;
  }

  throw std::runtime_error("Failed to read file: " + path);
}

bool FileHandler::write_file(const std::string &path,
                             const std::vector<uint8_t> &data) {
  std::ofstream file(path, std::ios::binary);
  if (!file) {
    std::cerr << "Could not open output file: " << path << std::endl;
    return false;
  }

  file.write(reinterpret_cast<const char *>(data.data()), data.size());
  return file.good();
}
