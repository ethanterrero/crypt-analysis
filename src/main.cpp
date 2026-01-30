#include "crypto/encryptor.h"
#include "io/file_handler.h"
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

// Mock Encryptor for testing infrastructure
class MockEncryptor : public Encryptor {
public:
  bool encrypt(const std::vector<uint8_t> &input, const std::string &key,
               std::vector<uint8_t> &output) override {
    // Just copy input to output and append 0xFF to simulate "encryption"
    output = input;
    output.push_back(0xFF);
    return true;
  }

  bool decrypt(const std::vector<uint8_t> &input, const std::string &key,
               std::vector<uint8_t> &output) override {
    // Remove the last byte
    if (input.empty())
      return false;
    output = input;
    output.pop_back();
    return true;
  }
};

enum class Operation { NONE, ENCRYPT, DECRYPT, BENCHMARK, VERIFY };

struct Config {
  std::string inputFile;
  std::string outputFile;
  std::string algorithm = "aes256";
  std::string mode = "cbc";
  std::string password;
  Operation op = Operation::NONE;
};

void print_help() {
  std::cout << "Usage: file-crypto [command] [options]\n"
            << "Commands:\n"
            << "  encrypt  Encrypt a file\n"
            << "  decrypt  Decrypt a file\n"
            << "Options:\n"
            << "  -i, --input <file>     Input file path\n"
            << "  -o, --output <file>    Output file path\n"
            << "  -p, --password <pass>  Encryption password\n"
            << "  -a, --algorithm <name> Algorithm (aes256, chacha20). "
               "Default: aes256\n"
            << "  -m, --mode <name>      Mode (cbc, ecb). Default: cbc\n"
            << "  -h, --help             Show this help message\n";
}

int main(int argc, char *argv[]) {
  Config config;

  // Basic argument parsing
  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];

    if (arg == "encrypt") {
      config.op = Operation::ENCRYPT;
    } else if (arg == "decrypt") {
      config.op = Operation::DECRYPT;
    } else if (arg == "-i" || arg == "--input") {
      if (i + 1 < argc)
        config.inputFile = argv[++i];
    } else if (arg == "-o" || arg == "--output") {
      if (i + 1 < argc)
        config.outputFile = argv[++i];
    } else if (arg == "-p" || arg == "--password") {
      if (i + 1 < argc)
        config.password = argv[++i];
    } else if (arg == "-a" || arg == "--algorithm") {
      if (i + 1 < argc)
        config.algorithm = argv[++i];
    } else if (arg == "-m" || arg == "--mode") {
      if (i + 1 < argc)
        config.mode = argv[++i];
    } else if (arg == "-h" || arg == "--help") {
      print_help();
      return 0;
    }
  }

  if (config.op == Operation::NONE) {
    std::cerr << "Error: No command specified (encrypt/decrypt).\n";
    print_help();
    return 1;
  }

  if (config.inputFile.empty() || config.outputFile.empty()) {
    std::cerr << "Error: Input and Output files are required.\n";
    return 1;
  }

  // Dispatcher
  std::unique_ptr<Encryptor> encryptor;

  // TODO: Instantiate real encryptors here
  if (config.algorithm == "mock") {
    encryptor = std::make_unique<MockEncryptor>();
  } else {
    std::cout << "Warning: Algorithm '" << config.algorithm
              << "' not implemented yet. Using MockEncryptor.\n";
    encryptor = std::make_unique<MockEncryptor>();
  }

  try {
    std::cout << "Reading " << config.inputFile << "...\n";
    auto inputData = FileHandler::read_file(config.inputFile);
    std::vector<uint8_t> outputData;
    bool success = false;

    if (config.op == Operation::ENCRYPT) {
      std::cout << "Encrypting...\n";
      success = encryptor->encrypt(inputData, config.password, outputData);
    } else {
      std::cout << "Decrypting...\n";
      success = encryptor->decrypt(inputData, config.password, outputData);
    }

    if (success) {
      if (FileHandler::write_file(config.outputFile, outputData)) {
        std::cout << "Success! Output written to " << config.outputFile << "\n";
      } else {
        return 1;
      }
    } else {
      std::cerr << "Operation failed.\n";
      return 1;
    }

  } catch (const std::exception &e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return 1;
  }

  return 0;
}
