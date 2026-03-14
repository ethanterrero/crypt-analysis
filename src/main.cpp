#include "crypto/encryptor.h"
#include "io/file_handler.h"
#include "crypto/chacha_cipher.h"
#include "crypto/aes_cipher.h"
#include "utils/hash.h"
#include "metrics/performance.h"
#include "analysis/entropy.h"
#include "analysis/frequency.h"
#include "analysis/avalanche.h"
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

enum class Operation { NONE, ENCRYPT, DECRYPT, BENCHMARK, VERIFY, ANALYZE };

struct Config {
  std::string inputFile;
  std::string outputFile;
  std::string algorithm = "aes256";
  std::string mode = "cbc";
  std::string password;
  Operation op = Operation::NONE;
  bool verify = false;
  std::vector<std::string> benchAlgorithms;
  std::vector<std::string> benchModes;
  std::string analyzeTest;  // "entropy", "frequency", "avalanche", or "" (all)
};

// Split a comma-separated string into tokens
static std::vector<std::string> splitCSV(const std::string &s) {
  std::vector<std::string> tokens;
  std::istringstream stream(s);
  std::string token;
  while (std::getline(stream, token, ',')) {
    if (!token.empty()) tokens.push_back(token);
  }
  return tokens;
}

void print_help() {
  std::cout << "Usage: file-crypto [command] [options]\n"
            << "Commands:\n"
            << "  encrypt    Encrypt a file\n"
            << "  decrypt    Decrypt a file\n"
            << "  verify     Verify file integrity using .hash sidecar\n"
            << "  benchmark  Run encryption benchmarks\n"
            << "  analyze    Run cryptographic analysis on a file\n"
            << "Options:\n"
            << "  -i, --input <file>         Input file path\n"
            << "  -o, --output <file>        Output file path\n"
            << "  -p, --password <pass>      Encryption password\n"
            << "  -a, --algorithm <name>     Algorithm (aes256, chacha20). "
               "Default: aes256\n"
            << "  -m, --mode <name>          Mode (cbc, ecb, gcm). Default: cbc\n"
            << "  --verify                   Generate .hash sidecar on encrypt\n"
            << "  --algorithms <list>        Comma-separated algorithms for benchmark\n"
            << "  --modes <list>             Comma-separated modes for benchmark\n"
            << "  --test <name>              Analysis test to run: entropy, frequency,\n"
            << "                             avalanche. Omit to run all three.\n"
            << "  -h, --help                 Show this help message\n";
}

int main(int argc, char *argv[]) {
  Config config;

  // Argument parsing
  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];

    if (arg == "encrypt") {
      config.op = Operation::ENCRYPT;
    } else if (arg == "decrypt") {
      config.op = Operation::DECRYPT;
    } else if (arg == "verify") {
      config.op = Operation::VERIFY;
    } else if (arg == "benchmark") {
      config.op = Operation::BENCHMARK;
    } else if (arg == "analyze") {
      config.op = Operation::ANALYZE;
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
    } else if (arg == "--verify") {
      config.verify = true;
    } else if (arg == "--algorithms") {
      if (i + 1 < argc)
        config.benchAlgorithms = splitCSV(argv[++i]);
    } else if (arg == "--modes") {
      if (i + 1 < argc)
        config.benchModes = splitCSV(argv[++i]);
    } else if (arg == "--test") {
      if (i + 1 < argc)
        config.analyzeTest = argv[++i];
    } else if (arg == "-h" || arg == "--help") {
      print_help();
      return 0;
    }
  }

  if (config.op == Operation::NONE) {
    std::cerr << "Error: No command specified (encrypt/decrypt/verify/benchmark).\n";
    print_help();
    return 1;
  }

  // --- VERIFY command ---
  if (config.op == Operation::VERIFY) {
    if (config.inputFile.empty()) {
      std::cerr << "Error: Input file is required for verify.\n";
      return 1;
    }

    std::string hashFile = config.inputFile + ".hash";
    try {
      std::ifstream hf(hashFile);
      if (!hf) {
        std::cerr << "Error: Hash file not found: " << hashFile << "\n";
        return 1;
      }
      std::string expectedHex;
      hf >> expectedHex;

      auto actualHash = HashUtil::hash_file(config.inputFile);
      std::string actualHex = HashUtil::to_hex_string(actualHash);

      if (expectedHex == actualHex) {
        std::cout << "PASS: File integrity verified.\n";
        std::cout << "SHA-256: " << actualHex << "\n";
        return 0;
      } else {
        std::cerr << "FAIL: File integrity check failed!\n";
        std::cerr << "Expected: " << expectedHex << "\n";
        std::cerr << "Actual:   " << actualHex << "\n";
        return 1;
      }
    } catch (const std::exception &e) {
      std::cerr << "Error: " << e.what() << std::endl;
      return 1;
    }
  }

  // --- ANALYZE command ---
  if (config.op == Operation::ANALYZE) {
    if (config.inputFile.empty()) {
      std::cerr << "Error: Input file is required for analyze (-i).\n";
      return 1;
    }

    const std::string& test = config.analyzeTest;
    if (!test.empty() && test != "entropy" && test != "frequency" && test != "avalanche") {
      std::cerr << "Error: Unknown --test value '" << test << "'. "
                << "Valid options: entropy, frequency, avalanche\n";
      return 1;
    }

    try {
      auto data = FileHandler::read_file(config.inputFile);
      bool runAll = test.empty();

      if (runAll || test == "entropy") {
        auto result = measure_entropy(data);
        print_entropy_result(config.inputFile, result);
      }

      if (runAll || test == "frequency") {
        auto result = run_frequency_test(data);
        print_frequency_result(config.inputFile, result);
      }

      if (runAll || test == "avalanche") {
        std::cout << "\n[Avalanche test encrypts the input as plaintext with a fixed random key/IV]\n";
        auto avCBC = run_avalanche_test(CipherType::AES256_CBC, data);
        print_avalanche_result("AES-256-CBC", avCBC);

        auto avECB = run_avalanche_test(CipherType::AES256_ECB, data);
        print_avalanche_result("AES-256-ECB", avECB);

        auto avChacha = run_avalanche_test(CipherType::CHACHA20, data);
        print_avalanche_result("ChaCha20", avChacha);
      }

    } catch (const std::exception& e) {
      std::cerr << "Error: " << e.what() << std::endl;
      return 1;
    }
    return 0;
  }

  // --- BENCHMARK command ---
  if (config.op == Operation::BENCHMARK) {
    if (config.inputFile.empty()) {
      std::cerr << "Error: Input file is required for benchmark (-i).\n";
      return 1;
    }
    if (config.password.empty()) {
      config.password = "benchmarkpass";
    }

    // Defaults
    if (config.benchAlgorithms.empty()) {
      config.benchAlgorithms = {"aes256", "chacha20"};
    }
    if (config.benchModes.empty()) {
      config.benchModes = {"cbc", "ecb", "gcm"};
    }

    try {
      auto inputData = FileHandler::read_file(config.inputFile);
      std::vector<PerformanceMetrics> results;

      for (const auto &algo : config.benchAlgorithms) {
        std::vector<std::string> modes;
        if (algo == "chacha20") {
          modes = {"none"};
        } else {
          modes = config.benchModes;
        }

        for (const auto &mode : modes) {
          std::unique_ptr<Encryptor> enc;
          if (algo == "aes256") {
            enc = std::make_unique<AesCipher>(mode);
          } else if (algo == "chacha20") {
            enc = std::make_unique<ChaChaCipher>();
          } else {
            std::cerr << "Skipping unknown algorithm: " << algo << "\n";
            continue;
          }

          std::vector<uint8_t> encrypted, decrypted;
          PerformanceTracker tracker;

          // Encrypt
          tracker.startTimer();
          bool encOk = enc->encrypt(inputData, config.password, encrypted);
          tracker.stopTimer();
          double encTime = tracker.getElapsedSeconds();

          if (!encOk) {
            std::cerr << "Encrypt failed for " << algo << "/" << mode << "\n";
            continue;
          }

          // Decrypt
          tracker.startTimer();
          bool decOk = enc->decrypt(encrypted, config.password, decrypted);
          tracker.stopTimer();
          double decTime = tracker.getElapsedSeconds();

          if (!decOk) {
            std::cerr << "Decrypt failed for " << algo << "/" << mode << "\n";
            continue;
          }

          auto m = PerformanceTracker::buildReport(algo, mode,
                                                    inputData.size(), encrypted.size(),
                                                    encTime, decTime);
          results.push_back(m);
        }
      }

      // Print comparison table
      std::cout << "\n";
      std::cout << std::left
                << std::setw(12) << "Algorithm"
                << std::setw(8)  << "Mode"
                << std::right
                << std::setw(12) << "Enc (MB/s)"
                << std::setw(12) << "Dec (MB/s)"
                << std::setw(12) << "Enc (s)"
                << std::setw(12) << "Dec (s)"
                << std::setw(12) << "Overhead"
                << std::setw(14) << "Out Size"
                << "\n";
      std::cout << std::string(82, '-') << "\n";

      for (const auto &m : results) {
        std::cout << std::left
                  << std::setw(12) << m.algorithm
                  << std::setw(8)  << m.mode
                  << std::right << std::fixed
                  << std::setw(12) << std::setprecision(2) << m.encryptThroughputMBps
                  << std::setw(12) << std::setprecision(2) << m.decryptThroughputMBps
                  << std::setw(12) << std::setprecision(6) << m.encryptTimeSeconds
                  << std::setw(12) << std::setprecision(6) << m.decryptTimeSeconds
                  << std::setw(11) << std::setprecision(1) << m.overheadPercent << "%"
                  << std::setw(14) << m.encryptedSize
                  << "\n";
      }
      std::cout << "\nInput size: " << inputData.size() << " bytes\n";

    } catch (const std::exception &e) {
      std::cerr << "Error: " << e.what() << std::endl;
      return 1;
    }
    return 0;
  }

  // --- ENCRYPT / DECRYPT ---
  if (config.inputFile.empty() || config.outputFile.empty()) {
    std::cerr << "Error: Input and Output files are required.\n";
    return 1;
  }

  // Dispatcher
  std::unique_ptr<Encryptor> encryptor;

  if (config.algorithm == "aes256") {
    encryptor = std::make_unique<AesCipher>(config.mode);
  } else if (config.algorithm == "chacha20") {
    encryptor = std::make_unique<ChaChaCipher>();
  } else {
    std::cerr << "Error: Unknown algorithm '" << config.algorithm << "'.\n";
    return 1;
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

        if (config.op == Operation::ENCRYPT && config.verify) {
          auto hash = HashUtil::hash_file(config.outputFile);
          std::string hashHex = HashUtil::to_hex_string(hash);
          std::string hashPath = config.outputFile + ".hash";
          std::ofstream hf(hashPath);
          if (hf) {
            hf << hashHex << "\n";
            std::cout << "Hash sidecar written to " << hashPath << "\n";
          } else {
            std::cerr << "Warning: Could not write hash file: " << hashPath << "\n";
          }
        }
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
