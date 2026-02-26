#pragma once

#include "crypto/encryptor.h"
#include <vector>
#include <string>

// Mock Encryptor for testing infrastructure
class MockEncryptor : public Encryptor {
public:
    bool encrypt(const std::vector<uint8_t> &input, const std::string &key,
                 std::vector<uint8_t> &output) override {
        output = input;
        output.push_back(0xFF);
        return true;
    }

    bool decrypt(const std::vector<uint8_t> &input, const std::string &key,
                 std::vector<uint8_t> &output) override {
        if (input.empty()) return false;
        output = input;
        output.pop_back();
        return true;
    }
};
