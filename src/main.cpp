#include <iostream>
#include <openssl/crypto.h>

int main(int argc, char* argv[]) {
    std::cout << "File Encryption Tester v1.0" << std::endl;
    std::cout << "Linked against: " << OpenSSL_version(OPENSSL_VERSION) << std::endl;
    
    // TODO: Argument parsing and command dispatch

    return 0;
}
