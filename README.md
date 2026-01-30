# File Encryption Tester

A command-line utility for encrypting and decrypting files with performance analysis and algorithm comparison.

**Team Members**: Ethan Terrero, Miles Anderson, Noel Hernandez  
**Course**: CS 433 - Class Project  
**University of Oregon**

## Overview

File Encryption Tester provides a practical tool for secure file encryption while offering insights into performance characteristics across different encryption algorithms and modes. The tool helps users understand the tradeoffs between security approaches through real-time metrics and comparative analysis.

## Features

- **Multiple Encryption Algorithms**
  - AES-256 (Advanced Encryption Standard)
  - ChaCha20 (Modern stream cipher)
  
- **Cipher Modes of Operation**
  - ECB (Electronic Codebook)
  - CBC (Cipher Block Chaining)
  - GCM (Galois/Counter Mode) *planned*

- **Performance Metrics**
  - Encryption/decryption speed (MB/s)
  - Processing time
  - File size overhead analysis
  - Memory usage tracking

- **Data Integrity**
  - SHA-256 hash verification
  - Pre/post encryption integrity checks
  - Corruption detection

- **Comparative Analysis**
  - Side-by-side algorithm performance
  - Mode comparison dashboards
  - Hardware-specific benchmarking

## Installation

### Prerequisites

- C++17 compatible compiler (GCC 9+, Clang 10+, or MSVC 2019+)
- OpenSSL development libraries (1.1.1 or later)
- CMake 3.15+

### Build Instructions

```bash
# Clone the repository
git clone https://github.com/yourusername/file-encryption-tester.git
cd file-encryption-tester

# Create build directory
mkdir build && cd build

# Configure and build
cmake ..
make

# Run tests (optional)
make test
```

### Installing OpenSSL

**Ubuntu/Debian:**
```bash
sudo apt-get install libssl-dev
```

**macOS:**
```bash
brew install openssl
```

**Windows:**
Download from [OpenSSL for Windows](https://slproweb.com/products/Win32OpenSSL.html)

## Usage

### Basic Encryption

```bash
# Encrypt a file with AES-256 in CBC mode
./file-crypto encrypt --input document.pdf --output document.enc --algorithm aes256 --mode cbc --password mySecurePassword

# Decrypt the file
./file-crypto decrypt --input document.enc --output document.pdf --algorithm aes256 --mode cbc --password mySecurePassword
```

### Performance Benchmarking

```bash
# Run performance comparison across algorithms
./file-crypto benchmark --input largefile.bin --algorithms aes256,chacha20 --modes cbc,ecb

# Output:
# Algorithm: AES-256-CBC
#   Encryption: 245.3 MB/s
#   Decryption: 267.8 MB/s
#   Overhead: 16 bytes
# 
# Algorithm: ChaCha20
#   Encryption: 312.1 MB/s
#   Decryption: 318.4 MB/s
#   Overhead: 0 bytes
```

### Integrity Verification

```bash
# Encrypt with automatic integrity checking
./file-crypto encrypt --input data.json --output data.enc --verify

# Verification hashes stored in data.enc.hash
```

## Command Reference

### Commands

- `encrypt` - Encrypt a file
- `decrypt` - Decrypt a file
- `benchmark` - Compare algorithm performance
- `verify` - Check file integrity
- `help` - Show help information

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `--input, -i` | Input file path | Required |
| `--output, -o` | Output file path | Required |
| `--algorithm, -a` | Encryption algorithm (aes256, chacha20) | aes256 |
| `--mode, -m` | Cipher mode (ecb, cbc, gcm) | cbc |
| `--password, -p` | Encryption password | Prompt if not provided |
| `--keyfile, -k` | Path to key file | None |
| `--verify, -v` | Enable integrity verification | false |
| `--verbose` | Show detailed output | false |

## Project Structure

```
file-encryption-tester/
├── src/
│   ├── main.cpp              # CLI entry point
│   ├── crypto/
│   │   ├── encryptor.h       # Encryption interface
│   │   ├── encryptor.cpp
│   │   ├── aes_cipher.h      # AES implementation
│   │   ├── aes_cipher.cpp
│   │   ├── chacha_cipher.h   # ChaCha20 implementation
│   │   └── chacha_cipher.cpp
│   ├── io/
│   │   ├── file_handler.h    # File I/O operations
│   │   └── file_handler.cpp
│   ├── metrics/
│   │   ├── performance.h     # Performance tracking
│   │   └── performance.cpp
│   └── utils/
│       ├── hash.h            # SHA-256 hashing
│       └── hash.cpp
├── tests/
│   ├── test_encryption.cpp
│   ├── test_performance.cpp
│   └── test_integrity.cpp
├── docs/
│   ├── ARCHITECTURE.md
│   ├── API.md
│   └── BENCHMARKS.md
├── CMakeLists.txt
├── README.md
└── LICENSE
```

## Development Timeline

- **Weeks 1-2**: Research & Setup
  - OpenSSL library integration
  - Basic file I/O implementation
  - Project structure setup

- **Weeks 3-5**: Core Implementation
  - AES-256 encryption/decryption
  - ChaCha20 integration
  - Multiple cipher modes (ECB, CBC)

- **Weeks 6-7**: Metrics & Analysis
  - Performance measurement system
  - Comparison dashboard
  - Integrity verification (SHA-256)

- **Weeks 8-9**: Polish & Testing
  - CLI refinement and UX
  - Edge case handling
  - Comprehensive test suite
  - User documentation

- **Week 10**: Finalization
  - Project report completion
  - Presentation preparation
  - Final code review

## Security Considerations

⚠️ **Educational Purpose**: This tool is designed for educational purposes to demonstrate encryption concepts and performance characteristics.

- Use strong, unique passwords for encryption
- ECB mode has known vulnerabilities - use CBC or GCM for production
- Password-based encryption uses PBKDF2 for key derivation
- Always verify file integrity after encryption/decryption
- Keep your encryption keys secure and backed up

## Technical Details

### Key Derivation
Passwords are converted to encryption keys using PBKDF2-HMAC-SHA256 with 100,000 iterations and a random salt.

### File Format
Encrypted files include a header with:
- Magic bytes (identification)
- Algorithm identifier
- Cipher mode
- Salt (for key derivation)
- Initialization Vector (IV)
- Encrypted data
- Optional integrity hash

### Performance Optimization
- Buffered I/O for large files
- Memory-mapped files for better performance
- Hardware AES-NI support when available

## Contributing

This is a class project, but we welcome feedback and suggestions:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Commit your changes (`git commit -am 'Add new feature'`)
4. Push to the branch (`git push origin feature/improvement`)
5. Open a Pull Request

## Testing

```bash
# Run all tests
make test

# Run specific test suite
./tests/test_encryption
./tests/test_performance
./tests/test_integrity

# Generate coverage report
make coverage
```

## Known Limitations

- Maximum file size: 2GB (due to current buffering strategy)
- Password length: 8-128 characters
- ECB mode warning: Not recommended for files with repetitive patterns
- Platform: Currently tested on Linux and macOS

## Future Enhancements

- [ ] GUI interface
- [ ] Additional algorithms (Twofish, Serpent)
- [ ] GCM mode implementation
- [ ] Multi-file batch processing
- [ ] Cloud storage integration
- [ ] Hardware acceleration benchmarking

## References

- [OpenSSL Documentation](https://www.openssl.org/docs/)
- [NIST Encryption Standards](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines)
- [Cryptography Best Practices](https://cryptographyacademy.com/)

## License

MIT License - See LICENSE file for details

## Acknowledgments

- University of Oregon CS Department
- OpenSSL Project
- Course Instructor and TAs

---

**Contact**: For questions or issues, please open a GitHub issue or contact the team members directly.