# Task Breakdown

**Project**: File Encryption Tester
**Team**: Ethan Terrero, Miles Anderson, Noel Hernandez
**Date**: 2026-02-11

---

## Core Crypto & CLI

### E1: Replace key derivation with PBKDF2
- **Files**: `src/crypto/aes_cipher.cpp`, `src/crypto/chacha_cipher.cpp`
- **Details**: Current `deriveKeyAndIV()` uses a single SHA-256 hash which is weak. Replace with `PKCS5_PBKDF2_HMAC` using SHA-256, 100,000 iterations, and a 16-byte random salt. Both ciphers share the same derivation logic — consider extracting it into a shared utility function.
- **Acceptance**: Encrypt/decrypt round-trip still works. Key derivation matches what the README documents.

### E2: Wire up cipher mode selection
- **Files**: `src/main.cpp`, `src/crypto/aes_cipher.h`, `src/crypto/aes_cipher.cpp`
- **Details**: The `--mode` flag is parsed into `config.mode` but never passed to the cipher. Update the `Encryptor` interface or `AesCipher` constructor to accept a mode string. `AesCipher` should select between `EVP_aes_256_cbc()`, `EVP_aes_256_ecb()`, and `EVP_aes_256_gcm()` based on the mode. ChaCha20 is a stream cipher — modes don't apply, so it can ignore the parameter.
- **Acceptance**: `./file-crypto encrypt -a aes256 -m ecb` uses ECB. CBC remains the default. Invalid modes produce an error.

### E3: Implement encrypted file header format
- **Files**: `src/crypto/aes_cipher.cpp`, `src/crypto/chacha_cipher.cpp` (or a new shared header utility)
- **Details**: Currently only the 8-byte salt is prepended. Implement the header described in the README:
  - Magic bytes (e.g. `0x46 0x43` for "FC")
  - Algorithm identifier (1 byte)
  - Cipher mode (1 byte)
  - Salt (16 bytes after PBKDF2 change)
  - IV (variable, written explicitly)
  - Encrypted data follows
- Decryption should read the header to auto-detect algorithm/mode.
- **Depends on**: E1, E2
- **Acceptance**: Encrypted files are self-describing. Decrypt works without needing `-a` and `-m` flags.

### E4: Implement `benchmark` command
- **Files**: `src/main.cpp`
- **Depends on**: M2 (performance module)
- **Details**: When the user runs `./file-crypto benchmark --input file --algorithms aes256,chacha20 --modes cbc,ecb`, iterate over each algorithm/mode combo, encrypt and decrypt the input, collect metrics, and print a comparison table matching the README example output.
- **Acceptance**: Benchmark output shows encryption/decryption speed (MB/s), processing time, and overhead for each combo.

---

## Metrics & Benchmarking

### M1: SHA-256 hash utility
- **Files**: New `src/utils/hash.h`, `src/utils/hash.cpp`
- **Details**: Implement a utility that:
  - Computes SHA-256 hash of a `std::vector<uint8_t>` buffer
  - Computes SHA-256 hash of a file on disk (streaming, not loading entire file)
  - Compares two hashes and returns match/mismatch
  - Returns hash as a hex string for display
- Use OpenSSL's `EVP_Digest` API.
- **Acceptance**: Can hash a buffer, hash a file, and compare hashes correctly.

### M2: Performance metrics module
- **Files**: New `src/metrics/performance.h`, `src/metrics/performance.cpp`
- **Details**: Build a module that:
  - Wraps operations with `std::chrono::high_resolution_clock` timers
  - Computes throughput in MB/s given bytes processed and elapsed time
  - Tracks file size overhead (encrypted size - original size)
  - Tracks peak memory usage (platform-specific: `getrusage` on macOS/Linux)
  - Has a `print_report()` or similar function to display results
- **Acceptance**: Can time an encrypt/decrypt call and produce the metrics listed in the README.

### M3: Implement `verify` command
- **Files**: `src/main.cpp`
- **Depends on**: M1 (hash utility)
- **Details**: When the user runs `./file-crypto encrypt --input data.json --output data.enc --verify`, compute and store the SHA-256 hash of the original file in a `.hash` sidecar file. The `verify` command should recompute the hash and compare. Should detect corruption.
- **Acceptance**: `--verify` flag produces a `.hash` file. `./file-crypto verify --input data.enc` checks integrity and reports pass/fail.

### M4: Update CMakeLists.txt for new source files
- **Files**: `CMakeLists.txt`
- **Details**: Add `src/utils/hash.cpp` and `src/metrics/performance.cpp` to the `add_executable` source list. Ensure everything still builds cleanly.
- **Acceptance**: `cmake .. && make` succeeds with all new files included.

---

## Testing & Documentation

### N1: Set up test framework
- **Files**: `CMakeLists.txt`, new `tests/` directory
- **Details**: Add Google Test (or Catch2) as a dependency. Configure CTest in CMakeLists.txt. Create the test directory structure. Ensure `make test` runs all test executables.
- **Acceptance**: `make test` runs and reports results, even if tests are just stubs initially.

### N2: Write encryption round-trip tests
- **Files**: New `tests/test_encryption.cpp`
- **Depends on**: N1
- **Details**: Test cases:
  - AES-256-CBC: encrypt then decrypt, verify output == input
  - AES-256-ECB: same round-trip
  - ChaCha20: same round-trip
  - Wrong password: decrypt should fail
  - Empty input: should handle gracefully
  - Large input (1MB+): should succeed without issues
- **Acceptance**: All tests pass. Covers each algorithm/mode combo.

### N3: Write integrity tests
- **Files**: New `tests/test_integrity.cpp`
- **Depends on**: N1, M1
- **Details**: Test cases:
  - Hash a known buffer and verify against expected SHA-256 output
  - Hash a file and verify it matches buffer hash of same content
  - Flip a byte in encrypted data, verify integrity check detects corruption
- **Acceptance**: All tests pass.

### N4: Write performance tests
- **Files**: New `tests/test_performance.cpp`
- **Depends on**: N1, M2
- **Details**: Sanity-check tests:
  - Metrics module returns non-zero throughput
  - Timing values are reasonable (> 0, < timeout)
  - Overhead calculation is correct (encrypted size - original size)
- **Acceptance**: All tests pass.

### N5: Documentation
- **Files**: New `docs/ARCHITECTURE.md`, `docs/API.md`, `docs/BENCHMARKS.md`
- **Depends on**: Most implementation tasks complete
- **Details**:
  - `ARCHITECTURE.md`: Describe the class hierarchy, file format, data flow
  - `API.md`: Document the public interfaces of each module
  - `BENCHMARKS.md`: Template for recording benchmark results, to be filled in after benchmarking works
- **Acceptance**: Docs exist and accurately reflect the codebase.

### N6: Project cleanup
- **Files**: `.gitignore`, `LICENSE`, `src/main.cpp`
- **Details**:
  - Add `build/` and `.cache/` to `.gitignore`
  - Add MIT `LICENSE` file
  - Move `MockEncryptor` out of `main.cpp` into test code
- **Acceptance**: `git status` doesn't show build artifacts. LICENSE exists.

---

## Dependency Graph

```
E1 (PBKDF2) ──┐
E2 (modes)  ───┤
               ├──> E3 (file header) ──> E4 (benchmark cmd)
M1 (hash)  ────┤                    ──> M3 (verify cmd)
M2 (metrics) ──┤──> M4 (CMake update)
               │
N1 (test framework) ──> N2 (encryption tests)
                   ──> N3 (integrity tests, needs M1)
                   ──> N4 (perf tests, needs M2)
                   ──> N5 (docs, after implementation)
                   ──> N6 (cleanup, anytime)
```

## Suggested Order

1. **Start in parallel**: E1 + E2 | M1 + M2 | N1 + N6
2. **Second wave**: E3 | M3 + M4 | N2
3. **Third wave**: E4 | N3 + N4
4. **Final**: N5 (docs after everything works)
