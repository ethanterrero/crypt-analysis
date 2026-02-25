# Project Status & Term Plan

**Project**: File Encryption Tester
**Team**: Ethan Terrero, Miles Anderson, Noel Hernandez
**Course**: CS 433 — University of Oregon
**Date**: 2026-02-11
**Remaining**: 4 weeks

---

## What's Been Completed

### Build System
- CMake configuration with C++17 and OpenSSL linking
- macOS Homebrew OpenSSL path detection
- Project compiles and produces the `file-crypto` binary

### Encryption Core
- **`Encryptor` base class** — abstract interface with `encrypt()`/`decrypt()` virtual methods
- **`AesCipher`** — AES-256-CBC encryption and decryption using OpenSSL EVP API, with salt prepended to output
- **`ChaChaCipher`** — ChaCha20 encryption and decryption using OpenSSL EVP API, same salt pattern
- Both ciphers use SHA-256-based key derivation from a user password

### File I/O
- **`FileHandler`** — binary file read (load entire file into memory) and write operations

### CLI
- Argument parser supporting `encrypt` and `decrypt` commands
- Flags: `--input`, `--output`, `--password`, `--algorithm`, `--mode`, `--help`
- Algorithm dispatch for `aes256`, `chacha20`, and a `mock` test cipher
- End-to-end pipeline: read file, encrypt/decrypt, write output

### Current File Structure
```
src/
  main.cpp                 -- CLI entry point + arg parsing
  crypto/
    encryptor.h            -- abstract base class
    aes_cipher.h/.cpp      -- AES-256-CBC implementation
    chacha_cipher.h/.cpp   -- ChaCha20 implementation
  io/
    file_handler.h/.cpp    -- binary file read/write
CMakeLists.txt
README.md
.gitignore
```

---

## Known Gaps

| Area | Gap | Severity |
|------|-----|----------|
| Key derivation | Uses single SHA-256 instead of PBKDF2 w/ 100k iterations | High — security issue |
| Cipher modes | `--mode` flag is parsed but ignored; AES hardcoded to CBC | High — advertised feature missing |
| File format | Only 8-byte salt prepended; no magic bytes, algorithm ID, mode, or IV in header | Medium |
| Benchmarking | `benchmark` command not implemented | Medium |
| Integrity | No SHA-256 hashing, no `verify` command, no `.hash` sidecar files | Medium |
| Performance metrics | `src/metrics/` directory doesn't exist | Medium |
| Hash utility | `src/utils/` directory doesn't exist | Medium |
| Tests | `tests/` directory doesn't exist; zero test coverage | High |
| Docs | `docs/` directory doesn't exist | Low |
| License | `LICENSE` file missing | Low |
| .gitignore | `build/` directory not ignored | Low |

---

## 4-Week Plan

### Week 1 — Foundations (Feb 11 - Feb 18)

All three members work in parallel on independent tasks.

| Who | Task | Ref |
|-----|------|-----|
| Ethan | Replace key derivation with PBKDF2 in both ciphers | E1 |
| Ethan | Wire `--mode` flag through to AesCipher (ECB, CBC, GCM) | E2 |
| Miles | Build SHA-256 hash utility (`src/utils/hash.h/.cpp`) | M1 |
| Miles | Build performance metrics module (`src/metrics/performance.h/.cpp`) | M2 |
| Noel | Set up Google Test / CTest framework, create `tests/` directory | N1 |
| Noel | Add `build/` and `.cache/` to `.gitignore`, add `LICENSE`, move `MockEncryptor` to tests | N6 |

**Week 1 deliverable**: All new modules compile. Key derivation is secure. Cipher modes work. Test framework runs stub tests.

---

### Week 2 — Integration (Feb 18 - Feb 25)

Connect the new modules to the CLI and begin testing the crypto layer.

| Who | Task | Ref |
|-----|------|-----|
| Ethan | Implement encrypted file header format (magic bytes, algo ID, mode, salt, IV) | E3 |
| Miles | Implement `verify` command using hash utility | M3 |
| Miles | Update `CMakeLists.txt` with all new source files | M4 |
| Noel | Write encryption round-trip tests (AES-CBC, AES-ECB, ChaCha20, wrong password, edge cases) | N2 |

**Week 2 deliverable**: Encrypted files are self-describing. Integrity verification works. Core encryption has test coverage.

---

### Week 3 — Features & Testing (Feb 25 - Mar 4)

Finish the remaining CLI commands and complete the test suite.

| Who | Task | Ref |
|-----|------|-----|
| Ethan | Implement `benchmark` command with comparison table output | E4 |
| Miles | Help with benchmark integration, run benchmarks on sample files | — |
| Noel | Write integrity tests | N3 |
| Noel | Write performance/metrics tests | N4 |

**Week 3 deliverable**: All CLI commands (`encrypt`, `decrypt`, `benchmark`, `verify`) are functional. Full test suite passes.

---

### Week 4 — Polish & Presentation (Mar 4 - Mar 11)

Documentation, bug fixes, and final deliverables.

| Who | Task | Ref |
|-----|------|-----|
| Noel | Write `docs/ARCHITECTURE.md`, `docs/API.md`, `docs/BENCHMARKS.md` | N5 |
| Ethan | Final code review, edge case fixes, CLI polish | — |
| Miles | Run full benchmarks, populate `BENCHMARKS.md` with real data | — |
| All | Update `README.md` to reflect final state | — |
| All | Prepare presentation, write project report | — |

**Week 4 deliverable**: All README features are implemented. Documentation is complete. Project is presentation-ready.

---

## Milestones Summary

| Date | Milestone |
|------|-----------|
| Feb 18 | Secure key derivation, cipher modes, new modules compile, test framework ready |
| Feb 25 | File header format, verify command, encryption tests passing |
| Mar 4 | Benchmark command, full test suite passing |
| Mar 11 | Docs complete, benchmarks recorded, presentation ready |
