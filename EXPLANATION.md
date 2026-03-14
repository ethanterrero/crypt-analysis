# File Encryption Tester - Project Explanation

**Course:** CS 433 - University of Oregon
**Team:** Ethan Terrero, Miles Anderson, Noel Hernandez

---

## What We Built

A command-line file encryption tool written in C++17 that supports multiple encryption algorithms, cipher modes, integrity verification, and performance benchmarking. The tool reads any file, encrypts it with a password-derived key, and writes the encrypted output with a self-describing header so decryption can auto-detect settings.

### Core Features

1. **Encryption/Decryption** with two algorithms:
   - **AES-256** in three cipher modes: CBC, ECB, and GCM
   - **ChaCha20** (stream cipher)

2. **Secure Key Derivation** using PBKDF2-HMAC-SHA256 with 100,000 iterations and a 16-byte random salt. This replaces a naive single-pass SHA-256 hash and makes brute-force attacks significantly harder.

3. **Self-Describing File Header** so encrypted files carry their own metadata:
   ```
   [2 bytes "FC" magic] [1 byte algorithm ID] [1 byte mode ID] [16 bytes salt] [IV] [ciphertext]
   ```
   On decryption, the tool reads the header to determine which algorithm and mode were used.

4. **Integrity Verification** using SHA-256 hashing. The `--verify` flag on encrypt produces a `.hash` sidecar file, and the `verify` command checks whether the encrypted file has been tampered with.

5. **Performance Benchmarking** that runs encrypt/decrypt across all algorithm+mode combinations and prints a comparison table with throughput (MB/s), timing, and overhead.

---

## Project Structure

```
crypt-analysis/
├── src/
│   ├── main.cpp                    # CLI entry point and argument parser
│   ├── crypto/
│   │   ├── encryptor.h             # Abstract base class (interface)
│   │   ├── aes_cipher.h/.cpp       # AES-256 implementation (CBC/ECB/GCM)
│   │   ├── chacha_cipher.h/.cpp    # ChaCha20 implementation
│   │   ├── key_derivation.h/.cpp   # Shared PBKDF2 key derivation
│   │   └── file_format.h/.cpp      # File header read/write
│   ├── io/
│   │   └── file_handler.h/.cpp     # Binary file read/write
│   ├── utils/
│   │   └── hash.h/.cpp             # SHA-256 hashing utilities
│   ├── metrics/
│   │   └── performance.h/.cpp      # Timing, throughput, memory tracking
│   ├── benchmark/
│   │   └── profiler.h/.cpp         # CPU cycle counter and wall-clock timer
│   └── analysis/
│       ├── avalanche.h/.cpp        # Avalanche effect (bit-flip diffusion) test
│       ├── entropy.h/.cpp          # Shannon entropy measurement
│       └── frequency.h/.cpp        # Chi-squared byte frequency uniformity test
├── tests/
│   ├── test_helpers.h              # MockEncryptor for test infrastructure
│   ├── test_encryption.cpp         # Encryption round-trip tests (19 tests)
│   ├── test_integrity.cpp          # SHA-256 hash verification tests (10 tests)
│   ├── test_performance.cpp        # Metrics and throughput tests (9 tests)
│   └── test_analysis.cpp           # Entropy, frequency, avalanche tests (20 tests)
├── demo/
│   ├── hexcompare.py               # Visual hex diff of two encrypted files
│   ├── freqdist.py                 # Visual byte frequency bar chart
│   └── clean.sh                    # Deletes .enc/.dec/.hash files from demo/
├── CMakeLists.txt                  # Build configuration
└── EXPLANATION.md                  # This file
```

---

## What We Changed (Week 1-2 Work)

All changes were made in 9 incremental commits on the `dev/ethan` branch:

| Commit | Task | Description |
|--------|------|-------------|
| 1 | E1 | Replaced weak SHA-256 key derivation with PBKDF2 (100k iterations, 16-byte salt) |
| 2 | E2 | Added AES cipher mode selection (CBC, ECB, GCM) with GCM auth tag handling |
| 3 | M1 | Created SHA-256 hash utility with streaming file hashing |
| 4 | M2 | Built performance metrics module and implemented CPU cycle profiler |
| 5 | N1+N6 | Set up Google Test framework, moved MockEncryptor to tests, cleaned up .gitignore |
| 6 | E3 | Implemented self-describing encrypted file header with magic bytes and metadata |
| 7 | M3 | Added `verify` command and `--verify` flag for integrity checking |
| 8 | E4 | Added `benchmark` command with formatted comparison table |
| 9 | N2-N4 | Completed full test suite: encryption, integrity, and performance tests |

### Key Technical Decisions

- **PBKDF2 over SHA-256 for key derivation:** A single SHA-256 hash is trivially brute-forced. PBKDF2 with 100,000 iterations adds computational cost that slows attackers while remaining fast enough for normal use.

- **IV stored in header, not derived from password:** Deriving the IV from the password means the same password always produces the same IV, which is a known weakness for CBC mode. Storing a random IV in the header ensures unique ciphertext even for identical plaintext+password combinations.

- **GCM authentication tag appended after ciphertext:** GCM provides authenticated encryption. The 16-byte tag is appended to the ciphertext on encrypt and extracted on decrypt. If the ciphertext or tag is tampered with, decryption fails immediately.

- **Shared LIB_SOURCES in CMake:** The same set of library source files is compiled into both the main executable and the test executable, avoiding code duplication and ensuring tests run against the same code that ships.

---

## How We Tested It

### Automated Tests (38 total, all passing)

Built with Google Test (v1.14.0) fetched via CMake's `FetchContent`. Tests run through CTest.

**Encryption Tests (19 tests in `test_encryption.cpp`):**
- Round-trip encrypt/decrypt for every algorithm+mode (AES-CBC, AES-ECB, AES-GCM, ChaCha20)
- Wrong password rejection (CBC/ECB fail on padding, GCM fails on auth tag)
- Empty input handling
- Large file support (1 MB)
- GCM tamper detection (flipping a ciphertext byte causes auth failure)
- Invalid cipher mode throws an exception
- Encrypted output differs from plaintext

**Integrity Tests (10 tests in `test_integrity.cpp`):**
- SHA-256 hash consistency (same data produces same hash)
- Different data produces different hashes
- Known hash value for empty input matches the published SHA-256 of ""
- File hash matches buffer hash for the same data
- Corruption detection (modifying a file changes its hash)
- Hex string formatting
- Non-existent file throws an error

**Performance Tests (9 tests in `test_performance.cpp`):**
- Timer measures positive elapsed time
- Throughput calculation returns reasonable values
- Overhead calculation (10% for 1000 -> 1100 bytes)
- Zero and empty-input edge cases
- Memory usage reports a non-zero value
- BuildReport populates all fields correctly
- AES-CBC and ChaCha20 both achieve >1 MB/s on any modern hardware

**Analysis Tests (`test_analysis.cpp`):**
- Shannon entropy: empty input, all-same byte (zero entropy), all-byte-values (max entropy = 8.0), pseudo-random data
- Chi-squared frequency: non-uniform data fails, perfectly uniform data scores suspiciously high, pseudo-random data passes
- Avalanche effect: AES-CBC average bit change near 50%, ChaCha20 near 0% (expected for stream ciphers), min ≤ avg ≤ max invariant

### Manual Testing

Every commit was verified with a manual encrypt/decrypt round-trip:
```bash
./build/file-crypto encrypt -i testfile -o testfile.enc -p testpass
./build/file-crypto decrypt -i testfile.enc -o testfile.dec -p testpass
diff testfile testfile.dec   # no output = files are identical
```

This was repeated for all modes (`-m cbc`, `-m ecb`, `-m gcm`) and both algorithms (`-a aes256`, `-a chacha20`).

---

## How to Build and Run

### Prerequisites

- C++17 compiler (GCC 7+, Clang 5+, or MSVC 2017+)
- CMake 3.15+
- OpenSSL 1.1.1+ (on macOS: `brew install openssl@3`)

### Build

```bash
cmake -B build -S .
cmake --build build
```

### Run Tests

```bash
cd build && ctest --output-on-failure
```

---

## How to Use the Application

### Encrypt a file

```bash
./build/file-crypto encrypt -i myfile.txt -o myfile.enc -p "my password"
```

With a specific algorithm and mode:
```bash
./build/file-crypto encrypt -i myfile.txt -o myfile.enc -p "my password" -a aes256 -m gcm
```

With integrity hash sidecar:
```bash
./build/file-crypto encrypt -i myfile.txt -o myfile.enc -p "my password" --verify
# Creates myfile.enc and myfile.enc.hash
```

### Decrypt a file

```bash
./build/file-crypto decrypt -i myfile.enc -o myfile.txt -p "my password"
```

The algorithm and mode are auto-detected from the file header. You can still pass `-a` and `-m` explicitly but they are not required for decryption.

### Verify file integrity

After encrypting with `--verify`:
```bash
./build/file-crypto verify -i myfile.enc
# Output: PASS or FAIL with SHA-256 hash
```

### Run benchmarks

Compare all algorithms and modes:
```bash
./build/file-crypto benchmark -i myfile.txt
```

Compare specific combinations:
```bash
./build/file-crypto benchmark -i myfile.txt --algorithms aes256,chacha20 --modes cbc,gcm
```

Example output:
```
Algorithm   Mode      Enc (MB/s)  Dec (MB/s)     Enc (s)     Dec (s)    Overhead      Out Size
----------------------------------------------------------------------------------
aes256      cbc            24.63       29.06    0.040593    0.034408        0.0%       1048628
aes256      ecb            29.30       29.26    0.034130    0.034175        0.0%       1048612
aes256      gcm            28.95       29.17    0.034548    0.034280        0.0%       1048624
chacha20    none           28.49       28.98    0.035095    0.034511        0.0%       1048612

Input size: 1048576 bytes
```

### Command reference

| Command | Required flags | Optional flags |
|---------|---------------|----------------|
| `encrypt` | `-i`, `-o`, `-p` | `-a`, `-m`, `--verify` |
| `decrypt` | `-i`, `-o`, `-p` | `-a`, `-m` |
| `verify` | `-i` | |
| `benchmark` | `-i` | `-p`, `--algorithms`, `--modes` |
| `analyze` | `-i` | |

### Run cryptographic analysis

Run entropy, frequency, and avalanche analysis on any file (plaintext or ciphertext):
```bash
./build/file-crypto analyze -i myfile.enc
```

Output includes:
- **Shannon entropy** (bits/byte) — ideal ciphertext scores ~8.0
- **Chi-squared byte frequency test** — p-value between 0.05 and 0.95 means the distribution looks random
- **Avalanche effect** — per-cipher test showing how many ciphertext bits flip when one input bit changes; AES-CBC targets ~50%, ChaCha20 will score near 0% by design (stream cipher)

### Algorithm and mode options

| Algorithm | Flag value | Description |
|-----------|-----------|-------------|
| AES-256 | `aes256` | Block cipher, 256-bit key (default) |
| ChaCha20 | `chacha20` | Stream cipher, 256-bit key |

| Mode | Flag value | Notes |
|------|-----------|-------|
| CBC | `cbc` | Cipher Block Chaining (default) |
| ECB | `ecb` | Electronic Codebook (not recommended - identical blocks produce identical ciphertext) |
| GCM | `gcm` | Galois/Counter Mode (authenticated encryption, recommended) |

ChaCha20 does not use a mode flag (it is always a stream cipher).

---

## Encrypted File Format

Every encrypted file begins with a header that allows the tool to auto-detect settings:

```
Offset  Size  Field
0       2     Magic bytes ("FC" = 0x46 0x43)
2       1     Algorithm ID (0x01 = AES-256, 0x02 = ChaCha20)
3       1     Mode ID (0x01 = CBC, 0x02 = ECB, 0x03 = GCM, 0x00 = none)
4       16    Salt (random, used for PBKDF2 key derivation)
20      var   IV (16 bytes for CBC/ChaCha20, 12 bytes for GCM, 0 for ECB)
var     var   Ciphertext
var     16    GCM auth tag (only present in GCM mode)
```

---

## Live Demo Script

Below is a step-by-step walkthrough you can follow to demonstrate the tool in front of the class. Each section builds on the previous one and highlights a different feature. All commands assume you are in the project root directory.

### 0. Setup (do this before the presentation)

```bash
# Build the project from scratch
rm -rf build
cmake -B build -S .
cmake --build build

# Create a sample file to work with
echo "CS 433 - Cryptography is awesome!" > demo.txt
```

### 1. Basic Encrypt / Decrypt

Show the simplest use case: encrypt a file and get it back.

```bash
# Encrypt with default settings (AES-256-CBC)
./build/file-crypto encrypt -i demo.txt -o demo.enc -p secret123

# Show that the encrypted file is binary gibberish
cat demo.enc

# Decrypt it back
./build/file-crypto decrypt -i demo.enc -o demo_recovered.txt -p secret123

# Prove the recovered file matches the original
cat demo_recovered.txt
diff demo.txt demo_recovered.txt && echo "Files are identical"
```

**Talking point:** The plaintext goes in, unreadable ciphertext comes out, and only the correct password can reverse it.

### 2. Wrong Password Fails

Demonstrate that the wrong password does not silently produce garbage — it actually fails.

```bash
./build/file-crypto decrypt -i demo.enc -o demo_bad.txt -p wrongpassword
# Output: "Operation failed."
```

**Talking point:** CBC and ECB modes use PKCS#7 padding. If the wrong key is used, the padding bytes are invalid and OpenSSL rejects the decryption. GCM goes further — its authentication tag will not match, so tampering is also caught.

### 3. Comparing Cipher Modes

Show how the same file looks different under each mode.

```bash
# Create a file with repeated content to highlight ECB's weakness
python3 -c "print('AAAA' * 1000)" > repeated.txt

# Encrypt with each mode
./build/file-crypto encrypt -i repeated.txt -o repeated_cbc.enc -p demo -m cbc
./build/file-crypto encrypt -i repeated.txt -o repeated_ecb.enc -p demo -m ecb
./build/file-crypto encrypt -i repeated.txt -o repeated_gcm.enc -p demo -m gcm

# Compare file sizes (ECB has no IV, GCM has an auth tag)
ls -l repeated_cbc.enc repeated_ecb.enc repeated_gcm.enc

# All three decrypt correctly
./build/file-crypto decrypt -i repeated_gcm.enc -o repeated_check.txt -p demo
diff repeated.txt repeated_check.txt && echo "GCM round-trip OK"
```

**Talking point:** ECB encrypts each block independently — identical plaintext blocks produce identical ciphertext blocks. CBC and GCM do not have this weakness. GCM additionally provides authentication, which is why it is recommended for real-world use.

### 3b. ECB Pattern Leakage — Visual Hex Comparison

Use `demo/hexcompare.py` to show the repeating block pattern in ECB output side-by-side with CBC output. Differing bytes are highlighted in red.

```bash
python3 demo/hexcompare.py repeated_ecb.enc repeated_cbc.enc
```

**Talking point:** In the ECB output, the same 16-byte ciphertext block repeats over and over because every plaintext block (`AAAA...`) is identical and is encrypted independently with the same key. In CBC output, every block is different — the previous ciphertext is XOR'd into each new block before encryption, destroying the pattern. The percentage at the bottom shows how many bytes differ between the two files.

### 4. ChaCha20 (Stream Cipher)

Show the alternative algorithm.

```bash
./build/file-crypto encrypt -i demo.txt -o demo_chacha.enc -p secret123 -a chacha20
./build/file-crypto decrypt -i demo_chacha.enc -o demo_chacha.txt -p secret123 -a chacha20
diff demo.txt demo_chacha.txt && echo "ChaCha20 round-trip OK"
```

**Talking point:** ChaCha20 is a stream cipher designed by Daniel Bernstein. It does not use block modes — it generates a keystream and XORs it with the plaintext. It is widely used in TLS 1.3 and WireGuard.

### 5. File Header (Self-Describing Format)

Show that encrypted files carry metadata so the tool knows how to decrypt them.

```bash
# Look at the first few bytes of an encrypted file
xxd demo.enc | head -3
# First two bytes are 0x46 0x43 ("FC" magic)
# Third byte is the algorithm ID (0x01 = AES-256)
# Fourth byte is the mode ID (0x01 = CBC)
```

**Talking point:** The header means you do not have to remember which algorithm or mode you used. The tool reads the magic bytes and metadata on decrypt and selects the right cipher automatically.

### 6. Integrity Verification

Demonstrate tamper detection using SHA-256 hash sidecars.

```bash
# Encrypt with --verify to generate a .hash file
./build/file-crypto encrypt -i demo.txt -o demo_verified.enc -p secret123 --verify

# Show the hash file
cat demo_verified.enc.hash

# Verify passes on an untouched file
./build/file-crypto verify -i demo_verified.enc

# Now tamper with the encrypted file
echo "tampered" >> demo_verified.enc

# Verify catches the tampering
./build/file-crypto verify -i demo_verified.enc
# Output: FAIL with mismatched hashes
```

**Talking point:** The `.hash` sidecar stores a SHA-256 digest of the encrypted file at the time of creation. If even a single byte is changed — whether by an attacker, disk corruption, or a bad network transfer — the verify command detects it.

### 7. Performance Benchmarks

Run the benchmark and discuss the results.

```bash
# Create a 1 MB test file
dd if=/dev/urandom of=bench_input.bin bs=1024 count=1024 2>/dev/null

# Run benchmarks across all algorithms and modes
./build/file-crypto benchmark -i bench_input.bin
```

Expected output:
```
Algorithm   Mode      Enc (MB/s)  Dec (MB/s)     Enc (s)     Dec (s)    Overhead      Out Size
----------------------------------------------------------------------------------
aes256      cbc            24.63       29.06    0.040593    0.034408        0.0%       1048628
aes256      ecb            29.30       29.26    0.034130    0.034175        0.0%       1048612
aes256      gcm            28.95       29.17    0.034548    0.034280        0.0%       1048624
chacha20    none           28.49       28.98    0.035095    0.034511        0.0%       1048612

Input size: 1048576 bytes
```

**Talking points:**
- ECB is slightly faster because it has no IV and no chaining dependency between blocks.
- GCM adds only 16 bytes of overhead (the auth tag) while providing authentication.
- ChaCha20 throughput is competitive with AES on ARM hardware (Apple Silicon has hardware AES acceleration, so AES may appear faster on Intel/AMD).
- Overhead is near zero for all modes on a 1 MB file because the header and padding are tiny relative to the data.

### 7b. Byte Frequency Distribution and Chi-Squared Test

Use `demo/freqdist.py` to show that good ciphertext has a flat, uniform byte distribution — statistically indistinguishable from random noise.

```bash
python3 demo/freqdist.py demo.txt demo.enc
```

**Talking points:**
- The plaintext side will show spikes — ASCII letters cluster around 0x61–0x7a (lowercase), 0x20 (space), etc.
- The ciphertext side shows a flat histogram — all 256 byte values appear roughly equally often.
- The chi-squared test at the bottom formalizes this: the plaintext FAILS (non-uniform), the ciphertext PASSES (uniform at p=0.05). A PASS means there is no statistically detectable bias in the byte distribution.

### 8. Automated Test Suite

Show that everything is backed by automated tests.

```bash
cd build && ctest --output-on-failure
```

Expected output:
```
100% tests passed, 0 tests failed out of 38
```

**Talking point:** We have 38 automated tests covering encryption round-trips for every algorithm and mode, wrong-password rejection, empty input, 1 MB files, GCM tamper detection, SHA-256 hashing, and performance sanity checks. The tests run in under 2 seconds.

### 9. Cleanup

```bash
rm -f demo.txt demo.enc demo_recovered.txt demo_bad.txt demo_chacha.enc demo_chacha.txt
rm -f demo_verified.enc demo_verified.enc.hash
rm -f repeated.txt repeated_cbc.enc repeated_ecb.enc repeated_gcm.enc repeated_check.txt
rm -f bench_input.bin bench_input.bin.enc
```

---

### Demo Cheat Sheet (Quick Reference)

If you are short on time, these four commands cover the most important features:

```bash
# 1. Encrypt
./build/file-crypto encrypt -i demo.txt -o demo.enc -p secret123 --verify

# 2. Decrypt
./build/file-crypto decrypt -i demo.enc -o demo.dec -p secret123

# 3. Verify integrity
./build/file-crypto verify -i demo.enc

# 4. Benchmark
./build/file-crypto benchmark -i demo.txt
```
