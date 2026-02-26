cmake_minimum_required(VERSION 3.15)
project(file-encryption-tester VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# --- MAC OPENSSL FIX ---
# If on macOS, tell CMake where Homebrew likely hid OpenSSL
if(APPLE)
    if(EXISTS "/opt/homebrew/opt/openssl@3")
        set(OPENSSL_ROOT_DIR "/opt/homebrew/opt/openssl@3")
    elseif(EXISTS "/usr/local/opt/openssl@3")
        set(OPENSSL_ROOT_DIR "/usr/local/opt/openssl@3")
    endif()
endif()

# Find OpenSSL - failing if not found
find_package(OpenSSL REQUIRED)

# Include directories (This fixes the "cannot open source file" error)
include_directories(${OPENSSL_INCLUDE_DIR})
include_directories(src) # Add src to path so we can include headers easily

# --- Shared library of crypto/io/utils sources (used by main and tests) ---
set(LIB_SOURCES
    src/crypto/aes_cipher.cpp
    src/crypto/chacha_cipher.cpp
    src/crypto/key_derivation.cpp
    src/crypto/file_format.cpp
    src/io/file_handler.cpp
    src/utils/hash.cpp
    src/metrics/performance.cpp
    src/benchmark/profiler.cpp
)

# Define the executable
add_executable(file-crypto
    src/main.cpp
    ${LIB_SOURCES}
)

# Link against OpenSSL
target_link_libraries(file-crypto
    OpenSSL::Crypto
)

# ---- Testing with Google Test ----
enable_testing()

include(FetchContent)
FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
)
# Prevent GoogleTest from overriding compiler/linker settings on Windows
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_executable(run_tests
    tests/test_encryption.cpp
    ${LIB_SOURCES}
)

target_link_libraries(run_tests
    GTest::gtest_main
    OpenSSL::Crypto
)

include(GoogleTest)
gtest_discover_tests(run_tests)
