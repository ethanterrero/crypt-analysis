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

# Threads required by cpp-httplib
find_package(Threads REQUIRED)

# Include directories (This fixes the "cannot open source file" error)
include_directories(${OPENSSL_INCLUDE_DIR})
include_directories(src)          # headers under src/
include_directories(third_party)  # httplib.h

# Define the executable
add_executable(file-crypto
    src/main.cpp
    src/crypto/aes_cipher.cpp
    src/crypto/chacha_cipher.cpp
    src/io/file_handler.cpp
    src/benchmark/profiler.cpp
    src/analysis/avalanche.cpp
    src/analysis/entropy.cpp
    src/analysis/frequency.cpp
    src/server/server.cpp
)

# Link against OpenSSL and pthreads (httplib requires threads)
target_link_libraries(file-crypto
    OpenSSL::Crypto
    Threads::Threads
)

# Enable testing
enable_testing()