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

# Define the executable
add_executable(file-crypto
    src/main.cpp
    src/crypto/aes_cipher.cpp
    src/crypto/chacha_cipher.cpp
    src/crypto/key_derivation.cpp
    src/io/file_handler.cpp
)

# Link against OpenSSL
target_link_libraries(file-crypto
    OpenSSL::Crypto
)

# Enable testing
enable_testing()