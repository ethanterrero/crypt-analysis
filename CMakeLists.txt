cmake_minimum_required(VERSION 3.15)
project(file-encryption-tester VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find OpenSSL - failing if not found
find_package(OpenSSL REQUIRED)

# Include directories
include_directories(${OPENSSL_INCLUDE_DIR})

# Define the executable
# We will add more source files here as we implement them
add_executable(file-crypto
    src/main.cpp
)

# Link against OpenSSL
target_link_libraries(file-crypto
    OpenSSL::Crypto
)

# Enable testing
enable_testing()
