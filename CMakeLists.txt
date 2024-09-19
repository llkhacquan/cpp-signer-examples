cmake_minimum_required(VERSION 3.10)
project(eip712_signer)

set(CMAKE_CXX_STANDARD 17)

# Find required packages
find_package(nlohmann_json 3.2.0 REQUIRED)
find_package(OpenSSL REQUIRED)  # Added for OpenSSL

# Manually find secp256k1 library and include directories
find_path(SECP256K1_INCLUDE_DIR secp256k1.h)
find_library(SECP256K1_LIBRARY secp256k1)

# Check if secp256k1 was found
if (SECP256K1_INCLUDE_DIR AND SECP256K1_LIBRARY)
    message(STATUS "Found secp256k1 library and include files.")
else()
    message(FATAL_ERROR "Could not find secp256k1 library and/or include files.")
endif()

# Manually find CryptoPP library and include directories
find_path(CRYPTOPP_INCLUDE_DIR cryptopp/cryptlib.h)
find_library(CRYPTOPP_LIBRARY cryptopp)

# Check if CryptoPP was found
if (CRYPTOPP_INCLUDE_DIR AND CRYPTOPP_LIBRARY)
    message(STATUS "Found CryptoPP library and include files.")
else()
    message(FATAL_ERROR "Could not find CryptoPP library and/or include files.")
endif()

find_library(SECP256K1_LIBRARY secp256k1 REQUIRED)

# Add the executable
add_executable(eip712_signer main.cpp)

# Include directories
target_include_directories(eip712_signer PRIVATE
    ${SECP256K1_INCLUDE_DIR}
    ${CRYPTOPP_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}  # Added for OpenSSL
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Link libraries
target_link_libraries(eip712_signer PRIVATE
    ${SECP256K1_LIBRARY}
    ${CRYPTOPP_LIBRARY}
    OpenSSL::SSL  # Link OpenSSL
    OpenSSL::Crypto  # Link OpenSSL crypto library
    ${SECP256K1_LIBRARY}
    nlohmann_json::nlohmann_json
)
