#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>
#include <nlohmann/json.hpp>
#include <cryptopp/keccak.h>
#include <cryptopp/filters.h>
#include <secp256k1.h>

using json = nlohmann::json;

// Helper function to read the JSON file
json read_json(const std::string& filename) {
    std::ifstream file(filename);
    json j;
    file >> j;
    return j;
}

// Helper function to convert a string to hex
std::string string_to_hex(const std::string& input) {
    static const char hex_digits[] = "0123456789abcdef";
    std::string output;
    output.reserve(input.length() * 2);
    for (unsigned char c : input) {
        output.push_back(hex_digits[c >> 4]);
        output.push_back(hex_digits[c & 15]);
    }
    return output;
}

// Helper function to compute Keccak-256 hash
std::string keccak256(const std::string& input) {
    CryptoPP::Keccak_256 hash;
    std::string digest;
    CryptoPP::StringSource ss(input, true,
        new CryptoPP::HashFilter(hash,
            new CryptoPP::StringSink(digest)
        )
    );
    return digest;
}

// Helper function to convert hex string to byte array
std::vector<unsigned char> hex_to_bytes(const std::string& hex) {
    std::vector<unsigned char> bytes;

    if (hex.length() % 2 != 0) {
        throw std::invalid_argument("Hex string has invalid length");
    }

    for (size_t i = 0; i < hex.length(); i += 2) {
        unsigned int byte;
        std::stringstream ss(hex.substr(i, 2));
        ss >> std::hex >> byte;
        bytes.push_back(static_cast<unsigned char>(byte));
    }

    return bytes;
}

// Function to compute domain separator and message hash
void compute_hashes(const json& j, std::string& domain_hash, std::string& message_hash) {
    // For simplicity, we'll assume the type hashes are precomputed.
    // In practice, you'd need to compute the type hashes based on the EIP-712 spec.

    // Example domain separator
    std::string domain_separator = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
    std::string domain_type_hash = keccak256(domain_separator);

    // Hash domain fields
    std::string name_hash = keccak256(j["domain"]["name"]);
    std::string version_hash = keccak256(j["domain"]["version"]);

    // Convert chainId and verifyingContract to appropriate format
    std::stringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(64) << j["domain"]["chainId"].get<uint64_t>();
    std::string chainId_hex = ss.str();

    std::string verifyingContract = j["domain"]["verifyingContract"];
    verifyingContract.erase(0, 2); // Remove '0x'

    // Concatenate and hash
    std::string domain_data = domain_type_hash + name_hash + version_hash + chainId_hex + verifyingContract;
    domain_hash = keccak256(domain_data);

    // Similarly compute message hash
    std::string message_type = "Register(address key,string message,uint64 nonce)";
    std::string message_type_hash = keccak256(message_type);

    std::string key = j["message"]["key"];
    key.erase(0, 2); // Remove '0x'

    std::string message = keccak256(j["message"]["message"]);

    uint64_t nonce_value;

    // Check if nonce is a string or a number
    if (j["message"]["nonce"].is_string()) {
        // Convert string to uint64_t
        std::string nonce_str = j["message"]["nonce"];
        nonce_value = std::stoull(nonce_str);
    } else if (j["message"]["nonce"].is_number_unsigned()) {
        // Directly get the unsigned number
        nonce_value = j["message"]["nonce"].get<uint64_t>();
    } else {
        throw std::runtime_error("Invalid nonce type");
    }

    ss.str("");
    ss << std::hex << std::setfill('0') << std::setw(16) << nonce_value;
    std::string nonce_hex = ss.str();

    std::string message_data = message_type_hash + key + message + nonce_hex;
    message_hash = keccak256(message_data);
}

// Function to sign the hash
void sign_hash(const std::string& hash, std::string& signature) {
    // Initialize secp256k1 context
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

    // Private key as hex string
    std::string privkey_hex = "0000000000000000000000000000000000000000000000000000000000000001"; // Replace with your actual private key

    // Convert hex string to byte array
    std::vector<unsigned char> seckey = hex_to_bytes(privkey_hex);

    if (seckey.size() != 32) {
        std::cerr << "Invalid private key size: " << seckey.size() << " bytes. Expected 32 bytes." << std::endl;
        secp256k1_context_destroy(ctx);
        throw std::runtime_error("Invalid private key size");
    }

    // Message hash
    unsigned char msg_hash[32];
    memcpy(msg_hash, hash.data(), 32);

    // Signature
    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_sign(ctx, &sig, msg_hash, seckey.data(), NULL, NULL)) {
        std::cerr << "Failed to create signature\n";
        secp256k1_context_destroy(ctx);
        throw std::runtime_error("Failed to create signature");
    }

    // Serialize signature
    unsigned char output64[64];
    secp256k1_ecdsa_signature_serialize_compact(ctx, output64, &sig);

    // Convert to hex string
    std::ostringstream oss;
    for (int i = 0; i < 64; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)output64[i];
    }
    signature = oss.str();

    // Destroy context
    secp256k1_context_destroy(ctx);
}

int main() {
    try {
        // Read JSON data
        json j = read_json("data.json");

        // Compute hashes
        std::string domain_hash, message_hash;
        compute_hashes(j, domain_hash, message_hash);

        // Combine domain hash and message hash
        std::string eip712_data = "\x19\x01" + domain_hash + message_hash;
        std::string eip712_hash = keccak256(eip712_data);

        // Sign the hash
        std::string signature;
        sign_hash(eip712_hash, signature);

        // Output the signature
        // 0x58343fc20c55526920837f4f0bbad2f1823730b9dc2cb154e6d7feb4ca750cae6db86703abba6985fb271bef2a248c5e930849ccf26eec511ea7fa8d773be3fb
        std::cout << "Signature: 0x" << signature << std::endl;

    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        return EXIT_FAILURE;
    }

    return 0;
}
