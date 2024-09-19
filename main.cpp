#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/obj_mac.h>
#include <cryptopp/keccak.h>
#include <cryptopp/hex.h>
#include <cryptopp/secblock.h>
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <iomanip>
#include <sstream>
#include <vector>
#include <string>
#include <stdexcept>
#include <iostream>


struct Domain {
    std::string name; //
    std::string version; // just a string
    std::string chain_id; // Should match the chain.id
    std::string verifying_contract; // an address prefixed by "0x"
};

struct Order {
    std::string sender; // an address prefixed by "0x"
    std::string size; // an integer string
    std::string price; // an integer string
    std::string nonce;// an integer string
    std::string product_index; // an integer string
    uint8_t side; // 0 is buy; 1 is sell
};

// Helper function to convert a string to hex format
std::string toHex(const std::vector<unsigned char>& data) {
    std::ostringstream oss;
    for (auto byte : data)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    return oss.str();
}

// Keccak-256 hash function using Crypto++ Keccak
std::vector<unsigned char> keccak256(const std::vector<unsigned char>& data) {
    CryptoPP::Keccak_256 hash;  // Keccak 256-bit hash (SHA3)
    std::vector<unsigned char> digest(CryptoPP::Keccak_256::DIGESTSIZE);
    hash.Update(data.data(), data.size());
    hash.TruncatedFinal(digest.data(), digest.size());
    return digest;
}

// Helper function to convert a hex string to bytes
std::vector<unsigned char> hexToBytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    for (unsigned int i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = (unsigned char) strtol(byteString.c_str(), nullptr, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

std::vector<unsigned char> padTo32Bytes(const std::vector<unsigned char>& input) {
    std::vector<unsigned char> padded(32, 0);
    std::copy(input.begin(), input.end(), padded.begin() + (32 - input.size()));
    return padded;
}


// Hash the domain separator for EIP-712
std::vector<unsigned char> hashTypedDataDomain(const Domain& domain) {
    std::string domainType = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
    std::vector<unsigned char> domainTypeHash = keccak256(std::vector<unsigned char>(domainType.begin(), domainType.end()));

    std::vector<unsigned char> nameHash = keccak256(std::vector<unsigned char>(domain.name.begin(), domain.name.end()));
    std::vector<unsigned char> versionHash = keccak256(std::vector<unsigned char>(domain.version.begin(), domain.version.end()));

    // Convert chain ID to a 32-byte padded integer
    long long chainId = std::stoll(domain.chain_id);
    std::vector<unsigned char> chainIdBytes(32, 0);
    for (int i = 31; i >= 0; --i) {
        chainIdBytes[i] = chainId & 0xFF;
        chainId >>= 8;
    }

    // Verifying Contract (Ethereum address, prefixed by "0x"), padded to 32 bytes
    std::vector<unsigned char> verifyingContractBytes = padTo32Bytes(hexToBytes(domain.verifying_contract.substr(2))); // Remove "0x"

    // Concatenate the hashes and the padded data in the correct order
    std::vector<unsigned char> encodedData;
    encodedData.insert(encodedData.end(), domainTypeHash.begin(), domainTypeHash.end());
    encodedData.insert(encodedData.end(), nameHash.begin(), nameHash.end());
    encodedData.insert(encodedData.end(), versionHash.begin(), versionHash.end());
    encodedData.insert(encodedData.end(), chainIdBytes.begin(), chainIdBytes.end());
    encodedData.insert(encodedData.end(), verifyingContractBytes.begin(), verifyingContractBytes.end());

    // Return the final hash
    return keccak256(encodedData);
}

// Convert a decimal string to a big-endian byte array and pad to 32 bytes
std::vector<unsigned char> decimalStringToBytes(const std::string& decimalStr) {
    BIGNUM* bn = BN_new();
    BN_dec2bn(&bn, decimalStr.c_str());

    std::vector<unsigned char> bytes(32, 0);
    int numBytes = BN_num_bytes(bn);
    BN_bn2bin(bn, &bytes[32 - numBytes]);  // Right-align and pad to 32 bytes

    BN_free(bn);
    return bytes;
}

// Hash the Order (pad all fields to 32 bytes)
std::vector<unsigned char> hashOrder(const Order& order) {
    std::string typeHash = "Order(address sender,uint128 size,uint128 price,uint64 nonce,uint8 productIndex,uint8 orderSide)";
    std::vector<unsigned char> typeHashBytes = keccak256(std::vector<unsigned char>(typeHash.begin(), typeHash.end()));

    // Convert and pad the sender (remove "0x" and pad the 20-byte address to 32 bytes)
    std::vector<unsigned char> senderBytes = padTo32Bytes(hexToBytes(order.sender.substr(2)));  // Remove "0x"

    // Convert size, price, and nonce to big-endian bytes and pad them to 32 bytes
    std::vector<unsigned char> sizeBytes = decimalStringToBytes(order.size);
    std::vector<unsigned char> priceBytes = decimalStringToBytes(order.price);
    std::vector<unsigned char> nonceBytes = decimalStringToBytes(order.nonce);

    // Convert productIndex and orderSide to 32-byte padded integers
    std::vector<unsigned char> productIndexBytes(32, 0);
    productIndexBytes[31] = std::stoi(order.product_index);  // 1 byte at the end (uint8)

    std::vector<unsigned char> orderSideBytes(32, 0);
    orderSideBytes[31] = order.side;  // 1 byte at the end (0 or 1)

    // Concatenate all fields in the correct order
    std::vector<unsigned char> encodedData;
    encodedData.insert(encodedData.end(), typeHashBytes.begin(), typeHashBytes.end());
    encodedData.insert(encodedData.end(), senderBytes.begin(), senderBytes.end());
    encodedData.insert(encodedData.end(), sizeBytes.begin(), sizeBytes.end());
    encodedData.insert(encodedData.end(), priceBytes.begin(), priceBytes.end());
    encodedData.insert(encodedData.end(), nonceBytes.begin(), nonceBytes.end());
    encodedData.insert(encodedData.end(), productIndexBytes.begin(), productIndexBytes.end());
    encodedData.insert(encodedData.end(), orderSideBytes.begin(), orderSideBytes.end());

    return keccak256(encodedData);  // Final hash of the encoded order
}

std::vector<unsigned char> ManualSignOrder(const Domain& domain, const Order& order) {
    // Hardcoded private key: 0000000000000000000000000000000000000000000000000000000000000001
    const char* hexPrivateKey = "0000000000000000000000000000000000000000000000000000000000000001";

    // Convert the hex private key to BIGNUM
    BIGNUM* bnPrivateKey = BN_new();
    BN_hex2bn(&bnPrivateKey, hexPrivateKey);

    // Create the EC key from the private key
    EC_KEY* privateKey = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!EC_KEY_set_private_key(privateKey, bnPrivateKey)) {
        throw std::runtime_error("Failed to set private key");
    }

    // Initialize the secp256k1 context for signing
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);  // <-- Here we declare 'ctx'

    // Hash the domain and order data
    std::vector<unsigned char> domainSeparator = hashTypedDataDomain(domain);
    std::vector<unsigned char> orderHash = hashOrder(order);

    // Print the hash for debugging
    std::cout << "Domain Hash: " << toHex(domainSeparator) << std::endl;
    std::cout << "Order Hash: " << toHex(orderHash) << std::endl;

    // Calculate "\x19\x01" + domainSeparator + orderHash
    std::vector<unsigned char> data = {0x19, 0x01};
    data.insert(data.end(), domainSeparator.begin(), domainSeparator.end());
    data.insert(data.end(), orderHash.begin(), orderHash.end());

    // Keccak256 hash the final data
    std::vector<unsigned char> dataHash = keccak256(data);

    // Convert private key to a byte array
    std::vector<unsigned char> privateKeyBytes = hexToBytes(hexPrivateKey);

    // Prepare the signature output and the extra recovery id for V
    secp256k1_ecdsa_recoverable_signature signature;
    int recid;

    // Sign the hash using secp256k1
    if (!secp256k1_ecdsa_sign_recoverable(ctx, &signature, dataHash.data(), privateKeyBytes.data(), nullptr, nullptr)) {
        throw std::runtime_error("Failed to sign the data hash");
    }

    // Serialize the signature to the [R || S || V] format
    std::vector<unsigned char> output(65);
    secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, output.data(), &recid, &signature);

    // V is recid (0 or 1), append it at the end of the signature
    output[64] = recid;

    // Ethereum's signature formatting: add 27 to recovery id (v) to conform with the standard
	output[64] += 27;

    // Clean up the secp256k1 context
    secp256k1_context_destroy(ctx);  // <-- Here we clean up 'ctx'

    return output;
}

int main() {
    // Example usage of ManualSignOrder

    // Define the domain
    Domain domain = {"BSX Testnet", "1", "421614", "0xbff51a8e5ea77199a1cf7237ba1562a9d74a92d1"};

    // Define the order
    Order order = {"0x75F585337F28e7420B684A5b41fCfA1c55A7f2E6", "1235000000000000000", "1800000000000000000000", "1713373872246000000", "1", 0};

    // Generate and sign the order
    try {
        std::vector<unsigned char> signature = ManualSignOrder(domain, order);
        std::cout << "Signature: " << toHex(signature) << std::endl;
        // expected: fdcb1edf939e9d4b824e12e764a9a23565e54e1dee3dd265cdb5c90960e85f990dee78f331ebdca161ca512b5462f00cd495ecddd9936e7740648a0f68c83c8b1b
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
    }
    return 0;
}
