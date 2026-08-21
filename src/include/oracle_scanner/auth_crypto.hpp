#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace oracle_scanner {

// Returns bytes from OpenSSL's operating-system-backed CSPRNG. This is used
// for ephemeral authentication material and must never be replaced with a
// deterministic generator.
std::vector<uint8_t> SecureRandomBytes(size_t size);
std::string Base64Encode(const std::vector<uint8_t> &value);
std::vector<uint8_t> Pbkdf2Sha512(const std::vector<uint8_t> &password, const std::vector<uint8_t> &salt,
                                  uint32_t iterations, size_t output_size);
std::vector<uint8_t> Sha512(const std::vector<std::vector<uint8_t>> &parts);
std::vector<uint8_t> AesCbcEncrypt(const std::vector<uint8_t> &key, const std::vector<uint8_t> &plaintext);
std::vector<uint8_t> AesCbcDecrypt(const std::vector<uint8_t> &key, const std::vector<uint8_t> &ciphertext);
std::vector<uint8_t> AesCbcEncryptRaw(const std::vector<uint8_t> &key, const std::vector<uint8_t> &plaintext);
std::vector<uint8_t> AesCbcDecryptRaw(const std::vector<uint8_t> &key, const std::vector<uint8_t> &ciphertext);
std::string UpperHex(const std::vector<uint8_t> &value);
std::vector<uint8_t> DecodeHex(const std::string &value, size_t maximum_bytes);

struct O5LogonChallenge {
    std::string verifier_data_hex;
    std::string server_session_key_hex;
    std::string combo_key_salt_hex;
    uint32_t verifier_iterations = 0;
    uint32_t combo_key_iterations = 0;
    uint32_t verifier_type = 0;
};

struct O5LogonResponse {
    std::string client_session_key_hex;
    std::string speedy_key_hex;
    std::string encrypted_password_hex;
    std::vector<uint8_t> combo_key;
};

O5LogonResponse BuildO5LogonResponse(const std::string &password, const O5LogonChallenge &challenge,
                                     const std::vector<uint8_t> &client_session_key,
                                     const std::vector<uint8_t> &password_salt,
                                     const std::vector<uint8_t> &speedy_key_salt);
bool VerifyO5LogonServerResponse(const O5LogonResponse &response, const std::string &server_response_hex);

} // namespace oracle_scanner
