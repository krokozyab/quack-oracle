#include "oracle_scanner/auth_crypto.hpp"
#include "oracle_scanner/protocol_error.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <algorithm>
#include <limits>
#include <memory>
#include <utility>

namespace oracle_scanner {

using CipherContext = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

static const EVP_CIPHER *CipherForKey(size_t key_size) {
    switch (key_size) {
    case 16:
        return EVP_aes_128_cbc();
    case 24:
        return EVP_aes_192_cbc();
    case 32:
        return EVP_aes_256_cbc();
    default:
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "AES-CBC key must contain 16, 24, or 32 bytes");
    }
}

std::vector<uint8_t> SecureRandomBytes(size_t size) {
    if (size == 0 || size > 1024 || size > static_cast<size_t>(std::numeric_limits<int>::max())) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "requested random material exceeds supported bounds");
    }
    std::vector<uint8_t> result(size);
    if (RAND_bytes(result.data(), static_cast<int>(result.size())) != 1) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "OpenSSL CSPRNG failed");
    }
    return result;
}

std::string Base64Encode(const std::vector<uint8_t> &value) {
    if (value.empty() || value.size() > 768) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "base64 input exceeds supported bounds");
    }
    std::string result(((value.size() + 2) / 3) * 4, '\0');
    const auto encoded_size = EVP_EncodeBlock(reinterpret_cast<unsigned char *>(&result[0]), value.data(),
                                               static_cast<int>(value.size()));
    if (encoded_size <= 0 || static_cast<size_t>(encoded_size) != result.size()) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "OpenSSL base64 encoding failed");
    }
    return result;
}

std::vector<uint8_t> Pbkdf2Sha512(const std::vector<uint8_t> &password, const std::vector<uint8_t> &salt,
                                  uint32_t iterations, size_t output_size) {
    if (iterations == 0 || iterations > 10000000 || output_size == 0 || output_size > 1024 ||
        password.size() > static_cast<size_t>(std::numeric_limits<int>::max()) ||
        salt.size() > static_cast<size_t>(std::numeric_limits<int>::max()) ||
        output_size > static_cast<size_t>(std::numeric_limits<int>::max())) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "PBKDF2 parameters exceed supported bounds");
    }
    std::vector<uint8_t> output(output_size);
    auto result = PKCS5_PBKDF2_HMAC(reinterpret_cast<const char *>(password.data()), static_cast<int>(password.size()),
                                   salt.data(), static_cast<int>(salt.size()), static_cast<int>(iterations), EVP_sha512(),
                                   static_cast<int>(output.size()), output.data());
    if (result != 1) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "OpenSSL PBKDF2-HMAC-SHA512 failed");
    }
    return output;
}

std::vector<uint8_t> Sha512(const std::vector<std::vector<uint8_t>> &parts) {
    EVP_MD_CTX *raw_context = EVP_MD_CTX_new();
    if (!raw_context) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "OpenSSL SHA-512 allocation failed");
    }
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context(raw_context, EVP_MD_CTX_free);
    if (EVP_DigestInit_ex(context.get(), EVP_sha512(), nullptr) != 1) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "OpenSSL SHA-512 initialization failed");
    }
    for (const auto &part : parts) {
        if (EVP_DigestUpdate(context.get(), part.data(), part.size()) != 1) {
            throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "OpenSSL SHA-512 update failed");
        }
    }
    std::vector<uint8_t> output(SHA512_DIGEST_LENGTH);
    unsigned int output_size = 0;
    if (EVP_DigestFinal_ex(context.get(), output.data(), &output_size) != 1 || output_size != output.size()) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "OpenSSL SHA-512 finalization failed");
    }
    return output;
}

static std::vector<uint8_t> AesCbc(const std::vector<uint8_t> &key, const std::vector<uint8_t> &input, bool encrypt,
                                   bool padding) {
    if (!encrypt && (input.empty() || input.size() % 16 != 0)) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "AES-CBC ciphertext must be a non-empty block sequence");
    }
    CipherContext context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!context) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "OpenSSL AES-CBC allocation failed");
    }
    uint8_t iv[16] = {0};
    auto cipher = CipherForKey(key.size());
    if (EVP_CipherInit_ex(context.get(), cipher, nullptr, key.data(), iv, encrypt ? 1 : 0) != 1) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "OpenSSL AES-CBC initialization failed");
    }
    EVP_CIPHER_CTX_set_padding(context.get(), padding ? 1 : 0);
    if (!padding && (input.empty() || input.size() % 16 != 0)) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "raw AES-CBC input must be a non-empty block sequence");
    }
    if (input.size() > static_cast<size_t>(std::numeric_limits<int>::max())) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "AES-CBC input exceeds supported bounds");
    }
    std::vector<uint8_t> output(input.size() + 16);
    int first_size = 0;
    int final_size = 0;
    if (EVP_CipherUpdate(context.get(), output.data(), &first_size, input.data(), static_cast<int>(input.size())) != 1 ||
        EVP_CipherFinal_ex(context.get(), output.data() + first_size, &final_size) != 1) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "OpenSSL AES-CBC operation or padding validation failed");
    }
    output.resize(static_cast<size_t>(first_size + final_size));
    return output;
}

std::vector<uint8_t> AesCbcEncrypt(const std::vector<uint8_t> &key, const std::vector<uint8_t> &plaintext) {
    return AesCbc(key, plaintext, true, true);
}

std::vector<uint8_t> AesCbcDecrypt(const std::vector<uint8_t> &key, const std::vector<uint8_t> &ciphertext) {
    return AesCbc(key, ciphertext, false, true);
}

std::vector<uint8_t> AesCbcEncryptRaw(const std::vector<uint8_t> &key, const std::vector<uint8_t> &plaintext) {
    return AesCbc(key, plaintext, true, false);
}

std::vector<uint8_t> AesCbcDecryptRaw(const std::vector<uint8_t> &key, const std::vector<uint8_t> &ciphertext) {
    return AesCbc(key, ciphertext, false, false);
}

std::string UpperHex(const std::vector<uint8_t> &value) {
    static constexpr char digits[] = "0123456789ABCDEF";
    std::string output(value.size() * 2, '0');
    for (size_t index = 0; index < value.size(); index++) {
        output[index * 2] = digits[value[index] >> 4U];
        output[index * 2 + 1] = digits[value[index] & 0x0fU];
    }
    return output;
}

std::vector<uint8_t> DecodeHex(const std::string &value, size_t maximum_bytes) {
    if (value.size() % 2 != 0 || value.size() / 2 > maximum_bytes) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "hex value is odd-sized or exceeds configured limit");
    }
    auto nibble = [](char character) -> uint8_t {
        if (character >= '0' && character <= '9') {
            return static_cast<uint8_t>(character - '0');
        }
        if (character >= 'a' && character <= 'f') {
            return static_cast<uint8_t>(character - 'a' + 10);
        }
        if (character >= 'A' && character <= 'F') {
            return static_cast<uint8_t>(character - 'A' + 10);
        }
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "hex value contains a non-hexadecimal character");
    };
    std::vector<uint8_t> output(value.size() / 2);
    for (size_t index = 0; index < output.size(); index++) {
        output[index] = static_cast<uint8_t>((nibble(value[index * 2]) << 4U) | nibble(value[index * 2 + 1]));
    }
    return output;
}

O5LogonResponse BuildO5LogonResponse(const std::string &password, const O5LogonChallenge &challenge,
                                     const std::vector<uint8_t> &client_session_key,
                                     const std::vector<uint8_t> &password_salt,
                                     const std::vector<uint8_t> &speedy_key_salt) {
    if (password.empty() || password.size() > 1024 || client_session_key.size() != 32 || password_salt.size() != 16 ||
        speedy_key_salt.size() != 16) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "invalid O5LOGON password or random material");
    }
    auto verifier = DecodeHex(challenge.verifier_data_hex, 64);
    auto encrypted_server_key = DecodeHex(challenge.server_session_key_hex, 64);
    auto combo_salt = DecodeHex(challenge.combo_key_salt_hex, 64);
    // 0x4815 is the 12c PBKDF2-SHA512 verifier used by the generated
    // response below. Treat an absent flag as 12c for the deterministic unit
    // fixtures retained from before verifier flags were decoded.
    if ((challenge.verifier_type != 0 && challenge.verifier_type != 0x4815) || verifier.size() != 16 ||
        encrypted_server_key.size() != 32 || combo_salt.size() != 16 ||
        challenge.verifier_iterations == 0 || challenge.verifier_iterations > 10000000 ||
        challenge.combo_key_iterations == 0 || challenge.combo_key_iterations > 10000000) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "unsupported or malformed 12c O5LOGON challenge");
    }

    std::vector<uint8_t> password_bytes(password.begin(), password.end());
    std::vector<uint8_t> verifier_salt = verifier;
    static constexpr char speedy_key[] = "AUTH_PBKDF2_SPEEDY_KEY";
    verifier_salt.insert(verifier_salt.end(), speedy_key, speedy_key + sizeof(speedy_key) - 1);
    auto password_key = Pbkdf2Sha512(password_bytes, verifier_salt, challenge.verifier_iterations, 64);
    auto password_digest = Sha512({password_key, verifier});
    password_digest.resize(32);

    auto server_session_key = AesCbcDecryptRaw(password_digest, encrypted_server_key);
    auto encrypted_client_key = AesCbcEncryptRaw(password_digest, client_session_key);
    std::vector<uint8_t> combined = client_session_key;
    combined.insert(combined.end(), server_session_key.begin(), server_session_key.end());
    auto combined_hex = UpperHex(combined);
    std::vector<uint8_t> combined_hex_bytes(combined_hex.begin(), combined_hex.end());
    auto combo_key = Pbkdf2Sha512(combined_hex_bytes, combo_salt, challenge.combo_key_iterations, 32);

    std::vector<uint8_t> password_plaintext = password_salt;
    password_plaintext.insert(password_plaintext.end(), password_bytes.begin(), password_bytes.end());
    auto encrypted_password = AesCbcEncrypt(combo_key, password_plaintext);
    std::vector<uint8_t> speedy_plaintext = speedy_key_salt;
    speedy_plaintext.insert(speedy_plaintext.end(), password_key.begin(), password_key.end());
    auto speedy_ciphertext = AesCbcEncrypt(combo_key, speedy_plaintext);
    if (speedy_ciphertext.size() < 80) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "O5LOGON speedy-key ciphertext is truncated");
    }
    speedy_ciphertext.resize(80);
    return {UpperHex(encrypted_client_key), UpperHex(speedy_ciphertext), UpperHex(encrypted_password), std::move(combo_key)};
}

bool VerifyO5LogonServerResponse(const O5LogonResponse &response, const std::string &server_response_hex) {
    if (response.combo_key.size() != 32) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "O5LOGON response has no valid combo key");
    }
    auto ciphertext = DecodeHex(server_response_hex, 256);
    auto plaintext = AesCbcDecrypt(response.combo_key, ciphertext);
    static constexpr char proof[] = "SERVER_TO_CLIENT";
    return plaintext.size() >= 32 &&
           std::equal(proof, proof + sizeof(proof) - 1, plaintext.begin() + 16, plaintext.begin() + 32);
}

} // namespace oracle_scanner
