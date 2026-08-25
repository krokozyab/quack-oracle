#include "oracle_scanner/sso_wallet.hpp"

#include "oracle_scanner/protocol_error.hpp"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>

#include <array>
#include <cstdint>
#include <memory>
#include <string>

namespace oracle_scanner {

namespace {

constexpr size_t MAX_SSO_WALLET_BYTES = 1U << 20U;

// The three bytes every Oracle wallet file starts with, followed by a flavour
// byte: '6' and '7' are ordinary auto-login wallets, '8' marks one locked to
// the machine that created it.
constexpr unsigned char SSO_MAGIC_0 = 0xA1;
constexpr unsigned char SSO_MAGIC_1 = 0xF8;
constexpr unsigned char SSO_MAGIC_2 = 0x4E;
constexpr unsigned char SSO_FLAVOUR_AUTO_LOGIN_6 = '6';
constexpr unsigned char SSO_FLAVOUR_AUTO_LOGIN_7 = '7';
constexpr unsigned char SSO_FLAVOUR_AUTO_LOGIN_LOCAL = '8';

// Header version accompanying every wallet this code has evidence for.
constexpr uint32_t SSO_HEADER_VERSION = 6;

// How the header carries the store password.
constexpr unsigned char SSO_PASSWORD_ABSENT = 0x05;
constexpr unsigned char SSO_PASSWORD_AES = 0x06;
constexpr unsigned char SSO_PASSWORD_DES_HEX = 0x35;

constexpr size_t SSO_AES_KEY_BYTES = 16;
constexpr size_t SSO_DES_KEY_HEX_CHARS = 16;
constexpr size_t SSO_DES_PAYLOAD_HEX_CHARS = 0x30;

// The obfuscation IV Oracle fixes for the AES-wrapped password. It is a
// constant of the format, not a secret: the wallet is "auto-login" precisely
// because anything that can read the file can also unwrap the password.
constexpr std::array<unsigned char, 16> SSO_AES_IV = {0xC0, 0x34, 0xD8, 0x31, 0x1C, 0x02, 0xCE, 0xF8,
                                                      0x51, 0xF0, 0x14, 0x4B, 0x81, 0xED, 0x4B, 0xF2};

using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;
using Pkcs12Ptr = std::unique_ptr<PKCS12, decltype(&PKCS12_free)>;
using PrivateKeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using CertificatePtr = std::unique_ptr<X509, decltype(&X509_free)>;
using CipherContextPtr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

void FreeCertificateStack(STACK_OF(X509) * chain) {
    sk_X509_pop_free(chain, X509_free);
}

using CertificateStackPtr = std::unique_ptr<STACK_OF(X509), decltype(&FreeCertificateStack)>;

// Wipes a buffer that held key or password material before it is released.
void Scrub(std::string &value) {
    if (!value.empty()) {
        OPENSSL_cleanse(value.data(), value.size());
    }
    value.clear();
}

struct ScrubbedString {
    std::string value;

    ~ScrubbedString() {
        Scrub(value);
    }
};

uint32_t ReadBigEndian32(const std::string &bytes, size_t offset) {
    return (static_cast<uint32_t>(static_cast<unsigned char>(bytes[offset])) << 24U) |
           (static_cast<uint32_t>(static_cast<unsigned char>(bytes[offset + 1])) << 16U) |
           (static_cast<uint32_t>(static_cast<unsigned char>(bytes[offset + 2])) << 8U) |
           static_cast<uint32_t>(static_cast<unsigned char>(bytes[offset + 3]));
}

void RequireBytes(const std::string &bytes, size_t offset, size_t count, const char *what) {
    if (count > bytes.size() || offset > bytes.size() - count) {
        throw ProtocolError(ProtocolErrorKind::TRUNCATED,
                            std::string("Oracle auto-login wallet is truncated at ") + what);
    }
}

std::string DecodeHex(const std::string &bytes, size_t offset, size_t count, const char *what) {
    RequireBytes(bytes, offset, count, what);
    if (count % 2 != 0) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED,
                            std::string("Oracle auto-login wallet has an odd-length ") + what);
    }
    std::string decoded(count / 2, '\0');
    for (size_t index = 0; index < count; index += 2) {
        int nibbles[2] = {0, 0};
        for (size_t half = 0; half < 2; half++) {
            const auto character = static_cast<unsigned char>(bytes[offset + index + half]);
            if (character >= '0' && character <= '9') {
                nibbles[half] = character - '0';
            } else if (character >= 'a' && character <= 'f') {
                nibbles[half] = character - 'a' + 10;
            } else if (character >= 'A' && character <= 'F') {
                nibbles[half] = character - 'A' + 10;
            } else {
                throw ProtocolError(ProtocolErrorKind::MALFORMED,
                                    std::string("Oracle auto-login wallet has a non-hexadecimal ") + what);
            }
        }
        decoded[index / 2] = static_cast<char>((nibbles[0] << 4) | nibbles[1]);
    }
    return decoded;
}

// One raw CBC block decryption with padding left in place; the callers below
// know which of the two shapes carries PKCS#7 padding and which does not.
std::string DecryptCbcNoPadding(const EVP_CIPHER *cipher, const std::string &key, const unsigned char *iv,
                                const std::string &input, const char *what) {
    const auto block_size = static_cast<size_t>(EVP_CIPHER_block_size(cipher));
    if (input.empty() || input.size() % block_size != 0) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED,
                            std::string("Oracle auto-login wallet has a misaligned ") + what);
    }
    auto context = CipherContextPtr(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!context) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "OpenSSL could not allocate a wallet cipher context");
    }
    if (EVP_DecryptInit_ex(context.get(), cipher, nullptr, reinterpret_cast<const unsigned char *>(key.data()), iv) !=
        1) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED,
                            std::string("OpenSSL could not start decrypting the ") + what);
    }
    EVP_CIPHER_CTX_set_padding(context.get(), 0);
    std::string output(input.size() + block_size, '\0');
    int produced = 0;
    if (EVP_DecryptUpdate(context.get(), reinterpret_cast<unsigned char *>(output.data()), &produced,
                          reinterpret_cast<const unsigned char *>(input.data()),
                          static_cast<int>(input.size())) != 1) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, std::string("OpenSSL could not decrypt the ") + what);
    }
    int final_produced = 0;
    if (EVP_DecryptFinal_ex(context.get(), reinterpret_cast<unsigned char *>(output.data()) + produced,
                            &final_produced) != 1) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED,
                            std::string("OpenSSL could not finish decrypting the ") + what);
    }
    output.resize(static_cast<size_t>(produced) + static_cast<size_t>(final_produced));
    return output;
}

// Removes PKCS#7 padding when it is well formed, and leaves the buffer alone
// when it is not — the DES-wrapped shape stores passwords that fill the block
// exactly as often as it stores padded ones.
void StripPkcs7Padding(std::string &value, size_t block_size) {
    if (value.empty()) {
        return;
    }
    const auto padding = static_cast<size_t>(static_cast<unsigned char>(value.back()));
    if (padding == 0 || padding > block_size || padding > value.size()) {
        return;
    }
    for (size_t index = value.size() - padding; index < value.size(); index++) {
        if (static_cast<unsigned char>(value[index]) != padding) {
            return;
        }
    }
    value.resize(value.size() - padding);
}

struct SsoHeader {
    std::string password;
    size_t payload_offset = 0;
};

SsoHeader ParseHeader(const std::string &bytes) {
    RequireBytes(bytes, 0, 4, "the magic");
    if (static_cast<unsigned char>(bytes[0]) != SSO_MAGIC_0 || static_cast<unsigned char>(bytes[1]) != SSO_MAGIC_1 ||
        static_cast<unsigned char>(bytes[2]) != SSO_MAGIC_2) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle auto-login wallet has an unknown magic");
    }
    const auto flavour = static_cast<unsigned char>(bytes[3]);
    if (flavour == SSO_FLAVOUR_AUTO_LOGIN_LOCAL) {
        throw ProtocolError(ProtocolErrorKind::UNSUPPORTED,
                            "Oracle auto-login local wallet is bound to the host and user that created it; "
                            "supply WALLET_PASSWORD with ewallet.pem instead");
    }
    if (flavour != SSO_FLAVOUR_AUTO_LOGIN_6 && flavour != SSO_FLAVOUR_AUTO_LOGIN_7) {
        throw ProtocolError(ProtocolErrorKind::UNSUPPORTED, "Oracle auto-login wallet has an unsupported version");
    }

    size_t offset = 4;
    RequireBytes(bytes, offset, 8, "the header");
    const auto header_version = ReadBigEndian32(bytes, offset);
    offset += 4;
    const auto header_size = ReadBigEndian32(bytes, offset);
    offset += 4;
    if (header_version != SSO_HEADER_VERSION) {
        throw ProtocolError(ProtocolErrorKind::UNSUPPORTED,
                            "Oracle auto-login wallet has an unsupported header version");
    }
    if (header_size > MAX_SSO_WALLET_BYTES) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED,
                            "Oracle auto-login wallet header exceeds supported bounds");
    }

    RequireBytes(bytes, offset, 1, "the password kind");
    const auto password_kind = static_cast<unsigned char>(bytes[offset]);
    SsoHeader header;

    if (password_kind == SSO_PASSWORD_ABSENT) {
        // No wrapped password: the store is opened with an empty one, and the
        // PKCS#12 payload starts at this byte rather than after it.
        header.payload_offset = offset;
        return header;
    }

    offset += 1;
    if (password_kind == SSO_PASSWORD_AES) {
        if (header_size < 1 + SSO_AES_KEY_BYTES + 1) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle auto-login wallet header is too small for a key");
        }
        const auto password_length = static_cast<size_t>(header_size) - 1 - SSO_AES_KEY_BYTES;
        RequireBytes(bytes, offset, SSO_AES_KEY_BYTES, "the password key");
        const std::string key(bytes, offset, SSO_AES_KEY_BYTES);
        offset += SSO_AES_KEY_BYTES;
        RequireBytes(bytes, offset, password_length, "the wrapped password");
        const std::string wrapped(bytes, offset, password_length);
        offset += password_length;
        header.password = DecryptCbcNoPadding(EVP_aes_128_cbc(), key, SSO_AES_IV.data(), wrapped, "wallet password");
        StripPkcs7Padding(header.password, 16);
    } else if (password_kind == SSO_PASSWORD_DES_HEX) {
        const auto key = DecodeHex(bytes, offset, SSO_DES_KEY_HEX_CHARS, "password key");
        offset += SSO_DES_KEY_HEX_CHARS;
        const auto wrapped = DecodeHex(bytes, offset, SSO_DES_PAYLOAD_HEX_CHARS, "wrapped password");
        offset += SSO_DES_PAYLOAD_HEX_CHARS;
        const std::array<unsigned char, 8> zero_iv = {};
        header.password = DecryptCbcNoPadding(EVP_des_cbc(), key, zero_iv.data(), wrapped, "wallet password");
        StripPkcs7Padding(header.password, 8);
    } else {
        throw ProtocolError(ProtocolErrorKind::UNSUPPORTED,
                            "Oracle auto-login wallet has an unsupported password kind");
    }

    // PKCS12_parse takes the password as a C string, so an embedded NUL would
    // silently truncate it into a different password.
    if (header.password.find('\0') != std::string::npos) {
        Scrub(header.password);
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle auto-login wallet password is not a text string");
    }
    header.payload_offset = offset;
    return header;
}

std::string WritePem(EVP_PKEY *key, X509 *certificate, STACK_OF(X509) * chain) {
    auto bio = BioPtr(BIO_new(BIO_s_mem()), BIO_free);
    if (!bio) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "OpenSSL could not allocate a wallet PEM buffer");
    }
    // The key is written unencrypted because it only ever exists in this
    // process: it goes straight into the TLS context and is never persisted.
    if (PEM_write_bio_PrivateKey(bio.get(), key, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "OpenSSL could not serialise the wallet private key");
    }
    if (PEM_write_bio_X509(bio.get(), certificate) != 1) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "OpenSSL could not serialise the wallet certificate");
    }
    if (chain) {
        for (int index = 0; index < sk_X509_num(chain); index++) {
            auto *entry = sk_X509_value(chain, index);
            if (entry && PEM_write_bio_X509(bio.get(), entry) != 1) {
                throw ProtocolError(ProtocolErrorKind::MALFORMED,
                                    "OpenSSL could not serialise a wallet chain certificate");
            }
        }
    }
    char *data = nullptr;
    const auto length = BIO_get_mem_data(bio.get(), &data);
    if (!data || length <= 0) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle auto-login wallet produced an empty PEM bundle");
    }
    return std::string(data, static_cast<size_t>(length));
}

} // namespace

bool HasSsoWalletMagic(const std::string &bytes) {
    return bytes.size() >= 4 && static_cast<unsigned char>(bytes[0]) == SSO_MAGIC_0 &&
           static_cast<unsigned char>(bytes[1]) == SSO_MAGIC_1 && static_cast<unsigned char>(bytes[2]) == SSO_MAGIC_2;
}

std::string SsoWalletToPem(const std::string &bytes) {
    if (bytes.empty() || bytes.size() > MAX_SSO_WALLET_BYTES) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "Oracle auto-login wallet exceeds the supported size");
    }
    ScrubbedString password;
    size_t payload_offset = 0;
    {
        auto header = ParseHeader(bytes);
        password.value = std::move(header.password);
        payload_offset = header.payload_offset;
    }
    if (payload_offset >= bytes.size()) {
        throw ProtocolError(ProtocolErrorKind::TRUNCATED, "Oracle auto-login wallet has no PKCS#12 payload");
    }

    const auto *payload = reinterpret_cast<const unsigned char *>(bytes.data()) + payload_offset;
    // d2i_PKCS12 takes a long by definition; the cast is the API, not a choice.
    // NOLINTNEXTLINE(google-runtime-int)
    const auto payload_size = static_cast<long>(bytes.size() - payload_offset);
    auto store = Pkcs12Ptr(d2i_PKCS12(nullptr, &payload, payload_size), PKCS12_free);
    if (!store) {
        ERR_clear_error();
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle auto-login wallet does not contain a PKCS#12 store");
    }

    EVP_PKEY *raw_key = nullptr;
    X509 *raw_certificate = nullptr;
    STACK_OF(X509) *raw_chain = nullptr;
    if (PKCS12_parse(store.get(), password.value.c_str(), &raw_key, &raw_certificate, &raw_chain) != 1) {
        ERR_clear_error();
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "OpenSSL could not open the Oracle auto-login wallet store");
    }
    auto key = PrivateKeyPtr(raw_key, EVP_PKEY_free);
    auto certificate = CertificatePtr(raw_certificate, X509_free);
    auto chain = CertificateStackPtr(raw_chain, FreeCertificateStack);
    if (!key || !certificate) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED,
                            "Oracle auto-login wallet has no client certificate and private key");
    }
    return WritePem(key.get(), certificate.get(), chain.get());
}

} // namespace oracle_scanner
