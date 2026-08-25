#include "oracle_scanner/wallet_archive.hpp"

#include "oracle_scanner/protocol_error.hpp"
#include "oracle_scanner/sso_wallet.hpp"

#include "miniz.hpp"

#include <array>
#include <fstream>
#include <memory>
#include <string>

namespace oracle_scanner {

namespace {

using duckdb_miniz::mz_free;
using duckdb_miniz::mz_uint;
using duckdb_miniz::mz_zip_archive;
using duckdb_miniz::mz_zip_archive_file_stat;
using duckdb_miniz::mz_zip_reader_end;
using duckdb_miniz::mz_zip_reader_extract_to_heap;
using duckdb_miniz::mz_zip_reader_file_stat;
using duckdb_miniz::mz_zip_reader_get_num_files;
using duckdb_miniz::mz_zip_reader_init_mem;
using duckdb_miniz::mz_zip_is_zip64;
using duckdb_miniz::mz_zip_zero_struct;

constexpr size_t MAX_WALLET_ARCHIVE_BYTES = 16U << 20U;
constexpr size_t MAX_WALLET_ARCHIVE_ENTRIES = 32;
constexpr size_t MAX_WALLET_PEM_BYTES = 1U << 20U;

bool HasZipSignature(const std::string &path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "could not open Oracle wallet file");
    }
    std::array<unsigned char, 4> signature {};
    input.read(reinterpret_cast<char *>(signature.data()), static_cast<std::streamsize>(signature.size()));
    const auto count = input.gcount();
    return count == static_cast<std::streamsize>(signature.size()) && signature[0] == 'P' && signature[1] == 'K' &&
           ((signature[2] == 3 && signature[3] == 4) || (signature[2] == 5 && signature[3] == 6) ||
            (signature[2] == 7 && signature[3] == 8));
}

std::string ReadWalletFile(const std::string &path, size_t maximum_size, const char *description) {
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, std::string("could not open ") + description);
    }
    const auto end = input.tellg();
    if (end < 0) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE,
                            std::string("could not determine ") + description + " size");
    }
    const auto size = static_cast<size_t>(end);
    if (size == 0 || size > maximum_size) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, std::string(description) + " exceeds the supported size");
    }
    std::string contents(size, '\0');
    input.seekg(0);
    input.read(contents.data(), static_cast<std::streamsize>(contents.size()));
    if (input.gcount() != static_cast<std::streamsize>(contents.size())) {
        throw ProtocolError(ProtocolErrorKind::TRUNCATED, std::string(description) + " could not be read");
    }
    return contents;
}

class ZipReader {
public:
    explicit ZipReader(const std::string &contents) {
        mz_zip_zero_struct(&archive);
        if (!mz_zip_reader_init_mem(&archive, contents.data(), contents.size(), 0)) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle wallet ZIP is malformed");
        }
        initialized = true;
    }

    ~ZipReader() {
        if (initialized) {
            mz_zip_reader_end(&archive);
        }
    }

    mz_zip_archive archive {};

private:
    bool initialized = false;
};

void ValidatePemContents(const std::string &pem, const char *description) {
    if (pem.find('\0') != std::string::npos) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, std::string(description) + " contains NUL bytes");
    }
    if (pem.find("-----BEGIN ") == std::string::npos) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, std::string(description) + " is not PEM data");
    }
}

// Extracts one member of an already-bounded wallet ZIP, or returns an empty
// string when the archive does not carry it. A member that is present but
// unusable is still an error: a wallet with, say, an encrypted cwallet.sso
// entry is broken rather than absent.
std::string ExtractOptionalMember(const std::string &contents, const char *member, size_t maximum_size) {
    ZipReader reader(contents);
    const auto count = mz_zip_reader_get_num_files(&reader.archive);
    if (count == 0 || count > MAX_WALLET_ARCHIVE_ENTRIES || mz_zip_is_zip64(&reader.archive)) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "Oracle wallet ZIP has unsupported bounds");
    }
    int member_index = -1;
    for (mz_uint index = 0; index < count; index++) {
        mz_zip_archive_file_stat entry {};
        if (!mz_zip_reader_file_stat(&reader.archive, index, &entry)) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle wallet ZIP directory is malformed");
        }
        if (entry.m_is_directory || std::string(entry.m_filename) != member) {
            continue;
        }
        if (member_index != -1 || entry.m_is_encrypted || !entry.m_is_supported || entry.m_uncomp_size == 0 ||
            entry.m_uncomp_size > maximum_size) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED,
                                std::string("Oracle wallet ZIP has an invalid ") + member + " entry");
        }
        member_index = static_cast<int>(index);
    }
    if (member_index == -1) {
        return {};
    }
    size_t extracted_size = 0;
    auto *extracted = static_cast<char *>(
        mz_zip_reader_extract_to_heap(&reader.archive, static_cast<mz_uint>(member_index), &extracted_size, 0));
    if (!extracted || extracted_size == 0 || extracted_size > maximum_size) {
        if (extracted) {
            mz_free(extracted);
        }
        throw ProtocolError(ProtocolErrorKind::MALFORMED,
                            std::string("Oracle wallet ZIP could not extract ") + member);
    }
    std::unique_ptr<char, decltype(&mz_free)> owned(extracted, mz_free);
    return std::string(extracted, extracted_size);
}

} // namespace

std::string ReadWalletPemArchive(const std::string &path) {
    if (!HasZipSignature(path)) {
        return {};
    }
    const auto contents = ReadWalletFile(path, MAX_WALLET_ARCHIVE_BYTES, "Oracle wallet archive");
    ZipReader reader(contents);
    const auto count = mz_zip_reader_get_num_files(&reader.archive);
    if (count == 0 || count > MAX_WALLET_ARCHIVE_ENTRIES || mz_zip_is_zip64(&reader.archive)) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "Oracle wallet ZIP has unsupported bounds");
    }

    int wallet_index = -1;
    for (mz_uint index = 0; index < count; index++) {
        mz_zip_archive_file_stat entry {};
        if (!mz_zip_reader_file_stat(&reader.archive, index, &entry)) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle wallet ZIP directory is malformed");
        }
        if (entry.m_is_directory) {
            continue;
        }
        if (std::string(entry.m_filename) != "ewallet.pem") {
            continue;
        }
        if (wallet_index != -1 || entry.m_is_encrypted || !entry.m_is_supported || entry.m_uncomp_size == 0 ||
            entry.m_uncomp_size > MAX_WALLET_PEM_BYTES) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle wallet ZIP has an invalid ewallet.pem entry");
        }
        wallet_index = static_cast<int>(index);
    }
    if (wallet_index == -1) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle wallet ZIP does not contain ewallet.pem");
    }

    size_t extracted_size = 0;
    auto *extracted = static_cast<char *>(
        mz_zip_reader_extract_to_heap(&reader.archive, static_cast<mz_uint>(wallet_index), &extracted_size, 0));
    if (!extracted || extracted_size == 0 || extracted_size > MAX_WALLET_PEM_BYTES) {
        if (extracted) {
            mz_free(extracted);
        }
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle wallet ZIP could not extract ewallet.pem");
    }
    std::unique_ptr<char, decltype(&mz_free)> owned(extracted, mz_free);
    std::string pem(extracted, extracted_size);
    ValidatePemContents(pem, "Oracle wallet ZIP ewallet.pem");
    return pem;
}

std::string ReadWalletPemFile(const std::string &path) {
    if (HasZipSignature(path)) {
        return ReadWalletPemArchive(path);
    }
    return ReadPemFile(path);
}

std::string ReadWalletIdentityPem(const std::string &path, bool have_wallet_password) {
    if (HasZipSignature(path)) {
        const auto contents = ReadWalletFile(path, MAX_WALLET_ARCHIVE_BYTES, "Oracle wallet archive");
        // With a password the encrypted ewallet.pem is what the caller asked
        // for; without one the auto-login store is the only member that can be
        // opened at all, so it is tried first.
        if (!have_wallet_password) {
            const auto sso = ExtractOptionalMember(contents, "cwallet.sso", MAX_WALLET_PEM_BYTES);
            if (!sso.empty()) {
                return SsoWalletToPem(sso);
            }
        }
        auto pem = ExtractOptionalMember(contents, "ewallet.pem", MAX_WALLET_PEM_BYTES);
        if (!pem.empty()) {
            ValidatePemContents(pem, "Oracle wallet ZIP ewallet.pem");
            return pem;
        }
        const auto sso = ExtractOptionalMember(contents, "cwallet.sso", MAX_WALLET_PEM_BYTES);
        if (!sso.empty()) {
            return SsoWalletToPem(sso);
        }
        throw ProtocolError(ProtocolErrorKind::MALFORMED,
                            "Oracle wallet ZIP contains neither ewallet.pem nor cwallet.sso");
    }
    auto contents = ReadWalletFile(path, MAX_WALLET_PEM_BYTES, "Oracle wallet file");
    if (HasSsoWalletMagic(contents)) {
        return SsoWalletToPem(contents);
    }
    ValidatePemContents(contents, "Oracle wallet PEM");
    return contents;
}

std::string ReadPemFile(const std::string &path) {
    if (HasZipSignature(path)) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle PEM file must not be a ZIP archive");
    }
    const auto pem = ReadWalletFile(path, MAX_WALLET_PEM_BYTES, "Oracle wallet PEM");
    ValidatePemContents(pem, "Oracle wallet PEM");
    return pem;
}

std::string ReadWalletTnsNamesArchive(const std::string &path) {
    if (!HasZipSignature(path)) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle TNS_ALIAS requires a wallet ZIP");
    }
    const auto contents = ReadWalletFile(path, MAX_WALLET_ARCHIVE_BYTES, "Oracle wallet archive");
    ZipReader reader(contents);
    const auto count = mz_zip_reader_get_num_files(&reader.archive);
    if (count == 0 || count > MAX_WALLET_ARCHIVE_ENTRIES || mz_zip_is_zip64(&reader.archive)) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "Oracle wallet ZIP has unsupported bounds");
    }
    int tnsnames_index = -1;
    for (mz_uint index = 0; index < count; index++) {
        mz_zip_archive_file_stat entry {};
        if (!mz_zip_reader_file_stat(&reader.archive, index, &entry)) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle wallet ZIP directory is malformed");
        }
        if (entry.m_is_directory || std::string(entry.m_filename) != "tnsnames.ora") {
            continue;
        }
        if (tnsnames_index != -1 || entry.m_is_encrypted || !entry.m_is_supported || entry.m_uncomp_size == 0 ||
            entry.m_uncomp_size > MAX_WALLET_PEM_BYTES) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle wallet ZIP has an invalid tnsnames.ora entry");
        }
        tnsnames_index = static_cast<int>(index);
    }
    if (tnsnames_index == -1) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle wallet ZIP does not contain tnsnames.ora");
    }
    size_t extracted_size = 0;
    auto *extracted = static_cast<char *>(
        mz_zip_reader_extract_to_heap(&reader.archive, static_cast<mz_uint>(tnsnames_index), &extracted_size, 0));
    if (!extracted || extracted_size == 0 || extracted_size > MAX_WALLET_PEM_BYTES) {
        if (extracted) {
            mz_free(extracted);
        }
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle wallet ZIP could not extract tnsnames.ora");
    }
    std::unique_ptr<char, decltype(&mz_free)> owned(extracted, mz_free);
    std::string tnsnames(extracted, extracted_size);
    if (tnsnames.find('\0') != std::string::npos) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle wallet ZIP tnsnames.ora contains NUL bytes");
    }
    return tnsnames;
}

} // namespace oracle_scanner
