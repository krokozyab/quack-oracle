#pragma once

#include <string>

namespace oracle_scanner {

// Returns the ewallet.pem member of a bounded OCI wallet ZIP without writing
// any archive member to disk. An empty result means the supplied path is a
// plain PEM file; callers that accept both formats should use
// ReadWalletPemFile instead.
std::string ReadWalletPemArchive(const std::string &path);

// Returns a bounded PEM bundle from either a plain ewallet.pem file or a
// wallet ZIP. The returned data is kept in memory and never written to a
// temporary file.
std::string ReadWalletPemFile(const std::string &path);

// Returns a bounded plain PEM file. ZIP archives are rejected, keeping a
// dedicated CA trust file distinct from a wallet archive.
std::string ReadPemFile(const std::string &path);

// Returns tnsnames.ora from the same bounded ZIP. It is only used when a
// caller explicitly requests a TNS_ALIAS.
std::string ReadWalletTnsNamesArchive(const std::string &path);

} // namespace oracle_scanner
