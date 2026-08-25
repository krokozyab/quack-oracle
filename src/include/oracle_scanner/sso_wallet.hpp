#pragma once

#include <string>

namespace oracle_scanner {

// True when the bytes start with the Oracle auto-login wallet magic. The check
// is only the three-byte signature, so callers still have to parse the header.
bool HasSsoWalletMagic(const std::string &bytes);

// Converts an Oracle auto-login wallet (cwallet.sso) into the PEM bundle the
// TLS layer already understands: the client private key followed by its
// certificate chain.
//
// An auto-login wallet is a PKCS#12 store whose password is carried, obfuscated,
// in the file header, which is why SQL*Plus and JDBC open it without asking for
// one. Everything here happens in memory: the recovered password never leaves
// this function, and no archive member is written to disk.
//
// A wallet stamped "auto-login local" is refused: its password is derived from
// the hostname and user account that created it, so it cannot be opened
// anywhere else, and silently failing later would be worse than saying so here.
std::string SsoWalletToPem(const std::string &bytes);

} // namespace oracle_scanner
