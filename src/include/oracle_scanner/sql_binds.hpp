#pragma once

#include "oracle_scanner/bind_validation.hpp"

#include <string>
#include <vector>

namespace oracle_scanner {

// Extracts distinct Oracle bind placeholders in first-occurrence order. SQL
// strings, quoted identifiers, q-quoted strings, and comments are ignored.
std::vector<std::string> ExtractOracleBindPlaceholders(const std::string &sql);
void ValidateOracleStatementBinds(const std::string &sql, const std::vector<OracleBind> &binds, OracleBindUse use);

// Oracle SQL OALL bind values are positional even when their placeholders are
// named. Validate the bind set and return it in the first-occurrence order of
// the SQL placeholders, preserving each original bind name and wire value.
std::vector<OracleBind> OrderOracleStatementBinds(const std::string &sql, const std::vector<OracleBind> &binds,
                                                  OracleBindUse use);

} // namespace oracle_scanner
