#pragma once

#include "oracle_scanner/session.hpp"

#include <string>
#include <vector>

namespace oracle_scanner {

enum class OracleBindUse { QUERY, DML, CALL };

// Validates and folds a bind identifier according to the unquoted Oracle bind
// grammar. The returned upper-case form is used only for duplicate detection.
std::string CanonicalOracleBindName(const std::string &value);
void ValidateOracleBinds(const std::vector<OracleBind> &binds, OracleBindUse use);
void ValidateOracleBindBatch(const std::vector<std::vector<OracleBind>> &rows);

} // namespace oracle_scanner
