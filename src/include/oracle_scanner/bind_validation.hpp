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
// One later row of a batch whose first row has passed ValidateOracleBinds: the
// same names, types and directions in the same places, and values within
// bounds. Cheaper than validating the row whole, which re-folds every name.
void ValidateOracleBatchRow(const std::vector<OracleBind> &first, const std::vector<OracleBind> &row);

} // namespace oracle_scanner
