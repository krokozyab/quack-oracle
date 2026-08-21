#pragma once

#include "oracle_scanner/sql_binds.hpp"

namespace oracle_scanner {

enum class OracleSqlKind { QUERY, DML, PLSQL, DDL_OR_OTHER };

OracleSqlKind ClassifyOracleSql(const std::string &sql);
void ValidateOracleQuery(const std::string &sql, const std::vector<OracleBind> &binds);
void ValidateOracleDml(const std::string &sql, const std::vector<OracleBind> &binds);

} // namespace oracle_scanner
