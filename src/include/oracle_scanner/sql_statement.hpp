#pragma once

#include "oracle_scanner/sql_binds.hpp"

namespace oracle_scanner {

enum class OracleSqlKind { QUERY, DML, PLSQL, DDL_OR_OTHER, ADMIN };

OracleSqlKind ClassifyOracleSql(const std::string &sql);
void ValidateOracleQuery(const std::string &sql, const std::vector<OracleBind> &binds);
void ValidateOracleDml(const std::string &sql, const std::vector<OracleBind> &binds);
void ValidateOracleAdmin(const std::string &sql);
bool OracleQueryUsesTransientCursor(const std::string &sql);
// An anonymous PL/SQL block, as the text a client sends: it begins with BEGIN or
// DECLARE and ends with the `;` that closes its last END. A SQL*Plus-style
// terminator, a `/` alone on the last line, is dropped. Returns the text to
// send. Unlike a single statement a block is full of `;`, so nothing about
// terminators is checked here; the server rejects a second statement.
std::string NormalizeOracleAnonymousBlock(const std::string &block);

} // namespace oracle_scanner
