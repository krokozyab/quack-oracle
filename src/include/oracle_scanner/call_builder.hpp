#pragma once

#include "oracle_scanner/session.hpp"

#include <string>
#include <vector>

namespace oracle_scanner {

// Validates a schema[.package].procedure name without changing its case or
// quote semantics. Database links and arbitrary SQL expressions are excluded.
std::string ParseOracleCallableName(const std::string &value);

// The same name split into the components the data dictionary stores: an
// unquoted identifier folded to upper case, a quoted one kept as its text with
// doubled quotes collapsed. One to three components, validated exactly as
// ParseOracleCallableName validates them.
std::vector<std::string> SplitOracleCallableName(const std::string &value);

// Produces an anonymous PL/SQL procedure block. Argument names are used both
// as named PL/SQL arguments and as bind placeholders, so they are strictly
// validated and case-insensitively unique.
std::string BuildOracleProcedureCallBlock(const std::string &qualified_name,
                                          const std::vector<OracleBind> &arguments);

// Produces an anonymous PL/SQL function block. The return bind must be OUT or
// IN OUT and must not collide with a named function argument.
std::string BuildOracleFunctionCallBlock(const std::string &qualified_name, const OracleBind &return_bind,
                                         const std::vector<OracleBind> &arguments);

std::string BuildOracleCallBlock(const OracleCallRequest &request);

} // namespace oracle_scanner
