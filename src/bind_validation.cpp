#include "oracle_scanner/bind_validation.hpp"
#include "oracle_scanner/protocol_error.hpp"

#include <algorithm>
#include <cctype>
#include <set>

namespace oracle_scanner {

namespace {

constexpr size_t MAX_BIND_COUNT = 65535;
constexpr size_t MAX_BIND_VALUE_BYTES = 16U << 20U;

bool IsIdentifierStart(char character) {
    const auto value = static_cast<unsigned char>(character);
    return std::isalpha(value) || character == '_';
}

bool IsIdentifierPart(char character) {
    const auto value = static_cast<unsigned char>(character);
    return std::isalnum(value) || character == '_' || character == '$' || character == '#';
}

} // namespace

std::string CanonicalOracleBindName(const std::string &value) {
    const bool positional = !value.empty() && std::all_of(value.begin(), value.end(), [](char character) {
        return std::isdigit(static_cast<unsigned char>(character));
    });
    if (value.empty() || value.size() > 128 ||
        (positional ? (value.size() > 1 && value.front() == '0')
                    : (!IsIdentifierStart(value.front()) || !std::all_of(value.begin() + 1, value.end(), IsIdentifierPart)))) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle bind name is invalid");
    }
    std::string result = value;
    std::transform(result.begin(), result.end(), result.begin(), [](unsigned char character) {
        return static_cast<char>(std::toupper(character));
    });
    return result;
}

void ValidateOracleBinds(const std::vector<OracleBind> &binds, OracleBindUse use) {
    if (binds.size() > MAX_BIND_COUNT) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "Oracle bind count exceeds supported bounds");
    }
    std::set<std::string> names;
    size_t total_value_bytes = 0;
    for (const auto &bind : binds) {
        if (!names.emplace(CanonicalOracleBindName(bind.name)).second) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle bind names must be unique");
        }
        if (use != OracleBindUse::CALL && bind.direction != BindDirection::BIND_IN) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle query and DML binds must be input-only");
        }
        if (use == OracleBindUse::CALL && bind.direction != BindDirection::BIND_IN && bind.oracle_type == 0) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle OUT bind must declare a wire type");
        }
        if (bind.maximum_bytes > MAX_BIND_VALUE_BYTES) {
            throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "Oracle bind output buffer exceeds supported bounds");
        }
        if (bind.value) {
            if (bind.value->size() > MAX_BIND_VALUE_BYTES || total_value_bytes > MAX_BIND_VALUE_BYTES - bind.value->size()) {
                throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "Oracle bind values exceed supported bounds");
            }
            total_value_bytes += bind.value->size();
        }
    }
}

void ValidateOracleBindBatch(const std::vector<std::vector<OracleBind>> &rows) {
    if (rows.empty()) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle DML batch must contain at least one row");
    }
    if (rows.size() > MAX_BIND_COUNT) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "Oracle DML batch has too many rows");
    }
    ValidateOracleBinds(rows.front(), OracleBindUse::DML);
    for (size_t row_index = 1; row_index < rows.size(); row_index++) {
        ValidateOracleBinds(rows[row_index], OracleBindUse::DML);
        if (rows[row_index].size() != rows.front().size()) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle DML batch rows have different bind counts");
        }
        for (size_t bind_index = 0; bind_index < rows.front().size(); bind_index++) {
            const auto &expected = rows.front()[bind_index];
            const auto &actual = rows[row_index][bind_index];
            if (CanonicalOracleBindName(actual.name) != CanonicalOracleBindName(expected.name) ||
                actual.oracle_type != expected.oracle_type || actual.direction != expected.direction) {
                throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle DML batch bind metadata differs between rows");
            }
        }
    }
}

} // namespace oracle_scanner
