#include "oracle_scanner/bind_validation.hpp"
#include "oracle_scanner/protocol_error.hpp"
#include "oracle_scanner/temp_lob.hpp"

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

namespace {

// What every bind must satisfy on its own, apart from its name: direction,
// buffer and value bounds. `total_value_bytes` accumulates across the binds of
// one execution.
void ValidateOracleBindValue(const OracleBind &bind, OracleBindUse use, size_t &total_value_bytes) {
    if (use != OracleBindUse::CALL && bind.direction != BindDirection::BIND_IN) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle query and DML binds must be input-only");
    }
    if (use == OracleBindUse::CALL && bind.direction != BindDirection::BIND_IN && bind.oracle_type == 0) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle OUT bind must declare a wire type");
    }
    if (bind.maximum_bytes > MAX_BIND_VALUE_BYTES) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "Oracle bind output buffer exceeds supported bounds");
    }
    if (bind.value && bind.lob_content != 0) {
        // LOB content past what an ordinary bind carries goes through a
        // temporary LOB, so it answers to the LOB bound instead and does
        // not count toward the statement's inline budget.
        if (bind.value->size() > TEMP_LOB_MAXIMUM_BYTES) {
            throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "Oracle LOB value exceeds supported bounds");
        }
        if (bind.value->size() <= TEMP_LOB_THRESHOLD_BYTES) {
            if (total_value_bytes > MAX_BIND_VALUE_BYTES - bind.value->size()) {
                throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "Oracle bind values exceed supported bounds");
            }
            total_value_bytes += bind.value->size();
        }
    } else if (bind.value) {
        if (bind.value->size() > MAX_BIND_VALUE_BYTES || total_value_bytes > MAX_BIND_VALUE_BYTES - bind.value->size()) {
            throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "Oracle bind values exceed supported bounds");
        }
        total_value_bytes += bind.value->size();
    }
}

} // namespace

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
        ValidateOracleBindValue(bind, use, total_value_bytes);
    }
}

void ValidateOracleBatchRow(const std::vector<OracleBind> &first, const std::vector<OracleBind> &row) {
    if (row.size() != first.size()) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle DML batch rows have different bind counts");
    }
    size_t total_value_bytes = 0;
    for (size_t bind_index = 0; bind_index < first.size(); bind_index++) {
        const auto &expected = first[bind_index];
        const auto &actual = row[bind_index];
        // The first row's names were checked whole, so a name spelled the same
        // needs no second look; one spelled differently must still fold to it.
        const bool same_name = actual.name == expected.name ||
                               CanonicalOracleBindName(actual.name) == CanonicalOracleBindName(expected.name);
        if (!same_name || actual.oracle_type != expected.oracle_type || actual.direction != expected.direction) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle DML batch bind metadata differs between rows");
        }
        ValidateOracleBindValue(actual, OracleBindUse::DML, total_value_bytes);
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
        ValidateOracleBatchRow(rows.front(), rows[row_index]);
    }
}

} // namespace oracle_scanner
