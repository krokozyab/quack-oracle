#include "oracle_scanner/sql_binds.hpp"
#include "oracle_scanner/protocol_error.hpp"

#include <cctype>
#include <set>
#include <unordered_map>

namespace oracle_scanner {

namespace {

constexpr size_t MAX_SQL_BYTES = 1U << 20U;

bool IsBindStart(char character) {
    const auto value = static_cast<unsigned char>(character);
    return std::isalpha(value) || character == '_' || std::isdigit(value);
}

bool IsBindPart(char character) {
    const auto value = static_cast<unsigned char>(character);
    return std::isalnum(value) || character == '_' || character == '$' || character == '#';
}

char QQuoteTerminator(char opener) {
    switch (opener) {
    case '[':
        return ']';
    case '(':
        return ')';
    case '{':
        return '}';
    case '<':
        return '>';
    default:
        return opener;
    }
}

} // namespace

std::vector<std::string> ExtractOracleBindPlaceholders(const std::string &sql) {
    if (sql.empty() || sql.size() > MAX_SQL_BYTES || sql.find('\0') != std::string::npos) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle SQL text is empty or exceeds supported bounds");
    }
    std::vector<std::string> result;
    std::set<std::string> seen;
    for (size_t index = 0; index < sql.size();) {
        const auto character = sql[index];
        if (character == '-' && index + 1 < sql.size() && sql[index + 1] == '-') {
            index += 2;
            while (index < sql.size() && sql[index] != '\n' && sql[index] != '\r') {
                index++;
            }
            continue;
        }
        if (character == '/' && index + 1 < sql.size() && sql[index + 1] == '*') {
            const auto end = sql.find("*/", index + 2);
            if (end == std::string::npos) {
                throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle SQL contains an unterminated comment");
            }
            index = end + 2;
            continue;
        }
        if (character == '\'' || character == '"') {
            const auto quote = character;
            index++;
            bool closed = false;
            while (index < sql.size()) {
                if (sql[index] == quote) {
                    if (index + 1 < sql.size() && sql[index + 1] == quote) {
                        index += 2;
                        continue;
                    }
                    index++;
                    closed = true;
                    break;
                }
                index++;
            }
            if (!closed) {
                throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle SQL contains an unterminated quoted value");
            }
            continue;
        }
        if ((character == 'q' || character == 'Q') && index + 2 < sql.size() && sql[index + 1] == '\'') {
            const auto terminator = QQuoteTerminator(sql[index + 2]);
            const auto end = sql.find(std::string() + terminator + "'", index + 3);
            if (end == std::string::npos) {
                throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle SQL contains an unterminated q-quoted value");
            }
            index = end + 2;
            continue;
        }
        if (character == ':' && index + 1 < sql.size() && sql[index + 1] != ':' && IsBindStart(sql[index + 1])) {
            const auto begin = ++index;
            while (index < sql.size() && IsBindPart(sql[index])) {
                index++;
            }
            const auto canonical = CanonicalOracleBindName(sql.substr(begin, index - begin));
            if (seen.emplace(canonical).second) {
                result.push_back(canonical);
            }
            continue;
        }
        index++;
    }
    return result;
}

void ValidateOracleStatementBinds(const std::string &sql, const std::vector<OracleBind> &binds, OracleBindUse use) {
    ValidateOracleBinds(binds, use);
    const auto placeholders = ExtractOracleBindPlaceholders(sql);
    std::set<std::string> expected(placeholders.begin(), placeholders.end());
    std::set<std::string> actual;
    for (const auto &bind : binds) {
        actual.emplace(CanonicalOracleBindName(bind.name));
    }
    if (actual != expected) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle SQL placeholders and supplied binds do not match");
    }
}

std::vector<OracleBind> OrderOracleStatementBinds(const std::string &sql, const std::vector<OracleBind> &binds,
                                                  OracleBindUse use) {
    ValidateOracleStatementBinds(sql, binds, use);
    std::unordered_map<std::string, size_t> indexes;
    indexes.reserve(binds.size());
    for (size_t index = 0; index < binds.size(); index++) {
        indexes.emplace(CanonicalOracleBindName(binds[index].name), index);
    }
    std::vector<OracleBind> result;
    const auto placeholders = ExtractOracleBindPlaceholders(sql);
    result.reserve(placeholders.size());
    for (const auto &placeholder : placeholders) {
        result.push_back(binds[indexes.at(placeholder)]);
    }
    return result;
}

} // namespace oracle_scanner
