#include "oracle_scanner/sql_statement.hpp"
#include "oracle_scanner/protocol_error.hpp"

#include <cctype>

namespace oracle_scanner {

namespace {

constexpr size_t MAX_SQL_BYTES = 1U << 20U;

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

void SkipQuoted(const std::string &sql, size_t &index, char quote) {
    index++;
    while (index < sql.size()) {
        if (sql[index] == quote) {
            if (index + 1 < sql.size() && sql[index + 1] == quote) {
                index += 2;
                continue;
            }
            index++;
            return;
        }
        index++;
    }
    throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle SQL contains an unterminated quoted value");
}

void SkipTrivia(const std::string &sql, size_t &index) {
    while (index < sql.size()) {
        if (std::isspace(static_cast<unsigned char>(sql[index]))) {
            index++;
        } else if (sql[index] == '-' && index + 1 < sql.size() && sql[index + 1] == '-') {
            index += 2;
            while (index < sql.size() && sql[index] != '\n' && sql[index] != '\r') {
                index++;
            }
        } else if (sql[index] == '/' && index + 1 < sql.size() && sql[index + 1] == '*') {
            const auto end = sql.find("*/", index + 2);
            if (end == std::string::npos) {
                throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle SQL contains an unterminated comment");
            }
            index = end + 2;
        } else {
            break;
        }
    }
}

std::string FirstKeyword(const std::string &sql) {
    if (sql.empty() || sql.size() > MAX_SQL_BYTES || sql.find('\0') != std::string::npos) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle SQL text is empty or exceeds supported bounds");
    }
    size_t index = 0;
    SkipTrivia(sql, index);
    const auto begin = index;
    while (index < sql.size() && std::isalpha(static_cast<unsigned char>(sql[index]))) {
        index++;
    }
    if (begin == index) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle SQL does not begin with a statement keyword");
    }
    std::string result = sql.substr(begin, index - begin);
    for (auto &character : result) {
        character = static_cast<char>(std::toupper(static_cast<unsigned char>(character)));
    }
    return result;
}

void RejectStatementTerminators(const std::string &sql) {
    for (size_t index = 0; index < sql.size();) {
        if (sql[index] == '-' && index + 1 < sql.size() && sql[index + 1] == '-') {
            index += 2;
            while (index < sql.size() && sql[index] != '\n' && sql[index] != '\r') {
                index++;
            }
        } else if (sql[index] == '/' && index + 1 < sql.size() && sql[index + 1] == '*') {
            const auto end = sql.find("*/", index + 2);
            if (end == std::string::npos) {
                throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle SQL contains an unterminated comment");
            }
            index = end + 2;
        } else if (sql[index] == '\'' || sql[index] == '"') {
            SkipQuoted(sql, index, sql[index]);
        } else if ((sql[index] == 'q' || sql[index] == 'Q') && index + 2 < sql.size() && sql[index + 1] == '\'') {
            const auto end = sql.find(std::string() + QQuoteTerminator(sql[index + 2]) + "'", index + 3);
            if (end == std::string::npos) {
                throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle SQL contains an unterminated q-quoted value");
            }
            index = end + 2;
        } else if (sql[index] == ';') {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle SQL statement terminators are not accepted");
        } else {
            index++;
        }
    }
}

} // namespace

bool OracleQueryUsesTransientCursor(const std::string &sql) {
    size_t index = 0;
    unsigned snapshot_words = 0;
    while (index < sql.size()) {
        SkipTrivia(sql, index);
        if (index == sql.size()) {
            break;
        }
        if ((sql[index] == 'q' || sql[index] == 'Q') && index + 2 < sql.size() && sql[index + 1] == '\'') {
            const auto end = sql.find(std::string() + QQuoteTerminator(sql[index + 2]) + "'", index + 3);
            if (end == std::string::npos) {
                return true;
            }
            index = end + 2;
            snapshot_words = 0;
            continue;
        }
        if (sql[index] == '\'' || sql[index] == '"') {
            const auto start = index;
            const auto quote = sql[index];
            SkipQuoted(sql, index, quote);
            if (quote == '"' && sql.substr(start, index - start) == "\"ROWID\"") {
                return true;
            }
            snapshot_words = 0;
            continue;
        }
        if (std::isalpha(static_cast<unsigned char>(sql[index])) || sql[index] == '_') {
            std::string word;
            while (index < sql.size() && (std::isalnum(static_cast<unsigned char>(sql[index])) ||
                   sql[index] == '_' || sql[index] == '$' || sql[index] == '#')) {
                word += static_cast<char>(std::toupper(static_cast<unsigned char>(sql[index++])));
            }
            if (word == "ROWID" || (snapshot_words == 2 && word == "SCN")) {
                return true;
            }
            snapshot_words = word == "AS" ? 1 : (snapshot_words == 1 && word == "OF" ? 2 : 0);
        } else {
            ++index;
            snapshot_words = 0;
        }
    }
    return false;
}

OracleSqlKind ClassifyOracleSql(const std::string &sql) {
    const auto keyword = FirstKeyword(sql);
    if (keyword == "SELECT" || keyword == "WITH") {
        return OracleSqlKind::QUERY;
    }
    if (keyword == "INSERT" || keyword == "UPDATE" || keyword == "DELETE" || keyword == "MERGE") {
        return OracleSqlKind::DML;
    }
    if (keyword == "BEGIN" || keyword == "DECLARE" || keyword == "CALL") {
        return OracleSqlKind::PLSQL;
    }
    return OracleSqlKind::DDL_OR_OTHER;
}

void ValidateOracleQuery(const std::string &sql, const std::vector<OracleBind> &binds) {
    RejectStatementTerminators(sql);
    if (ClassifyOracleSql(sql) != OracleSqlKind::QUERY) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "oracle_query accepts only SELECT or WITH queries");
    }
    ValidateOracleStatementBinds(sql, binds, OracleBindUse::QUERY);
}

void ValidateOracleDml(const std::string &sql, const std::vector<OracleBind> &binds) {
    RejectStatementTerminators(sql);
    if (ClassifyOracleSql(sql) != OracleSqlKind::DML) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED,
                            "oracle_execute accepts only INSERT, UPDATE, DELETE, or MERGE");
    }
    ValidateOracleStatementBinds(sql, binds, OracleBindUse::DML);
}

std::string NormalizeOracleAnonymousBlock(const std::string &block) {
    const auto keyword = FirstKeyword(block);
    if (keyword != "BEGIN" && keyword != "DECLARE") {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "an anonymous PL/SQL block begins with BEGIN or DECLARE");
    }
    auto text = block;
    const auto trim = [&text] {
        while (!text.empty() && std::isspace(static_cast<unsigned char>(text.back()))) {
            text.pop_back();
        }
    };
    trim();
    if (!text.empty() && text.back() == '/') {
        const auto line_start = text.find_last_of("\r\n");
        if (line_start != std::string::npos) {
            const auto line = text.substr(line_start + 1);
            if (line == "/") {
                text.erase(line_start);
                trim();
            }
        }
    }
    if (text.empty() || text.back() != ';') {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "an anonymous PL/SQL block ends with the ; after its last END");
    }
    return text;
}

void ValidateOracleAdmin(const std::string &sql) {
    RejectStatementTerminators(sql);
    const auto keyword = FirstKeyword(sql);
    if (keyword != "CREATE" && keyword != "ALTER" && keyword != "DROP" && keyword != "GRANT" &&
        keyword != "REVOKE" && keyword != "COMMENT" && keyword != "TRUNCATE") {
        throw ProtocolError(ProtocolErrorKind::MALFORMED,
                            "oracle_execute_admin accepts only one administrative DDL statement");
    }
    ValidateOracleStatementBinds(sql, {}, OracleBindUse::DML);
}

} // namespace oracle_scanner
