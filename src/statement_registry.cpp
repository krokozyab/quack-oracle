#include "oracle_scanner/statement_registry.hpp"
#include "oracle_scanner/protocol_error.hpp"

#include <limits>

namespace oracle_scanner {

OracleStatementRegistry::OracleStatementRegistry(size_t maximum_open_statements_p)
    : maximum_open_statements(maximum_open_statements_p) {
    if (maximum_open_statements == 0) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle statement registry limit must be positive");
    }
}

OracleStatementHandle OracleStatementRegistry::Open(OracleSqlKind kind) {
    if (kind != OracleSqlKind::QUERY && kind != OracleSqlKind::DML && kind != OracleSqlKind::PLSQL) {
        throw ProtocolError(ProtocolErrorKind::UNSUPPORTED, "Oracle statement kind is not executable");
    }
    std::lock_guard<std::mutex> guard(mutex);
    if (statements.size() == maximum_open_statements) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "too many open Oracle statements");
    }
    if (next_statement_id == 0 || next_statement_id == std::numeric_limits<uint32_t>::max()) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "Oracle statement ids are exhausted");
    }
    const OracleStatementHandle handle {next_statement_id++};
    statements.emplace(handle.statement_id, StatementRecord {});
    return handle;
}

void OracleStatementRegistry::BindRemoteCursor(OracleStatementHandle handle, uint32_t remote_cursor_id) {
    std::lock_guard<std::mutex> guard(mutex);
    auto &record = RequireOpen(handle);
    if (remote_cursor_id == 0 || record.remote_cursor_id != 0) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle remote cursor id is invalid or already bound");
    }
    for (const auto &entry : statements) {
        if (entry.second.remote_cursor_id == remote_cursor_id) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle remote cursor id is already in use");
        }
    }
    record.remote_cursor_id = remote_cursor_id;
}

uint32_t OracleStatementRegistry::RemoteCursorId(OracleStatementHandle handle) const {
    std::lock_guard<std::mutex> guard(mutex);
    if (handle.statement_id == 0) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle statement handle has a zero id");
    }
    const auto found = statements.find(handle.statement_id);
    if (found == statements.end() || found->second.remote_cursor_id == 0) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "Oracle statement has no server cursor id");
    }
    return found->second.remote_cursor_id;
}

std::optional<uint32_t> OracleStatementRegistry::TryRemoteCursorId(OracleStatementHandle handle) const {
    std::lock_guard<std::mutex> guard(mutex);
    if (handle.statement_id == 0) {
        return std::nullopt;
    }
    const auto found = statements.find(handle.statement_id);
    if (found == statements.end() || found->second.remote_cursor_id == 0) {
        return std::nullopt;
    }
    return found->second.remote_cursor_id;
}

OracleStatementRegistry::StatementRecord &OracleStatementRegistry::RequireOpen(OracleStatementHandle handle) {
    if (handle.statement_id == 0) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle statement handle has a zero id");
    }
    const auto found = statements.find(handle.statement_id);
    if (found == statements.end()) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "Oracle statement handle is closed or unknown");
    }
    return found->second;
}

void OracleStatementRegistry::MarkExecuted(OracleStatementHandle handle, bool has_rows) {
    std::lock_guard<std::mutex> guard(mutex);
    auto &record = RequireOpen(handle);
    if (record.state != OracleStatementState::OPEN) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "Oracle statement was already executed");
    }
    record.state = has_rows ? OracleStatementState::EXECUTED : OracleStatementState::EXHAUSTED;
}

void OracleStatementRegistry::BeginFetch(OracleStatementHandle handle) {
    std::lock_guard<std::mutex> guard(mutex);
    auto &record = RequireOpen(handle);
    if (record.state != OracleStatementState::EXECUTED && record.state != OracleStatementState::FETCHING) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "Oracle statement is not ready for fetch");
    }
    record.state = OracleStatementState::FETCHING;
}

void OracleStatementRegistry::MarkExhausted(OracleStatementHandle handle) {
    std::lock_guard<std::mutex> guard(mutex);
    auto &record = RequireOpen(handle);
    if (record.state != OracleStatementState::EXECUTED && record.state != OracleStatementState::FETCHING) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "Oracle statement cannot become exhausted in the current state");
    }
    record.state = OracleStatementState::EXHAUSTED;
}

void OracleStatementRegistry::Poison(OracleStatementHandle handle) {
    std::lock_guard<std::mutex> guard(mutex);
    auto &record = RequireOpen(handle);
    record.state = OracleStatementState::POISONED;
}

bool OracleStatementRegistry::Close(OracleStatementHandle handle) {
    std::lock_guard<std::mutex> guard(mutex);
    if (handle.statement_id == 0) {
        return false;
    }
    return statements.erase(handle.statement_id) != 0;
}

void OracleStatementRegistry::CloseAll() noexcept {
    std::lock_guard<std::mutex> guard(mutex);
    statements.clear();
}

OracleStatementState OracleStatementRegistry::State(OracleStatementHandle handle) const {
    std::lock_guard<std::mutex> guard(mutex);
    if (handle.statement_id == 0) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle statement handle has a zero id");
    }
    const auto found = statements.find(handle.statement_id);
    if (found == statements.end()) {
        return OracleStatementState::CLOSED;
    }
    return found->second.state;
}

size_t OracleStatementRegistry::OpenCount() const {
    std::lock_guard<std::mutex> guard(mutex);
    return statements.size();
}

} // namespace oracle_scanner
