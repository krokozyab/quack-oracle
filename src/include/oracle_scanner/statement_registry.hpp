#pragma once

#include "oracle_scanner/sql_statement.hpp"

#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>

namespace oracle_scanner {

enum class OracleStatementState { OPEN, EXECUTED, FETCHING, EXHAUSTED, CLOSED, POISONED };

struct OracleStatementHandle {
    uint32_t statement_id = 0;
};

// Tracks local statement handles independently from procedure results. Oracle
// assigns a remote cursor after initial OALL8, so that remote id is bound only
// from a validated server response and is never guessed by this registry.
class OracleStatementRegistry {
public:
    explicit OracleStatementRegistry(size_t maximum_open_statements = 64);

    OracleStatementHandle Open(OracleSqlKind kind);
    void BindRemoteCursor(OracleStatementHandle handle, uint32_t remote_cursor_id);
    uint32_t RemoteCursorId(OracleStatementHandle handle) const;
    std::optional<uint32_t> TryRemoteCursorId(OracleStatementHandle handle) const;
    void MarkExecuted(OracleStatementHandle handle, bool has_rows);
    void BeginFetch(OracleStatementHandle handle);
    void MarkExhausted(OracleStatementHandle handle);
    void Poison(OracleStatementHandle handle);
    bool Close(OracleStatementHandle handle);
    void CloseAll() noexcept;
    OracleStatementState State(OracleStatementHandle handle) const;
    size_t OpenCount() const;

private:
    struct StatementRecord {
        OracleStatementState state = OracleStatementState::OPEN;
        uint32_t remote_cursor_id = 0;
    };

    StatementRecord &RequireOpen(OracleStatementHandle handle);

    mutable std::mutex mutex;
    std::map<uint32_t, StatementRecord> statements;
    uint32_t next_statement_id = 1;
    size_t maximum_open_statements;
};

} // namespace oracle_scanner
