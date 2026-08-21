#pragma once

#include "oracle_scanner/session.hpp"

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace oracle_scanner {

struct CursorHandle {
    uint64_t call_id = 0;
    uint32_t cursor_id = 0;
};

// A portable representation for the future SQL oracle_cursor(handle) surface.
// Handles remain valid only in the DuckDB connection that created them.
std::string FormatCursorHandle(const CursorHandle &handle);
CursorHandle ParseCursorHandle(const std::string &value);

// Owns procedure result cursors for one DuckDB connection. Taking a cursor is
// destructive: a SQL handle can therefore be consumed at most once.
class CallRegistry {
public:
    explicit CallRegistry(size_t maximum_open_cursors = 64);
    ~CallRegistry();

    CallRegistry(const CallRegistry &) = delete;
    CallRegistry &operator=(const CallRegistry &) = delete;

    std::vector<CursorHandle> Register(std::vector<std::unique_ptr<OracleCursor>> cursors);
    std::vector<CursorHandle> Register(OracleCallResult result);
    std::unique_ptr<OracleCursor> Take(const CursorHandle &handle);
    bool Close(uint64_t call_id);
    void CloseAll() noexcept;
    size_t OpenCursorCount() const;

private:
    using CursorMap = std::map<uint32_t, std::unique_ptr<OracleCursor>>;

    mutable std::mutex mutex;
    std::map<uint64_t, CursorMap> calls;
    uint64_t next_call_id = 1;
    size_t open_cursor_count = 0;
    size_t maximum_open_cursors;
};

} // namespace oracle_scanner
