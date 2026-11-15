#pragma once

#include "oracle_scanner/session.hpp"
#include "oracle_scanner/statement_registry.hpp"

#include <list>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace oracle_scanner {

struct OraclePreparedQuery {
    std::string key;
    OracleStatementHandle handle;
    std::vector<OracleColumn> columns;

    size_t Bytes() const {
        size_t bytes = sizeof(*this) + 2 * sizeof(void *) + key.capacity() + columns.capacity() * sizeof(OracleColumn);
        for (const auto &column : columns) {
            bytes += column.name.capacity();
        }
        return bytes;
    }
};

// Idle cursors only. Taking an entry transfers exclusive ownership to its
// executing cursor; returning it updates recency. The caller closes evictions.
// All operations run under the native session's TTC call lock.
class OracleQueryCache {
public:
    static constexpr size_t MAX_ENTRIES = 20;
    static constexpr size_t MAX_BYTES = 2U << 20U;

    std::optional<OraclePreparedQuery> Take(const std::string &key) {
        for (auto it = entries.begin(); it != entries.end(); ++it) {
            if (it->key == key) {
                bytes -= it->Bytes();
                auto result = std::move(*it);
                entries.erase(it);
                return result;
            }
        }
        return std::nullopt;
    }

    template <class Close>
    void Put(OraclePreparedQuery entry, Close close) {
        const auto size = entry.Bytes();
        if (entry.key.empty() || size > MAX_BYTES) {
            close(entry.handle);
            return;
        }
        // Two concurrent readers of one SQL may finish in either order. Keep
        // one idle copy, without aliasing or closing the still-active reader.
        if (auto previous = Take(entry.key)) {
            close(previous->handle);
        }
        while (entries.size() >= MAX_ENTRIES || bytes > MAX_BYTES - size) {
            Evict(close);
        }
        entries.push_front(std::move(entry));
        bytes += size;
    }

    template <class Close>
    void Evict(Close close) {
        if (!entries.empty()) {
            close(entries.back().handle);
            bytes -= entries.back().Bytes();
            entries.pop_back();
        }
    }

    template <class Close>
    void Clear(Close close) {
        while (!entries.empty()) {
            Evict(close);
        }
    }

    size_t Size() const { return entries.size(); }
    size_t Bytes() const { return bytes; }

private:
    std::list<OraclePreparedQuery> entries;
    size_t bytes = 0;
};

} // namespace oracle_scanner
