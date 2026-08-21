#include "oracle_scanner/call_registry.hpp"
#include "oracle_scanner/protocol_error.hpp"

#include <charconv>
#include <limits>
#include <string_view>
#include <utility>

namespace oracle_scanner {

namespace {

constexpr std::string_view CURSOR_HANDLE_PREFIX = "oracle:";

template <class INTEGER>
INTEGER ParsePositiveDecimal(std::string_view value, const char *error_message) {
    INTEGER result = 0;
    const auto parsed = std::from_chars(value.data(), value.data() + value.size(), result);
    if (value.empty() || (value.size() > 1 && value.front() == '0') || parsed.ec != std::errc {} ||
        parsed.ptr != value.data() + value.size() || result == 0) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, error_message);
    }
    return result;
}

} // namespace

std::string FormatCursorHandle(const CursorHandle &handle) {
    if (handle.call_id == 0 || handle.cursor_id == 0) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle cursor handle contains a zero identifier");
    }
    return std::string(CURSOR_HANDLE_PREFIX) + std::to_string(handle.call_id) + ":" + std::to_string(handle.cursor_id);
}

CursorHandle ParseCursorHandle(const std::string &value) {
    if (value.compare(0, CURSOR_HANDLE_PREFIX.size(), CURSOR_HANDLE_PREFIX) != 0) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle cursor handle has an invalid prefix");
    }
    const std::string_view rest(value.data() + CURSOR_HANDLE_PREFIX.size(), value.size() - CURSOR_HANDLE_PREFIX.size());
    const auto separator = rest.find(':');
    if (separator == std::string_view::npos || rest.find(':', separator + 1) != std::string_view::npos) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle cursor handle has an invalid shape");
    }
    return {ParsePositiveDecimal<uint64_t>(rest.substr(0, separator), "Oracle cursor call id is invalid"),
            ParsePositiveDecimal<uint32_t>(rest.substr(separator + 1), "Oracle cursor id is invalid")};
}

CallRegistry::CallRegistry(size_t maximum_open_cursors_p) : maximum_open_cursors(maximum_open_cursors_p) {
    if (maximum_open_cursors == 0) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "cursor registry limit must be positive");
    }
}

CallRegistry::~CallRegistry() {
    CloseAll();
}

std::vector<CursorHandle> CallRegistry::Register(std::vector<std::unique_ptr<OracleCursor>> cursors) {
    std::lock_guard<std::mutex> guard(mutex);
    if (cursors.empty()) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "a call must expose at least one cursor");
    }
    if (cursors.size() > maximum_open_cursors - open_cursor_count) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "too many open Oracle procedure cursors");
    }
    for (const auto &cursor : cursors) {
        if (!cursor) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "a call returned a null cursor");
        }
    }

    while (next_call_id == 0 || calls.count(next_call_id) != 0) {
        next_call_id++;
    }
    const auto call_id = next_call_id++;
    CursorMap owned;
    std::vector<CursorHandle> handles;
    handles.reserve(cursors.size());
    uint32_t cursor_id = 1;
    for (auto &cursor : cursors) {
        owned.emplace(cursor_id, std::move(cursor));
        handles.push_back({call_id, cursor_id});
        cursor_id++;
    }
    open_cursor_count += owned.size();
    calls.emplace(call_id, std::move(owned));
    return handles;
}

std::vector<CursorHandle> CallRegistry::Register(OracleCallResult result) {
    std::vector<std::unique_ptr<OracleCursor>> cursors;
    cursors.reserve(result.explicit_cursors.size() + result.implicit_cursors.size());
    for (auto &cursor : result.explicit_cursors) {
        cursors.push_back(std::move(cursor));
    }
    for (auto &cursor : result.implicit_cursors) {
        cursors.push_back(std::move(cursor));
    }
    return Register(std::move(cursors));
}

std::unique_ptr<OracleCursor> CallRegistry::Take(const CursorHandle &handle) {
    std::lock_guard<std::mutex> guard(mutex);
    auto call = calls.find(handle.call_id);
    if (call == calls.end()) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "Oracle call handle is closed or unknown");
    }
    auto cursor = call->second.find(handle.cursor_id);
    if (cursor == call->second.end()) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "Oracle cursor handle was already consumed");
    }
    auto result = std::move(cursor->second);
    call->second.erase(cursor);
    open_cursor_count--;
    if (call->second.empty()) {
        calls.erase(call);
    }
    return result;
}

bool CallRegistry::Close(uint64_t call_id) {
    CursorMap cursors;
    {
        std::lock_guard<std::mutex> guard(mutex);
        auto call = calls.find(call_id);
        if (call == calls.end()) {
            return false;
        }
        cursors = std::move(call->second);
        open_cursor_count -= cursors.size();
        calls.erase(call);
    }
    for (auto &entry : cursors) {
        entry.second->Close();
    }
    return true;
}

void CallRegistry::CloseAll() noexcept {
    std::map<uint64_t, CursorMap> owned;
    {
        std::lock_guard<std::mutex> guard(mutex);
        owned.swap(calls);
        open_cursor_count = 0;
    }
    for (auto &call : owned) {
        for (auto &entry : call.second) {
            try {
                entry.second->Close();
            } catch (...) {
            }
        }
    }
}

size_t CallRegistry::OpenCursorCount() const {
    std::lock_guard<std::mutex> guard(mutex);
    return open_cursor_count;
}

} // namespace oracle_scanner
