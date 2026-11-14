#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace oracle_scanner {

// A TTC piggyback precedes the next FUNCTION call in the same client message.
// Oracle Thin uses CLOSE_CURSORS to release server cursor ids after a statement
// is discarded; it is not a standalone request/response operation.
constexpr uint8_t TTC_MESSAGE_PIGGYBACK = 17;
constexpr uint8_t TTC_PIGGYBACK_CLOSE_CURSORS = 105;

constexpr uint8_t TTC_PIGGYBACK_END_TO_END = 135;
constexpr uint8_t TTC_FUNCTION_PING = 147;

// The attributes Oracle shows in V$SESSION and SYS_CONTEXT('USERENV', ...) and
// that tracing and resource management key on. A field that is not set is left
// as it was; `module` also clears the action unless one is given, which is what
// python-oracledb Thin sends (see PROVENANCE.md).
struct TtcEndToEndAttributes {
    std::optional<std::string> client_identifier;
    std::optional<std::string> module;
    std::optional<std::string> action;
    std::optional<std::string> client_info;

    bool Empty() const {
        return !client_identifier && !module && !action && !client_info;
    }
};

// Oracle's documented limits, in bytes.
constexpr size_t TTC_CLIENT_IDENTIFIER_MAXIMUM = 64;
constexpr size_t TTC_MODULE_MAXIMUM = 48;
constexpr size_t TTC_ACTION_MAXIMUM = 32;
constexpr size_t TTC_CLIENT_INFO_MAXIMUM = 64;

// A message the server puts in front of or inside a response (type 23): the
// report of session attributes just set, Transaction Guard's LTXID with a
// COMMIT, Application Continuity's replay context, and the rest of the opcodes
// python-oracledb and rust-oracledb know. Each is skipped, and an unknown one is
// refused rather than guessed at. Returns the offset after it.
constexpr uint8_t TTC_MESSAGE_SERVER_PIGGYBACK = 23;
size_t SkipTtcServerPiggyback(const std::vector<uint8_t> &message, size_t offset);
//! The same on a buffer: how many bytes of it the piggyback at its start takes.
size_t SkippedTtcServerPiggybackBytes(const uint8_t *data, size_t size);

std::vector<uint8_t> EncodeTtcEndToEndPiggyback(uint8_t sequence, const TtcEndToEndAttributes &attributes);
std::vector<uint8_t> EncodeTtcCloseCursorsPiggyback(uint8_t sequence, const std::vector<uint32_t> &cursor_ids);

} // namespace oracle_scanner
