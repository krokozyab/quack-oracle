#pragma once

#include <cstdint>
#include <vector>

namespace oracle_scanner {

// A TTC piggyback precedes the next FUNCTION call in the same client message.
// Oracle Thin uses CLOSE_CURSORS to release server cursor ids after a statement
// is discarded; it is not a standalone request/response operation.
constexpr uint8_t TTC_MESSAGE_PIGGYBACK = 17;
constexpr uint8_t TTC_PIGGYBACK_CLOSE_CURSORS = 105;

std::vector<uint8_t> EncodeTtcCloseCursorsPiggyback(uint8_t sequence, const std::vector<uint32_t> &cursor_ids);

} // namespace oracle_scanner
