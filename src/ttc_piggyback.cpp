#include "oracle_scanner/ttc_piggyback.hpp"
#include "oracle_scanner/byte_buffer.hpp"
#include "oracle_scanner/protocol_error.hpp"

namespace oracle_scanner {

std::vector<uint8_t> EncodeTtcCloseCursorsPiggyback(uint8_t sequence, const std::vector<uint32_t> &cursor_ids) {
    if (cursor_ids.empty()) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC CLOSE_CURSORS piggyback has no cursor ids");
    }
    ByteWriter writer;
    writer.WriteByte(TTC_MESSAGE_PIGGYBACK).WriteByte(TTC_PIGGYBACK_CLOSE_CURSORS).WriteByte(sequence);
    // Python Thin capture (Oracle 19c) uses the non-null collection pointer
    // here: 11 69 <seq> 01 <count> <cursor ids>. A null marker makes 19c
    // discard the session before it reaches the following function call.
    writer.WriteByte(1).WriteUB4(static_cast<uint32_t>(cursor_ids.size()));
    for (const auto cursor_id : cursor_ids) {
        if (cursor_id == 0) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC CLOSE_CURSORS piggyback has a zero cursor id");
        }
        writer.WriteUB4(cursor_id);
    }
    return writer.Take();
}

} // namespace oracle_scanner
