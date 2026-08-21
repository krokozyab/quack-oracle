#include "oracle_scanner/ttc_fetch.hpp"
#include "oracle_scanner/byte_buffer.hpp"
#include "oracle_scanner/protocol_error.hpp"
#include "oracle_scanner/ttc_auth.hpp"

namespace oracle_scanner {

namespace {

constexpr uint32_t MAX_FETCH_ROWS = 1U << 20U;

void Validate(const TtcFetchRequest &request) {
    if (request.cursor_id == 0 || request.requested_rows == 0 || request.requested_rows > MAX_FETCH_ROWS) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC fetch request has invalid cursor id or row count");
    }
}

} // namespace

std::vector<uint8_t> EncodeTtcFetchRequest(const TtcFetchRequest &request) {
    Validate(request);
    ByteWriter writer;
    writer.WriteByte(TTC_MESSAGE_FUNCTION).WriteByte(TTC_FUNCTION_FETCH).WriteByte(request.sequence);
    writer.WriteUB4(request.cursor_id).WriteUB4(request.requested_rows);
    return writer.Take();
}

TtcFetchRequest DecodeTtcFetchRequest(const std::vector<uint8_t> &message) {
    ByteReader reader(message);
    if (reader.ReadByte() != TTC_MESSAGE_FUNCTION || reader.ReadByte() != TTC_FUNCTION_FETCH) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "expected TTC FETCH function message");
    }
    TtcFetchRequest result;
    result.sequence = reader.ReadByte();
    result.cursor_id = reader.ReadUB4();
    result.requested_rows = reader.ReadUB4();
    if (reader.Remaining() != 0) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC FETCH request has trailing bytes");
    }
    Validate(result);
    return result;
}

} // namespace oracle_scanner
