#include "oracle_scanner/ttc_io_vector.hpp"

#include "oracle_scanner/byte_buffer.hpp"
#include "oracle_scanner/protocol_error.hpp"

namespace oracle_scanner {

namespace {

constexpr size_t MAX_BINDS = 65535;
bool IsDirection(uint8_t value) {
    return value == TTC_BIND_DIRECTION_IN || value == TTC_BIND_DIRECTION_OUT || value == TTC_BIND_DIRECTION_IN_OUT;
}

} // namespace

TtcIoVector DecodeTtcIoVectorPrefix(const std::vector<uint8_t> &message) {
    ByteReader reader(message);
    if (reader.ReadByte() != TTC_MESSAGE_IO_VECTOR) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "expected TTC IO_VECTOR message");
    }
    reader.Skip(1);
    const auto low_bind_count = reader.ReadUB2();
    const auto high_bind_count = reader.ReadUB4();
    if (high_bind_count > (MAX_BINDS - low_bind_count) / 256U) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "TTC IO_VECTOR bind count exceeds supported bounds");
    }
    const auto bind_count = static_cast<size_t>(high_bind_count) * 256U + low_bind_count;
    const auto iteration_count = reader.ReadUB4();
    reader.ReadUB2();
    const auto fast_fetch_length = reader.ReadUB2();
    reader.Skip(fast_fetch_length);
    const auto rowid_length = reader.ReadUB2();
    reader.Skip(rowid_length);
    std::vector<uint8_t> directions;
    directions.reserve(bind_count);
    for (size_t index = 0; index < bind_count; index++) {
        const auto direction = reader.ReadByte();
        if (!IsDirection(direction)) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC IO_VECTOR contains an unknown bind direction");
        }
        directions.push_back(direction);
    }
    return {iteration_count, std::move(directions), reader.Position()};
}

TtcIoVector DecodeTtcIoVector(const std::vector<uint8_t> &message) {
    auto result = DecodeTtcIoVectorPrefix(message);
    if (result.bytes_consumed != message.size()) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC IO_VECTOR has trailing bytes");
    }
    return result;
}

std::vector<size_t> GetTtcOutputBindIndexes(const TtcIoVector &io_vector, const std::vector<OracleBind> &binds) {
    if (io_vector.directions.size() != binds.size()) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC IO_VECTOR bind count does not match execute request");
    }
    std::vector<size_t> result;
    for (size_t index = 0; index < binds.size(); index++) {
        // This vector describes Oracle's internal allocation direction, not
        // the public PL/SQL parameter mode. Live 19c sends IN for a scalar
        // OUT bind and IN OUT for an OUT SYS_REFCURSOR while returning both
        // values in ROW_DATA. The request's declared mode is authoritative
        // for deciding which slots to decode; the vector is still bounded and
        // validated to one of Oracle's three known direction bytes above.
        if (binds[index].direction != BindDirection::IN) {
            result.push_back(index);
        }
    }
    return result;
}

} // namespace oracle_scanner
