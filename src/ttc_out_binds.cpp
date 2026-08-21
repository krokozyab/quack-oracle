#include "oracle_scanner/ttc_out_binds.hpp"

#include "oracle_scanner/byte_buffer.hpp"
#include "oracle_scanner/protocol_error.hpp"
#include "oracle_scanner/ttc_execute.hpp"
#include "oracle_scanner/ttc_row_data.hpp"

namespace oracle_scanner {

namespace {

constexpr size_t MAX_VALUE_BYTES = 16U << 20U;

void SkipSB4(ByteReader &reader) {
    const auto size = reader.ReadByte();
    const auto width = static_cast<size_t>(size & 0x7fU);
    if (width > 4) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC OUT bind actual-length SB4 has invalid width");
    }
    reader.Skip(width);
}

} // namespace

TtcOutBindsResult DecodeTtcOutBindsRow(const std::vector<uint8_t> &message, const std::vector<OracleBind> &binds,
                                       const std::vector<size_t> &output_indexes, uint8_t ttc_field_version) {
    ByteReader reader(message);
    if (reader.ReadByte() != TTC_MESSAGE_ROW_DATA) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "expected TTC ROW_DATA for PL/SQL OUT binds");
    }
    TtcOutBindsResult result;
    result.scalar_values.resize(output_indexes.size());
    result.cursor_values.resize(output_indexes.size());
    for (size_t output_position = 0; output_position < output_indexes.size(); output_position++) {
        const auto bind_index = output_indexes[output_position];
        if (bind_index >= binds.size()) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC OUT bind index exceeds execute bind count");
        }
        const auto &bind = binds[bind_index];
        if (bind.oracle_type == ORACLE_WIRE_TYPE_CURSOR) {
            const auto marker = reader.ReadByte();
            if (marker == 0 || marker == TNS_NULL_LENGTH_INDICATOR) {
                SkipSB4(reader);
                continue;
            }
            // Oracle 19c sends the embedded descriptor byte length here (for
            // example 0x4c), not a boolean marker. The descriptor itself is
            // self-delimiting, so only null markers are special.
            const auto remaining = reader.ReadRaw(reader.Remaining());
            auto descriptor = DecodeTtcRefCursorDescriptor(remaining, ttc_field_version);
            // Rebuild a cursor over the original tail so the SB4 trailer is
            // read in place and bytes_consumed remains relative to message.
            const auto descriptor_end = message.size() - remaining.size() + descriptor.bytes_consumed;
            ByteReader trailer_reader(message.data() + descriptor_end, message.size() - descriptor_end);
            SkipSB4(trailer_reader);
            const auto trailer_bytes = trailer_reader.Position();
            const auto next_offset = descriptor_end + trailer_bytes;
            reader = ByteReader(message.data() + next_offset, message.size() - next_offset);
            result.cursor_values[output_position] = std::move(descriptor);
            continue;
        }
        result.scalar_values[output_position] = reader.ReadLengthPrefixed(MAX_VALUE_BYTES);
        SkipSB4(reader);
    }
    result.bytes_consumed = message.size() - reader.Remaining();
    return result;
}

TtcPlsqlOutBindsResponse DecodeTtcPlsqlOutBindsResponse(const std::vector<uint8_t> &message,
                                                         const std::vector<OracleBind> &binds,
                                                         uint8_t ttc_field_version) {
    const auto io_vector = DecodeTtcIoVectorPrefix(message);
    if (io_vector.bytes_consumed >= message.size()) {
        throw ProtocolError(ProtocolErrorKind::TRUNCATED, "PL/SQL response has no OUT-bind ROW_DATA message");
    }
    const auto output_indexes = GetTtcOutputBindIndexes(io_vector, binds);
    const std::vector<uint8_t> row_message(message.begin() + static_cast<std::ptrdiff_t>(io_vector.bytes_consumed),
                                           message.end());
    auto values = DecodeTtcOutBindsRow(row_message, binds, output_indexes, ttc_field_version);
    return {io_vector, output_indexes, std::move(values), io_vector.bytes_consumed + values.bytes_consumed};
}

} // namespace oracle_scanner
