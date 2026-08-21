#include "oracle_scanner/ttc_cursor.hpp"

#include "oracle_scanner/byte_buffer.hpp"
#include "oracle_scanner/protocol_error.hpp"

namespace oracle_scanner {

namespace {

constexpr size_t MAX_COLUMNS = 1024;
constexpr size_t MAX_NAME_BYTES = 1024;
constexpr size_t MAX_IMPLICIT_CURSORS = 64;
constexpr uint16_t ORACLE_CURSOR_TYPE = 102;

std::string ReadString(ByteReader &reader, size_t declared_size) {
    if (declared_size > MAX_NAME_BYTES) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "TTC cursor descriptor name is too large");
    }
    if (declared_size == 0) {
        return {};
    }
    const auto value = reader.ReadLengthPrefixed(declared_size);
    if (!value || value->size() != declared_size) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC cursor descriptor name length disagrees with payload");
    }
    return {value->begin(), value->end()};
}

void SkipString(ByteReader &reader) {
    const auto length = reader.ReadUB4();
    (void)ReadString(reader, length);
}

OracleColumn ReadColumn(ByteReader &reader, uint8_t field_version) {
    OracleColumn column;
    column.oracle_type = reader.ReadByte();
    reader.Skip(1); // flags
    const auto precision = static_cast<int8_t>(reader.ReadByte());
    const auto scale = static_cast<int8_t>(reader.ReadByte());
    const auto maximum_size = reader.ReadUB4();
    reader.ReadUB4(); // max array elements
    reader.ReadUB8(); // continuation flags
    const auto oid_size = reader.ReadUB4();
    if (oid_size != 0) {
        (void)ReadString(reader, oid_size);
    }
    reader.ReadUB2(); // type version
    reader.ReadUB2(); // charset id
    column.character_set_form = reader.ReadByte();
    const auto size = reader.ReadUB4();
    // OALL8 embedded descriptors include oaccolid even when TTIPRO reports
    // server version 6; its gate is independent from that legacy byte.
    reader.ReadUB4();
    column.nullable = reader.ReadByte() != 0;
    reader.Skip(1); // V7 name length
    column.name = ReadString(reader, reader.ReadUB4());
    SkipString(reader); // schema
    SkipString(reader); // type name
    reader.ReadUB2();   // position
    reader.ReadUB4();   // UDS flags
    if (field_version >= 17) {
        throw ProtocolError(ProtocolErrorKind::UNSUPPORTED,
                            "23c cursor-descriptor domain fields require a versioned decoder");
    }
    column.byte_width = column.oracle_type == 23 ? maximum_size : size;
    // Same rule as the top-level describe: a zero declared maximum means the
    // column sends nothing in ROW_DATA. See OracleColumn::omitted_from_row_data.
    column.omitted_from_row_data = maximum_size == 0 && column.oracle_type != ORACLE_CURSOR_TYPE;
    if (column.oracle_type == ORACLE_CURSOR_TYPE) {
        column.byte_width = 4;
    }
    column.precision = precision;
    column.scale = scale;
    return column;
}

} // namespace

TtcRefCursorDescriptor DecodeTtcRefCursorDescriptor(const std::vector<uint8_t> &message, uint8_t ttc_field_version) {
    ByteReader reader(message);
    reader.ReadUB4(); // max row size
    const auto column_count = reader.ReadUB4();
    if (column_count == 0 || column_count > MAX_COLUMNS) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "REF CURSOR descriptor has an invalid column count");
    }
    reader.Skip(1);
    std::vector<OracleColumn> columns;
    columns.reserve(column_count);
    for (uint32_t index = 0; index < column_count; index++) {
        columns.push_back(ReadColumn(reader, ttc_field_version));
    }
    const auto current_date_size = reader.ReadUB4();
    if (current_date_size != 0) {
        (void)ReadString(reader, current_date_size);
    }
    reader.ReadUB4();
    reader.ReadUB4();
    reader.ReadUB4();
    reader.ReadUB4();
    const auto tail_size = reader.ReadUB4();
    if (tail_size != 0) {
        (void)ReadString(reader, tail_size);
    }
    const auto cursor_id = reader.ReadUB2();
    if (cursor_id == 0) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "REF CURSOR descriptor has a zero server cursor id");
    }
    return {cursor_id, std::move(columns), reader.Position()};
}

TtcImplicitResultSet DecodeTtcImplicitResultSetPrefix(const std::vector<uint8_t> &message, uint8_t ttc_field_version) {
    ByteReader reader(message);
    if (reader.ReadByte() != TTC_MESSAGE_IMPLICIT_RESULT_SET) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "expected TTC implicit-result-set message");
    }
    const auto cursor_count = reader.ReadUB4();
    if (cursor_count > MAX_IMPLICIT_CURSORS) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "too many implicit Oracle result cursors");
    }
    TtcImplicitResultSet result;
    result.cursors.reserve(cursor_count);
    for (uint32_t index = 0; index < cursor_count; index++) {
        const auto opaque_size = reader.ReadByte();
        reader.Skip(opaque_size);
        const auto descriptor_start = reader.Position();
        const std::vector<uint8_t> descriptor_message(message.begin() + static_cast<std::ptrdiff_t>(descriptor_start),
                                                      message.end());
        auto descriptor = DecodeTtcRefCursorDescriptor(descriptor_message, ttc_field_version);
        reader.Skip(descriptor.bytes_consumed);
        result.cursors.push_back(std::move(descriptor));
    }
    result.bytes_consumed = reader.Position();
    return result;
}

TtcImplicitResultSet DecodeTtcImplicitResultSet(const std::vector<uint8_t> &message, uint8_t ttc_field_version) {
    auto result = DecodeTtcImplicitResultSetPrefix(message, ttc_field_version);
    if (result.bytes_consumed != message.size()) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC implicit-result-set message has trailing bytes");
    }
    return result;
}

} // namespace oracle_scanner
