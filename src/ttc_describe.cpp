#include "oracle_scanner/ttc_describe.hpp"

#include "oracle_scanner/byte_buffer.hpp"
#include "oracle_scanner/protocol_error.hpp"

#include <limits>

namespace oracle_scanner {

namespace {

constexpr uint8_t TTC_MESSAGE_DESCRIBE_INFO = 16;
constexpr uint32_t MAX_COLUMNS = 4096;
constexpr uint32_t MAX_METADATA_BYTES = 1U << 20U;

void ReadDeclaredBytes(ByteReader &reader) {
    const auto declared = reader.ReadUB4();
    if (declared == 0) {
        return;
    }
    if (declared > MAX_METADATA_BYTES) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "TTC describe metadata field is too large");
    }
    const auto value = reader.ReadLengthPrefixed(declared);
    if (!value || value->size() != declared) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC describe metadata field length disagrees with payload");
    }
}

std::string ReadDeclaredText(ByteReader &reader) {
    const auto declared = reader.ReadUB4();
    if (declared == 0) {
        return {};
    }
    if (declared > MAX_METADATA_BYTES) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "TTC describe identifier is too large");
    }
    const auto value = reader.ReadLengthPrefixed(declared);
    if (!value || value->size() != declared) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC describe identifier length disagrees with payload");
    }
    return {value->begin(), value->end()};
}

OracleColumn DecodeColumn(ByteReader &reader, uint8_t field_version) {
    OracleColumn column;
    column.oracle_type = reader.ReadByte();
    reader.ReadByte(); // flags
    column.precision = static_cast<int8_t>(reader.ReadByte());
    column.scale = static_cast<int8_t>(reader.ReadByte());
    const auto maximum_size = reader.ReadUB4();
    reader.ReadUB4(); // maximum array elements
    reader.ReadUB8(); // continuation flags
    ReadDeclaredBytes(reader); // object id
    reader.ReadUB2(); // version
    reader.ReadUB2(); // character set id
    column.character_set_form = reader.ReadByte();
    const auto size = reader.ReadUB4();
    // TTIPRO's server version is not the version gate for OALL8 describe
    // metadata. A live 19c response reports TTIPRO version 6 yet includes
    // oaccolid followed by nullable. This is also the shape emitted after the
    // OALL8 request used by python-oracledb, so retain it unconditionally for
    // the supported modern TTC execution profile.
    reader.ReadUB4(); // oaccolid
    column.nullable = reader.ReadByte() != 0;
    reader.ReadByte(); // V7 name length
    column.name = ReadDeclaredText(reader);
    ReadDeclaredText(reader); // schema
    ReadDeclaredText(reader); // type name
    reader.ReadUB2(); // column position
    reader.ReadUB4(); // UDS flags
    if (field_version >= 17) {
        ReadDeclaredText(reader); // domain schema
        ReadDeclaredText(reader); // domain name
    }
    if (field_version >= 20) {
        const auto annotation_size = reader.ReadUB4();
        if (annotation_size != 0) {
            throw ProtocolError(ProtocolErrorKind::UNSUPPORTED, "TTC describe annotations are not yet supported");
        }
    }
    if (field_version >= 24) {
        reader.ReadUB4();
        reader.ReadByte();
        reader.ReadByte();
    }
    column.byte_width = column.oracle_type == 23 ? maximum_size : size;
    // The declared maximum, not the size field, is what says whether the column
    // carries bytes at all: NUMBER and DATE report size 0 while still sending a
    // value, and only a zero maximum means nothing is sent. A REF CURSOR is
    // never a ROW_DATA column, so it is excluded rather than reasoned about.
    column.omitted_from_row_data = maximum_size == 0 && column.oracle_type != 102;
    if (column.oracle_type == 102) {
        column.byte_width = 4;
    }
    return column;
}

} // namespace

TtcDescribeInfo DecodeTtcDescribeInfoPrefix(const std::vector<uint8_t> &message, uint8_t ttc_field_version) {
    ByteReader reader(message);
    if (reader.ReadByte() != TTC_MESSAGE_DESCRIBE_INFO) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "expected TTC DESCRIBE_INFO message");
    }
    (void)reader.ReadLengthPrefixed(MAX_METADATA_BYTES); // version bytes
    reader.ReadUB4(); // maximum row size
    const auto column_count = reader.ReadUB4();
    if (column_count == 0 || column_count > MAX_COLUMNS) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC describe has an invalid column count");
    }
    reader.ReadByte();
    TtcDescribeInfo result;
    result.columns.reserve(column_count);
    for (uint32_t index = 0; index < column_count; ++index) {
        try {
            result.columns.push_back(DecodeColumn(reader, ttc_field_version));
        } catch (const ProtocolError &error) {
            throw ProtocolError(error.Kind(), "TTC describe column " + std::to_string(index) + " at offset " +
                                                   std::to_string(reader.Position()) + ": " + error.what());
        }
    }
    try {
        ReadDeclaredBytes(reader); // current date
        reader.ReadUB4();
        reader.ReadUB4();
        reader.ReadUB4();
        reader.ReadUB4();
        ReadDeclaredBytes(reader); // descriptor tail
    } catch (const ProtocolError &error) {
        throw ProtocolError(error.Kind(), "TTC describe trailer at offset " + std::to_string(reader.Position()) + ": " +
                                               error.what());
    }
    result.bytes_consumed = reader.Position();
    return result;
}

} // namespace oracle_scanner
