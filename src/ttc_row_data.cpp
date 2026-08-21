#include "oracle_scanner/ttc_row_data.hpp"
#include "oracle_scanner/byte_buffer.hpp"
#include "oracle_scanner/protocol_error.hpp"

namespace oracle_scanner {

// The maximum locator this accepts. Oracle's own are 40 (python-oracledb) to
// 114 (what 19c sends here) bytes; a declared length far past that is a
// misread rather than a locator, and it would otherwise become an allocation.
constexpr size_t MAX_LOB_LOCATOR_BYTES = 4096;

TtcRowDataPrefix DecodeTtcRowDataPrefix(const std::vector<uint8_t> &message, const std::vector<bool> &is_lob,
                                        size_t maximum_value_bytes) {
    if (is_lob.empty() || is_lob.size() > 4096 || maximum_value_bytes == 0 || maximum_value_bytes > (16U << 20U)) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC row-data decoder bounds are invalid");
    }
    ByteReader reader(message);
    if (reader.ReadByte() != TTC_MESSAGE_ROW_DATA) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "expected TTC ROW_DATA message");
    }
    TtcRowData result;
    result.reserve(is_lob.size());
    for (size_t column = 0; column < is_lob.size(); column++) {
        if (!is_lob[column]) {
            result.push_back(reader.ReadLengthPrefixed(maximum_value_bytes));
            continue;
        }
        const auto locator_size = reader.ReadUB4();
        if (locator_size == 0) {
            // A NULL LOB, framed like any other NULL.
            result.push_back(std::nullopt);
            continue;
        }
        if (locator_size > MAX_LOB_LOCATOR_BYTES) {
            throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "TTC LOB locator length is implausible");
        }
        // The ub4 above is the locator's size, and the locator then follows in
        // the ordinary length-prefixed form — so its length is stated twice.
        // Reading the ub4 and then `locator_size` raw bytes consumes exactly as
        // many bytes as this does, which is why the wrong reading stays in
        // frame across every column and only shows up as ORA-22275 when the
        // locator is sent back one byte out of place.
        auto locator = reader.ReadLengthPrefixed(MAX_LOB_LOCATOR_BYTES);
        if (!locator || locator->size() != locator_size) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC LOB locator length disagrees with its prefix");
        }
        result.push_back(std::move(*locator));
    }
    return {std::move(result), reader.Position()};
}

TtcRowDataPrefix DecodeTtcRowDataPrefix(const std::vector<uint8_t> &message, size_t column_count,
                                        size_t maximum_value_bytes) {
    if (column_count == 0 || column_count > 4096 || maximum_value_bytes == 0 || maximum_value_bytes > (16U << 20U)) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC row-data decoder bounds are invalid");
    }
    ByteReader reader(message);
    if (reader.ReadByte() != TTC_MESSAGE_ROW_DATA) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "expected TTC ROW_DATA message");
    }
    TtcRowData result;
    result.reserve(column_count);
    for (size_t column = 0; column < column_count; column++) {
        result.push_back(reader.ReadLengthPrefixed(maximum_value_bytes));
    }
    return {std::move(result), reader.Position()};
}

TtcRowData DecodeTtcRowData(const std::vector<uint8_t> &message, size_t column_count, size_t maximum_value_bytes) {
    auto result = DecodeTtcRowDataPrefix(message, column_count, maximum_value_bytes);
    if (result.bytes_consumed != message.size()) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC ROW_DATA has trailing bytes");
    }
    return std::move(result.values);
}

} // namespace oracle_scanner
