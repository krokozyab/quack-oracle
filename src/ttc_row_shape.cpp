#include "oracle_scanner/ttc_row_shape.hpp"

#include "oracle_scanner/byte_buffer.hpp"
#include "oracle_scanner/protocol_error.hpp"

#include <string>
#include <utility>

namespace oracle_scanner {

namespace {

constexpr uint8_t TTC_MESSAGE_ROW_HEADER = 6;
constexpr uint8_t TTC_MESSAGE_ROW_CONTINUATION = 21;

} // namespace

std::vector<uint8_t> Tail(const std::vector<uint8_t> &message, size_t offset) {
    return {message.begin() + static_cast<std::ptrdiff_t>(offset), message.end()};
}

TtcRowHeaderPrefix DecodeRowHeaderPrefix(const uint8_t *data, size_t size, size_t column_count) {
    ByteReader reader(data, size);
    if (reader.ReadByte() != TTC_MESSAGE_ROW_HEADER) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "expected TTC ROW_HEADER message");
    }
    reader.Skip(1);
    reader.ReadUB2();
    reader.ReadUB4();
    reader.ReadUB4();
    reader.ReadUB2();
    const auto bit_vector_size = reader.ReadUB4();
    std::optional<std::vector<size_t>> present_columns;
    if (bit_vector_size != 0) {
        const auto expected_bitmap_size = (column_count + 7U) / 8U;
        if (bit_vector_size != expected_bitmap_size) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED,
                                "TTC ROW_HEADER bit-vector width disagrees with described columns");
        }
        const auto bit_vector = reader.ReadLengthPrefixed(bit_vector_size);
        if (!bit_vector || bit_vector->size() != bit_vector_size) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED,
                                "TTC ROW_HEADER bit-vector length disagrees with payload");
        }
        present_columns.emplace();
        for (size_t column = 0; column < column_count; column++) {
            if (((*bit_vector)[column / 8U] & static_cast<uint8_t>(1U << (column % 8U))) != 0) {
                present_columns->push_back(column);
            }
        }
        // An all-zero vector selects no column, which means the row that
        // follows repeats the previous one and its ROW_DATA carries no values
        // at all — the message byte and nothing else. Treating the empty
        // selection as "no selection" instead made the decoder read a full row
        // out of the next message's bytes, and every scan of a table with
        // repeating consecutive values died a few rows later on whatever byte
        // it landed on. Captured from 19c: a header with a one-byte 0x00
        // vector, then `07`, then BIT_VECTOR/ROW_DATA pairs, then ORA-01403.
    }
    const auto rowid_size = reader.ReadUB4();
    if (rowid_size != 0) {
        const auto rowid = reader.ReadLengthPrefixed(rowid_size);
        if (!rowid || rowid->size() != rowid_size) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC ROW_HEADER rowid length disagrees with payload");
        }
    }
    return {std::move(present_columns), reader.Position()};
}

TtcRowContinuationPrefix DecodeRowContinuationPrefix(const uint8_t *data, size_t size, size_t column_count,
                                                     std::vector<size_t> *reuse) {
    ByteReader reader(data, size);
    if (reader.ReadByte() != TTC_MESSAGE_ROW_CONTINUATION) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "expected TTC row continuation marker");
    }
    const auto bitmap_size = (column_count + 7U) / 8U;
    // Two independently observed server profiles exist. The classic form
    // carries a little-endian 16-bit count (`15 02 00 06` means columns 1 and
    // 2 in a three-column row). Free 23ai's wide fetch uses a TTC UB2 count
    // instead (`15 01 01 01 00`: one changed column, then a two-byte bitmap).
    // Select a profile only when its bitmap's population count corroborates
    // its count, so malformed input cannot be reinterpreted opportunistically.
    const auto decode = [&](ByteReader &source, size_t present_count) -> std::optional<TtcRowContinuationPrefix> {
        if (present_count > column_count) {
            return std::nullopt;
        }
        const auto bitmap_at = source.Position();
        source.Skip(bitmap_size);
        const auto *bitmap = data + bitmap_at;
        std::vector<size_t> present_columns;
        if (reuse) {
            present_columns.swap(*reuse);
            present_columns.clear();
        }
        present_columns.reserve(present_count);
        for (size_t column = 0; column < column_count; column++) {
            if ((bitmap[column / 8U] & static_cast<uint8_t>(1U << (column % 8U))) != 0) {
                present_columns.push_back(column);
            }
        }
        if (present_columns.size() != present_count) {
            if (reuse) {
                present_columns.swap(*reuse);
            }
            return std::nullopt;
        }
        return TtcRowContinuationPrefix {std::move(present_columns), source.Position()};
    };

    const auto little_endian_count = reader.ReadUInt16LE();
    if (auto decoded = decode(reader, little_endian_count)) {
        return std::move(*decoded);
    }

    ByteReader universal_reader(data, size);
    universal_reader.ReadByte();
    const auto universal_count = universal_reader.ReadUB2();
    if (auto decoded = decode(universal_reader, universal_count)) {
        return std::move(*decoded);
    }
    throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC row continuation count and bitmap disagree with " +
                                                          std::to_string(column_count) + " described columns");
}

TtcRowData MergeChangedColumns(const TtcRowData &previous_row, const std::vector<size_t> &present_columns,
                               const TtcRowData &values, size_t column_count) {
    if (previous_row.size() != column_count || present_columns.size() != values.size()) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC partial row disagrees with cursor columns");
    }
    auto row = previous_row;
    for (size_t index = 0; index < present_columns.size(); index++) {
        row.CopyCell(present_columns[index], values, index);
    }
    return row;
}

// A column whose declared maximum length is zero can only ever be SQL NULL, and
// the server leaves it out of ROW_DATA entirely — not even a NULL length byte.
// Live capture on 19c, `SELECT '' AS e, 'x' AS f FROM dual`: E is declared with
// maximum 0, F with maximum 1, and the row arrives as `07 01 78` — one value
// for two columns. Reading a value per described column therefore assigns 'x'
// to the wrong column and then desynchronizes the whole response. Free 23ai and
// OCI Autonomous send the same shape. The declared maximum is the discriminator
// and the size field is not: NUMBER and DATE report size 0 yet send values.
//
// The returned indices are the columns that do carry bytes, in wire order,
// narrowed to a row header's selected columns when one is present.
std::vector<size_t> WireCarryingColumns(const std::vector<OracleColumn> &columns,
                                        const std::optional<std::vector<size_t>> &selected_columns) {
    std::vector<size_t> result;
    if (selected_columns) {
        for (const auto column : *selected_columns) {
            if (column >= columns.size()) {
                throw ProtocolError(ProtocolErrorKind::MALFORMED, "prefetched selected column exceeds describe");
            }
            if (!columns[column].omitted_from_row_data) {
                result.push_back(column);
            }
        }
        return result;
    }
    for (size_t column = 0; column < columns.size(); column++) {
        if (!columns[column].omitted_from_row_data) {
            result.push_back(column);
        }
    }
    return result;
}

// Places the values that were on the wire at their described column positions
// and leaves every omitted zero-width column as SQL NULL.
TtcRowData ExpandWireRow(size_t column_count, const std::vector<size_t> &wire_columns, TtcRowData values) {
    if (wire_columns.size() != values.size()) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC row disagrees with the columns that carry values");
    }
    // Wire columns ascend without repeats, so as many as there are columns
    // means every column, already in place.
    if (values.size() == column_count) {
        return values;
    }
    TtcRowData row(column_count, values.Arena());
    for (size_t index = 0; index < wire_columns.size(); index++) {
        row.CopyCell(wire_columns[index], values, index);
    }
    return row;
}

} // namespace oracle_scanner
