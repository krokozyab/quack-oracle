#include "oracle_scanner/lob_prefetch_cursor.hpp"

// Candidate derived from the frozen scalar/compression decoder. Existing
// runtime and ABI are unchanged; only this new function reads prefetch cells.

#include "oracle_scanner/byte_buffer.hpp"
#include "oracle_scanner/protocol_error.hpp"
#include "oracle_scanner/ttc_piggyback.hpp"
#include "oracle_scanner/ttc_parameter.hpp"

#include <string>

namespace oracle_scanner {

namespace {

constexpr uint8_t TTC_MESSAGE_ROW_HEADER = 6;
constexpr uint8_t TTC_MESSAGE_ROW_CONTINUATION = 21;
constexpr uint8_t PREFETCH_TTC_MESSAGE_STATUS = 9;
constexpr uint8_t TTC_MESSAGE_END_OF_REQUEST = 29;

std::vector<uint8_t> Tail(const std::vector<uint8_t> &message, size_t offset) {
    return {message.begin() + static_cast<std::ptrdiff_t>(offset), message.end()};
}

struct TtcRowHeaderPrefix {
    std::optional<std::vector<size_t>> present_columns;
    size_t bytes_consumed = 0;
};

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
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC ROW_HEADER bit-vector length disagrees with payload");
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

struct TtcRowContinuationPrefix {
    std::vector<size_t> present_columns;
    size_t bytes_consumed = 0;
};

TtcRowContinuationPrefix DecodeRowContinuationPrefix(const uint8_t *data, size_t size, size_t column_count) {
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
        const auto bitmap = source.ReadRaw(bitmap_size);
        std::vector<size_t> present_columns;
        present_columns.reserve(present_count);
        for (size_t column = 0; column < column_count; column++) {
            if ((bitmap[column / 8U] & static_cast<uint8_t>(1U << (column % 8U))) != 0) {
                present_columns.push_back(column);
            }
        }
        if (present_columns.size() != present_count) {
            return std::nullopt;
        }
        return TtcRowContinuationPrefix {std::move(present_columns), source.Position()};
    };

    const auto little_endian_count = reader.ReadUInt16LE();
    if (const auto decoded = decode(reader, little_endian_count)) {
        return *decoded;
    }

    ByteReader universal_reader(data, size);
    universal_reader.ReadByte();
    const auto universal_count = universal_reader.ReadUB2();
    if (const auto decoded = decode(universal_reader, universal_count)) {
        return *decoded;
    }
    throw ProtocolError(ProtocolErrorKind::MALFORMED,
                        "TTC row continuation count and bitmap disagree with " + std::to_string(column_count) +
                            " described columns");
}

TtcRowDataPrefix DecodePrefetchedRow(const uint8_t *data, size_t size, const std::vector<size_t> &wire_columns,
                                     const std::vector<OracleColumn> &columns, const OracleLobPrefetchLimits &limits,
                                     const OracleRowData::ArenaPtr &arena) {
    ByteReader reader(data, size);
    if (reader.ReadByte() != TTC_MESSAGE_ROW_DATA) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED,"expected prefetched TTC ROW_DATA");
    }
    TtcRowData values(0, arena);
    const auto checkpoint = arena->Size();
    try {
        size_t row_bytes = 0;
        for (const auto index : wire_columns) {
            if (index >= columns.size()) {
                throw ProtocolError(ProtocolErrorKind::MALFORMED, "prefetched column index exceeds describe");
            }
            const auto &column = columns[index];
            if (!IsOracleLobType(column.oracle_type)) {
                AppendTtcScalarCell(reader, data, values, limits.maximum_row_bytes - row_bytes);
            } else {
                const auto start = reader.Position();
                const auto value = DecodeCursorLobPrefetchCell(reader, column.oracle_type == 112, limits.prefix_units,
                                                               limits.maximum_content_bytes);
                if (!value) {
                    values.emplace_back(std::nullopt);
                } else {
                    const auto length = reader.Position() - start;
                    if (length > limits.maximum_row_bytes - row_bytes) {
                        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED,
                                            "prefetched row exceeds stored byte budget");
                    }
                    values.Append(OracleByteView(data + start, reader.Position() - start));
                }
            }
            if (values.back()) {
                row_bytes += values.back()->size();
            }
        }
        return {std::move(values), reader.Position()};
    } catch (...) {
        arena->Truncate(checkpoint);
        throw;
    }
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
                throw ProtocolError(ProtocolErrorKind::MALFORMED,"prefetched selected column exceeds describe");
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
TtcRowData ExpandWireRow(size_t column_count, const std::vector<size_t> &wire_columns, const TtcRowData &values) {
    if (wire_columns.size() != values.size()) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC row disagrees with the columns that carry values");
    }
    TtcRowData row(column_count, values.Arena());
    for (size_t index = 0; index < wire_columns.size(); index++) {
        row.CopyCell(wire_columns[index], values, index);
    }
    return row;
}

} // namespace

LobPrefetchFetchResponseDecoder::LobPrefetchFetchResponseDecoder(const std::vector<OracleColumn> &columns_p,
    const OracleLobPrefetchLimits &limits_p,uint8_t server_field_version_p,const std::optional<TtcRowData> &preceding_row_p)
    : columns(columns_p), limits(limits_p), server_field_version(server_field_version_p), preceding_row(preceding_row_p) {
    if (preceding_row) {
        preceding_row = preceding_row->Clone(row_arena);
        kept_arena_bytes = row_arena->Size();
    }
    if (columns.empty() || columns.size() > 4096) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC fetch response has an invalid cursor column count");
    }
    (void)BoundedLobPrefetchRows(columns,1,limits);
    if (preceding_row && preceding_row->size()!=columns.size()) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED,"prefetched preceding row column count is invalid");
    }
}

const TtcRowData *LobPrefetchFetchResponseDecoder::PreviousRow() const {
    if (!result.rows.empty()) { return &result.rows.back(); }
    return preceding_row ? &*preceding_row : nullptr;
}

bool LobPrefetchFetchResponseDecoder::Decode(const std::vector<uint8_t> &message) {
    if (message.size() > (64U << 20U)) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED,"prefetched response exceeds wire byte budget");
    }
    if (message.size() < resume_offset) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "TTC fetch response is shorter than what was decoded");
    }
    // Rows before resume_offset, and the budget they used, are kept between
    // calls; everything after them is decided again, exactly as one pass over
    // the joined response would decide it.
    result.rows.erase(result.rows.begin() + static_cast<std::ptrdiff_t>(kept_rows), result.rows.end());
    row_arena->Truncate(kept_arena_bytes);
    result.used_row_header_selection = kept_row_header_selection;
    result.used_row_continuation = kept_row_continuation;
    result.completion.reset();
    result.exhausted = false;
    result.completed = false;
    size_t stored_batch_bytes=kept_batch_bytes;
    // Account the reconstructed row before compression causes any value copy.
    const auto account_row = [&](const TtcRowData &values,const std::vector<size_t> &selected,
                                 const TtcRowData *previous=nullptr) {
        if (values.size()!=selected.size() || (previous && previous->size()!=columns.size())) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED,"prefetched row budget map disagrees with columns");
        }
        size_t stored_row_bytes=0,changed=0;
        for (size_t column=0;column<columns.size();++column) {
            auto value = previous ? (*previous)[column] : std::nullopt;
            if (changed < selected.size() && selected[changed] == column) {
                value = values[changed++];
            }
            if (!value) {
                continue;
            }
            if (value->size() > limits.maximum_row_bytes - stored_row_bytes) {
                throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED,"prefetched expanded row exceeds byte budget");
            }
            stored_row_bytes += value->size();
        }
        if (changed!=selected.size()) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED,"prefetched row budget column selection is invalid");
        }
        if (result.rows.size()>=limits.maximum_rows || stored_row_bytes>limits.maximum_batch_bytes-stored_batch_bytes) {
            throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED,"prefetched expanded batch exceeds budget");
        }
        stored_batch_bytes+=stored_row_bytes;
    };
    if (preceding_row && resume_offset == 0) {
        // The preceding row must itself fit a row; it does not count against
        // this batch.
        account_row({}, {}, &*preceding_row);stored_batch_bytes=kept_batch_bytes;
    }
    std::optional<std::vector<size_t>> row_header_present_columns;
    size_t offset = resume_offset;
    const auto keep_row = [&](TtcRowData row) {
        result.rows.push_back(std::move(row));
        if (!row_header_present_columns) {
            resume_offset = offset;
            kept_rows = result.rows.size();
            kept_arena_bytes = row_arena->Size();
            kept_batch_bytes = stored_batch_bytes;
            kept_row_header_selection = result.used_row_header_selection;
            kept_row_continuation = result.used_row_continuation;
        }
    };
    while (offset < message.size() && !result.completed) {
        const auto *at = message.data() + offset;
        const auto remaining = message.size() - offset;
        switch (*at) {
        case TTC_MESSAGE_ROW_HEADER: {
            const auto row_header = DecodeRowHeaderPrefix(at, remaining, columns.size());
            offset += row_header.bytes_consumed;
            row_header_present_columns = row_header.present_columns;
            break;
        }
        case TTC_MESSAGE_ROW_DATA: {
            const auto wire_columns = WireCarryingColumns(columns, row_header_present_columns);
            TtcRowData values(0, row_arena);
            if (wire_columns.empty()) {
                // Every column this row would carry is zero-width, so ROW_DATA
                // is its message byte and nothing else.
                offset += 1;
            } else {
                auto row = DecodePrefetchedRow(at, remaining, wire_columns, columns, limits, row_arena);
                values = std::move(row.values);
                offset += row.bytes_consumed;
            }
            if (row_header_present_columns) {
                const auto *previous_row = PreviousRow();
                if (previous_row == nullptr) {
                    throw ProtocolError(ProtocolErrorKind::MALFORMED,
                                        "TTC ROW_HEADER selected columns before a complete row");
                }
                // Selected zero-width columns keep the previous row's value,
                // which is already NULL for them.
                account_row(values,wire_columns,previous_row);
                auto merged = MergeChangedColumns(*previous_row,wire_columns,values,columns.size());
                result.used_row_header_selection = true;
                row_header_present_columns.reset();
                keep_row(std::move(merged));
            } else {
                account_row(values,wire_columns);
                keep_row(ExpandWireRow(columns.size(),wire_columns,values));
            }
            break;
        }
        case TTC_MESSAGE_ROW_CONTINUATION: {
            const auto *previous_row = PreviousRow();
            if (previous_row == nullptr) {
                throw ProtocolError(ProtocolErrorKind::MALFORMED,
                                    "TTC row continuation appeared before a complete row");
            }
            const auto continuation = DecodeRowContinuationPrefix(at, remaining, columns.size());
            // Zero-width columns carry no bytes here either, so they are
            // dropped from the selection before the values are read.
            const auto wire_columns = WireCarryingColumns(columns, continuation.present_columns);
            const auto partial =
                DecodePrefetchedRow(at + continuation.bytes_consumed, remaining - continuation.bytes_consumed,
                                    wire_columns, columns, limits, row_arena);
            offset += continuation.bytes_consumed + partial.bytes_consumed;
            account_row(partial.values,wire_columns,previous_row);
            auto merged = MergeChangedColumns(*previous_row,wire_columns,partial.values,columns.size());
            result.used_row_continuation = true;
            keep_row(std::move(merged));
            break;
        }
        case TTC_MESSAGE_PARAMETER: {
            const auto parameter = DecodeTtcReturnParameterPrefix(Tail(message, offset));
            offset += parameter.bytes_consumed;
            break;
        }
        case TTC_MESSAGE_ERROR: {
            // No fallback: the end-of-call is decoded structurally, and a
            // failure to do so is a real disagreement with the server rather
            // than something to paper over by swallowing the rest of the
            // message.
            const auto completion = DecodeTtcErrorPrefix(Tail(message, offset), server_field_version);
            result.exhausted = completion.error_number == 1403;
            result.completion = completion;
            if (completion.error_number != 0 && !result.exhausted) {
                throw ProtocolError(ProtocolErrorKind::INVALID_STATE,
                                    completion.message.empty() ? "Oracle returned a TTC fetch error" : completion.message,
                                    completion.error_number);
            }
            // The end-of-call is consumed by what was actually decoded, not by
            // declaring the rest of the message part of it. That stand-in was
            // needed only while the tail was mis-parsed; with the padding field
            // and the version-gated trailer read correctly, a terminal
            // end-of-call consumes its message exactly.
            offset += completion.bytes_consumed;
            result.completed = result.exhausted || completion.bytes_consumed == remaining;
            break;
        }
        case PREFETCH_TTC_MESSAGE_STATUS: {
            ByteReader reader(at, remaining);
            reader.ReadByte();
            reader.ReadUB4();
            reader.ReadUB2();
            offset += reader.Position();
            result.completed = true;
            break;
        }
        case TTC_MESSAGE_END_OF_REQUEST:
            offset++;
            result.completed = true;
            break;
        case TTC_MESSAGE_SERVER_PIGGYBACK:
            offset += SkippedTtcServerPiggybackBytes(at, remaining);
            break;
        default:
            throw ProtocolError(ProtocolErrorKind::MALFORMED,
                                "unknown TTC message " + std::to_string(*at) + " in fetch response");
        }
    }
    result.bytes_consumed = offset;
    return result.completed;
}

TtcFetchResponse LobPrefetchFetchResponseDecoder::Take() {
    if (const auto *last = PreviousRow()) {
        result.last_row = last->Clone();
    } else {
        result.last_row.reset();
    }
    return std::move(result);
}

TtcFetchResponse DecodeLobPrefetchFetchResponse(const std::vector<uint8_t> &message, const std::vector<OracleColumn> &columns,
    const OracleLobPrefetchLimits &limits,uint8_t ttc_field_version, const std::optional<TtcRowData> &preceding_row) {
    LobPrefetchFetchResponseDecoder decoder(columns,limits,ttc_field_version,preceding_row);
    decoder.Decode(message);
    return decoder.Take();
}

} // namespace oracle_scanner
