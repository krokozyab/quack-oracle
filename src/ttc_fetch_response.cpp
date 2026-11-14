#include "oracle_scanner/ttc_fetch_response.hpp"

#include "oracle_scanner/byte_buffer.hpp"
#include "oracle_scanner/protocol_error.hpp"
#include "oracle_scanner/ttc_piggyback.hpp"
#include "oracle_scanner/ttc_parameter.hpp"

#include <string>

namespace oracle_scanner {

namespace {

constexpr uint8_t TTC_MESSAGE_ROW_HEADER = 6;
constexpr uint8_t TTC_MESSAGE_ROW_CONTINUATION = 21;
constexpr uint8_t TTC_MESSAGE_STATUS = 9;
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

TtcRowDataPrefix DecodePartialRowDataPrefix(const uint8_t *data, size_t size,
                                             const std::vector<size_t> &present_columns,
                                             const std::vector<TtcColumnFraming> &framing) {
    if (framing.size() != present_columns.size()) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC partial row framing map disagrees with its columns");
    }
    if (present_columns.empty()) {
        // A bit vector that selects nothing says the row repeats the previous
        // one, and ROW_DATA is then its message byte and nothing else.
        ByteReader reader(data, size);
        if (reader.ReadByte() != TTC_MESSAGE_ROW_DATA) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "expected TTC ROW_DATA after row continuation");
        }
        return {TtcRowData {}, reader.Position()};
    }
    // A continued row carries its values exactly as a full one does, LOB
    // locators included. Reading them as ordinary length-prefixed values costs
    // nothing on the first row of a fetch and desynchronizes every row after
    // the first bit vector, which is why this shares the full decoder.
    return DecodeTtcRowDataPrefix(data, size, framing, 16U << 20U);
}

TtcRowData MergeChangedColumns(const TtcRowData &previous_row, const std::vector<size_t> &present_columns,
                               TtcRowData values, size_t column_count) {
    if (previous_row.size() != column_count || present_columns.size() != values.size()) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC partial row disagrees with cursor columns");
    }
    auto row = previous_row;
    for (size_t index = 0; index < present_columns.size(); index++) {
        row[present_columns[index]] = std::move(values[index]);
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
            if (column < columns.size() && !columns[column].omitted_from_row_data) {
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

// How each of the given columns frames its value: a plain length, a LOB locator, a ROWID.
std::vector<TtcColumnFraming> ColumnFraming(const std::vector<OracleColumn> &columns, const std::vector<size_t> &wire_columns) {
    std::vector<TtcColumnFraming> framing;
    framing.reserve(wire_columns.size());
    for (const auto index : wire_columns) {
        const auto &column = columns[index];
        if (column.inline_lob_cells && IsOracleLocatorType(column.oracle_type)) {
            framing.push_back(column.oracle_type == ORACLE_WIRE_TYPE_JSON || column.oracle_type == ORACLE_WIRE_TYPE_VECTOR
                                  ? TtcColumnFraming::LOB_WITH_PREFIX
                                  : TtcColumnFraming::LOB_WITHOUT_PREFIX);
        } else {
            framing.push_back(TtcFramingForType(column.oracle_type));
        }
    }
    return framing;
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
    TtcRowData row(column_count);
    for (size_t index = 0; index < wire_columns.size(); index++) {
        row[wire_columns[index]] = std::move(values[index]);
    }
    return row;
}

// Same scalar framing as DecodeTtcRowDataPrefix, writing into a bounded arena.
size_t DecodePackedRow(const uint8_t *data, size_t size, const std::vector<size_t> &selected, OraclePackedBatch &batch,
                       bool continued) {
    ByteReader reader(data, size);
    if (reader.ReadByte() != TTC_MESSAGE_ROW_DATA) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "expected TTC ROW_DATA after row continuation");
    }
    batch.AppendRow(continued);
    constexpr size_t maximum_value_bytes = 16U << 20U;
    for (const auto column : selected) {
        batch.ClearCell(column);
        const auto first = reader.ReadByte();
        if (first == 0 || first == TNS_NULL_LENGTH_INDICATOR) {
            continue;
        }
        if (first != TNS_LONG_LENGTH_INDICATOR) {
            const auto at = reader.Position();
            reader.Skip(first);
            batch.AppendCellBytes(column, data + at, first);
            continue;
        }
        size_t total = 0;
        for (;;) {
            const auto count = reader.ReadUB4();
            if (!count) {
                break;
            }
            if (count > maximum_value_bytes - total) {
                throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "chunked TTC value exceeds configured limit");
            }
            const auto at = reader.Position();
            reader.Skip(count);
            batch.AppendCellBytes(column, data + at, count);
            total += count;
        }
    }
    return reader.Position();
}

} // namespace

TtcFetchResponseDecoder::TtcFetchResponseDecoder(const std::vector<OracleColumn> &columns_p,
                                                 uint8_t ttc_field_version_p,
                                                 const std::optional<TtcRowData> &preceding_row_p, bool packed_scalars,
                                                 size_t reserve_rows)
    : columns(columns_p), ttc_field_version(ttc_field_version_p), preceding_row(preceding_row_p) {
    if (columns.empty() || columns.size() > 4096) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC fetch response has an invalid cursor column count");
    }
    row_columns = WireCarryingColumns(columns, std::nullopt);
    row_framing = ColumnFraming(columns, row_columns);
    if (packed_scalars) {
        for (const auto framing : row_framing) {
            if (framing != TtcColumnFraming::SCALAR) {
                throw ProtocolError(ProtocolErrorKind::UNSUPPORTED, "packed fetch requires scalar framing");
            }
        }
        try {
            result.packed.emplace(columns.size());
            result.packed->ReserveRows(reserve_rows);
            if (preceding_row) {
                if (preceding_row->size() != columns.size()) {
                    throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC preceding row disagrees with cursor columns");
                }
                result.packed->AppendRow();
                for (size_t i = 0; i < columns.size(); i++) {
                    if ((*preceding_row)[i]) {
                        const auto &cell = *(*preceding_row)[i];
                        result.packed->AppendCellBytes(i, cell.data(), cell.size());
                    }
                }
                packed_seed = true;
                kept_rows = 1;
                kept_bytes = result.packed->ByteCount();
            }
        } catch (const ProtocolError &error) {
            if (error.Kind() != ProtocolErrorKind::LIMIT_EXCEEDED ||
                std::string(error.what()) != "Oracle packed batch exceeds its memory limit") {
                throw;
            }
            // A compressed logical row can exceed the budget even though
            // each response that contributed its values was bounded.
            result.packed.reset();
            packed_seed = false;
            kept_rows = kept_bytes = 0;
        }
    }
}

const TtcRowData *TtcFetchResponseDecoder::PreviousRow() const {
    if (!result.rows.empty()) {
        return &result.rows.back();
    }
    return preceding_row ? &*preceding_row : nullptr;
}

bool TtcFetchResponseDecoder::Decode(const std::vector<uint8_t> &message) {
    try {
        return DecodeInternal(message);
    } catch (const ProtocolError &error) {
        if (!result.packed || error.Kind() != ProtocolErrorKind::LIMIT_EXCEEDED ||
            std::string(error.what()) != "Oracle packed batch exceeds its memory limit") {
            throw;
        }
        // The caller retains all received bytes. Release the arena and restart
        // this response through the legacy path; never retry a remote fetch.
        result = TtcFetchResponse {};
        resume_offset = kept_rows = kept_bytes = 0;
        packed_seed = false;
        kept_row_header_selection = kept_row_continuation = false;
        return DecodeInternal(message);
    }
}

bool TtcFetchResponseDecoder::DecodeInternal(const std::vector<uint8_t> &message) {
    if (message.size() < resume_offset) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "TTC fetch response is shorter than what was decoded");
    }
    // Only the rows before resume_offset are kept between calls. Everything
    // after them — a row header waiting for its ROW_DATA, the rows that header
    // was still waiting over, the end-of-call and whether it ends the response
    // — is decided again from the bytes as they now stand, exactly as one pass
    // over the joined response would decide it.
    if (result.packed) {
        result.packed->Truncate(kept_rows, kept_bytes);
    } else {
        result.rows.erase(result.rows.begin() + static_cast<std::ptrdiff_t>(kept_rows), result.rows.end());
    }
    result.used_row_header_selection = kept_row_header_selection;
    result.used_row_continuation = kept_row_continuation;
    result.completion.reset();
    result.exhausted = false;
    result.completed = false;
    std::optional<std::vector<size_t>> row_header_present_columns;
    size_t offset = resume_offset;
    // Each message is read in place. Copying what was left of the response
    // for every message made a fetch quadratic in its own size.
    const auto keep_row = [&](TtcRowData row) {
        result.rows.push_back(std::move(row));
        if (!row_header_present_columns) {
            resume_offset = offset;
            kept_rows = result.rows.size();
            kept_row_header_selection = result.used_row_header_selection;
            kept_row_continuation = result.used_row_continuation;
        }
    };
    const auto keep_packed = [&] {
        if (!row_header_present_columns) {
            resume_offset = offset;
            kept_rows = result.packed->RowCount();
            kept_bytes = result.packed->ByteCount();
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
            // A row without a row header carries every column that carries
            // bytes at all, the same for each row, so that set is worked out once.
            std::vector<size_t> selected_columns;
            std::vector<TtcColumnFraming> selected_framing;
            if (row_header_present_columns) {
                selected_columns = WireCarryingColumns(columns, row_header_present_columns);
                selected_framing = ColumnFraming(columns, selected_columns);
            }
            const auto &wire_columns = row_header_present_columns ? selected_columns : row_columns;
            const auto &framing = row_header_present_columns ? selected_framing : row_framing;
            if (result.packed) {
                const bool continued = row_header_present_columns.has_value();
                offset += DecodePackedRow(at, remaining, wire_columns, *result.packed, continued);
                if (continued) {
                    result.used_row_header_selection = true;
                    row_header_present_columns.reset();
                }
                keep_packed();
                break;
            }
            TtcRowData values;
            if (wire_columns.empty()) {
                // Every column this row would carry is zero-width, so ROW_DATA
                // is its message byte and nothing else.
                offset += 1;
            } else {
                auto row = DecodeTtcRowDataPrefix(at, remaining, framing, 16U << 20U);
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
                auto merged = MergeChangedColumns(*previous_row, wire_columns, std::move(values), columns.size());
                result.used_row_header_selection = true;
                row_header_present_columns.reset();
                keep_row(std::move(merged));
            } else {
                keep_row(ExpandWireRow(columns.size(), wire_columns, std::move(values)));
            }
            break;
        }
        case TTC_MESSAGE_ROW_CONTINUATION: {
            if (result.packed) {
                const auto continuation = DecodeRowContinuationPrefix(at, remaining, columns.size());
                const auto selected = WireCarryingColumns(columns, continuation.present_columns);
                const auto consumed =
                    DecodePackedRow(at + continuation.bytes_consumed, remaining - continuation.bytes_consumed, selected,
                                    *result.packed, true);
                offset += continuation.bytes_consumed + consumed;
                result.used_row_continuation = true;
                keep_packed();
                break;
            }
            const auto *previous_row = PreviousRow();
            if (previous_row == nullptr) {
                throw ProtocolError(ProtocolErrorKind::MALFORMED,
                                    "TTC row continuation appeared before a complete row");
            }
            const auto continuation = DecodeRowContinuationPrefix(at, remaining, columns.size());
            // Zero-width columns carry no bytes here either, so they are
            // dropped from the selection before the values are read.
            const auto wire_columns = WireCarryingColumns(columns, continuation.present_columns);
            const auto partial_framing = ColumnFraming(columns, wire_columns);
            auto partial = DecodePartialRowDataPrefix(at + continuation.bytes_consumed,
                                                            remaining - continuation.bytes_consumed, wire_columns,
                                                            partial_framing);
            offset += continuation.bytes_consumed + partial.bytes_consumed;
            auto merged = MergeChangedColumns(*previous_row, wire_columns, std::move(partial.values), columns.size());
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
            const auto completion = DecodeTtcErrorPrefix(Tail(message, offset), ttc_field_version);
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
        case TTC_MESSAGE_STATUS: {
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

TtcFetchResponse TtcFetchResponseDecoder::Take() {
    if (result.packed) {
        if (result.packed->RowCount()) {
            result.last_row = result.packed->MaterializeRow(result.packed->RowCount() - 1);
        }
        if (packed_seed) {
            result.packed->RemoveFirstRow();
        }
        return std::move(result);
    }
    if (const auto *last = PreviousRow()) {
        result.last_row = *last;
    } else {
        result.last_row.reset();
    }
    return std::move(result);
}

TtcFetchResponse DecodeTtcFetchResponse(const std::vector<uint8_t> &message, const std::vector<OracleColumn> &columns,
                                        uint8_t ttc_field_version, const std::optional<TtcRowData> &preceding_row) {
    TtcFetchResponseDecoder decoder(columns, ttc_field_version, preceding_row);
    decoder.Decode(message);
    return decoder.Take();
}

} // namespace oracle_scanner
