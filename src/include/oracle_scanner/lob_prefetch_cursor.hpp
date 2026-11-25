#pragma once

#include "lob_prefetch_wire.hpp"
#include "oracle_scanner/ttc_fetch_response.hpp"
#include <algorithm>
#include <limits>

namespace oracle_scanner {

// Candidate cursor profile. Unsupported scalar/charset profiles retain the
// existing locator path; they are never guessed or retried after DEFINE.
struct OracleLobPrefetchLimits {
    uint32_t prefix_units = 4096;
    size_t maximum_content_bytes = (std::numeric_limits<size_t>::max)() / 2;
    size_t maximum_row_bytes = 1U << 20U;
    // Rows at their declared widths, so the bound is the worst case. 4 MiB and
    // 128 rows held a 50-column scan to about 60 rows a round trip; 48 MiB stays
    // under the 64 MiB response limit, and 2048 is what a scan asks for.
    size_t maximum_batch_bytes = 48U << 20U;
    uint32_t maximum_rows = 2048;
};

inline bool SupportsLobPrefetchColumns(const std::vector<OracleColumn> &columns, uint8_t field_version) {
    if (field_version < 12 || columns.empty() || columns.size() > 4096) { return false; }
    bool lob = false;
    for (const auto &column : columns) {
        if (column.character_set_form > 1) { return false; }
        switch (column.oracle_type) {
        case 112: case 113: lob = true; break;
        case 1: case 2: case 23: case 12: case 180: break;
        // JDBC defines a CHAR as VARCHAR2 in this profile, omitted (19.3) or
        // not (23.7, jdbc_lob_prefetch_define_char), and the value comes back
        // blank-padded, as a CHAR reads. National forms are refused above.
        case 96: break;
        default: return false;
        }
    }
    return lob;
}

inline uint32_t BoundedLobPrefetchRows(const std::vector<OracleColumn> &columns, size_t desired,
                                     const OracleLobPrefetchLimits &limits) {
    if (!SupportsLobPrefetchColumns(columns,12) || desired == 0 || limits.prefix_units > 32768 ||
        limits.maximum_content_bytes == 0 || limits.maximum_row_bytes == 0 ||
        limits.maximum_batch_bytes < limits.maximum_row_bytes || limits.maximum_rows == 0 ||
        limits.maximum_rows > 2048 || limits.maximum_batch_bytes > (64U << 20U)) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED,"invalid bounded LOB prefetch cursor profile");
    }
    size_t per_row = 0;
    for (const auto &column : columns) {
        if (column.omitted_from_row_data) { continue; }
        // Scalar values occupy the same reconstructed row and batch budgets.
        // Prefer the described maximum byte width. Synthetic/unknown widths
        // use the existing DEFINE capacity or fixed scalar encoding maximum.
        size_t cell = column.byte_width;
        if (IsOracleLobType(column.oracle_type)) {
            cell = static_cast<size_t>(limits.prefix_units) * (column.oracle_type == 112 ? 2U : 1U) + 4096U + 64U;
        } else {
            switch (column.oracle_type) {
            case 1: case 96: if (cell == 0) { cell = 131068; } break;
            case 23: if (cell == 0) { cell = 32767; } break;
            case 2: cell = (std::max)(cell,size_t(22)); break;
            case 12: cell = (std::max)(cell,size_t(7)); break;
            case 180: cell = (std::max)(cell,size_t(11)); break;
            default: break; // Omitted CHAR was skipped above.
            }
        }
        if (cell > limits.maximum_row_bytes - per_row) {
            throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED,"LOB prefetch row estimate exceeds row budget");
        }
        per_row += cell;
    }
    const auto row_bytes = (std::max)(per_row,size_t(1));
    return static_cast<uint32_t>((std::min)({desired,size_t(limits.maximum_rows),limits.maximum_batch_bytes / row_bytes}));
}

// All OAC profiles below, including omitted VARCHAR2, are byte-equal to the
// ordinary JDBC mixed SELECT captures. DEFINE carries no SQL and fetches on
// the existing cursor. Subsequent batches use the existing OFETCH encoder.
inline std::vector<uint8_t> EncodeLobPrefetchDefine(uint8_t sequence,uint32_t cursor,
    const std::vector<OracleColumn> &columns,uint32_t rows,uint8_t field_version,
    const OracleLobPrefetchLimits &limits) {
    if (sequence == 0 || cursor == 0 || !SupportsLobPrefetchColumns(columns,field_version) ||
        rows == 0 || BoundedLobPrefetchRows(columns,rows,limits) != rows) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED,"invalid LOB prefetch DEFINE request");
    }
    ByteWriter writer;
    writer.WriteByte(3).WriteByte(94).WriteByte(sequence).WriteUB4(0x8050).WriteUB4(cursor);
    writer.WriteByte(0).WriteUB4(0).WriteByte(1).WriteUB4(13).WriteByte(0).WriteByte(0);
    writer.WriteUB4(0).WriteUB4(0).WriteUB4(0x7fffffff).WriteByte(0).WriteUB4(0);
    for (unsigned i=0;i<5;++i) { writer.WriteByte(0); }
    writer.WriteByte(1).WriteUB4(static_cast<uint32_t>(columns.size())).WriteUB4(0);
    writer.WriteByte(0).WriteByte(1).WriteByte(0).WriteUB4(0).WriteByte(0).WriteUB4(0).WriteUB4(0);
    writer.WriteByte(0).WriteUB4(0).WriteByte(0);
    writer.WriteByte(0).WriteUB4(0).WriteByte(0).WriteUB4(0).WriteByte(0);
    writer.WriteByte(0).WriteUB4(0);
    for (unsigned i=0;i<13;++i) { writer.WriteUB4(i == 1 ? rows : i == 7 ? 1 : 0); }
    for (const auto &column : columns) {
        const auto type=column.oracle_type == 96 ? 1 : column.oracle_type;
        const bool lob=IsOracleLobType(type);
        const uint32_t maximum=lob ? 0 : type == 1 ? 131068 : type == 23 ? 32767 : 0x7fffffff;
        writer.WriteByte(static_cast<uint8_t>(type)).WriteByte(3).WriteByte(0).WriteByte(0);
        writer.WriteUB4(maximum).WriteUB4(0).WriteUB8(lob ? 0x02000000 : type == 1 ? 16 : 0);
        writer.WriteUB4(0).WriteUB2(0).WriteUB2(873).WriteByte(1);
        writer.WriteUB4(lob ? limits.prefix_units : 0).WriteUB4(0);
    }
    return writer.Take();
}

// Raw prefetched LOB cells remain internal to this decoder/cursor. Their full
// wire slice is retained so column compression copies metadata, prefix and
// locator together. Only an explicit prefetched batch uses this representation.
TtcFetchResponse DecodeLobPrefetchFetchResponse(const std::vector<uint8_t> &message,
    const std::vector<OracleColumn> &columns,const OracleLobPrefetchLimits &limits,
    uint8_t server_field_version = 12,const std::optional<TtcRowData> &preceding_row = std::nullopt);

// The same response decoded as it arrives in DATA fragments, resuming after
// the last row it finished, as TtcFetchResponseDecoder does for a scalar fetch.
// The batch byte budget those rows used is kept with them. The columns and
// limits are held by reference and must outlive the decoder.
class LobPrefetchFetchResponseDecoder {
public:
    LobPrefetchFetchResponseDecoder(const std::vector<OracleColumn> &columns,const OracleLobPrefetchLimits &limits,
        uint8_t server_field_version,const std::optional<TtcRowData> &preceding_row);

    // True once the response is complete; throws TRUNCATED when the bytes end
    // inside a message, keeping the rows finished so far for the next call.
    bool Decode(const std::vector<uint8_t> &message);
    TtcFetchResponse Take();

private:
    // Valid only until the next row is added.
    const TtcRowData *PreviousRow() const;

    const std::vector<OracleColumn> &columns;
    const OracleLobPrefetchLimits &limits;
    uint8_t server_field_version;
    std::optional<TtcRowData> preceding_row;
    TtcFetchResponse result;
    OracleRowData::ArenaPtr row_arena = std::make_shared<OracleRowArena>();
    size_t kept_arena_bytes = 0;
    size_t resume_offset = 0;
    size_t kept_rows = 0;
    size_t kept_batch_bytes = 0;
    bool kept_row_header_selection = false;
    bool kept_row_continuation = false;
};

// Zero-length ordinary CLOB can omit charset metadata (owned JDBC capture).
// No character decoding is needed; any nonempty prefix still fails below.
inline std::optional<OracleLobPrefetch> DecodeCursorLobPrefetchCell(ByteReader &reader, bool character,
                                                                 uint32_t requested_units,
                                                                 size_t content_budget,
                                                                 uint16_t national_charset = 0) {
    if (requested_units > 32768 || content_budget == 0) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "invalid LOB prefetch decoder bounds");
    }
    const auto locator_size = reader.ReadUB4();
    if (locator_size == 0) { return std::nullopt; }
    if (locator_size > 4096) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "LOB prefetch locator exceeds bounds");
    }
    OracleLobPrefetch result;
    result.character = character;
    result.total_units = reader.ReadUB8();
    const auto width = character ? 2U : 1U;
    if (result.total_units > content_budget / width) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "LOB prefetch length exceeds content budget");
    }
    reader.ReadUB4(); // chunk size is metadata, not an allocation request
    if (requested_units != 0) {
        if (character) {
            const auto has_charset = reader.ReadByte();
            if (has_charset > 1) {
                throw ProtocolError(ProtocolErrorKind::MALFORMED, "invalid LOB prefetch charset flag");
            }
            const auto charset = has_charset ? reader.ReadUB2() : national_charset;
            const auto form = reader.ReadByte();
            const bool empty_without_charset = !has_charset && form == 1 && result.total_units == 0;
            if (!empty_without_charset && (charset != 2000 || (form != 1 && form != 2) || (!has_charset && form != 2))) {
                throw ProtocolError(ProtocolErrorKind::UNSUPPORTED, "LOB prefetch charset is not verified UTF-16BE");
            }
        }
        auto prefix = reader.ReadLengthPrefixed(static_cast<size_t>(requested_units) * width);
        if (prefix) { result.prefix = std::move(*prefix); }
        if (result.prefix.size() % width != 0) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "LOB prefetch has an incomplete UTF-16 unit");
        }
        result.prefix_units = result.prefix.size() / width;
        if (result.prefix_units > result.total_units) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "LOB prefetch exceeds its reported length");
        }
    }
    auto locator = reader.ReadLengthPrefixed(locator_size);
    if (!locator || locator->size() != locator_size) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "LOB prefetch locator length mismatch");
    }
    result.locator = std::move(*locator);
    return result;
}

inline std::optional<OracleLobPrefetch> DecodeStoredLobPrefetch(OracleByteView cell, bool character,
                                                                const OracleLobPrefetchLimits &limits) {
    if (cell.size() > limits.maximum_row_bytes) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED,"stored LOB prefetch cell exceeds row budget");
    }
    ByteReader reader(cell.data(), cell.size());
    auto value=DecodeCursorLobPrefetchCell(reader,character,limits.prefix_units,limits.maximum_content_bytes);
    if (!value || reader.Remaining() != 0) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED,"stored LOB prefetch cell is not one non-NULL value");
    }
    return value;
}

inline std::optional<OracleLobPrefetch> DecodeStoredLobPrefetch(const std::vector<uint8_t> &cell, bool character,
                                                                const OracleLobPrefetchLimits &limits) {
    return DecodeStoredLobPrefetch(OracleByteView(cell), character, limits);
}

} // namespace oracle_scanner
