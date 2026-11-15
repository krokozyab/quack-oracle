#pragma once

#include "oracle_scanner/session.hpp"
#include "oracle_scanner/ttc_error.hpp"
#include "oracle_scanner/ttc_row_data.hpp"

#include <cstddef>
#include <cstdint>
#include <exception>
#include <optional>
#include <vector>
#include <utility>

namespace oracle_scanner {

// A fully decoded reexecute failure before any row. Only this condition can
// request a fresh parse; ordinary fetches and partially delivered results cannot.
class TtcQueryInvalidated final : public ProtocolError {
public:
    explicit TtcQueryInvalidated(const TtcErrorInfo &completion)
        : ProtocolError(ProtocolErrorKind::INVALID_STATE, completion.message, completion.error_number),
          cursor_id(completion.cursor_id) {}
    uint32_t CursorId() const { return cursor_id; }
private:
    uint32_t cursor_id;
};

// Keep value-conversion failures distinct from incomplete wire framing. In
// particular, a sink's TRUNCATED must never request another network fragment.
class TtcRowSinkError final : public std::exception {
public:
    explicit TtcRowSinkError(std::exception_ptr cause) : cause(std::move(cause)) {
    }
    const char *what() const noexcept override {
        return "Oracle row sink failed";
    }
    [[noreturn]] void Rethrow() const {
        std::rethrow_exception(cause);
    }

private:
    std::exception_ptr cause;
};

struct TtcFetchResponse {
    std::vector<TtcRowData> rows;
    std::optional<OraclePackedBatch> packed;
    std::optional<TtcRowData> last_row;
    std::optional<TtcErrorInfo> completion;
    size_t direct_rows = 0;
    bool exhausted = false;
    bool completed = false;
    bool used_row_header_selection = false;
    bool used_row_continuation = false;
    size_t bytes_consumed = 0;
};

// Decodes a response for a previously described cursor, including the captured
// 0x15 continuation forms (legacy little-endian and compact TTC-UB2 counts)
// and the row-header selection form. Each supplies only values changed from
// the preceding row. A caller fetching a cursor across responses must pass the
// previous response's last row.
TtcFetchResponse DecodeTtcFetchResponse(const std::vector<uint8_t> &message, const std::vector<OracleColumn> &columns,
                                        uint8_t ttc_field_version = 12,
                                        const std::optional<TtcRowData> &preceding_row = std::nullopt);

// Decodes one fetch response as it arrives in DATA fragments, without decoding
// any row twice. Each call to Decode is given the whole response received so
// far, which must begin with what the previous call was given. A row is kept
// once it has been decoded completely, and the next call starts after the last
// kept row, so only part of one row and the few bytes that end a response are
// ever read again. Decoding is strictly left to right and nothing a row
// decodes to depends on the bytes after it, which is what makes the result the
// same as one DecodeTtcFetchResponse over the joined response.
//
// The columns are held by reference and must outlive the decoder.
class TtcFetchResponseDecoder {
public:
    TtcFetchResponseDecoder(const std::vector<OracleColumn> &columns, uint8_t ttc_field_version,
                            const std::optional<TtcRowData> &preceding_row, bool packed_scalars = false,
                            size_t reserve_rows = 0, OracleRowSink *sink = nullptr, bool allow_reparse = false);
    // A nonzero reserve_rows is also the requested response row limit.

    // True once the response is complete. Throws TRUNCATED, as
    // DecodeTtcFetchResponse does, when the bytes end inside a message, and
    // leaves every row kept so far in place for the next call.
    bool Decode(const std::vector<uint8_t> &message);
    TtcFetchResponse Take();

private:
    // The row a continuation would change: the last decoded row, or the one
    // that preceded this response, or null when there is neither. It points
    // into the decoded rows, so it is valid only until the next row is added.
    const TtcRowData *PreviousRow() const;
    bool DecodeInternal(const std::vector<uint8_t> &message);

    // Zero requests another fragment for an incomplete short scalar row.
    // No row reaches the sink until all selected cells have been read.
    size_t DecodeDirectRow(const std::vector<uint8_t> &message, size_t offset, const std::vector<size_t> &selected,
                           bool continued);
    void RefreshDirectViews();
    struct CellLocation {
        enum Kind { NULL_CELL, MESSAGE, SEED, CHUNKED } kind = NULL_CELL;
        size_t offset = 0;
        size_t size = 0;
    };
    OracleRowSink *sink;
    const std::vector<uint8_t> *direct_message = nullptr;
    std::vector<size_t> direct_selection;
    std::vector<CellLocation> locations;
    std::vector<std::vector<uint8_t>> chunked_cells;
    std::vector<std::optional<OracleByteView>> direct_views;
    bool direct_previous = false;
    size_t chunked_capacity = 0;
    const std::vector<OracleColumn> &columns;
    uint8_t ttc_field_version;
    size_t maximum_rows;
    std::optional<TtcRowData> preceding_row;
    // The columns a row without a row header carries, and how each frames its value.
    std::vector<size_t> row_columns;
    std::vector<TtcColumnFraming> row_framing;
    TtcFetchResponse result;
    OracleRowData::ArenaPtr row_arena = std::make_shared<OracleRowArena>();
    size_t kept_arena_bytes = 0;
    // What is kept between calls: the rows decoded before resume_offset, and
    // whether any of them needed a row header or a continuation. Rows after it
    // were decoded with a row header still waiting, and are decoded again.
    size_t resume_offset = 0;
    size_t kept_rows = 0;
    size_t kept_bytes = 0;
    bool packed_seed = false;
    bool kept_row_header_selection = false;
    bool kept_row_continuation = false;
    bool allow_reparse;
};

} // namespace oracle_scanner
