#pragma once

// The row-shape messages both fetch decoders read the same way: ROW_HEADER and
// ROW_CONTINUATION, which say which columns a row carries, and the expansion of
// a row's wire values back to its described columns. One copy, so a fix to how
// 19c or 23ai frames a row reaches the ordinary and the LOB-prefetch fetch alike.

#include "oracle_scanner/session.hpp"
#include "oracle_scanner/ttc_row_data.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace oracle_scanner {

struct TtcRowHeaderPrefix {
    std::optional<std::vector<size_t>> present_columns;
    size_t bytes_consumed = 0;
};

struct TtcRowContinuationPrefix {
    std::vector<size_t> present_columns;
    size_t bytes_consumed = 0;
};

std::vector<uint8_t> Tail(const std::vector<uint8_t> &message, size_t offset);
TtcRowHeaderPrefix DecodeRowHeaderPrefix(const uint8_t *data, size_t size, size_t column_count);
// `reuse` lends a vector whose capacity the decoded column list may take over.
TtcRowContinuationPrefix DecodeRowContinuationPrefix(const uint8_t *data, size_t size, size_t column_count,
                                                     std::vector<size_t> *reuse = nullptr);
TtcRowData MergeChangedColumns(const TtcRowData &previous_row, const std::vector<size_t> &present_columns,
                               const TtcRowData &values, size_t column_count);
std::vector<size_t> WireCarryingColumns(const std::vector<OracleColumn> &columns,
                                        const std::optional<std::vector<size_t>> &selected_columns);
TtcRowData ExpandWireRow(size_t column_count, const std::vector<size_t> &wire_columns, TtcRowData values);

} // namespace oracle_scanner
