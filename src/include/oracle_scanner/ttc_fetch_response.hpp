#pragma once

#include "oracle_scanner/session.hpp"
#include "oracle_scanner/ttc_error.hpp"
#include "oracle_scanner/ttc_row_data.hpp"

#include <cstddef>
#include <optional>
#include <vector>

namespace oracle_scanner {

struct TtcFetchResponse {
    std::vector<TtcRowData> rows;
    std::optional<TtcRowData> last_row;
    std::optional<TtcErrorInfo> completion;
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

} // namespace oracle_scanner
