#pragma once

#include "oracle_scanner/session.hpp"
#include "oracle_scanner/ttc_error.hpp"
#include "oracle_scanner/ttc_row_data.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace oracle_scanner {

struct TtcExecuteResponse {
    std::vector<OracleColumn> columns;
    std::vector<TtcRowData> rows;
    std::optional<TtcErrorInfo> completion;
    bool exhausted = false;
    bool completed = false;
    size_t bytes_consumed = 0;
};

// Decodes a query-shaped OALL8 response: DESCRIBE_INFO followed by row/fetch
// messages and its TTIOER completion. The completion cursor_id is the server
// cursor to use for OFETCH.
TtcExecuteResponse DecodeTtcExecuteResponse(const std::vector<uint8_t> &message, uint8_t ttc_field_version = 12,
                                            uint8_t server_field_version = 12);

// Non-query OALL8 calls finish directly with TTIOER. Its wire-level message
// type is ERROR even when its extended error number is zero, so callers must
// decode it before deciding whether the execution failed.
TtcErrorInfo DecodeTtcExecuteCompletion(const std::vector<uint8_t> &message,
                                        uint8_t ttc_field_version = 12);

} // namespace oracle_scanner
