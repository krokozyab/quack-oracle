#pragma once

#include "oracle_scanner/session.hpp"
#include "oracle_scanner/ttc_cursor.hpp"
#include "oracle_scanner/ttc_error.hpp"
#include "oracle_scanner/ttc_out_binds.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace oracle_scanner {

// Projection of one complete PL/SQL execute response. Explicit cursor OUT
// binds are held in out_binds; DBMS_SQL.RETURN_RESULT cursors are distinct in
// implicit_cursors and retain their own server cursor ids and describes.
struct TtcCallResponse {
    std::optional<TtcOutBindsResult> out_binds;
    std::vector<TtcRefCursorDescriptor> implicit_cursors;
    std::optional<TtcErrorInfo> completion;
    bool completed = false;
    size_t bytes_consumed = 0;
};

TtcCallResponse DecodeTtcCallResponse(const std::vector<uint8_t> &message, const std::vector<OracleBind> &binds,
                                      uint8_t ttc_field_version = 12, uint8_t server_field_version = 12);

} // namespace oracle_scanner
