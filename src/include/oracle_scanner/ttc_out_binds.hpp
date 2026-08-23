#pragma once

#include "oracle_scanner/session.hpp"
#include "oracle_scanner/ttc_cursor.hpp"
#include "oracle_scanner/ttc_io_vector.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace oracle_scanner {

struct TtcOutBindsResult {
    std::vector<std::optional<std::vector<uint8_t>>> scalar_values;
    std::vector<std::optional<TtcRefCursorDescriptor>> cursor_values;
    size_t bytes_consumed = 0;
};

// Decodes one PL/SQL OUT-bind ROW_DATA message. `output_indexes` is the
// server-validated order returned by GetTtcOutputBindIndexes(). Each value is
// followed by the Oracle SB4 actual-length field and the returned byte count
// permits the caller to continue with a subsequent TTC message.
TtcOutBindsResult DecodeTtcOutBindsRow(const std::vector<uint8_t> &message, const std::vector<OracleBind> &binds,
                                       const std::vector<size_t> &output_indexes, uint8_t ttc_field_version = 12);

struct TtcPlsqlOutBindsResponse {
    TtcIoVector io_vector;
    std::vector<size_t> output_indexes;
    TtcOutBindsResult values;
    size_t bytes_consumed = 0;
};

// Decodes the leading PL/SQL execution response sequence: IO_VECTOR followed
// by ROW_DATA for its OUT and IN OUT binds. Any later TTC messages (status,
// warnings, or additional result data) deliberately remain unconsumed.
TtcPlsqlOutBindsResponse DecodeTtcPlsqlOutBindsResponse(const std::vector<uint8_t> &message,
                                                         const std::vector<OracleBind> &binds,
                                                         uint8_t ttc_field_version = 12);

} // namespace oracle_scanner
