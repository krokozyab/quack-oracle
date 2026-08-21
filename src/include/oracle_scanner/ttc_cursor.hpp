#pragma once

#include "oracle_scanner/session.hpp"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace oracle_scanner {

struct TtcRefCursorDescriptor {
    uint32_t cursor_id = 0;
    std::vector<OracleColumn> columns;
    size_t bytes_consumed = 0;
};

constexpr uint8_t TTC_MESSAGE_IMPLICIT_RESULT_SET = 27;

struct TtcImplicitResultSet {
    std::vector<TtcRefCursorDescriptor> cursors;
    size_t bytes_consumed = 0;
};

// Decodes the embedded describe that follows an OUT SYS_REFCURSOR ROW_DATA
// marker and its trailing server cursor id. The input begins at the embedded
// describe's max-row-size field, not at TTC_MESSAGE_ROW_DATA.
TtcRefCursorDescriptor DecodeTtcRefCursorDescriptor(const std::vector<uint8_t> &message, uint8_t ttc_field_version = 12);

// Decodes one DBMS_SQL.RETURN_RESULT TTC message. Oracle prefixes every
// embedded cursor describe with an opaque per-result byte block; it is
// consumed but intentionally not interpreted here.
TtcImplicitResultSet DecodeTtcImplicitResultSet(const std::vector<uint8_t> &message,
                                                 uint8_t ttc_field_version = 12);
TtcImplicitResultSet DecodeTtcImplicitResultSetPrefix(const std::vector<uint8_t> &message,
                                                       uint8_t ttc_field_version = 12);

} // namespace oracle_scanner
