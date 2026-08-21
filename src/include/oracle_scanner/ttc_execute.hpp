#pragma once

#include "oracle_scanner/session.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace oracle_scanner {

constexpr uint8_t TTC_FUNCTION_EXECUTE = 94;
constexpr uint16_t ORACLE_WIRE_TYPE_CURSOR = 102;

// Initial OALL8 request for a fresh, bind-free statement. Its field layout is
// the 12.2+ form used by the bundled Thin negotiation profile. Bind metadata
// is deliberately separate so a procedure OUT/REF CURSOR bind cannot be
// silently encoded as an ordinary scalar.
struct TtcExecuteNoBindsRequest {
    uint8_t sequence = 1;
    // Extra OALL8 option bits. Core PARSE/EXECUTE/FETCH/NOT_PLSQL bits are
    // derived from is_query and are always present for a fresh statement.
    uint32_t options = 0;
    std::string sql;
    uint32_t prefetch_buffer_bytes = 0;
    uint32_t prefetch_rows = 2;
    uint32_t maximum_long_bytes = 0x7fffffff;
    // TTC field version 12 is the 19c Thin-compatible baseline: it includes
    // the 12.2 and extension tail but not the 23.1 token number.
    uint8_t ttc_field_version = 12;
    bool is_query = false;
    bool is_plsql = false;
};

std::vector<uint8_t> EncodeTtcExecuteNoBindsRequest(const TtcExecuteNoBindsRequest &request);

// OALL8 execute with scalar and PL/SQL bind metadata. OracleBind::value must
// already contain its Oracle wire representation (NUMBER, DATE, etc.); value
// conversion remains in value_codec. OUT SYS_REFCURSOR binds are represented
// by ORACLE_WIRE_TYPE_CURSOR and use their special non-null placeholder.
struct TtcExecuteBindsRequest {
    uint8_t sequence = 1;
    std::string sql;
    // Bind metadata for every execution, and the values of the first one.
    std::vector<OracleBind> binds;
    // Array DML: the values of each execution after the first. Oracle runs one
    // statement per iteration from a single parse and a single round trip, so
    // the metadata is written once — sized to the widest value across every
    // iteration — and one ROW_DATA message follows per iteration. Each entry
    // must match `binds` in count, type and direction; only IN binds and only
    // plain SQL DML can be batched this way.
    std::vector<std::vector<OracleBind>> additional_iterations;
    uint32_t prefetch_buffer_bytes = 0;
    uint32_t prefetch_rows = 1;
    uint32_t maximum_long_bytes = 0x7fffffff;
    uint8_t ttc_field_version = 12;
    bool is_query = false;
    bool is_plsql = false;
};

std::vector<uint8_t> EncodeTtcExecuteBindsRequest(const TtcExecuteBindsRequest &request);

} // namespace oracle_scanner
