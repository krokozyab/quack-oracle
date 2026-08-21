#pragma once

#include "oracle_scanner/session.hpp"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace oracle_scanner {

struct TtcDescribeInfo {
    std::vector<OracleColumn> columns;
    size_t bytes_consumed = 0;
};

// Decodes one DESCRIBE_INFO (type 16) prefix. The input may contain later TTC
// messages; bytes_consumed identifies the first byte after its descriptor.
TtcDescribeInfo DecodeTtcDescribeInfoPrefix(const std::vector<uint8_t> &message,
                                            uint8_t ttc_field_version = 12);

} // namespace oracle_scanner
