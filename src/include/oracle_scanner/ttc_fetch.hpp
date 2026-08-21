#pragma once

#include <cstdint>
#include <vector>

namespace oracle_scanner {

constexpr uint8_t TTC_FUNCTION_FETCH = 5;

// OFETCH is a self-contained TTC function call used after an initial query
// prefetch. Row decoding remains separate and is deliberately not inferred
// from this request message.
struct TtcFetchRequest {
    uint8_t sequence = 0;
    uint32_t cursor_id = 0;
    uint32_t requested_rows = 0;
};

std::vector<uint8_t> EncodeTtcFetchRequest(const TtcFetchRequest &request);
TtcFetchRequest DecodeTtcFetchRequest(const std::vector<uint8_t> &message);

} // namespace oracle_scanner
