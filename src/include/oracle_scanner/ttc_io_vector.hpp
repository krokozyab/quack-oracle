#pragma once

#include "oracle_scanner/session.hpp"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace oracle_scanner {

constexpr uint8_t TTC_MESSAGE_IO_VECTOR = 11;
constexpr uint8_t TTC_BIND_DIRECTION_IN = 16;
constexpr uint8_t TTC_BIND_DIRECTION_OUT = 32;
constexpr uint8_t TTC_BIND_DIRECTION_IN_OUT = 48;

struct TtcIoVector {
    uint32_t iteration_count = 0;
    std::vector<uint8_t> directions;
    size_t bytes_consumed = 0;
};

// Decodes an IO_VECTOR at the beginning of a TTC response and leaves any
// following response messages for the caller.  Use DecodeTtcIoVector() when
// the supplied buffer is required to contain exactly one IO_VECTOR.
TtcIoVector DecodeTtcIoVectorPrefix(const std::vector<uint8_t> &message);
TtcIoVector DecodeTtcIoVector(const std::vector<uint8_t> &message);
std::vector<size_t> GetTtcOutputBindIndexes(const TtcIoVector &io_vector, const std::vector<OracleBind> &binds);

} // namespace oracle_scanner
