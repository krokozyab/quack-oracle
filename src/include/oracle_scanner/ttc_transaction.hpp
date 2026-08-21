#pragma once

#include <cstdint>
#include <vector>

namespace oracle_scanner {

constexpr uint8_t TTC_FUNCTION_COMMIT = 14;
constexpr uint8_t TTC_FUNCTION_ROLLBACK = 15;
constexpr uint8_t TTC_MESSAGE_STATUS = 9;

struct TtcTransactionStatus {
    uint32_t call_status = 0;
    uint16_t end_to_end_sequence = 0;
};

std::vector<uint8_t> EncodeTtcCommitRequest(uint8_t sequence);
std::vector<uint8_t> EncodeTtcRollbackRequest(uint8_t sequence);
TtcTransactionStatus DecodeTtcTransactionStatus(const std::vector<uint8_t> &message);

} // namespace oracle_scanner
