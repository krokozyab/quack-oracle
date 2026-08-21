#pragma once

#include "oracle_scanner/ttc_parameter.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace oracle_scanner {

constexpr uint8_t TTC_MESSAGE_FUNCTION = 3;
constexpr uint8_t TTC_FUNCTION_AUTH_PHASE_ONE = 118;
constexpr uint8_t TTC_FUNCTION_AUTH_PHASE_TWO = 115;

// Encodes the classic TTC authentication function shape. It is generic so
// phase-one client metadata and phase-two proof parameters use one validator.
std::vector<uint8_t> EncodeTtcAuthFunction(uint8_t function_code, uint8_t sequence, const std::string &username,
                                           uint32_t auth_mode, const std::vector<TtcParameter> &parameters);
std::vector<TtcParameter> BuildO5LogonPhaseTwoParameters(const O5LogonResponse &response);

} // namespace oracle_scanner
