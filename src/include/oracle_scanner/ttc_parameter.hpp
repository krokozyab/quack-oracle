#pragma once

#include "oracle_scanner/auth_crypto.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace oracle_scanner {

constexpr uint8_t TTC_MESSAGE_PARAMETER = 8;

struct TtcParameter {
    std::string key;
    std::string value;
    uint32_t flags = 0;
};

struct TtcReturnParameterPrefix {
    size_t bytes_consumed = 0;
};

std::vector<uint8_t> EncodeTtcParameters(const std::vector<TtcParameter> &parameters);
std::vector<TtcParameter> DecodeTtcParameters(const std::vector<uint8_t> &message);
// Drains the execute-response RETURN_PARAMETER body (message type 8). It is
// distinct from the authentication key/value PARAMETER grammar above.
TtcReturnParameterPrefix DecodeTtcReturnParameterPrefix(const std::vector<uint8_t> &message);
O5LogonChallenge O5LogonChallengeFromParameters(const std::vector<TtcParameter> &parameters);

} // namespace oracle_scanner
