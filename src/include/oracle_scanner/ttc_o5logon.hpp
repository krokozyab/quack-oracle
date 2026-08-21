#pragma once

#include "oracle_scanner/ttc_auth.hpp"
#include "oracle_scanner/ttc_channel.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace oracle_scanner {

struct O5LogonRequest {
    std::string username;
    std::string password;
    uint32_t auth_mode = 0;
    std::vector<TtcParameter> phase_one_parameters;
    std::vector<TtcParameter> phase_two_parameters;
    std::vector<uint8_t> client_session_key;
    std::vector<uint8_t> password_salt;
    std::vector<uint8_t> speedy_key_salt;
};

// Performs the TTC parameter exchange for the 12c verifier. The caller must
// run TNS and TTC negotiation first and provide fresh 32/16-byte randomness.
O5LogonResponse RunO5Logon(TtcChannel &channel, const O5LogonRequest &request);

} // namespace oracle_scanner
