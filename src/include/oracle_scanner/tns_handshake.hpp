#pragma once

#include "oracle_scanner/byte_stream.hpp"
#include "oracle_scanner/tns_connect.hpp"

#include <cstdint>
#include <string>

namespace oracle_scanner {

enum class TnsConnectDisposition { ACCEPTED, REDIRECTED };

// The ACCEPT protocol version below which a server cannot offer a
// transport-level end of response, and the flags2 bit that offers it. A legacy
// 19c profile answers 318 with neither, so its data responses carry no
// END_OF_RESPONSE and only the TTC decoder can delimit them.
constexpr uint16_t TNS_VERSION_MIN_END_OF_RESPONSE = 319;
constexpr uint32_t TNS_ACCEPT_FLAG_HAS_END_OF_RESPONSE = 0x02000000;

struct TnsConnectResult {
    TnsConnectDisposition disposition = TnsConnectDisposition::ACCEPTED;
    uint16_t negotiated_sdu = 0;
    bool check_oob = false;
    uint16_t accept_version = 0;
    // Whether the server offered a transport-level end of response.
    bool end_of_response = false;
    std::string redirect_descriptor;
};

// Runs only the CONNECT/ACCEPT/REFUSE/REDIRECT exchange. TTC negotiation and
// authentication begin only after an ACCEPT result is returned.
TnsConnectResult RunTnsConnect(TnsPacketStream &stream, const std::string &descriptor,
                               const TnsConnectOptions &options = {});

} // namespace oracle_scanner
