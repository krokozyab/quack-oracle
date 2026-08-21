#pragma once

#include "oracle_scanner/tns_packet.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace oracle_scanner {

struct TnsConnectOptions {
    uint16_t desired_version = 319;
    uint16_t minimum_version = 300;
    uint16_t requested_sdu = 8192;
    uint16_t requested_tdu = 8192;
    // TCPS cannot carry Oracle Net's TCP urgent-byte OOB probe.
    bool supports_oob = true;
};

// Builds the pre-negotiation CONNECT exchange. CONNECT and any connect-data
// DATA continuation use legacy TNS lengths.
std::vector<TnsPacket> BuildTnsConnectPackets(const std::string &descriptor,
                                              const TnsConnectOptions &options = {});

} // namespace oracle_scanner
