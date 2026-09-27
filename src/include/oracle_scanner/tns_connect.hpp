#pragma once

#include "oracle_scanner/tns_packet.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace oracle_scanner {

constexpr uint8_t TNS_PACKET_FLAG_REDIRECT = 0x04;

struct TnsConnectOptions {
    uint16_t desired_version = 319;
    uint16_t minimum_version = 300;
    uint16_t requested_sdu = 8192;
    uint16_t requested_tdu = 8192;
    // TCPS cannot carry Oracle Net's TCP urgent-byte OOB probe.
    bool supports_oob = true;
    // The CONNECT packet's header flags. Zero for a first contact; a CONNECT
    // that follows a listener REDIRECT carries TNS_PACKET_FLAG_REDIRECT, which
    // is what both python-oracledb Thin (connection.pyx) and go-ora
    // (connect_packet.go) send. Only the CONNECT packet carries it: a DATA
    // continuation with long connect data keeps flags zero, as in both.
    uint8_t packet_flags = 0;
};

// Builds the pre-negotiation CONNECT exchange. CONNECT and any connect-data
// DATA continuation use legacy TNS lengths.
std::vector<TnsPacket> BuildTnsConnectPackets(const std::string &descriptor,
                                              const TnsConnectOptions &options = {});

} // namespace oracle_scanner
