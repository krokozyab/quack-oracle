#pragma once

#include "oracle_scanner/ttc_channel.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace oracle_scanner {

constexpr uint8_t TTC_MESSAGE_PROTOCOL = 1;
constexpr uint8_t TTC_MESSAGE_DATA_TYPES = 2;
constexpr uint16_t ORACLE_CHARSET_AL32UTF8 = 873;
// Index of TNS_CCAP_FIELD_VERSION in a TTC capability vector, and the value
// this client advertises in its TTIDTY request. The bundled 19c template
// carries 12 at that index, and every decoder gate has to agree with what was
// actually offered rather than with a literal written at the call site.
constexpr size_t TTC_CAPABILITY_FIELD_VERSION_INDEX = 7;
constexpr uint8_t ORACLE_CLIENT_TTC_FIELD_VERSION = 12;

struct TtcProtocolInfo {
    uint8_t server_version = 0;
    // The lower of what this client advertised and what the server reported,
    // which is the shape both sides then speak for the request-driven parts of
    // the protocol. Live values: Oracle 19c reports 12, Free 23ai and OCI
    // Autonomous report 27, so all three negotiate to this client's 12.
    uint8_t field_version = ORACLE_CLIENT_TTC_FIELD_VERSION;
    // What the server reported, before that minimum is taken. Some parts of a
    // response are shaped by this rather than by the negotiated value — the
    // end-of-call trailer is one, see TTC_FIELD_VERSION_ERROR_TRAILER.
    uint8_t server_field_version = ORACLE_CLIENT_TTC_FIELD_VERSION;
    std::string server_banner;
    uint16_t charset_id = 0;
    uint8_t server_flags = 0;
    std::vector<uint8_t> compile_capabilities;
    std::vector<uint8_t> runtime_capabilities;
};

struct TtcNegotiationOptions {
    uint8_t ttc_version = 6;
    // The bundled TTIDTY table was captured from this Thin client profile.
    // Keep TTIPRO aligned with it: Oracle uses the pair when selecting some
    // version-dependent session behavior.
    std::string driver_name = "python-oracledb";
    std::vector<uint8_t> compile_capabilities;
    std::vector<uint8_t> runtime_capabilities;
};

std::vector<uint8_t> BuildTtcProtocolRequest(const TtcNegotiationOptions &options = {});
TtcProtocolInfo ParseTtcProtocolResponse(const std::vector<uint8_t> &message);
std::vector<uint8_t> BuildTtcDataTypesRequest(const TtcNegotiationOptions &options = {});
void ValidateTtcDataTypesResponse(const std::vector<uint8_t> &message);
TtcProtocolInfo RunTtcNegotiation(TtcChannel &channel, const TtcNegotiationOptions &options = {});

} // namespace oracle_scanner
