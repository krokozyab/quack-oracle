#pragma once

#include "oracle_scanner/byte_stream.hpp"
#include "oracle_scanner/tns_connect.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace oracle_scanner {

enum class TnsConnectDisposition { ACCEPTED, REDIRECTED };

// The ACCEPT protocol version below which a server cannot offer a
// transport-level end of response, and the flags2 bit that offers it. A legacy
// 19c profile answers 318 with neither, so its data responses carry no
// END_OF_RESPONSE and only the TTC decoder can delimit them.
constexpr uint16_t TNS_VERSION_MIN_END_OF_RESPONSE = 319;
constexpr uint32_t TNS_ACCEPT_FLAG_HAS_END_OF_RESPONSE = 0x02000000;

// A REDIRECT packet's header flag saying the redirect data carries reconnect
// data after a NUL. go-ora (network/session.go) splits on the NUL only when
// this bit is set; python-oracledb Thin (connection.pyx) always expects the
// NUL. This client splits whenever the NUL is present and treats the bit as a
// promise that it is: flagged data without a NUL is malformed.
constexpr uint8_t TNS_REDIRECT_FLAG_HAS_RECONNECT_DATA = 0x02;

// Bounds on the redirect data a listener may send. The length is a UB2, so it
// is already bounded by 65535; the continuation count bounds how many DATA
// packets the client reads to assemble it.
constexpr size_t TNS_MAX_REDIRECT_CONTINUATIONS = 16;

// The redirect data split into the two things it carries. Neither has been
// parsed as a descriptor yet: that is the connect loop's business, and it is
// kept apart so the byte-level rules can be tested on their own.
struct TnsRedirect {
    // Where to go next: a (DESCRIPTION=...), (ADDRESS_LIST=...) or
    // (ADDRESS=...) as the listener wrote it, surrounding whitespace removed.
    std::string address;
    // What to send as the next CONNECT's connect data, verbatim, when the
    // listener supplied it. Empty means it did not, and the client rebuilds the
    // connect data for the new address from its own logical service.
    std::string reconnect_data;
};

struct TnsConnectResult {
    TnsConnectDisposition disposition = TnsConnectDisposition::ACCEPTED;
    uint16_t negotiated_sdu = 0;
    bool check_oob = false;
    uint16_t accept_version = 0;
    // Whether the server offered a transport-level end of response.
    bool end_of_response = false;
    TnsRedirect redirect;
};

// What a REFUSE packet said. The ORA- code is taken from the listener's
// (ERR=NNNNN) element, which is where both go-ora (refuse_packet.go) and
// python-oracledb (connect.pyx) look for it.
struct TnsRefusal {
    uint8_t user_reason = 0;
    uint8_t system_reason = 0;
    uint32_t oracle_error = 0;
    // The printable part of the listener's text, bounded.
    std::string message;
};

// Splits assembled redirect data into address and reconnect data. `flags` is
// the REDIRECT packet's header flags byte.
TnsRedirect ParseTnsRedirectData(const std::vector<uint8_t> &data, uint8_t flags);

// Reads what a REFUSE payload carries. It never throws on a short or
// inconsistent payload: the connection is being refused either way, and
// whatever can be read is only diagnostics.
TnsRefusal ParseTnsRefusal(const std::vector<uint8_t> &payload);

// Runs only the CONNECT/ACCEPT/REFUSE/REDIRECT exchange. TTC negotiation and
// authentication begin only after an ACCEPT result is returned. A REFUSE is
// thrown as an OracleConnectError with ConnectFailure::LISTENER_REFUSED; a
// transport that fails mid-exchange as ConnectFailure::TRANSPORT_LOST.
TnsConnectResult RunTnsConnect(TnsPacketStream &stream, const std::string &descriptor,
                               const TnsConnectOptions &options = {});

} // namespace oracle_scanner
