#pragma once

#include "oracle_scanner/byte_stream.hpp"
#include "oracle_scanner/client_identity.hpp"
#include "oracle_scanner/connect_descriptor.hpp"
#include "oracle_scanner/tns_handshake.hpp"
#include "oracle_scanner/ttc_channel.hpp"
#include "oracle_scanner/ttc_negotiation.hpp"
#include "oracle_scanner/ttc_o5logon.hpp"

#include <cstdint>
#include <memory>

namespace oracle_scanner {

enum class OracleConnectionState { TRANSPORT_CONNECTED, TTC_NEGOTIATED, AUTHENTICATED, CLOSED };

// Owns one accepted TNS transport and enforces the TTC bootstrap order. It
// does not expose a usable authenticated session until both negotiation and
// the server proof in O5LOGON have completed.
class TnsClientConnection {
public:
    static std::unique_ptr<TnsClientConnection> Connect(const ConnectionConfig &config,
                                                        const TlsConfiguration &tls = {});
    ~TnsClientConnection();

    TnsClientConnection(const TnsClientConnection &) = delete;
    TnsClientConnection &operator=(const TnsClientConnection &) = delete;

    TnsPacketStream &Packets();
    TtcChannel &Ttc();
    uint16_t NegotiatedSdu() const;
    // The TTC field version both sides speak, available after Negotiate. Every
    // response decoder has to be given this rather than a literal.
    uint8_t TtcFieldVersion() const;
    // What the server reported, which shapes the parts of a response it does
    // not adapt to the negotiated value.
    uint8_t TtcServerFieldVersion() const;
    // Whether the server offered a transport-level end of response. Without it
    // only the TTC decoder can tell where a response ends.
    bool EndOfResponseNegotiated() const;
    OracleConnectionState State() const;
    TtcProtocolInfo Negotiate(const TtcNegotiationOptions &options = {});
    O5LogonResponse AuthenticateO5Logon(const std::string &username, const std::string &password,
                                        uint32_t auth_mode = 1,
                                        const std::vector<TtcParameter> &phase_one_parameters = {});
    void Close();

private:
    TnsClientConnection(std::unique_ptr<ByteStream> stream, uint16_t negotiated_sdu, std::string connect_descriptor,
                        std::string auth_connect_string, OracleClientIdentity client_identity, bool cancellation_supported,
                        bool end_of_response_negotiated);

    std::unique_ptr<ByteStream> stream;
    std::unique_ptr<TnsPacketStream> packets;
    std::unique_ptr<TtcChannel> ttc;
    uint16_t negotiated_sdu;
    uint8_t ttc_field_version = ORACLE_CLIENT_TTC_FIELD_VERSION;
    uint8_t ttc_server_field_version = ORACLE_CLIENT_TTC_FIELD_VERSION;
    bool end_of_response_negotiated = false;
    std::string connect_descriptor;
    std::string auth_connect_string;
    OracleClientIdentity client_identity;
    OracleConnectionState state = OracleConnectionState::TRANSPORT_CONNECTED;
};

} // namespace oracle_scanner
