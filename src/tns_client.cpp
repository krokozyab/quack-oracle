#include "oracle_scanner/tns_client.hpp"
#include "oracle_scanner/auth_crypto.hpp"
#include "oracle_scanner/client_identity.hpp"
#include "oracle_scanner/descriptor_parser.hpp"
#include "oracle_scanner/protocol_error.hpp"
#include "oracle_scanner/transport_factory.hpp"

#include <string>
#include <utility>

namespace oracle_scanner {

namespace {

void RunCheckOobProbe(ByteStream &stream, uint16_t negotiated_sdu) {
    stream.SendUrgent(0x21);
    TnsPacketStream packets(stream, true, negotiated_sdu);
    // Current Thin clients use the reset-form marker to finish the OOB
    // check. The listener's CONTROL response is only meaningful after this
    // exact marker shape.
    packets.Send({TnsPacketType::MARKER, 0, {0x01, 0x00, 0x02}});
    const auto reply = packets.Receive();
    // The two-byte CONTROL body is listener-version dependent (19c emits a
    // different value than newer Free builds); it is an acknowledgement, not
    // a negotiated value. Its exact width and framing are the contract.
    if (reply.type != TnsPacketType::CONTROL || reply.flags != 0x20 || reply.payload.size() != 2) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED,
                            "Oracle CHECK_OOB probe returned invalid CONTROL reply (type " +
                                std::to_string(static_cast<uint8_t>(reply.type)) + ", flags " +
                                std::to_string(reply.flags) + ", payload bytes " + std::to_string(reply.payload.size()) + ")");
    }
}

} // namespace

TnsClientConnection::TnsClientConnection(std::unique_ptr<ByteStream> stream_p, uint16_t negotiated_sdu_p,
                                         std::string connect_descriptor_p, std::string auth_connect_string_p,
                                         OracleClientIdentity client_identity_p, bool cancellation_supported,
                                         bool end_of_response_negotiated_p)
    : stream(std::move(stream_p)), packets(std::make_unique<TnsPacketStream>(*stream, true, negotiated_sdu_p)),
      ttc(std::make_unique<TtcChannel>(*packets, negotiated_sdu_p, 16U << 20U, cancellation_supported)),
      negotiated_sdu(negotiated_sdu_p), end_of_response_negotiated(end_of_response_negotiated_p),
      connect_descriptor(std::move(connect_descriptor_p)), auth_connect_string(std::move(auth_connect_string_p)),
      client_identity(std::move(client_identity_p)) {
}

TnsClientConnection::~TnsClientConnection() {
    Close();
}

std::unique_ptr<TnsClientConnection> TnsClientConnection::Connect(const ConnectionConfig &config,
                                                                   const TlsConfiguration &tls) {
    ValidateConnectionConfig(config);
    auto effective_config = config;
    if (effective_config.connection_id.empty()) {
        effective_config.connection_id = Base64Encode(SecureRandomBytes(16));
    }
    if (effective_config.client_program.empty()) {
        effective_config.client_program = CurrentExecutablePath();
    }
    std::string descriptor = BuildConnectDescriptor(effective_config);
    std::string host = config.host;
    uint16_t port = config.port;
    auto protocol = config.protocol;

    for (size_t redirects = 0; redirects <= 3; redirects++) {
        auto stream = OpenOracleTransport(host, port, config.connect_timeout_seconds, config.read_timeout_seconds,
                                          protocol == TransportProtocol::TCPS, tls);
        TnsPacketStream handshake_packets(*stream, false);
        TnsConnectOptions connect_options;
        connect_options.supports_oob = protocol != TransportProtocol::TCPS;
        auto result = RunTnsConnect(handshake_packets, descriptor, connect_options);
        if (result.disposition == TnsConnectDisposition::ACCEPTED) {
            if (result.check_oob) {
                RunCheckOobProbe(*stream, result.negotiated_sdu);
            }
            return std::unique_ptr<TnsClientConnection>(
                new TnsClientConnection(std::move(stream), result.negotiated_sdu, descriptor,
                                        BuildAuthConnectString(effective_config),
                                        CurrentOracleClientIdentity(effective_config.client_program),
                                        protocol != TransportProtocol::TCPS, result.end_of_response));
        }
        if (redirects == 3) {
            throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "Oracle listener exceeded redirect limit");
        }
        auto redirected = ParseConnectDescriptor(result.redirect_descriptor);
        // A redirect may carry several addresses. This first implementation
        // chooses the declared first address; failover will be added with TTC
        // session recovery so it cannot replay a non-idempotent operation.
        const auto &endpoint = redirected.endpoints.front();
        host = endpoint.host;
        port = endpoint.port;
        protocol = endpoint.protocol;
        descriptor = result.redirect_descriptor;
    }
    throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "Oracle redirect state is unreachable");
}

TnsPacketStream &TnsClientConnection::Packets() {
    if (!packets) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "Oracle TNS connection is closed");
    }
    return *packets;
}

TtcChannel &TnsClientConnection::Ttc() {
    if (!ttc) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "Oracle TTC connection is closed");
    }
    return *ttc;
}

uint16_t TnsClientConnection::NegotiatedSdu() const {
    return negotiated_sdu;
}

uint8_t TnsClientConnection::TtcFieldVersion() const {
    return ttc_field_version;
}

uint8_t TnsClientConnection::TtcServerFieldVersion() const {
    return ttc_server_field_version;
}

bool TnsClientConnection::EndOfResponseNegotiated() const {
    return end_of_response_negotiated;
}

OracleConnectionState TnsClientConnection::State() const {
    return state;
}

TtcProtocolInfo TnsClientConnection::Negotiate(const TtcNegotiationOptions &options) {
    if (state != OracleConnectionState::TRANSPORT_CONNECTED) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "TTC negotiation is not valid in the current connection state");
    }
    auto result = RunTtcNegotiation(Ttc(), options);
    ttc_field_version = result.field_version;
    ttc_server_field_version = result.server_field_version;
    state = OracleConnectionState::TTC_NEGOTIATED;
    return result;
}

O5LogonResponse TnsClientConnection::AuthenticateO5Logon(const std::string &username, const std::string &password,
                                                          uint32_t auth_mode,
                                                          const std::vector<TtcParameter> &phase_one_parameters) {
    if (state != OracleConnectionState::TTC_NEGOTIATED) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "O5LOGON requires completed TTC negotiation");
    }
    O5LogonRequest request;
    request.username = username;
    request.password = password;
    request.auth_mode = auth_mode;
    request.phase_one_parameters = phase_one_parameters;
    if (request.phase_one_parameters.empty()) {
        request.phase_one_parameters = {{"AUTH_TERMINAL", client_identity.terminal, 0},
                                        {"AUTH_PROGRAM_NM", client_identity.program, 0},
                                        {"AUTH_MACHINE", client_identity.machine, 0},
                                        {"AUTH_PID", client_identity.process_id, 0},
                                        {"AUTH_SID", client_identity.os_user, 0}};
    }
    request.phase_two_parameters = {{"SESSION_CLIENT_CHARSET", "873", 0},
                                    {"SESSION_CLIENT_DRIVER_NAME", "python-oracledb thn : 4.0.1", 0},
                                    // Oracle's authentication parser retains the NUL terminator as part of this value.
                                    {"SESSION_CLIENT_VERSION", "67112960", 0},
                                    {"AUTH_ALTER_SESSION",
                                     std::string("ALTER SESSION SET TIME_ZONE='+04:00'\0",
                                                 sizeof("ALTER SESSION SET TIME_ZONE='+04:00'\0") - 1),
                                     1},
                                    {"AUTH_CONNECT_STRING", auth_connect_string, 0}};
    request.client_session_key = SecureRandomBytes(32);
    request.password_salt = SecureRandomBytes(16);
    request.speedy_key_salt = SecureRandomBytes(16);
    auto result = RunO5Logon(Ttc(), request);
    state = OracleConnectionState::AUTHENTICATED;
    return result;
}

void TnsClientConnection::Close() {
    ttc.reset();
    packets.reset();
    if (stream) {
        stream->Close();
        stream.reset();
    }
    state = OracleConnectionState::CLOSED;
}

} // namespace oracle_scanner
