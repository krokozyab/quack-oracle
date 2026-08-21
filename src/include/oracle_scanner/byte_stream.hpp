#pragma once

#include "oracle_scanner/tns_packet.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

namespace oracle_scanner {

class ByteStream {
public:
    virtual ~ByteStream() = default;
    virtual size_t Read(uint8_t *destination, size_t maximum_size) = 0;
    virtual size_t Write(const uint8_t *source, size_t size) = 0;
    virtual void Close() = 0;

    // Sends a single TCP urgent byte for the legacy Oracle CHECK_OOB probe.
    // It is on the interface rather than on one implementation because the
    // handshake runs it against whatever transport is installed, and a
    // transport with no out-of-band channel — TLS, and anything tunnelled —
    // has to be able to say so by kind rather than by type.
    virtual void SendUrgent(uint8_t value);
};

void ReadExact(ByteStream &stream, uint8_t *destination, size_t size);
void WriteAll(ByteStream &stream, const uint8_t *source, size_t size);

struct TlsConfiguration {
    // Empty server_name uses ConnectionConfig::host for certificate
    // verification. sni_name selects the TLS virtual host independently, as
    // required by services whose certificate name differs from the endpoint.
    // Certificate verification is mandatory for TCPS; no insecure opt-out
    // exists in this API.
    std::string server_name;
    std::string sni_name;
    // Bounded PEM contents for an explicit server-trust allow-list. When
    // present, system roots are not added.
    std::string ca_pem_contents;
    // Bounded PEM contents loaded from either an ewallet.pem file or a ZIP
    // wallet. It must never be logged or written to a temporary file.
    std::string client_pem_contents;
    std::string client_pem_password;
    // The server certificate's expected subject DN, from a descriptor's
    // (security=(ssl_server_cert_dn=...)) or from the secret. It is an extra
    // check on top of hostname verification, never a substitute: when it is
    // empty nothing is relaxed.
    std::string expected_server_dn;
};

// Compares two X.509 distinguished names the way Oracle's DN match does:
// component by component, ignoring the order they are written in and the case
// of the attribute names, and requiring the values to be equal. Exposed for
// testing, since a live server offers only its own DN.
bool OracleServerDnMatches(const std::string &expected, const std::string &actual);

// Cross-platform TCP/TCPS stream implemented with OpenSSL BIO. It is kept
// separate from TNS so all protocol tests can use deterministic fake streams.
class OpenSslByteStream final : public ByteStream {
public:
    static std::unique_ptr<OpenSslByteStream> Connect(const std::string &host, uint16_t port,
                                                      uint32_t connect_timeout_seconds,
                                                      uint32_t read_timeout_seconds, bool use_tls,
                                                      const TlsConfiguration &tls = {});
    ~OpenSslByteStream() override;

    size_t Read(uint8_t *destination, size_t maximum_size) override;
    size_t Write(const uint8_t *source, size_t size) override;
    // TNS over TLS has no equivalent, and this rejects it explicitly.
    void SendUrgent(uint8_t value) override;
    void Close() override;

private:
    struct Impl;
    explicit OpenSslByteStream(std::unique_ptr<Impl> implementation);

    std::unique_ptr<Impl> implementation;
};

// Adds packet boundaries to a potentially short-reading/short-writing stream.
// It deliberately owns no socket, making framing and failure paths testable
// without an Oracle server.
class TnsPacketStream {
public:
    TnsPacketStream(ByteStream &stream, bool large_length, size_t packet_limit = MAX_TNS_PACKET_LENGTH);

    void Send(const TnsPacket &packet);
    void Send(const std::vector<TnsPacket> &packets);
    TnsPacket Receive();

private:
    ByteStream &stream;
    bool large_length;
    size_t packet_limit;
};

} // namespace oracle_scanner
