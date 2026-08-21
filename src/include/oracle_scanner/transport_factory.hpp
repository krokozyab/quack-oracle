#pragma once

#include "oracle_scanner/byte_stream.hpp"
#include "oracle_scanner/tns_client.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <string>

namespace oracle_scanner {

// The single seam through which a byte transport is opened, mirroring
// OpenOracleSession one layer down. Everything above it — framing, the TNS
// handshake, TTC, the codecs — already speaks only to ByteStream, so the
// concrete transport is named in exactly one place rather than in the connect
// path itself.
//
// Two things this is for. A test can drive a real handshake against a scripted
// transport, with no socket and no OpenSSL, which is what makes CONNECT,
// ACCEPT, REDIRECT and REFUSE reachable offline. And a build for a target with
// no raw TCP socket — a WebAssembly one, say — becomes a matter of installing a
// different transport rather than of threading a second type through the
// connect path.
//
// What it deliberately does not decide: a transport that cannot block in Read
// still needs an answer above this layer, because every TTC exchange is a
// synchronous request and response. The seam makes that work possible; it does
// not make it done.
using OracleTransportFactory = std::function<std::unique_ptr<ByteStream>(
    const std::string &host, uint16_t port, uint32_t connect_timeout_seconds, uint32_t read_timeout_seconds,
    bool use_tls, const TlsConfiguration &tls)>;

std::unique_ptr<ByteStream> OpenOracleTransport(const std::string &host, uint16_t port,
                                                uint32_t connect_timeout_seconds, uint32_t read_timeout_seconds,
                                                bool use_tls, const TlsConfiguration &tls = {});

// Installs a replacement factory and restores the previous one on destruction,
// including when the installers nest. This exists for tests; production code
// never installs a factory.
class ScopedOracleTransportFactory {
public:
    explicit ScopedOracleTransportFactory(OracleTransportFactory factory);
    ~ScopedOracleTransportFactory();

    ScopedOracleTransportFactory(const ScopedOracleTransportFactory &) = delete;
    ScopedOracleTransportFactory &operator=(const ScopedOracleTransportFactory &) = delete;

private:
    OracleTransportFactory previous;
};

} // namespace oracle_scanner
