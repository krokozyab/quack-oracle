#pragma once

#include "oracle_scanner/byte_stream.hpp"
#include "oracle_scanner/tns_client.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

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

// Name resolution, the other half of reaching a listener. It is a seam of its
// own because the default transport cannot be trusted with a name that
// resolves to several addresses: OpenSSL's connect BIO does move on after an
// address that refuses at once, but an address that swallows the SYN holds it
// until the whole timeout is gone, and BIO_do_connect_retry then starts the
// list again from the top. A SCAN name with one dead IP would spend every
// attempt on it. So the connect loop resolves the name itself and dials each
// address as its own attempt, with its own timeout.
//
// The resolver returns numeric addresses in the order to try them. An IP
// literal is never passed to it. With no resolver installed, a name goes to
// the default resolver — unless a transport factory is installed, in which case
// the name is handed to that transport unresolved: a scripted transport decides
// for itself what a name means, and a test should not touch DNS by accident.
using OracleHostResolver = std::function<std::vector<std::string>(const std::string &host, uint16_t port)>;

// Resolves `host` for dialing. Throws OracleConnectError with
// ConnectFailure::UNREACHABLE when the name does not resolve. Returns at most
// MAX_RESOLVED_ADDRESSES addresses, duplicates removed, order kept.
std::vector<std::string> ResolveOracleHost(const std::string &host, uint16_t port);

class ScopedOracleHostResolver {
public:
    explicit ScopedOracleHostResolver(OracleHostResolver resolver);
    ~ScopedOracleHostResolver();

    ScopedOracleHostResolver(const ScopedOracleHostResolver &) = delete;
    ScopedOracleHostResolver &operator=(const ScopedOracleHostResolver &) = delete;

private:
    OracleHostResolver previous;
};

} // namespace oracle_scanner
