#include "oracle_scanner/transport_factory.hpp"
#include "oracle_scanner/connect_error.hpp"
#include "oracle_scanner/connect_plan.hpp"
#include "oracle_scanner/protocol_error.hpp"

#include <algorithm>
#include <mutex>
#include <utility>

namespace oracle_scanner {

namespace {

std::mutex &FactoryLock() {
    static std::mutex lock;
    return lock;
}

OracleTransportFactory &InstalledFactory() {
    static OracleTransportFactory factory;
    return factory;
}

OracleHostResolver &InstalledResolver() {
    static OracleHostResolver resolver;
    return resolver;
}

} // namespace

std::unique_ptr<ByteStream> OpenOracleTransport(const std::string &host, uint16_t port,
                                                uint32_t connect_timeout_seconds, uint32_t read_timeout_seconds,
                                                bool use_tls, const TlsConfiguration &tls) {
    OracleTransportFactory factory;
    {
        std::lock_guard<std::mutex> guard(FactoryLock());
        factory = InstalledFactory();
    }
    // Copied out and invoked without the lock, for the same reason the session
    // factory is: connecting blocks, and holding the lock across it would
    // serialize every other connection behind the slowest one.
    auto transport = factory ? factory(host, port, connect_timeout_seconds, read_timeout_seconds, use_tls, tls)
                             : OpenSslByteStream::Connect(host, port, connect_timeout_seconds, read_timeout_seconds,
                                                          use_tls, tls);
    if (!transport) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "Oracle transport factory returned no transport");
    }
    return transport;
}

ScopedOracleTransportFactory::ScopedOracleTransportFactory(OracleTransportFactory factory) {
    std::lock_guard<std::mutex> guard(FactoryLock());
    previous = std::move(InstalledFactory());
    InstalledFactory() = std::move(factory);
}

ScopedOracleTransportFactory::~ScopedOracleTransportFactory() {
    std::lock_guard<std::mutex> guard(FactoryLock());
    InstalledFactory() = std::move(previous);
}

std::vector<std::string> ResolveOracleHost(const std::string &host, uint16_t port) {
    if (IsIpLiteral(host)) {
        return {host};
    }
    OracleHostResolver resolver;
    bool transport_installed = false;
    {
        std::lock_guard<std::mutex> guard(FactoryLock());
        resolver = InstalledResolver();
        transport_installed = static_cast<bool>(InstalledFactory());
    }
    std::vector<std::string> resolved;
    if (resolver) {
        resolved = resolver(host, port);
    } else if (transport_installed) {
        return {host};
    } else {
        resolved = OpenSslResolveHost(host, port);
    }
    std::vector<std::string> result;
    for (auto &address : resolved) {
        if (std::find(result.begin(), result.end(), address) == result.end()) {
            result.push_back(std::move(address));
        }
        if (result.size() == MAX_RESOLVED_ADDRESSES) {
            break;
        }
    }
    if (result.empty()) {
        throw OracleConnectError(ProtocolErrorKind::TRUNCATED, ConnectFailure::UNREACHABLE,
                                 "Oracle host name '" + host + "' resolved to no address");
    }
    return result;
}

ScopedOracleHostResolver::ScopedOracleHostResolver(OracleHostResolver resolver) {
    std::lock_guard<std::mutex> guard(FactoryLock());
    previous = std::move(InstalledResolver());
    InstalledResolver() = std::move(resolver);
}

ScopedOracleHostResolver::~ScopedOracleHostResolver() {
    std::lock_guard<std::mutex> guard(FactoryLock());
    InstalledResolver() = std::move(previous);
}

} // namespace oracle_scanner
