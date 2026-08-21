#include "oracle_scanner/transport_factory.hpp"
#include "oracle_scanner/protocol_error.hpp"

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

} // namespace oracle_scanner
