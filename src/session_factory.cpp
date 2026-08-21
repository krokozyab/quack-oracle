#include "oracle_scanner/session_factory.hpp"
#include "oracle_scanner/native_session.hpp"
#include "oracle_scanner/protocol_error.hpp"
#include "oracle_scanner/validating_session.hpp"

#include <mutex>
#include <utility>

namespace oracle_scanner {

namespace {

std::mutex &FactoryLock() {
    static std::mutex lock;
    return lock;
}

OracleSessionFactory &InstalledFactory() {
    static OracleSessionFactory factory;
    return factory;
}

std::unique_ptr<OracleSession> ConnectNativeSession(const ConnectionConfig &config, const std::string &password) {
    return std::make_unique<ValidatedOracleSession>(NativeOracleSession::Connect(config, password));
}

} // namespace

std::unique_ptr<OracleSession> OpenOracleSession(const ConnectionConfig &config, const std::string &password) {
    OracleSessionFactory factory;
    {
        std::lock_guard<std::mutex> guard(FactoryLock());
        factory = InstalledFactory();
    }
    // The factory is copied out and invoked without the lock so a connect,
    // which performs blocking network I/O, never serializes other sessions.
    auto session = factory ? factory(config, password) : ConnectNativeSession(config, password);
    if (!session) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "Oracle session factory returned no session");
    }
    return session;
}

ScopedOracleSessionFactory::ScopedOracleSessionFactory(OracleSessionFactory factory) {
    std::lock_guard<std::mutex> guard(FactoryLock());
    previous = std::move(InstalledFactory());
    InstalledFactory() = std::move(factory);
}

ScopedOracleSessionFactory::~ScopedOracleSessionFactory() {
    std::lock_guard<std::mutex> guard(FactoryLock());
    InstalledFactory() = std::move(previous);
}

} // namespace oracle_scanner
