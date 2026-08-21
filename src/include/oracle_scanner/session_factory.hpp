#pragma once

#include "oracle_scanner/session.hpp"
#include "oracle_scanner/tns_client.hpp"

#include <functional>
#include <memory>
#include <string>

namespace oracle_scanner {

// The single seam through which an Oracle session is opened. The DuckDB
// adapter goes through it instead of naming a concrete session type, so the
// adapter depends only on the OracleSession contract and a test can run those
// paths against a fake session with no database and no network.
//
// The default factory returns a native TNS/TTC session wrapped in
// ValidatedOracleSession. That wrapper is what makes the public SQL, batch, and
// callable invariants hold at the transport boundary rather than only at the
// DuckDB binder, so no caller can reach the wire with an unvalidated statement.
using OracleSessionFactory =
    std::function<std::unique_ptr<OracleSession>(const ConnectionConfig &config, const std::string &password)>;

std::unique_ptr<OracleSession> OpenOracleSession(const ConnectionConfig &config, const std::string &password);

// Installs a replacement factory and restores the previous one on destruction,
// including when the installers nest. This exists for tests; production code
// never installs a factory.
class ScopedOracleSessionFactory {
public:
    explicit ScopedOracleSessionFactory(OracleSessionFactory factory);
    ~ScopedOracleSessionFactory();

    ScopedOracleSessionFactory(const ScopedOracleSessionFactory &) = delete;
    ScopedOracleSessionFactory &operator=(const ScopedOracleSessionFactory &) = delete;

private:
    OracleSessionFactory previous;
};

} // namespace oracle_scanner
