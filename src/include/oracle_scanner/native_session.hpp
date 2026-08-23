#pragma once

#include "oracle_scanner/session.hpp"
#include "oracle_scanner/statement_registry.hpp"
#include "oracle_scanner/tns_client.hpp"
#include "oracle_scanner/ttc_statement_channel.hpp"

#include <cstdint>
#include <memory>
#include <vector>

namespace oracle_scanner {

struct NativeSessionLifetime;

// Direct, dependency-free OracleSession backed by the native TNS/TTC client.
// Query and scalar DML use the live-verified OALL8 paths, including scalar IN
// binds. Batch DML deliberately reuses that scalar layout until an array-bind
// OALL8 form is capture-verified; callable dispatch has its own wire path.
class NativeOracleSession final : public OracleSession {
public:
    static std::unique_ptr<NativeOracleSession> Connect(const ConnectionConfig &config, const std::string &password);
    ~NativeOracleSession() override;

    std::unique_ptr<OracleCursor> Query(const std::string &sql, const std::vector<OracleBind> &binds) override;
    uint64_t Execute(const std::string &sql, const std::vector<OracleBind> &binds) override;
    // Executes one validated DML statement through a bounded anonymous PL/SQL
    // block and returns SQL%ROWCOUNT via a NUMBER OUT bind.
    uint64_t ExecuteWithRowCount(const std::string &sql, const std::vector<OracleBind> &binds) override;
    uint64_t ExecuteBatch(const std::string &sql, const std::vector<std::vector<OracleBind>> &rows) override;
    std::vector<OracleBind> ExecuteReturning(const std::string &sql, const std::vector<OracleBind> &binds) override;
    OracleCallResult Call(const OracleCallRequest &request) override;
    void Commit() override;
    void Rollback() override;
    void Cancel() override;
    void Close() override;

private:
    explicit NativeOracleSession(std::unique_ptr<TnsClientConnection> connection);
    uint8_t NextSequence();
    void RequireOpen() const;

    std::unique_ptr<TnsClientConnection> connection;
    OracleStatementRegistry statements;
    std::unique_ptr<TtcStatementChannel> channel;
    std::shared_ptr<NativeSessionLifetime> lifetime;
    uint8_t next_sequence = 1;
};

} // namespace oracle_scanner
