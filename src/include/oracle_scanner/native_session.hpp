#pragma once

#include "oracle_scanner/session.hpp"
#include "oracle_scanner/statement_registry.hpp"
#include "oracle_scanner/tns_client.hpp"
#include "oracle_scanner/ttc_statement_channel.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <utility>
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
    std::unique_ptr<OracleCursor> QueryWithInitialFetch(const std::string &sql,
                                                     const std::vector<OracleBind> &binds, size_t rows) override;
    uint64_t Execute(const std::string &sql, const std::vector<OracleBind> &binds) override;
    void ExecuteAdmin(const std::string &sql) override;
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
    bool ReadyForReuse() const override;
    OracleIoStats IoStats() const override;
    bool BindIoDeadline(std::shared_ptr<OracleIoDeadline> source) override;
    void SetStatementCacheEnabled(bool enabled) override;

private:
    explicit NativeOracleSession(std::unique_ptr<TnsClientConnection> connection);
    uint8_t NextSequence();
    void RequireOpen() const;
    std::unique_ptr<OracleCursor> OpenQuery(const std::string &sql, const std::vector<OracleBind> &binds, size_t initial_rows = 2);
    void AnnotateDatabaseZone(OracleCursor &cursor);
    void InvalidateQueries();
    uint64_t ExecuteStatement(const std::string &sql, const std::vector<OracleBind> &binds, OracleSqlKind kind);
    //! Runs `operation` with the binds of one statement, sending any LOB value
    //! too large for an ordinary bind through a temporary LOB that is released
    //! when the statement is done.
    template <class Operation>
    auto WithTemporaryLobs(const std::vector<OracleBind> &binds, Operation operation)
        -> decltype(operation(binds));

    std::unique_ptr<TnsClientConnection> connection;
    OracleStatementRegistry statements;
    std::unique_ptr<TtcStatementChannel> channel;
    std::shared_ptr<NativeSessionLifetime> lifetime;
    // Present when the session was opened to be reused across callers.
    std::shared_ptr<OracleIoDeadlineBinding> deadline_binding;
    uint8_t next_sequence = 1;
    // DBTIMEZONE as (offset in minutes, is a region), once something needed it.
    std::optional<std::pair<int16_t, bool>> database_zone;
};

} // namespace oracle_scanner
