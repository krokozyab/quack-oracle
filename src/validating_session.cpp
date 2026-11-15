#include "oracle_scanner/validating_session.hpp"
#include "oracle_scanner/bind_validation.hpp"
#include "oracle_scanner/call_builder.hpp"
#include "oracle_scanner/protocol_error.hpp"
#include "oracle_scanner/sql_statement.hpp"

#include <utility>

namespace oracle_scanner {

ValidatedOracleSession::ValidatedOracleSession(std::unique_ptr<OracleSession> inner_p) : inner(std::move(inner_p)) {
    if (!inner) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "validated Oracle session requires an inner session");
    }
}

OracleSession &ValidatedOracleSession::Inner() const {
    if (!inner) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "validated Oracle session is closed");
    }
    return *inner;
}

std::unique_ptr<OracleCursor> ValidatedOracleSession::Query(const std::string &sql, const std::vector<OracleBind> &binds) {
    ValidateOracleQuery(sql, binds);
    return Inner().Query(sql, binds);
}

std::unique_ptr<OracleCursor> ValidatedOracleSession::QueryWithInitialFetch(const std::string &sql,
                                                                        const std::vector<OracleBind> &binds,
                                                                        size_t rows) {
    RequireInitialFetchRows(rows);
    ValidateOracleQuery(sql, binds);
    return Inner().QueryWithInitialFetch(sql, binds, rows);
}

uint64_t ValidatedOracleSession::Execute(const std::string &sql, const std::vector<OracleBind> &binds) {
    ValidateOracleDml(sql, binds);
    return Inner().Execute(sql, binds);
}

void ValidatedOracleSession::ExecuteAdmin(const std::string &sql) {
    ValidateOracleAdmin(sql);
    Inner().ExecuteAdmin(sql);
}

uint64_t ValidatedOracleSession::ExecuteWithRowCount(const std::string &sql, const std::vector<OracleBind> &binds) {
    // Same statement class and bind rules as Execute; only the row-count
    // guarantee differs, and that is settled below this layer.
    ValidateOracleDml(sql, binds);
    return Inner().ExecuteWithRowCount(sql, binds);
}

uint64_t ValidatedOracleSession::ExecuteBatch(const std::string &sql,
                                              const std::vector<std::vector<OracleBind>> &rows) {
    ValidateOracleBindBatch(rows);
    ValidateOracleDml(sql, rows.front());
    return Inner().ExecuteBatch(sql, rows);
}

std::vector<OracleBind> ValidatedOracleSession::ExecuteReturning(const std::string &sql,
                                                                const std::vector<OracleBind> &binds) {
    // The statement is DML and the binds are a DML bind list with OUT slots,
    // which the callable validator is the one that accepts.
    ValidateOracleBinds(binds, OracleBindUse::CALL);
    return Inner().ExecuteReturning(sql, binds);
}

OracleCallResult ValidatedOracleSession::Call(const OracleCallRequest &request) {
    BuildOracleCallBlock(request);
    ValidateOracleBinds(request.arguments, OracleBindUse::CALL);
    if (request.return_bind) {
        ValidateOracleBinds({*request.return_bind}, OracleBindUse::CALL);
    }
    return Inner().Call(request);
}

void ValidatedOracleSession::Commit() {
    Inner().Commit();
}

void ValidatedOracleSession::Rollback() {
    Inner().Rollback();
}

void ValidatedOracleSession::Cancel() {
    Inner().Cancel();
}

void ValidatedOracleSession::Close() {
    if (inner) {
        inner->Close();
        inner.reset();
    }
}

OracleIoStats ValidatedOracleSession::IoStats() const {
    return inner ? inner->IoStats() : OracleIoStats();
}

bool ValidatedOracleSession::ReadyForReuse() const {
    return inner && inner->ReadyForReuse();
}

bool ValidatedOracleSession::BindIoDeadline(std::shared_ptr<OracleIoDeadline> source) {
    return inner && inner->BindIoDeadline(std::move(source));
}

void ValidatedOracleSession::SetStatementCacheEnabled(bool enabled) {
    Inner().SetStatementCacheEnabled(enabled);
}

} // namespace oracle_scanner
