#pragma once

#include "oracle_scanner/session.hpp"

#include <memory>

namespace oracle_scanner {

// Applies public SQL/call invariants immediately before transport work. The
// wrapped session owns TNS/TTC state; this layer owns no protocol data.
class ValidatedOracleSession : public OracleSession {
public:
    explicit ValidatedOracleSession(std::unique_ptr<OracleSession> inner);

    std::unique_ptr<OracleCursor> Query(const std::string &sql, const std::vector<OracleBind> &binds) override;
    uint64_t Execute(const std::string &sql, const std::vector<OracleBind> &binds) override;
    uint64_t ExecuteWithRowCount(const std::string &sql, const std::vector<OracleBind> &binds) override;
    uint64_t ExecuteBatch(const std::string &sql, const std::vector<std::vector<OracleBind>> &rows) override;
    std::vector<OracleBind> ExecuteReturning(const std::string &sql, const std::vector<OracleBind> &binds) override;
    OracleCallResult Call(const OracleCallRequest &request) override;
    void Commit() override;
    void Rollback() override;
    void Cancel() override;
    void Close() override;

private:
    OracleSession &Inner() const;
    std::unique_ptr<OracleSession> inner;
};

} // namespace oracle_scanner
