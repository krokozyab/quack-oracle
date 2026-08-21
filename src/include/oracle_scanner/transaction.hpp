#pragma once

#include "oracle_scanner/session.hpp"

#include <memory>
#include <mutex>
#include <string>

namespace oracle_scanner {

enum class TransactionState { ACTIVE, COMMITTING, ROLLING_BACK, COMMITTED, ROLLED_BACK, POISONED };

// DuckDB transaction-local state. A write pins exactly one Oracle session and
// rejects a second attached Oracle catalog because this extension has no 2PC.
class OracleTransaction {
public:
    OracleTransaction();
    ~OracleTransaction();

    OracleTransaction(const OracleTransaction &) = delete;
    OracleTransaction &operator=(const OracleTransaction &) = delete;

    OracleSession &RegisterWrite(const std::string &catalog, std::shared_ptr<OracleSession> session);
    void Commit();
    void Rollback();
    void Poison() noexcept;
    TransactionState State() const;
    std::string WriteCatalog() const;

private:
    void RequireActive() const;

    mutable std::mutex mutex;
    TransactionState state = TransactionState::ACTIVE;
    std::string write_catalog;
    std::shared_ptr<OracleSession> write_session;
};

} // namespace oracle_scanner
