#include "oracle_scanner/transaction.hpp"
#include "oracle_scanner/protocol_error.hpp"

#include <utility>

namespace oracle_scanner {

OracleTransaction::OracleTransaction() = default;

OracleTransaction::~OracleTransaction() {
    std::shared_ptr<OracleSession> session;
    {
        std::lock_guard<std::mutex> guard(mutex);
        if (state != TransactionState::ACTIVE || !write_session) {
            return;
        }
        state = TransactionState::ROLLED_BACK;
        session = std::move(write_session);
    }
    try {
        session->Rollback();
    } catch (...) {
        try {
            session->Close();
        } catch (...) {
        }
    }
}

void OracleTransaction::RequireActive() const {
    if (state != TransactionState::ACTIVE) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "Oracle transaction is no longer active");
    }
}

OracleSession &OracleTransaction::RegisterWrite(const std::string &catalog,
                                                std::shared_ptr<OracleSession> session) {
    std::lock_guard<std::mutex> guard(mutex);
    RequireActive();
    if (catalog.empty() || !session) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle write requires a catalog and session");
    }
    if (!write_catalog.empty() && write_catalog != catalog) {
        throw ProtocolError(ProtocolErrorKind::UNSUPPORTED,
                            "a DuckDB transaction may write to only one attached Oracle database");
    }
    if (!write_session) {
        write_catalog = catalog;
        write_session = std::move(session);
    } else if (write_session != session) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE,
                            "Oracle transaction attempted to replace its pinned session");
    }
    return *write_session;
}

void OracleTransaction::Commit() {
    std::shared_ptr<OracleSession> session;
    {
        std::lock_guard<std::mutex> guard(mutex);
        RequireActive();
        session = write_session;
        state = TransactionState::COMMITTING;
    }
    try {
        if (session) {
            session->Commit();
        }
    } catch (...) {
        Poison();
        if (session) {
            try {
                session->Close();
            } catch (...) {
            }
        }
        throw;
    }
    std::lock_guard<std::mutex> guard(mutex);
    state = TransactionState::COMMITTED;
    write_session.reset();
}

void OracleTransaction::Rollback() {
    std::shared_ptr<OracleSession> session;
    {
        std::lock_guard<std::mutex> guard(mutex);
        RequireActive();
        session = write_session;
        state = TransactionState::ROLLING_BACK;
    }
    try {
        if (session) {
            session->Rollback();
        }
    } catch (...) {
        Poison();
        if (session) {
            try {
                session->Close();
            } catch (...) {
            }
        }
        throw;
    }
    std::lock_guard<std::mutex> guard(mutex);
    state = TransactionState::ROLLED_BACK;
    write_session.reset();
}

void OracleTransaction::Poison() noexcept {
    std::lock_guard<std::mutex> guard(mutex);
    state = TransactionState::POISONED;
}

TransactionState OracleTransaction::State() const {
    std::lock_guard<std::mutex> guard(mutex);
    return state;
}

std::string OracleTransaction::WriteCatalog() const {
    std::lock_guard<std::mutex> guard(mutex);
    return write_catalog;
}

} // namespace oracle_scanner
