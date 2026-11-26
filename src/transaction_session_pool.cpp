#include "oracle_scanner/transaction_session_pool.hpp"

#include "oracle_scanner/io_deadline_binding.hpp"
#include "oracle_scanner/protocol_error.hpp"

#include <utility>

namespace oracle_scanner {

OracleTransactionSessionPool::OracleTransactionSessionPool(size_t maximum_idle_p, Opener opener_p, Probe probe_p,
                                                           std::chrono::steady_clock::duration maximum_idle_time_p,
                                                           Clock clock_p)
    : maximum_idle(maximum_idle_p), opener(std::move(opener_p)), probe(std::move(probe_p)),
      maximum_idle_time(maximum_idle_time_p), clock(std::move(clock_p)) {
    if (!opener || !probe || !clock) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "Oracle transaction session pool needs an opener");
    }
}

OracleTransactionSessionPool::~OracleTransactionSessionPool() {
    Close();
}

void OracleTransactionSessionPool::SelectFromDual(OracleSession &session) {
    auto cursor = session.Query("SELECT 1 FROM DUAL", {});
    const auto batch = cursor->Fetch(1);
    if (batch.rows.size() != 1) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle session probe returned no row");
    }
    cursor->Close();
}

void OracleTransactionSessionPool::CloseQuietly(const std::shared_ptr<OracleSession> &session) noexcept {
    if (!session) {
        return;
    }
    try {
        session->Close();
    } catch (...) {
    }
}

std::vector<std::shared_ptr<OracleSession>> OracleTransactionSessionPool::TakeExpiredLocked() {
    std::vector<std::shared_ptr<OracleSession>> expired;
    const auto now = clock();
    for (auto entry = idle.begin(); entry != idle.end();) {
        if (now - entry->since > maximum_idle_time) {
            expired.push_back(std::move(entry->session));
            entry = idle.erase(entry);
        } else {
            ++entry;
        }
    }
    counters.closed += expired.size();
    counters.idle = idle.size();
    return expired;
}

std::shared_ptr<OracleSession> OracleTransactionSessionPool::Acquire(std::shared_ptr<OracleIoDeadline> caller) {
    for (;;) {
        std::shared_ptr<OracleSession> candidate;
        std::vector<std::shared_ptr<OracleSession>> expired;
        {
            std::lock_guard<std::mutex> guard(mutex);
            expired = TakeExpiredLocked();
            if (!idle.empty()) {
                // The most recently returned session: the least likely to
                // have been timed out or killed while it waited.
                candidate = std::move(idle.back().session);
                idle.pop_back();
                counters.idle = idle.size();
            }
        }
        for (auto &session : expired) {
            CloseQuietly(session);
        }
        if (!candidate) {
            break;
        }
        // Bound before the probe, so the caller's interrupt reaches it.
        bool usable = candidate->BindIoDeadline(caller);
        if (usable) {
            try {
                probe(*candidate);
            } catch (...) {
                usable = false;
            }
        }
        if (usable && candidate->ReadyForReuse()) {
            std::lock_guard<std::mutex> guard(mutex);
            counters.reused++;
            counters.leased++;
            return candidate;
        }
        // Nothing of the transaction has been sent on it: drop it and try the
        // next one, or open a fresh session below.
        {
            std::lock_guard<std::mutex> guard(mutex);
            counters.probe_failures++;
            counters.closed++;
        }
        CloseQuietly(candidate);
    }
    auto session = opener(std::make_shared<OracleIoDeadlineBinding>(std::move(caller)));
    if (!session) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "Oracle transaction session pool opened no session");
    }
    std::lock_guard<std::mutex> guard(mutex);
    counters.opened++;
    counters.leased++;
    return session;
}

bool OracleTransactionSessionPool::Release(std::shared_ptr<OracleSession> session) noexcept {
    if (!session) {
        return false;
    }
    bool clean = false;
    try {
        // Sole ownership: a borrower such as an open scan still holds it
        // otherwise, and a session is never shared between two transactions.
        clean = session.use_count() == 1 && session->ReadyForReuse() && session->BindIoDeadline(nullptr);
    } catch (...) {
        clean = false;
    }
    bool kept = false;
    std::vector<std::shared_ptr<OracleSession>> expired;
    {
        std::lock_guard<std::mutex> guard(mutex);
        if (counters.leased > 0) {
            counters.leased--;
        }
        try {
            expired = TakeExpiredLocked();
            if (clean && !closed && idle.size() < maximum_idle) {
                const auto since = clock();
                // The one step that can fail, taken before the session moves.
                idle.reserve(idle.size() + 1);
                idle.push_back({std::move(session), since});
                counters.returned++;
                counters.idle = idle.size();
                kept = true;
            } else {
                counters.closed++;
            }
        } catch (...) {
            // No room to keep it: it is closed below instead.
            counters.closed++;
        }
    }
    for (auto &entry : expired) {
        CloseQuietly(entry);
    }
    if (!kept) {
        CloseQuietly(session);
    }
    return kept;
}

// By value on purpose: the pool takes the caller's reference, so the session
// is destroyed here, after it is closed, not whenever the caller's goes.
// NOLINTNEXTLINE(performance-unnecessary-value-param)
void OracleTransactionSessionPool::Discard(std::shared_ptr<OracleSession> session) noexcept {
    if (!session) {
        return;
    }
    {
        std::lock_guard<std::mutex> guard(mutex);
        if (counters.leased > 0) {
            counters.leased--;
        }
        counters.closed++;
    }
    CloseQuietly(session);
}

void OracleTransactionSessionPool::Close() noexcept {
    std::vector<Idle> taken;
    {
        std::lock_guard<std::mutex> guard(mutex);
        closed = true;
        taken.swap(idle);
        counters.closed += taken.size();
        counters.idle = 0;
    }
    for (auto &entry : taken) {
        CloseQuietly(entry.session);
    }
}

OracleTransactionPoolCounters OracleTransactionSessionPool::Counters() const {
    std::lock_guard<std::mutex> guard(mutex);
    return counters;
}

} // namespace oracle_scanner
