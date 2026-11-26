#include "oracle_scanner/session_pool.hpp"
#include "oracle_scanner/protocol_error.hpp"

#include <utility>

namespace oracle_scanner {

OracleSessionLease::OracleSessionLease(OracleSessionPool *pool_p, std::shared_ptr<OracleSession> session_p)
    : pool(pool_p), session(std::move(session_p)) {
}

OracleSessionLease::OracleSessionLease(OracleSessionLease &&other) noexcept
    : pool(other.pool), session(std::move(other.session)), poisoned(other.poisoned) {
    other.pool = nullptr;
    other.poisoned = false;
}

OracleSessionLease &OracleSessionLease::operator=(OracleSessionLease &&other) noexcept {
    if (this != &other) {
        Release();
        pool = other.pool;
        session = std::move(other.session);
        poisoned = other.poisoned;
        other.pool = nullptr;
        other.poisoned = false;
    }
    return *this;
}

OracleSessionLease::~OracleSessionLease() {
    Release();
}

OracleSession &OracleSessionLease::Get() const {
    if (!session) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "Oracle session lease is empty");
    }
    return *session;
}

OracleSession *OracleSessionLease::operator->() const {
    return &Get();
}

OracleSessionLease::operator bool() const {
    return static_cast<bool>(session);
}

void OracleSessionLease::Poison() noexcept {
    poisoned = true;
}

void OracleSessionLease::Release() noexcept {
    if (pool && session) {
        pool->Release(std::move(session), poisoned);
    }
    pool = nullptr;
    poisoned = false;
}

OracleSessionPool::OracleSessionPool(size_t maximum_sessions_p, Factory factory_p, Probe probe_p,
                                     std::chrono::steady_clock::duration probe_after_p, Clock clock_p)
    : maximum_sessions(maximum_sessions_p), factory(std::move(factory_p)), probe(std::move(probe_p)),
      probe_after(probe_after_p), clock(std::move(clock_p)) {
    if (maximum_sessions == 0 || !factory || !clock) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle session pool configuration is invalid");
    }
}

OracleSessionPool::~OracleSessionPool() {
    std::vector<Idle> sessions;
    {
        std::lock_guard<std::mutex> guard(mutex);
        sessions.swap(idle);
        live_sessions -= sessions.size();
    }
    for (auto &entry : sessions) {
        try {
            entry.session->Close();
        } catch (...) {
        }
    }
}

OracleSessionLease OracleSessionPool::Acquire() {
    std::shared_ptr<OracleSession> result;
    for (;;) {
        bool stale = false;
        {
            std::lock_guard<std::mutex> guard(mutex);
            if (!idle.empty()) {
                // The most recently returned: the least likely to have died idle.
                result = std::move(idle.back().session);
                stale = clock() - idle.back().since >= probe_after;
                idle.pop_back();
            } else {
                if (live_sessions == maximum_sessions) {
                    throw OracleSessionPoolExhausted();
                }
                live_sessions++;
            }
        }
        if (!result || !stale || !probe) {
            break;
        }
        try {
            probe(*result);
            break;
        } catch (...) {
        }
        // Dead while it waited; nothing of the caller's has been sent on it.
        try {
            result->Close();
        } catch (...) {
        }
        result.reset();
        std::lock_guard<std::mutex> guard(mutex);
        live_sessions--;
    }
    if (!result) {
        try {
            result = factory();
        } catch (...) {
            std::lock_guard<std::mutex> guard(mutex);
            live_sessions--;
            throw;
        }
        if (!result) {
            std::lock_guard<std::mutex> guard(mutex);
            live_sessions--;
            throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "Oracle session pool factory returned null");
        }
    }
    return OracleSessionLease(this, std::move(result));
}

void OracleSessionPool::Release(std::shared_ptr<OracleSession> session, bool poisoned) noexcept {
    if (!session) {
        return;
    }
    if (!poisoned) {
        try {
            const auto now = clock();
            std::lock_guard<std::mutex> guard(mutex);
            // The one step that can fail, taken before the session moves.
            idle.reserve(idle.size() + 1);
            idle.push_back({std::move(session), now});
            return;
        } catch (...) {
            // No room to keep it idle: it is closed below, as a poisoned one is.
        }
    }
    try {
        session->Close();
    } catch (...) {
    }
    std::lock_guard<std::mutex> guard(mutex);
    live_sessions--;
}

size_t OracleSessionPool::IdleCount() const {
    std::lock_guard<std::mutex> guard(mutex);
    return idle.size();
}

size_t OracleSessionPool::LiveCount() const {
    std::lock_guard<std::mutex> guard(mutex);
    return live_sessions;
}

} // namespace oracle_scanner
