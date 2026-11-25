#pragma once

#include "oracle_scanner/protocol_error.hpp"
#include "oracle_scanner/session.hpp"

#include <chrono>
#include <cstddef>
#include <functional>
#include <memory>
#include <mutex>
#include <vector>

namespace oracle_scanner {

class OracleSessionPool;

// Every session the pool may hold is leased. A type of its own, not just
// LIMIT_EXCEEDED, because a caller that falls back to an unpooled session on
// this must not do so for a failed connect that happens to carry the same kind
// — that would repeat the whole connect, retries and all.
class OracleSessionPoolExhausted : public ProtocolError {
public:
    OracleSessionPoolExhausted()
        : ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "Oracle session pool is exhausted") {
    }
};

class OracleSessionLease {
public:
    OracleSessionLease() = default;
    OracleSessionLease(OracleSessionLease &&other) noexcept;
    OracleSessionLease &operator=(OracleSessionLease &&other) noexcept;
    ~OracleSessionLease();

    OracleSessionLease(const OracleSessionLease &) = delete;
    OracleSessionLease &operator=(const OracleSessionLease &) = delete;

    OracleSession &Get() const;
    OracleSession *operator->() const;
    explicit operator bool() const;
    void Poison() noexcept;

private:
    friend class OracleSessionPool;
    OracleSessionLease(OracleSessionPool *pool, std::shared_ptr<OracleSession> session);
    void Release() noexcept;

    OracleSessionPool *pool = nullptr;
    std::shared_ptr<OracleSession> session;
    bool poisoned = false;
};

// A session that sat idle for probe_after or longer must answer the probe
// before it is leased: a server IDLE_TIME, a firewall or an Autonomous
// Database may have closed it meanwhile. One that fails is closed and the next
// idle or a new session is tried. A session back within probe_after is leased
// without a round trip.
class OracleSessionPool {
public:
    using Factory = std::function<std::shared_ptr<OracleSession>()>;
    // Proves an idle session still talks to its server; throws if not.
    using Probe = std::function<void(OracleSession &)>;
    using Clock = std::function<std::chrono::steady_clock::time_point()>;

    static constexpr std::chrono::seconds DEFAULT_PROBE_AFTER {30};

    OracleSessionPool(size_t maximum_sessions, Factory factory, Probe probe = nullptr,
                      std::chrono::steady_clock::duration probe_after = DEFAULT_PROBE_AFTER,
                      Clock clock = std::chrono::steady_clock::now);
    ~OracleSessionPool();

    OracleSessionPool(const OracleSessionPool &) = delete;
    OracleSessionPool &operator=(const OracleSessionPool &) = delete;

    OracleSessionLease Acquire();
    size_t IdleCount() const;
    size_t LiveCount() const;

private:
    friend class OracleSessionLease;
    void Release(std::shared_ptr<OracleSession> session, bool poisoned) noexcept;

    struct Idle {
        std::shared_ptr<OracleSession> session;
        std::chrono::steady_clock::time_point since;
    };

    mutable std::mutex mutex;
    size_t maximum_sessions;
    size_t live_sessions = 0;
    Factory factory;
    Probe probe;
    std::chrono::steady_clock::duration probe_after;
    Clock clock;
    std::vector<Idle> idle;
};

} // namespace oracle_scanner
