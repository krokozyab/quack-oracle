#pragma once

#include "oracle_scanner/session.hpp"

#include <cstddef>
#include <functional>
#include <memory>
#include <mutex>
#include <vector>

namespace oracle_scanner {

class OracleSessionPool;

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

class OracleSessionPool {
public:
    using Factory = std::function<std::shared_ptr<OracleSession>()>;

    OracleSessionPool(size_t maximum_sessions, Factory factory);
    ~OracleSessionPool();

    OracleSessionPool(const OracleSessionPool &) = delete;
    OracleSessionPool &operator=(const OracleSessionPool &) = delete;

    OracleSessionLease Acquire();
    size_t IdleCount() const;
    size_t LiveCount() const;

private:
    friend class OracleSessionLease;
    void Release(std::shared_ptr<OracleSession> session, bool poisoned) noexcept;

    mutable std::mutex mutex;
    size_t maximum_sessions;
    size_t live_sessions = 0;
    Factory factory;
    std::vector<std::shared_ptr<OracleSession>> idle;
};

} // namespace oracle_scanner
