#pragma once

#include "oracle_scanner/connect_descriptor.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace oracle_scanner {

// Hard bounds on one physical connect, on top of the time budget: how many
// listener redirects one chain may follow, and how many transports one connect
// may open in total across addresses, resolved IPs, redirects and retries.
constexpr size_t MAX_CONNECT_REDIRECTS = 3;
constexpr size_t MAX_CONNECT_TRANSPORT_OPENS = 256;
// How many resolved IPs of one host name are tried. A SCAN name resolves to
// three; this leaves room without letting a resolver hand back hundreds.
constexpr size_t MAX_RESOLVED_ADDRESSES = 8;

// The clock, the sleep and the randomness a connect uses. Production uses the
// steady clock, a real sleep and a seeded generator; a test installs its own
// so that retries, delays, budgets and LOAD_BALANCE are deterministic and take
// no wall time.
struct OracleConnectEnvironment {
    std::function<std::chrono::steady_clock::time_point()> now;
    std::function<void(std::chrono::milliseconds)> sleep;
    std::function<uint64_t()> random;
};

// The installed environment, or the production one.
OracleConnectEnvironment CurrentOracleConnectEnvironment();

// Installs an environment and restores the previous one on destruction. Any
// member left empty falls back to production behaviour. For tests.
class ScopedOracleConnectEnvironment {
public:
    explicit ScopedOracleConnectEnvironment(OracleConnectEnvironment environment);
    ~ScopedOracleConnectEnvironment();
    ScopedOracleConnectEnvironment(const ScopedOracleConnectEnvironment &) = delete;
    ScopedOracleConnectEnvironment &operator=(const ScopedOracleConnectEnvironment &) = delete;

private:
    OracleConnectEnvironment previous;
};

// Lets a caller interrupt connects made on this thread. The check runs before
// every attempt and throughout every retry delay; an attempt already in
// progress runs to its own per-attempt timeout first. Nests, and restores the
// previous check on destruction.
class ScopedOracleConnectCancellation {
public:
    explicit ScopedOracleConnectCancellation(std::function<bool()> cancelled);
    ~ScopedOracleConnectCancellation();
    ScopedOracleConnectCancellation(const ScopedOracleConnectCancellation &) = delete;
    ScopedOracleConnectCancellation &operator=(const ScopedOracleConnectCancellation &) = delete;

private:
    std::function<bool()> previous;
};

// Whether the check installed on this thread says to stop.
bool OracleConnectCancelled();

// Name resolution has no timeout of its own, so the connect loop runs it on a
// small pool of long-lived workers and waits for the answer within its budget.
// Both the pool and its queue are bounded: a resolver that hangs holds at most
// one worker, and however many connects give up on a hanging lookup, the
// number of threads never grows past MAX_RESOLVER_WORKERS. A request whose
// caller gave up while it was still queued is dropped, never run.
constexpr size_t MAX_RESOLVER_WORKERS = 4;
constexpr size_t MAX_RESOLVER_QUEUE = 16;

// Resolves `host` on the pool (see ResolveOracleHost for what it returns).
// `check` is called before the wait and at least every 100 ms during it, and
// stops the wait by throwing — the connect loop's budget and cancellation
// checks. `time_left` bounds each slice of the wait. A full queue is waited
// on the same way. A worker that cannot be started is
// ConnectFailure::RESOURCE_EXHAUSTED; there is no synchronous fallback,
// because that would give up both the deadline and cancellation.
std::vector<std::string> ResolveOracleHostOnPool(const std::string &host, uint16_t port,
                                                 const std::function<void()> &check,
                                                 const std::function<std::chrono::milliseconds()> &time_left);

// How many resolver workers exist now. For tests of the bound.
size_t OracleResolverWorkerCount();

// The order in which one physical connect tries the configured addresses:
// FAILOVER and LOAD_BALANCE applied first across the address lists and then
// within each, with the rules ConnectAddressList documents. `random` is drawn
// only when LOAD_BALANCE is on. Name resolution happens later, per address.
std::vector<ConnectAddress> PlanConnectOrder(const ConnectionConfig &config, const std::function<uint64_t()> &random);

} // namespace oracle_scanner
