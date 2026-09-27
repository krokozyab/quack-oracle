#include "oracle_scanner/connect_plan.hpp"
#include "oracle_scanner/connect_error.hpp"
#include "oracle_scanner/transport_factory.hpp"

#include <algorithm>
#include <condition_variable>
#include <deque>
#include <exception>
#include <memory>
#include <mutex>
#include <random>
#include <system_error>
#include <thread>
#include <utility>

namespace oracle_scanner {

namespace {

std::mutex &EnvironmentLock() {
    static std::mutex lock;
    return lock;
}

OracleConnectEnvironment &InstalledEnvironment() {
    static OracleConnectEnvironment environment;
    return environment;
}

std::function<bool()> &ThreadCancellation() {
    thread_local std::function<bool()> cancelled;
    return cancelled;
}

uint64_t ProductionRandom() {
    // Per thread, seeded once from the platform's entropy. LOAD_BALANCE needs
    // spread across connections, not secrecy, so this is not a CSPRNG.
    thread_local std::mt19937_64 generator(std::random_device {}());
    return generator();
}

// Fisher-Yates over the whole vector, drawing from `random`.
template <class T>
void Shuffle(std::vector<T> &values, const std::function<uint64_t()> &random) {
    for (size_t index = values.size(); index > 1; index--) {
        const auto chosen = static_cast<size_t>(random() % index);
        std::swap(values[index - 1], values[chosen]);
    }
}

// The four FAILOVER x LOAD_BALANCE rules, shared by both levels.
template <class T>
std::vector<T> ActiveChildren(const std::vector<T> &children, bool failover, bool load_balance,
                              const std::function<uint64_t()> &random) {
    if (children.size() <= 1) {
        return children;
    }
    if (failover) {
        auto result = children;
        if (load_balance) {
            Shuffle(result, random);
        }
        return result;
    }
    if (load_balance) {
        return {children[static_cast<size_t>(random() % children.size())]};
    }
    return {children.front()};
}

} // namespace

OracleConnectEnvironment CurrentOracleConnectEnvironment() {
    OracleConnectEnvironment result;
    {
        std::lock_guard<std::mutex> guard(EnvironmentLock());
        result = InstalledEnvironment();
    }
    if (!result.now) {
        result.now = [] { return std::chrono::steady_clock::now(); };
    }
    if (!result.sleep) {
        result.sleep = [](std::chrono::milliseconds duration) { std::this_thread::sleep_for(duration); };
    }
    if (!result.random) {
        result.random = ProductionRandom;
    }
    return result;
}

ScopedOracleConnectEnvironment::ScopedOracleConnectEnvironment(OracleConnectEnvironment environment) {
    std::lock_guard<std::mutex> guard(EnvironmentLock());
    previous = std::move(InstalledEnvironment());
    InstalledEnvironment() = std::move(environment);
}

ScopedOracleConnectEnvironment::~ScopedOracleConnectEnvironment() {
    std::lock_guard<std::mutex> guard(EnvironmentLock());
    InstalledEnvironment() = std::move(previous);
}

ScopedOracleConnectCancellation::ScopedOracleConnectCancellation(std::function<bool()> cancelled) {
    previous = std::move(ThreadCancellation());
    ThreadCancellation() = std::move(cancelled);
}

ScopedOracleConnectCancellation::~ScopedOracleConnectCancellation() {
    ThreadCancellation() = std::move(previous);
}

bool OracleConnectCancelled() {
    const auto &cancelled = ThreadCancellation();
    return cancelled && cancelled();
}

namespace {

struct ResolveRequest {
    std::string host;
    uint16_t port = 0;
    bool started = false;
    bool done = false;
    std::vector<std::string> result;
    std::exception_ptr error;
};

// The bounded resolver pool. Its workers are detached and it is never
// destroyed: a worker may be inside a platform lookup that will not return for
// a long time, and neither joining it at exit nor destroying state it still
// uses is acceptable. The pool is reachable for the life of the process, so
// it is not a leak, merely permanent.
class ResolverPool {
public:
    static ResolverPool &Instance() {
        static auto *pool = new ResolverPool();
        return *pool;
    }

    std::vector<std::string> Resolve(const std::string &host, uint16_t port, const std::function<void()> &check,
                                     const std::function<std::chrono::milliseconds()> &time_left) {
        auto request = std::make_shared<ResolveRequest>();
        request->host = host;
        request->port = port;
        std::unique_lock<std::mutex> guard(lock);
        while (queue.size() >= MAX_RESOLVER_QUEUE) {
            check();
            changed.wait_for(guard, Slice(time_left));
        }
        queue.push_back(request);
        if (queue.size() > idle && workers < MAX_RESOLVER_WORKERS) {
            try {
                std::thread([this] { Work(); }).detach();
                workers++;
            } catch (const std::system_error &) {
                if (workers == 0) {
                    Withdraw(request);
                    throw OracleConnectError(ProtocolErrorKind::INVALID_STATE, ConnectFailure::RESOURCE_EXHAUSTED,
                                             "Oracle connect could not start a name-resolution worker");
                }
                // The workers there are will get to it.
            }
        }
        work_ready.notify_one();
        while (!request->done) {
            try {
                check();
            } catch (...) {
                // Given up on: dropped from the queue if no worker has taken
                // it yet, so a dead request never costs a worker any time.
                Withdraw(request);
                throw;
            }
            changed.wait_for(guard, Slice(time_left));
        }
        if (request->error) {
            std::rethrow_exception(request->error);
        }
        return request->result;
    }

    size_t WorkerCount() {
        std::lock_guard<std::mutex> guard(lock);
        return workers;
    }

private:
    ResolverPool() = default;

    static std::chrono::milliseconds Slice(const std::function<std::chrono::milliseconds()> &time_left) {
        const auto left = time_left();
        return (std::max)(std::chrono::milliseconds(1), (std::min)(left, std::chrono::milliseconds(100)));
    }

    // Called with `lock` held.
    void Withdraw(const std::shared_ptr<ResolveRequest> &request) {
        if (!request->started) {
            queue.erase(std::remove(queue.begin(), queue.end(), request), queue.end());
            changed.notify_all();
        }
    }

    void Work() {
        std::unique_lock<std::mutex> guard(lock);
        while (true) {
            idle++;
            work_ready.wait(guard, [this] { return !queue.empty(); });
            idle--;
            auto request = std::move(queue.front());
            queue.pop_front();
            request->started = true;
            changed.notify_all();
            guard.unlock();
            std::vector<std::string> result;
            std::exception_ptr error;
            try {
                result = ResolveOracleHost(request->host, request->port);
            } catch (...) {
                error = std::current_exception();
            }
            guard.lock();
            request->result = std::move(result);
            request->error = error;
            request->done = true;
            changed.notify_all();
        }
    }

    std::mutex lock;
    std::condition_variable work_ready;
    std::condition_variable changed;
    std::deque<std::shared_ptr<ResolveRequest>> queue;
    size_t workers = 0;
    size_t idle = 0;
};

} // namespace

std::vector<std::string> ResolveOracleHostOnPool(const std::string &host, uint16_t port,
                                                 const std::function<void()> &check,
                                                 const std::function<std::chrono::milliseconds()> &time_left) {
    return ResolverPool::Instance().Resolve(host, port, check, time_left);
}

size_t OracleResolverWorkerCount() {
    return ResolverPool::Instance().WorkerCount();
}

std::vector<ConnectAddress> PlanConnectOrder(const ConnectionConfig &config, const std::function<uint64_t()> &random) {
    const auto lists = EffectiveAddressLists(config);
    std::vector<ConnectAddress> result;
    for (const auto &list : ActiveChildren(lists, config.routing.failover, config.routing.load_balance, random)) {
        for (const auto &address : ActiveChildren(list.addresses, list.failover, list.load_balance, random)) {
            result.push_back(address);
        }
    }
    return result;
}

} // namespace oracle_scanner
