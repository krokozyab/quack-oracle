// Reusing an authenticated Oracle session across statements.
//
// Opening one costs a TCP connect, a TLS handshake and an O5LOGON round trip —
// about a second against a cloud endpoint — and until now every statement paid
// it. The pool is per DuckDB connection and per secret identity, which is the
// only sharing that leaks nothing: the session was authenticated with that
// connection's own credentials, for that endpoint and that user.
//
// Only reads are pooled. A write pins its own session to the DuckDB transaction
// and a callable may hand a cursor back that outlives the statement, so neither
// can return a session to a pool without more care than the win is worth.

#include "oracle_adapter.hpp"

#include "duckdb/main/client_context.hpp"
#include "duckdb/main/client_context_state.hpp"
#include "duckdb/main/database.hpp"

#include "oracle_scanner/session_factory.hpp"
#include "oracle_scanner/session_pool.hpp"

#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

namespace duckdb {

using oracle_scanner::OracleSessionPool;

namespace {

// What a pooled session must agree on before it can answer a second statement.
// The password is deliberately not part of it: it is never copied anywhere it
// does not already have to be, and a caller reaching this key already holds the
// connection whose credentials opened the session.
std::string PoolKey(const std::string &secret_name, const ConnectionConfig &config) {
    return secret_name + "\x1f" + config.host + "\x1f" + std::to_string(config.port) + "\x1f" + config.service_name +
           "\x1f" + config.user + "\x1f" +
           (config.protocol == oracle_scanner::TransportProtocol::TCPS ? "tcps" : "tcp");
}

struct OraclePoolState final : ClientContextState {
    std::mutex lock;
    std::unordered_map<std::string, std::unique_ptr<OracleSessionPool>> pools;

    OracleSessionPool &PoolFor(const std::string &key, size_t maximum_sessions, const ConnectionConfig &config,
                               const std::string &password) {
        std::lock_guard<std::mutex> guard(lock);
        const auto existing = pools.find(key);
        if (existing != pools.end()) {
            return *existing->second;
        }
        auto pool = std::make_unique<OracleSessionPool>(maximum_sessions, [config, password]() {
            return std::shared_ptr<OracleSession>(oracle_scanner::OpenOracleSession(config, password));
        });
        auto &reference = *pool;
        pools.emplace(key, std::move(pool));
        return reference;
    }
};

size_t ConfiguredPoolSize(ClientContext &context) {
    Value setting;
    if (!context.TryGetCurrentSetting("oracle_session_pool_size", setting) || setting.IsNull()) {
        return 0;
    }
    const auto configured = BigIntValue::Get(setting);
    if (configured <= 0) {
        return 0;
    }
    return static_cast<size_t>(configured);
}

} // namespace

OracleSession &OracleSessionHandle::Get() const {
    if (borrowed) {
        return *borrowed;
    }
    if (owned) {
        return *owned;
    }
    return lease.Get();
}

void OracleSessionHandle::Poison() noexcept {
    // A session whose statement failed carries state this side cannot describe,
    // so it never goes back into the pool. An unpooled one is simply closed
    // when the handle dies.
    lease.Poison();
}

OracleSessionHandle AcquireOracleReadSession(ClientContext &context, const std::string &secret_name,
                                             const std::string &catalog_name, const ConnectionConfig &config,
                                             const std::string &password) {
    OracleSessionHandle handle;
    // A transaction that has written to this catalog already holds a session,
    // and its uncommitted rows exist on that session and nowhere else. Reading
    // through anything else would answer from before the write.
    if (!catalog_name.empty()) {
        handle.borrowed = TryTransactionSession(context, catalog_name);
        if (handle.borrowed) {
            return handle;
        }
    }
    const auto maximum_sessions = ConfiguredPoolSize(context);
    if (maximum_sessions > 0) {
        auto state = context.registered_state->GetOrCreate<OraclePoolState>("oracle_scanner.session_pool");
        auto &pool = state->PoolFor(PoolKey(secret_name, config), maximum_sessions, config, password);
        try {
            handle.lease = pool.Acquire();
            return handle;
        } catch (const oracle_scanner::ProtocolError &error) {
            if (error.Kind() != oracle_scanner::ProtocolErrorKind::LIMIT_EXCEEDED) {
                throw;
            }
            // Every pooled session is busy. One query can hold several at once
            // — a join across two Oracle tables does — and failing it to keep a
            // bound would trade a real answer for a number in a setting.
        }
    }
    handle.owned = oracle_scanner::OpenOracleSession(config, password);
    return handle;
}

void RegisterOracleSessionPool(ExtensionLoader &loader) {
    DBConfig::GetConfig(loader.GetDatabaseInstance())
        .AddExtensionOption("oracle_session_pool_size",
                            "How many authenticated Oracle sessions one DuckDB connection keeps for reuse, per secret. "
                            "0 opens a fresh session for every statement.",
                            LogicalType::BIGINT, Value::BIGINT(4));
}

} // namespace duckdb
