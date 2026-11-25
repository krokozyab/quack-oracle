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

#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

namespace duckdb {

using oracle_scanner::OracleSessionPool;

namespace {

// What a pooled session must agree on before it can answer a second statement.
// The password and the TLS/wallet settings take part only as a hash: a secret
// replaced under the same name (a rotated password, a tightened certificate
// check) must not keep logging in the old way, which with a wrong password
// counts towards the account's lockout.
std::string PoolKey(const std::string &secret_name, const ConnectionConfig &config, const std::string &password) {
    const auto credentials =
        std::hash<std::string> {}(password + '\x1f' + config.wallet_password + '\x1f' + config.wallet_pem_file + '\x1f' +
                                  config.tls_ca_file + '\x1f' + config.tls_server_cert_dn + '\x1f' +
                                  config.tls_server_name + '\x1f' + config.tls_sni_name + '\x1f' +
                                  config.client_identifier + '\x1f' + config.module + '\x1f' + config.action +
                                  '\x1f' + config.client_info);
    // The target key names every configured address, the service and the
    // routing policy — never where one connect happened to land — so two
    // sessions share a pool only when they would be opened the same way.
    return secret_name + "\x1f" + oracle_scanner::ConnectionTargetKey(config) + "\x1f" + config.user + "\x1f" +
           (config.protocol == oracle_scanner::TransportProtocol::TCPS ? "tcps" : "tcp") + "\x1f" +
           std::to_string(credentials);
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
                                             const std::string &catalog_name, const ConnectionConfig &original_config,
                                             const std::string &password) {
    auto config = original_config;
    Value cache_setting;
    if (context.TryGetCurrentSetting("oracle_statement_cache", cache_setting) && !cache_setting.IsNull()) {
        config.statement_cache = BooleanValue::Get(cache_setting);
    }
    OracleSessionHandle handle;
    // A transaction that has written to this catalog already holds a session,
    // and its uncommitted rows exist on that session and nowhere else. Reading
    // through anything else would answer from before the write.
    if (!catalog_name.empty()) {
        handle.borrowed = TryTransactionSession(context, catalog_name);
        if (handle.borrowed) {
            handle.Get().SetStatementCacheEnabled(config.statement_cache);
            return handle;
        }
    }
    const auto maximum_sessions = ConfiguredPoolSize(context);
    if (maximum_sessions > 0) {
        auto state = context.registered_state->GetOrCreate<OraclePoolState>("oracle_scanner.session_pool");
        auto &pool = state->PoolFor(PoolKey(secret_name, config, password), maximum_sessions, config, password);
        try {
            handle.lease = pool.Acquire();
            handle.Get().SetStatementCacheEnabled(config.statement_cache);
            return handle;
        } catch (const oracle_scanner::OracleSessionPoolExhausted &) {
            // Every pooled session is busy. One query can hold several at once
            // — a join across two Oracle tables does — and failing it to keep a
            // bound would trade a real answer for a number in a setting.
        }
    }
    handle.owned = oracle_scanner::OpenOracleSession(config, password);
    handle.Get().SetStatementCacheEnabled(config.statement_cache);
    return handle;
}

void RegisterOracleSessionPool(ExtensionLoader &loader) {
    DBConfig::GetConfig(loader.GetDatabaseInstance())
        .AddExtensionOption("oracle_statement_cache", "Reuse up to 20 parsed scalar queries per native Oracle session.",
                            LogicalType::BOOLEAN, Value::BOOLEAN(true));
    DBConfig::GetConfig(loader.GetDatabaseInstance())
        .AddExtensionOption("oracle_session_pool_size",
                            "How many authenticated Oracle sessions one DuckDB connection keeps for reuse, per secret. "
                            "0 opens a fresh session for every statement.",
                            LogicalType::BIGINT, Value::BIGINT(4));
}

} // namespace duckdb
