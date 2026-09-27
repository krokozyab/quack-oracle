#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace oracle_scanner {

enum class TransportProtocol { TCP, TCPS };

// One listener endpoint as the configuration names it. `host` is a DNS name or
// an IP literal; a name is resolved at connect time, and every address it
// resolves to is tried in the order the resolver returns them.
struct ConnectAddress {
    std::string host;
    uint16_t port = 1521;
    TransportProtocol protocol = TransportProtocol::TCP;
};

// One (ADDRESS_LIST=...), or the implicit list that a DESCRIPTION's own
// (ADDRESS=...) children form. FAILOVER and LOAD_BALANCE mean what Oracle
// Net says they mean, applied the way python-oracledb Thin applies them
// (connect_params.pyx, _set_active_children):
//   failover on,  load_balance off: every address, in the written order;
//   failover on,  load_balance on:  every address, shuffled per connection;
//   failover off, load_balance on:  one address, chosen at random;
//   failover off, load_balance off: the first address only.
struct ConnectAddressList {
    std::vector<ConnectAddress> addresses;
    bool failover = true;
    bool load_balance = false;
};

// Bounds on what a configuration may name. They exist so a descriptor cannot
// turn one connect into an unbounded amount of work.
constexpr size_t MAX_CONNECT_ADDRESSES = 16;
constexpr uint32_t MAX_CONNECT_RETRY_COUNT = 100;
constexpr uint32_t MAX_CONNECT_RETRY_DELAY_SECONDS = 3600;
constexpr uint32_t MAX_CONNECT_BUDGET_SECONDS = 3600;
// The overall budget when nothing sets one. It is at least the per-attempt
// transport timeout, so a single-address configuration behaves exactly as it
// did before the budget existed.
constexpr uint32_t DEFAULT_CONNECT_BUDGET_SECONDS = 60;

// How one physical connection is established: which addresses, in which
// order, how often, and within how long. Nothing here survives a successful
// connect or is shared between connects — every new physical session plans its
// own attempts from this, which is what keeps one attempt's redirect or
// shuffle out of a pool's configuration.
struct ConnectRouting {
    // Empty means the single address ConnectionConfig::host/port/protocol
    // names. Non-empty means a descriptor supplied the addresses, and
    // ConnectionConfig::host must then be empty.
    std::vector<ConnectAddressList> address_lists;
    // The DESCRIPTION-level FAILOVER and LOAD_BALANCE, applied across the
    // address lists with the same four rules as within one.
    bool failover = true;
    bool load_balance = false;
    // RETRY_COUNT: how many more passes over the whole address order after the
    // first one fails. RETRY_DELAY: the pause before each such pass.
    uint32_t retry_count = 0;
    uint32_t retry_delay_seconds = 1;
    // The overall budget for one physical connection — every attempt, every
    // redirect and every retry delay together. 0 means the default. A
    // descriptor's CONNECT_TIMEOUT sets it; see README for why that differs
    // from Oracle's per-attempt reading.
    uint32_t connect_budget_seconds = 0;
};

struct ConnectionConfig {
    // The single-address form, kept for HOST/PORT/SERVICE_NAME secrets. When
    // routing.address_lists is non-empty, host is empty and port is unused.
    std::string host;
    uint16_t port = 1521;
    std::string service_name;
    // Optional CONNECT_DATA elements a descriptor may carry. INSTANCE_NAME pins
    // the connection to one RAC instance; SERVER is DEDICATED or SHARED.
    std::string instance_name;
    std::string server_type;
    std::string user;
    std::string connection_id;
    std::string client_program;
    // TCPS when the configuration uses TLS anywhere: the single address's
    // protocol, or TCPS if any descriptor address is TCPS. The TLS and wallet
    // fields below require it.
    TransportProtocol protocol = TransportProtocol::TCP;
    // The per-attempt transport timeout: TCP connect plus, for TCPS, the TLS
    // handshake, for one resolved address.
    uint32_t connect_timeout_seconds = 10;
    uint32_t read_timeout_seconds = 30;
    ConnectRouting routing;
    // Asked before every connect attempt and during every retry delay; true
    // stops the connect with ConnectFailure::CANCELLED. Optional. The DuckDB
    // adapter points it at the query's interrupt flag. It never takes part in
    // pooling or comparison.
    std::function<bool()> connect_cancelled;
    // TCPS-only settings. wallet_pem_file is an ewallet.pem-compatible PEM
    // bundle containing the client certificate/key and, when needed, its CA.
    // tls_server_name, when set, is the name every hop's certificate is checked
    // against; when empty, each attempt checks against the HOST of the address
    // the user configured for it — never against a host a redirect named.
    std::string tls_server_name;
    std::string tls_sni_name;
    std::string tls_ca_file;
    // The server certificate's expected subject DN. It comes from a TNS
    // descriptor's (security=(ssl_server_cert_dn=...)) or from the secret, and
    // it is checked in addition to the hostname, never instead of it, on every
    // hop including redirect targets.
    std::string tls_server_cert_dn;
    std::string wallet_pem_file;
    std::string wallet_password;
};

void ValidateConnectionConfig(const ConnectionConfig &config);

// Whether `value` is an IPv4 or IPv6 literal rather than a name.
bool IsIpLiteral(const std::string &value);

// The address lists a connect actually works from: routing.address_lists, or
// one list holding the single host/port/protocol address.
std::vector<ConnectAddressList> EffectiveAddressLists(const ConnectionConfig &config);

// The overall connect budget in seconds, with the default applied.
uint32_t EffectiveConnectBudgetSeconds(const ConnectionConfig &config);

// A stable text naming the logical target — every configured address with its
// protocol, the service and the routing policy — for keying pools. It carries
// no credentials.
std::string ConnectionTargetKey(const ConnectionConfig &config);

// The connect data sent in CONNECT for one address, and the same without the
// listener-only CID block for O5LOGON's AUTH_CONNECT_STRING. CONNECTION_ID is
// part of both.
std::string BuildConnectDescriptor(const ConnectionConfig &config, const ConnectAddress &address);
std::string BuildAuthConnectString(const ConnectionConfig &config, const ConnectAddress &address);
// The single-address forms, for configurations that name host/port directly.
std::string BuildConnectDescriptor(const ConnectionConfig &config);
// AUTH_CONNECT_STRING repeats the TNS descriptor during O5LOGON, but excludes
// the listener-only CID block. CONNECTION_ID remains part of the value.
std::string BuildAuthConnectString(const ConnectionConfig &config);

} // namespace oracle_scanner
