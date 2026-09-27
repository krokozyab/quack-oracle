// Turning a named DuckDB secret into an Oracle connection configuration, with
// the endpoint, TLS, and wallet field combinations validated before any
// transport work.

#include "oracle_adapter.hpp"

#include "oracle_scanner/descriptor_parser.hpp"
#include "oracle_scanner/wallet_archive.hpp"

#include "duckdb/catalog/catalog_transaction.hpp"
#include "duckdb/main/secret/secret.hpp"
#include "duckdb/main/secret/secret_manager.hpp"

#include <string>

namespace duckdb {

namespace {

std::string RequireString(const KeyValueSecret &secret, const char *key) {
    const auto value = secret.TryGetValue(key, true);
    if (value.IsNull() || value.ToString().empty()) {
        throw BinderException("Oracle secret requires a non-empty %s", key);
    }
    return value.ToString();
}

uint32_t OptionalUInt(const KeyValueSecret &secret, const char *key, uint32_t default_value) {
    const auto value = secret.TryGetValue(key);
    if (value.IsNull()) {
        return default_value;
    }
    return value.GetValue<uint32_t>();
}

std::string OptionalString(const KeyValueSecret &secret, const char *key) {
    const auto value = secret.TryGetValue(key);
    return value.IsNull() ? std::string() : value.ToString();
}

} // namespace

void RequireAutoCommit(ClientContext &context, const char *function_name) {
    if (!context.transaction.IsAutoCommit()) {
        throw BinderException("%s cannot run inside an explicit DuckDB transaction", function_name);
    }
}

ConnectionConfig ConnectionFromSecret(ClientContext &context, const std::string &secret_name, std::string &password) {
    auto transaction = CatalogTransaction::GetSystemCatalogTransaction(context);
    const auto secret_entry = SecretManager::Get(context).GetSecretByName(transaction, secret_name);
    if (!secret_entry || !secret_entry->secret) {
        throw BinderException("Oracle secret '%s' was not found", secret_name);
    }
    const auto *secret = dynamic_cast<const KeyValueSecret *>(secret_entry->secret.get());
    if (!secret || secret->GetType() != "oracle") {
        throw BinderException("Secret '%s' is not an Oracle secret", secret_name);
    }
    ConnectionConfig config;
    config.user = RequireString(*secret, "user");
    password = RequireString(*secret, "password");
    config.connect_timeout_seconds = OptionalUInt(*secret, "connect_timeout", 10);
    // An interrupted query stops a connect that is still working through
    // addresses and retries. Held weakly: this config outlives the statement
    // in bind data and pools, and must never keep a context alive.
    const weak_ptr<ClientContext> weak_context = context.shared_from_this();
    config.connect_cancelled = [weak_context]() {
        const auto live = weak_context.lock();
        return live && live->interrupted.load();
    };
    config.read_timeout_seconds = OptionalUInt(*secret, "read_timeout", 30);

    const auto tns_alias = OptionalString(*secret, "tns_alias");
    const auto tls_server_name = OptionalString(*secret, "tls_server_name");
    const auto tls_sni_name = OptionalString(*secret, "tls_sni_name");
    const auto tls_ca_file = OptionalString(*secret, "tls_ca_file");
    const auto tls_server_cert_dn = OptionalString(*secret, "tls_server_cert_dn");
    const auto wallet_pem_file = OptionalString(*secret, "wallet_file");
    const auto wallet_password = OptionalString(*secret, "wallet_password");
    const bool has_tls_options = !tls_server_name.empty() || !tls_sni_name.empty() || !tls_ca_file.empty() ||
                                 !tls_server_cert_dn.empty() || !wallet_pem_file.empty() || !wallet_password.empty();
    const auto connect_descriptor = OptionalString(*secret, "connect_descriptor");
    const auto protocol = secret->TryGetValue("protocol");
    // Where the addresses come from: HOST/PORT/SERVICE_NAME, a TNS_ALIAS looked
    // up in a wallet's tnsnames.ora, or a CONNECT_DESCRIPTOR given inline.
    // Exactly one, so no setting is ever silently overridden by another.
    const bool names_host = !OptionalString(*secret, "host").empty() ||
                            !OptionalString(*secret, "service_name").empty() || !secret->TryGetValue("port").IsNull();
    if (!protocol.IsNull() && StringUtil::Lower(protocol.ToString()) != "tcp" &&
        StringUtil::Lower(protocol.ToString()) != "tcps") {
        throw BinderException("Oracle secret PROTOCOL must be 'tcp' or 'tcps'");
    }
    if (!tns_alias.empty() && !connect_descriptor.empty()) {
        throw BinderException("Oracle TNS_ALIAS and CONNECT_DESCRIPTOR cannot be combined");
    }
    const char *descriptor_source = !tns_alias.empty() ? "TNS_ALIAS" : "CONNECT_DESCRIPTOR";
    const bool from_descriptor = !tns_alias.empty() || !connect_descriptor.empty();
    if (from_descriptor) {
        if (names_host) {
            throw BinderException("Oracle %s cannot be combined with HOST, PORT, or SERVICE_NAME", descriptor_source);
        }
        if (!tns_alias.empty() && wallet_pem_file.empty()) {
            throw BinderException("Oracle TNS_ALIAS requires WALLET_FILE pointing to a wallet ZIP");
        }
        try {
            const auto descriptor =
                !tns_alias.empty() ? oracle_scanner::FindTnsAliasDescriptor(
                                         oracle_scanner::ReadWalletTnsNamesArchive(wallet_pem_file), tns_alias)
                                   : connect_descriptor;
            const auto parsed = oracle_scanner::ParseConnectDescriptor(descriptor);
            config.routing.address_lists = parsed.address_lists;
            config.routing.failover = parsed.failover;
            config.routing.load_balance = parsed.load_balance;
            if (parsed.retry_count) {
                config.routing.retry_count = *parsed.retry_count;
            }
            if (parsed.retry_delay_seconds) {
                config.routing.retry_delay_seconds = *parsed.retry_delay_seconds;
            }
            if (parsed.connect_timeout_seconds) {
                config.routing.connect_budget_seconds = *parsed.connect_timeout_seconds;
            }
            if (parsed.transport_connect_timeout_seconds) {
                // The per-attempt timeout has one home. A secret that sets it
                // too has to agree, rather than one of them quietly winning.
                if (!secret->TryGetValue("connect_timeout").IsNull() &&
                    config.connect_timeout_seconds != *parsed.transport_connect_timeout_seconds) {
                    throw BinderException("Oracle CONNECT_TIMEOUT disagrees with the %s TRANSPORT_CONNECT_TIMEOUT",
                                          descriptor_source);
                }
                config.connect_timeout_seconds = *parsed.transport_connect_timeout_seconds;
            }
            config.service_name = parsed.service_name;
            config.instance_name = parsed.instance_name;
            config.server_type = parsed.server_type;
            config.protocol = oracle_scanner::TransportProtocol::TCP;
            for (const auto &endpoint : parsed.endpoints) {
                if (endpoint.protocol == oracle_scanner::TransportProtocol::TCPS) {
                    config.protocol = oracle_scanner::TransportProtocol::TCPS;
                }
            }
            // The descriptor's own DN, when it names one. A secret that also
            // names one has to agree: silently preferring either would make the
            // check depend on where the value came from.
            if (!parsed.server_cert_dn.empty()) {
                if (!tls_server_cert_dn.empty() && tls_server_cert_dn != parsed.server_cert_dn) {
                    throw BinderException("Oracle TLS_SERVER_CERT_DN disagrees with the DN the %s descriptor names",
                                          descriptor_source);
                }
                config.tls_server_cert_dn = parsed.server_cert_dn;
            }
            if (!protocol.IsNull()) {
                // PROTOCOL beside a descriptor is an assertion about every
                // address in it, and a mixed descriptor cannot satisfy it.
                const auto wanted = StringUtil::Lower(protocol.ToString()) == "tcps"
                                        ? oracle_scanner::TransportProtocol::TCPS
                                        : oracle_scanner::TransportProtocol::TCP;
                for (const auto &endpoint : parsed.endpoints) {
                    if (endpoint.protocol != wanted) {
                        throw BinderException("Oracle %s protocol does not match PROTOCOL '%s'", descriptor_source,
                                              StringUtil::Lower(protocol.ToString()));
                    }
                }
            }
        } catch (const oracle_scanner::ProtocolError &error) {
            throw BinderException("Oracle %s could not be resolved: %s", descriptor_source, error.what());
        }
    } else {
        config.host = RequireString(*secret, "host");
        config.service_name = RequireString(*secret, "service_name");
        const auto port = OptionalUInt(*secret, "port", 1521);
        if (port == 0 || port > 65535) {
            throw BinderException("Oracle secret '%s' has an invalid port", secret_name);
        }
        config.port = static_cast<uint16_t>(port);
    }
    if (protocol.IsNull()) {
        if (has_tls_options && config.protocol != oracle_scanner::TransportProtocol::TCPS) {
            throw BinderException("Oracle TLS_* and WALLET_* options require PROTOCOL 'tcps'");
        }
    } else {
        const auto normalized = StringUtil::Lower(protocol.ToString());
        if (normalized == "tcps") {
            if (!from_descriptor) {
                config.protocol = oracle_scanner::TransportProtocol::TCPS;
            }
            config.tls_server_name = tls_server_name;
            config.tls_sni_name = tls_sni_name;
            config.tls_ca_file = tls_ca_file;
            if (config.tls_server_cert_dn.empty()) {
                config.tls_server_cert_dn = tls_server_cert_dn;
            }
            config.wallet_pem_file = wallet_pem_file;
            config.wallet_password = wallet_password;
        } else if (normalized != "tcp") {
            throw BinderException("Oracle secret PROTOCOL must be 'tcp' or 'tcps'");
        } else if (has_tls_options) {
            throw BinderException("Oracle TLS_* and WALLET_* options require PROTOCOL 'tcps'");
        }
    }
    if (from_descriptor && config.protocol == oracle_scanner::TransportProtocol::TCPS) {
        config.tls_server_name = tls_server_name;
        config.tls_sni_name = tls_sni_name;
        config.tls_ca_file = tls_ca_file;
        if (config.tls_server_cert_dn.empty()) {
            config.tls_server_cert_dn = tls_server_cert_dn;
        }
        config.wallet_pem_file = wallet_pem_file;
        config.wallet_password = wallet_password;
    }
    return config;
}

} // namespace duckdb
