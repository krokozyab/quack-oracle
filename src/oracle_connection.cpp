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
    const auto protocol = secret->TryGetValue("protocol");
    if (!tns_alias.empty()) {
        if (!OptionalString(*secret, "host").empty() || !OptionalString(*secret, "service_name").empty() ||
            !secret->TryGetValue("port").IsNull()) {
            throw BinderException("Oracle TNS_ALIAS cannot be combined with HOST, PORT, or SERVICE_NAME");
        }
        if (wallet_pem_file.empty()) {
            throw BinderException("Oracle TNS_ALIAS requires WALLET_FILE pointing to a wallet ZIP");
        }
        try {
            const auto descriptor = oracle_scanner::FindTnsAliasDescriptor(
                oracle_scanner::ReadWalletTnsNamesArchive(wallet_pem_file), tns_alias);
            const auto parsed = oracle_scanner::ParseConnectDescriptor(descriptor);
            if (parsed.endpoints.size() != 1) {
                throw BinderException("Oracle TNS_ALIAS must resolve to exactly one ADDRESS");
            }
            config.host = parsed.endpoints[0].host;
            config.port = parsed.endpoints[0].port;
            config.service_name = parsed.service_name;
            config.protocol = parsed.endpoints[0].protocol;
            // The descriptor's own DN, when it names one. A secret that also
            // names one has to agree: silently preferring either would make the
            // check depend on where the value came from.
            if (!parsed.server_cert_dn.empty()) {
                if (!tls_server_cert_dn.empty() && tls_server_cert_dn != parsed.server_cert_dn) {
                    throw BinderException(
                        "Oracle TLS_SERVER_CERT_DN disagrees with the DN the TNS_ALIAS descriptor names");
                }
                config.tls_server_cert_dn = parsed.server_cert_dn;
            }
        } catch (const oracle_scanner::ProtocolError &error) {
            throw BinderException("Oracle TNS_ALIAS could not be resolved: %s", error.what());
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
            if (!tns_alias.empty() && config.protocol != oracle_scanner::TransportProtocol::TCPS) {
                throw BinderException("Oracle TNS_ALIAS protocol does not match PROTOCOL 'tcps'");
            }
            config.protocol = oracle_scanner::TransportProtocol::TCPS;
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
        } else if (!tns_alias.empty() && config.protocol != oracle_scanner::TransportProtocol::TCP) {
            throw BinderException("Oracle TNS_ALIAS protocol does not match PROTOCOL 'tcp'");
        } else if (has_tls_options) {
            throw BinderException("Oracle TLS_* and WALLET_* options require PROTOCOL 'tcps'");
        }
    }
    if (!tns_alias.empty() && config.protocol == oracle_scanner::TransportProtocol::TCPS) {
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
