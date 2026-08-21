#include "duckdb.hpp"
#include "duckdb/main/secret/secret.hpp"

namespace duckdb {

static unique_ptr<BaseSecret> CreateOracleSecret(ClientContext &, CreateSecretInput &input) {
    auto secret = make_uniq<KeyValueSecret>(input.scope, input.type, input.provider, input.name);
    for (const auto &key : {"host", "port", "service_name", "user", "password", "protocol", "connect_timeout",
                            "read_timeout", "tls_server_name", "tls_sni_name", "tls_ca_file", "tls_server_cert_dn", "wallet_file",
                            "wallet_password", "tns_alias"}) {
        secret->TrySetValue(key, input);
    }
    secret->redact_keys = {"password", "wallet_password"};
    return std::move(secret);
}

void RegisterOracleSecrets(ExtensionLoader &loader) {
    SecretType type;
    type.name = "oracle";
    type.deserializer = KeyValueSecret::Deserialize<KeyValueSecret>;
    type.default_provider = "config";
    type.extension = "oracle_scanner";
    loader.RegisterSecretType(std::move(type));

    CreateSecretFunction function;
    function.secret_type = "oracle";
    function.provider = "config";
    function.function = CreateOracleSecret;
    function.named_parameters["host"] = LogicalType::VARCHAR;
    function.named_parameters["port"] = LogicalType::UINTEGER;
    function.named_parameters["service_name"] = LogicalType::VARCHAR;
    function.named_parameters["user"] = LogicalType::VARCHAR;
    function.named_parameters["password"] = LogicalType::VARCHAR;
    function.named_parameters["protocol"] = LogicalType::VARCHAR;
    function.named_parameters["connect_timeout"] = LogicalType::UINTEGER;
    function.named_parameters["read_timeout"] = LogicalType::UINTEGER;
    function.named_parameters["tls_server_name"] = LogicalType::VARCHAR;
    function.named_parameters["tls_sni_name"] = LogicalType::VARCHAR;
    function.named_parameters["tls_ca_file"] = LogicalType::VARCHAR;
    function.named_parameters["tls_server_cert_dn"] = LogicalType::VARCHAR;
    function.named_parameters["wallet_file"] = LogicalType::VARCHAR;
    function.named_parameters["wallet_password"] = LogicalType::VARCHAR;
    function.named_parameters["tns_alias"] = LogicalType::VARCHAR;
    loader.RegisterFunction(std::move(function));
}

} // namespace duckdb
