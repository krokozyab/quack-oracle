#pragma once

#include <cstdint>
#include <string>

namespace oracle_scanner {

enum class TransportProtocol { TCP, TCPS };

struct ConnectionConfig {
    std::string host;
    uint16_t port = 1521;
    std::string service_name;
    std::string user;
    std::string connection_id;
    std::string client_program;
    TransportProtocol protocol = TransportProtocol::TCP;
    uint32_t connect_timeout_seconds = 10;
    uint32_t read_timeout_seconds = 30;
    // TCPS-only settings. wallet_pem_file is an ewallet.pem-compatible PEM
    // bundle containing the client certificate/key and, when needed, its CA.
    std::string tls_server_name;
    std::string tls_sni_name;
    std::string tls_ca_file;
    // The server certificate's expected subject DN. It comes from a TNS
    // descriptor's (security=(ssl_server_cert_dn=...)) or from the secret, and
    // it is checked in addition to the hostname, never instead of it.
    std::string tls_server_cert_dn;
    std::string wallet_pem_file;
    std::string wallet_password;
};

void ValidateConnectionConfig(const ConnectionConfig &config);
std::string BuildConnectDescriptor(const ConnectionConfig &config);
// AUTH_CONNECT_STRING repeats the TNS descriptor during O5LOGON, but excludes
// the listener-only CID block. CONNECTION_ID remains part of the value.
std::string BuildAuthConnectString(const ConnectionConfig &config);

} // namespace oracle_scanner
