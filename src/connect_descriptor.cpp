#include "oracle_scanner/connect_descriptor.hpp"
#include "oracle_scanner/client_identity.hpp"
#include "oracle_scanner/protocol_error.hpp"

#include <cctype>
#include <sstream>

#if defined(_WIN32)
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

namespace oracle_scanner {

static bool IsDescriptorAtom(const std::string &value) {
    if (value.empty()) {
        return false;
    }
    for (auto character : value) {
        auto byte = static_cast<unsigned char>(character);
        if (!(std::isalnum(byte) || character == '.' || character == '_' || character == '-')) {
            return false;
        }
    }
    return true;
}

static bool IsSafeIpv6Literal(const std::string &value) {
#if defined(_WIN32)
    IN6_ADDR address {};
    return InetPtonA(AF_INET6, value.c_str(), &address) == 1;
#else
    in6_addr address {};
    return inet_pton(AF_INET6, value.c_str(), &address) == 1;
#endif
}

void ValidateConnectionConfig(const ConnectionConfig &config) {
    if (config.host.size() > 255 || config.tls_server_name.size() > 255 || config.tls_sni_name.size() > 255) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "Oracle host or TLS name exceeds the supported size");
    }
    if (!IsDescriptorAtom(config.host) && !IsSafeIpv6Literal(config.host)) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle host is empty or contains descriptor syntax");
    }
    if (!IsDescriptorAtom(config.service_name)) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED,
                            "Oracle service name is empty or contains descriptor syntax");
    }
    if (config.port == 0) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle port must be between 1 and 65535");
    }
    if (config.connection_id.size() > 128 || config.connection_id.find_first_of("()\0") != std::string::npos) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle connection id contains descriptor syntax");
    }
    if (config.connect_timeout_seconds == 0 || config.connect_timeout_seconds > 3600 ||
        config.read_timeout_seconds == 0 || config.read_timeout_seconds > 86400) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "Oracle timeout is outside the supported range");
    }
    if (!config.tls_server_name.empty() && !IsDescriptorAtom(config.tls_server_name)) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle TLS server name contains descriptor syntax");
    }
    if (!config.tls_sni_name.empty() && !IsDescriptorAtom(config.tls_sni_name)) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle TLS SNI name contains descriptor syntax");
    }
    if (config.tls_ca_file.size() > 4096 || config.tls_ca_file.find('\0') != std::string::npos ||
        config.wallet_pem_file.size() > 4096 || config.wallet_pem_file.find('\0') != std::string::npos ||
        config.wallet_password.size() > 32767 || config.wallet_password.find('\0') != std::string::npos) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "Oracle TLS wallet configuration exceeds supported bounds");
    }
    if (config.protocol == TransportProtocol::TCP &&
        (!config.tls_server_name.empty() || !config.tls_sni_name.empty() || !config.tls_ca_file.empty() ||
         !config.wallet_pem_file.empty() || !config.wallet_password.empty())) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle TLS options require PROTOCOL 'tcps'");
    }
}

static std::string BuildDescriptor(const ConnectionConfig &config, bool include_cid) {
    ValidateConnectionConfig(config);
    const auto identity = CurrentOracleClientIdentity(config.client_program);
    std::ostringstream result;
    result << "(DESCRIPTION=(ADDRESS=(PROTOCOL="
           << (config.protocol == TransportProtocol::TCPS ? "tcps" : "tcp") << ")(HOST=" << config.host
           << ")(PORT=" << config.port << "))(CONNECT_DATA=(SERVICE_NAME=" << config.service_name << ')';
    if (include_cid) {
        result << "(CID=(PROGRAM=" << identity.program << ")(HOST=" << identity.machine << ")(USER=" << identity.os_user
               << "))";
    }
    if (!config.connection_id.empty()) {
        result << "(CONNECTION_ID=" << config.connection_id << ')';
    }
    result << "))";
    auto descriptor = result.str();
    if (descriptor.size() > 65535) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "Oracle connect descriptor exceeds 65535 bytes");
    }
    return descriptor;
}

std::string BuildConnectDescriptor(const ConnectionConfig &config) {
    return BuildDescriptor(config, true);
}

std::string BuildAuthConnectString(const ConnectionConfig &config) {
    return BuildDescriptor(config, false);
}

} // namespace oracle_scanner
