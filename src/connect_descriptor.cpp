#include "oracle_scanner/connect_descriptor.hpp"
#include "oracle_scanner/client_identity.hpp"
#include "oracle_scanner/protocol_error.hpp"

#include <algorithm>
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

bool IsIpLiteral(const std::string &value) {
#if defined(_WIN32)
    IN_ADDR ipv4 {};
    IN6_ADDR ipv6 {};
    return InetPtonA(AF_INET, value.c_str(), &ipv4) == 1 || InetPtonA(AF_INET6, value.c_str(), &ipv6) == 1;
#else
    in_addr ipv4 {};
    in6_addr ipv6 {};
    return inet_pton(AF_INET, value.c_str(), &ipv4) == 1 || inet_pton(AF_INET6, value.c_str(), &ipv6) == 1;
#endif
}

static void ValidateAddress(const std::string &host, uint16_t port) {
    if (host.size() > 255) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "Oracle host or TLS name exceeds the supported size");
    }
    if (!IsDescriptorAtom(host) && !IsSafeIpv6Literal(host)) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle host is empty or contains descriptor syntax");
    }
    if (port == 0) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle port must be between 1 and 65535");
    }
}

static std::string Upper(std::string value) {
    for (auto &character : value) {
        character = static_cast<char>(std::toupper(static_cast<unsigned char>(character)));
    }
    return value;
}

static void ValidateAddresses(const ConnectionConfig &config) {
    const auto &routing = config.routing;
    if (routing.address_lists.empty()) {
        ValidateAddress(config.host, config.port);
    } else {
        // One source of addresses, never two: a host beside a descriptor's
        // addresses would leave it unclear which one a connect uses.
        if (!config.host.empty()) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED,
                                "Oracle configuration names both a host and a descriptor address list");
        }
        size_t total = 0;
        bool any_tcps = false;
        for (const auto &list : routing.address_lists) {
            if (list.addresses.empty()) {
                throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle address list is empty");
            }
            for (const auto &address : list.addresses) {
                if (++total > MAX_CONNECT_ADDRESSES) {
                    throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED,
                                        "Oracle configuration names too many addresses");
                }
                ValidateAddress(address.host, address.port);
                any_tcps = any_tcps || address.protocol == TransportProtocol::TCPS;
            }
        }
        // `protocol` says whether TLS is in play at all, which is what decides
        // whether TLS settings are loaded and allowed. It has to agree with the
        // addresses rather than be a second opinion about them.
        if (any_tcps != (config.protocol == TransportProtocol::TCPS)) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED,
                                "Oracle configuration protocol disagrees with its descriptor addresses");
        }
    }
    if (routing.retry_count > MAX_CONNECT_RETRY_COUNT) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "Oracle RETRY_COUNT exceeds the supported maximum");
    }
    if (routing.retry_delay_seconds > MAX_CONNECT_RETRY_DELAY_SECONDS ||
        routing.connect_budget_seconds > MAX_CONNECT_BUDGET_SECONDS) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "Oracle connect timing exceeds the supported maximum");
    }
    if (!config.instance_name.empty() && !IsDescriptorAtom(config.instance_name)) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle instance name contains descriptor syntax");
    }
    if (!config.server_type.empty() && Upper(config.server_type) != "DEDICATED" &&
        Upper(config.server_type) != "SHARED") {
        throw ProtocolError(ProtocolErrorKind::UNSUPPORTED, "Oracle SERVER must be DEDICATED or SHARED");
    }
}

std::vector<ConnectAddressList> EffectiveAddressLists(const ConnectionConfig &config) {
    if (!config.routing.address_lists.empty()) {
        return config.routing.address_lists;
    }
    ConnectAddressList single;
    single.addresses.push_back({config.host, config.port, config.protocol});
    return {single};
}

uint32_t EffectiveConnectBudgetSeconds(const ConnectionConfig &config) {
    if (config.routing.connect_budget_seconds != 0) {
        return config.routing.connect_budget_seconds;
    }
    return (std::max)(DEFAULT_CONNECT_BUDGET_SECONDS, config.connect_timeout_seconds);
}

std::string ConnectionTargetKey(const ConnectionConfig &config) {
    std::ostringstream result;
    for (const auto &list : EffectiveAddressLists(config)) {
        result << '[' << (list.failover ? 'F' : 'f') << (list.load_balance ? 'L' : 'l');
        for (const auto &address : list.addresses) {
            result << ' ' << (address.protocol == TransportProtocol::TCPS ? "tcps" : "tcp") << "://" << address.host
                   << ':' << address.port;
        }
        result << ']';
    }
    const auto &routing = config.routing;
    result << '/' << config.service_name << '/' << config.instance_name << '/' << Upper(config.server_type) << '/'
           << (routing.failover ? 'F' : 'f') << (routing.load_balance ? 'L' : 'l') << '/' << routing.retry_count << '/'
           << routing.retry_delay_seconds << '/' << routing.connect_budget_seconds << '/'
           << config.connect_timeout_seconds;
    return result.str();
}

void ValidateConnectionConfig(const ConnectionConfig &config) {
    if (config.tls_server_name.size() > 255 || config.tls_sni_name.size() > 255) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "Oracle host or TLS name exceeds the supported size");
    }
    ValidateAddresses(config);
    if (!IsDescriptorAtom(config.service_name)) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED,
                            "Oracle service name is empty or contains descriptor syntax");
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

static std::string BuildDescriptor(const ConnectionConfig &config, const ConnectAddress &address, bool include_cid) {
    ValidateConnectionConfig(config);
    ValidateAddress(address.host, address.port);
    const auto identity = CurrentOracleClientIdentity(config.client_program);
    std::ostringstream result;
    result << "(DESCRIPTION=(ADDRESS=(PROTOCOL="
           << (address.protocol == TransportProtocol::TCPS ? "tcps" : "tcp") << ")(HOST=" << address.host
           << ")(PORT=" << address.port << "))(CONNECT_DATA=(SERVICE_NAME=" << config.service_name << ')';
    if (!config.instance_name.empty()) {
        result << "(INSTANCE_NAME=" << config.instance_name << ')';
    }
    if (!config.server_type.empty()) {
        result << "(SERVER=" << Upper(config.server_type) << ')';
    }
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

std::string BuildConnectDescriptor(const ConnectionConfig &config, const ConnectAddress &address) {
    return BuildDescriptor(config, address, true);
}

std::string BuildAuthConnectString(const ConnectionConfig &config, const ConnectAddress &address) {
    return BuildDescriptor(config, address, false);
}

std::string BuildConnectDescriptor(const ConnectionConfig &config) {
    return BuildDescriptor(config, EffectiveAddressLists(config).front().addresses.front(), true);
}

std::string BuildAuthConnectString(const ConnectionConfig &config) {
    return BuildDescriptor(config, EffectiveAddressLists(config).front().addresses.front(), false);
}

} // namespace oracle_scanner
