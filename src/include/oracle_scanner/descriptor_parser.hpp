#pragma once

#include "oracle_scanner/connect_descriptor.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace oracle_scanner {

struct DescriptorEndpoint {
    std::string host;
    uint16_t port = 0;
    TransportProtocol protocol = TransportProtocol::TCP;
};

struct ParsedConnectDescriptor {
    std::vector<DescriptorEndpoint> endpoints;
    std::string service_name;
    // From (security=...). An empty DN means the descriptor named none, which
    // is what a current Autonomous Database wallet does; hostname verification
    // still applies. server_dn_match records what the descriptor asked for, but
    // nothing here can turn verification off.
    std::string server_cert_dn;
    bool server_dn_match = true;
};

// Parses the small descriptor subset the thin client actually honors. It
// rejects unknown address protocols and requires exactly one service name.
ParsedConnectDescriptor ParseConnectDescriptor(const std::string &descriptor);

// Finds one case-insensitive alias definition in tnsnames.ora and returns its
// complete DESCRIPTION value. The input is bounded by the wallet reader.
std::string FindTnsAliasDescriptor(const std::string &tnsnames, const std::string &alias);

} // namespace oracle_scanner
