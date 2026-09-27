#pragma once

#include "oracle_scanner/connect_descriptor.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace oracle_scanner {

struct DescriptorEndpoint {
    std::string host;
    uint16_t port = 0;
    TransportProtocol protocol = TransportProtocol::TCP;
};

struct ParsedConnectDescriptor {
    // Every address in the order written, flattened across address lists.
    std::vector<DescriptorEndpoint> endpoints;
    // The same addresses grouped the way the descriptor groups them, with each
    // group's FAILOVER and LOAD_BALANCE.
    std::vector<ConnectAddressList> address_lists;
    // The DESCRIPTION-level FAILOVER and LOAD_BALANCE (Oracle's defaults: on
    // and off).
    bool failover = true;
    bool load_balance = false;
    // Present only when the descriptor names them, so a caller can tell a
    // value it has to reconcile with its own from one it can default.
    std::optional<uint32_t> retry_count;
    std::optional<uint32_t> retry_delay_seconds;
    std::optional<uint32_t> connect_timeout_seconds;
    std::optional<uint32_t> transport_connect_timeout_seconds;
    std::string service_name;
    std::string instance_name;
    std::string server_type;
    // From (security=...). An empty DN means the descriptor named none, which
    // is what a current Autonomous Database wallet does; hostname verification
    // still applies. server_dn_match records what the descriptor asked for, but
    // nothing here can turn verification off.
    std::string server_cert_dn;
    bool server_dn_match = true;
};

// Parses the descriptor subset this client honours. Everything a descriptor
// can say either takes effect, is harmless and documented as ignored, or is
// refused by name — a setting that would silently change meaning (TAF's
// FAILOVER_MODE, SOURCE_ROUTE=ON, DESCRIPTION_LIST, SID, SERVER=POOLED) is
// UNSUPPORTED rather than dropped.
ParsedConnectDescriptor ParseConnectDescriptor(const std::string &descriptor);

// One address a listener redirect names. `protocol_given` is false when the
// listener left PROTOCOL out, in which case the address inherits the protocol
// of the connection it redirected.
struct RedirectAddress {
    ConnectAddress address;
    bool protocol_given = false;
};

// The listener's side of a redirect: a DESCRIPTION, an ADDRESS_LIST or a bare
// ADDRESS, as go-ora and python-oracledb both accept. Keys other than the
// addresses are the listener's own and are passed over.
std::vector<RedirectAddress> ParseRedirectAddresses(const std::string &text);

// Checks that a listener's reconnect data is a DESCRIPTION with CONNECT_DATA,
// within bounds, before it is sent back verbatim.
constexpr size_t MAX_RECONNECT_DATA_BYTES = 16384;
void ValidateRedirectReconnectData(const std::string &text);

// Finds one case-insensitive alias definition in tnsnames.ora and returns its
// complete DESCRIPTION value. The input is bounded by the wallet reader.
std::string FindTnsAliasDescriptor(const std::string &tnsnames, const std::string &alias);

} // namespace oracle_scanner
