#include "oracle_scanner/descriptor_parser.hpp"
#include "oracle_scanner/protocol_error.hpp"

#include <algorithm>
#include <cctype>
#include <limits>
#include <map>
#include <optional>
#include <utility>

namespace oracle_scanner {

namespace {

struct Node {
    std::string key;
    std::string value;
    std::vector<Node> children;
};

// How values are read. A descriptor the user wrote is held to the strict atom
// grammar: an unexpected character there is more likely a typo than intent.
// Text a listener sends back — a redirect address or reconnect data — is the
// listener's own, and it routinely carries values the strict grammar refuses:
// Oracle echoes the client's CONNECTION_ID, which is base64 and so ends in
// '=', and the client's CID, whose PROGRAM is a path that may contain spaces.
// There a value runs to the ')' that closes its node; only '(' and characters
// outside printable ASCII are refused, and any field that is used afterwards
// (a host, a port) is validated on its own.
enum class ValueGrammar { USER_WRITTEN, LISTENER_SUPPLIED };

class Parser {
public:
    explicit Parser(const std::string &input_p, ValueGrammar grammar_p = ValueGrammar::USER_WRITTEN)
        : input(input_p), grammar(grammar_p) {
        if (input.empty() || input.size() > 65535) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle descriptor has an invalid size");
        }
    }

    Node Parse() {
        SkipWhitespace();
        auto result = ParseNode(0);
        SkipWhitespace();
        if (position != input.size()) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle descriptor has trailing data");
        }
        return result;
    }

private:
    Node ParseNode(size_t depth) {
        if (depth > 16 || position >= input.size() || input[position] != '(') {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle descriptor nesting is invalid");
        }
        position++;
        SkipWhitespace();
        auto key = ParseAtom('=');
        SkipWhitespace();
        if (position >= input.size() || input[position] != '=') {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle descriptor key has no value");
        }
        position++;
        SkipWhitespace();
        Node result;
        result.key = Upper(key);
        if (position < input.size() && input[position] == '(') {
            while (position < input.size() && input[position] == '(') {
                result.children.push_back(ParseNode(depth + 1));
                SkipWhitespace();
            }
        } else {
            result.value = ParseAtom(')');
        }
        SkipWhitespace();
        if (position >= input.size() || input[position] != ')') {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle descriptor node is unterminated");
        }
        position++;
        return result;
    }

    // A value Oracle has to write with commas, spaces and '=' in it — the
    // server certificate DN is the only one in this subset — is double-quoted.
    // The quoted form is the only place those characters are allowed, so an
    // unquoted atom stays as strict as it was.
    std::string ParseQuotedAtom() {
        position++;
        const auto start = position;
        while (position < input.size() && input[position] != '"') {
            const auto byte = static_cast<unsigned char>(input[position]);
            if (byte < 0x20 || byte > 0x7e) {
                throw ProtocolError(ProtocolErrorKind::MALFORMED,
                                    "Oracle descriptor quoted value contains an invalid character");
            }
            position++;
        }
        if (position == input.size()) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle descriptor quoted value is unterminated");
        }
        const auto value = input.substr(start, position - start);
        position++;
        if (value.empty() || value.size() > 1024) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle descriptor quoted value has an invalid size");
        }
        return value;
    }

    std::string ParseAtom(char terminator) {
        if (terminator == ')' && position < input.size() && input[position] == '"') {
            auto value = ParseQuotedAtom();
            SkipWhitespace();
            if (position >= input.size() || input[position] != ')') {
                throw ProtocolError(ProtocolErrorKind::MALFORMED,
                                    "Oracle descriptor quoted value is not followed by the end of its node");
            }
            return value;
        }
        if (terminator == ')' && grammar == ValueGrammar::LISTENER_SUPPLIED) {
            return ParseListenerValue();
        }
        const auto start = position;
        while (position < input.size() && input[position] != terminator) {
            const auto byte = static_cast<unsigned char>(input[position]);
            if (std::isspace(byte)) {
                const auto end = position;
                SkipWhitespace();
                if (end == start || position == input.size() || input[position] != terminator) {
                    throw ProtocolError(ProtocolErrorKind::MALFORMED,
                                        "Oracle descriptor atom contains whitespace in the middle of a value");
                }
                return input.substr(start, end - start);
            }
            if (byte <= 0x20 || byte > 0x7e || input[position] == '(' || input[position] == '=') {
                throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle descriptor atom contains an invalid character");
            }
            position++;
        }
        if (position == start || position == input.size()) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle descriptor atom is empty or unterminated");
        }
        return input.substr(start, position - start);
    }

    // See ValueGrammar::LISTENER_SUPPLIED: everything up to the node's ')', trimmed.
    std::string ParseListenerValue() {
        const auto start = position;
        while (position < input.size() && input[position] != ')') {
            const auto byte = static_cast<unsigned char>(input[position]);
            if (input[position] == '(' || (byte < 0x20 && !std::isspace(byte)) || byte > 0x7e) {
                throw ProtocolError(ProtocolErrorKind::MALFORMED,
                                    "Oracle listener descriptor value contains an invalid character");
            }
            position++;
        }
        if (position == input.size()) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle listener descriptor value is unterminated");
        }
        auto end = position;
        auto first = start;
        while (first < end && std::isspace(static_cast<unsigned char>(input[first]))) {
            first++;
        }
        while (end > first && std::isspace(static_cast<unsigned char>(input[end - 1]))) {
            end--;
        }
        if (first == end) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle listener descriptor value is empty");
        }
        return input.substr(first, end - first);
    }

    void SkipWhitespace() {
        while (position < input.size() && std::isspace(static_cast<unsigned char>(input[position]))) {
            position++;
        }
    }

    static std::string Upper(std::string value) {
        std::transform(value.begin(), value.end(), value.begin(), [](unsigned char character) {
            return static_cast<char>(std::toupper(character));
        });
        return value;
    }

    const std::string &input;
    ValueGrammar grammar;
    size_t position = 0;
};

const Node &RequiredChild(const Node &node, const std::string &key) {
    const Node *result = nullptr;
    for (const auto &child : node.children) {
        if (child.key != key) {
            continue;
        }
        if (result) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle descriptor contains a duplicate required field");
        }
        result = &child;
    }
    if (!result || !result->children.empty() || result->value.empty()) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle descriptor is missing a required scalar field");
    }
    return *result;
}

// Returns a pointer rather than a reference because the caller keeps the
// result, and GCC's -Wdangling-reference cannot see that it points into `node`
// — which outlives the call — rather than into the temporary `key`. The
// warning is a false positive, but CI builds with -Werror, and a pointer says
// what is actually meant: this borrows from `node`.
const Node *RequiredContainer(const Node &node, const std::string &key) {
    const Node *result = nullptr;
    for (const auto &child : node.children) {
        if (child.key != key) {
            continue;
        }
        if (result) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle descriptor contains a duplicate required section");
        }
        result = &child;
    }
    if (!result || !result->value.empty()) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle descriptor is missing a required section");
    }
    return result;
}

uint16_t ParsePort(const std::string &value) {
    uint32_t result = 0;
    for (const auto character : value) {
        if (!std::isdigit(static_cast<unsigned char>(character))) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle descriptor port is not numeric");
        }
        result = result * 10 + static_cast<uint32_t>(character - '0');
        if (result > (std::numeric_limits<uint16_t>::max)()) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle descriptor port is outside range");
        }
    }
    if (result == 0) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle descriptor port must be positive");
    }
    return static_cast<uint16_t>(result);
}

std::string Upper(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char character) {
        return static_cast<char>(std::toupper(character));
    });
    return value;
}


// A scalar that may be absent but may not be given twice, since a descriptor
// that says FAILOVER twice has not said which one it means.
const Node *OptionalScalar(const Node &node, const std::string &key) {
    const Node *result = nullptr;
    for (const auto &child : node.children) {
        if (child.key != key) {
            continue;
        }
        if (result) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle descriptor gives " + key + " more than once");
        }
        if (!child.children.empty() || child.value.empty()) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle descriptor " + key + " must be a single value");
        }
        result = &child;
    }
    return result;
}

bool ParseSwitch(const Node &node) {
    const auto value = Upper(node.value);
    if (value == "ON" || value == "YES" || value == "TRUE") {
        return true;
    }
    if (value == "OFF" || value == "NO" || value == "FALSE") {
        return false;
    }
    throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle descriptor " + node.key + " must be ON or OFF");
}

// Whole seconds only. Oracle also accepts a millisecond form ("250 ms") for
// some of these; this client's transport timeouts are in seconds, so that form
// is refused by name rather than rounded into something the user did not ask.
uint32_t ParseSeconds(const Node &node, uint32_t maximum) {
    const auto &value = node.value;
    const auto upper = Upper(value);
    if (upper.size() > 2 && upper.compare(upper.size() - 2, 2, "MS") == 0) {
        throw ProtocolError(ProtocolErrorKind::UNSUPPORTED,
                            "Oracle descriptor " + node.key + " must be given in whole seconds");
    }
    uint64_t result = 0;
    for (const auto character : value) {
        if (!std::isdigit(static_cast<unsigned char>(character))) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle descriptor " + node.key + " is not a number");
        }
        result = result * 10 + static_cast<uint64_t>(character - '0');
        if (result > maximum) {
            throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED,
                                "Oracle descriptor " + node.key + " exceeds the supported maximum");
        }
    }
    return static_cast<uint32_t>(result);
}

std::string ParseProtocolName(const std::string &value) {
    const auto protocol = Upper(value);
    if (protocol != "TCP" && protocol != "TCPS") {
        throw ProtocolError(ProtocolErrorKind::UNSUPPORTED,
                            "Oracle descriptor address protocol '" + value + "' is unsupported; only TCP and TCPS are");
    }
    return protocol;
}

// Keys that are legal Oracle Net syntax, change nothing about which listener
// is reached or what is asked of it, and are therefore accepted and ignored.
bool IsIgnoredDescriptionKey(const std::string &key) {
    return key == "ENABLE" || key == "EXPIRE_TIME" || key == "SDU" || key == "TDU" || key == "RECV_BUF_SIZE" ||
           key == "SEND_BUF_SIZE" || key == "TYPE_OF_SERVICE" || key == "USE_SNI";
}

void RefuseSourceRoute(const Node &container) {
    const auto *source_route = OptionalScalar(container, "SOURCE_ROUTE");
    if (source_route && ParseSwitch(*source_route)) {
        // SOURCE_ROUTE=ON means "connect to the first address, and have it
        // relay to the next" (Connection Manager). Ignoring it would dial the
        // addresses directly, which is a different route entirely.
        throw ProtocolError(ProtocolErrorKind::UNSUPPORTED,
                            "Oracle SOURCE_ROUTE=ON (Connection Manager routing) is not supported");
    }
}

ConnectAddress ParseAddress(const Node &address) {
    ConnectAddress result;
    for (const auto &child : address.children) {
        const auto &key = child.key;
        if (key == "PROTOCOL" || key == "HOST" || key == "PORT" || key == "SEND_BUF_SIZE" || key == "RECV_BUF_SIZE") {
            continue;
        }
        if (key == "HTTPS_PROXY" || key == "HTTPS_PROXY_PORT") {
            throw ProtocolError(ProtocolErrorKind::UNSUPPORTED, "Oracle descriptor HTTPS_PROXY is not supported");
        }
        throw ProtocolError(ProtocolErrorKind::UNSUPPORTED, "Oracle descriptor ADDRESS element " + key +
                                                                " is not supported");
    }
    // PROTOCOL and PORT default the way Oracle Net defaults them.
    const auto *protocol = OptionalScalar(address, "PROTOCOL");
    result.protocol = protocol && ParseProtocolName(protocol->value) == "TCPS" ? TransportProtocol::TCPS
                                                                                : TransportProtocol::TCP;
    result.host = RequiredChild(address, "HOST").value;
    const auto *port = OptionalScalar(address, "PORT");
    result.port = port ? ParsePort(port->value) : 1521;
    return result;
}

ConnectAddressList ParseAddressList(const Node &list) {
    ConnectAddressList result;
    for (const auto &child : list.children) {
        const auto &key = child.key;
        if (key == "ADDRESS") {
            result.addresses.push_back(ParseAddress(child));
        } else if (key == "FAILOVER" || key == "LOAD_BALANCE" || key == "SOURCE_ROUTE" || key == "ENABLE") {
            continue;
        } else {
            throw ProtocolError(ProtocolErrorKind::UNSUPPORTED,
                                "Oracle descriptor ADDRESS_LIST element " + key + " is not supported");
        }
    }
    if (result.addresses.empty()) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle descriptor ADDRESS_LIST names no address");
    }
    RefuseSourceRoute(list);
    if (const auto *failover = OptionalScalar(list, "FAILOVER")) {
        result.failover = ParseSwitch(*failover);
    }
    if (const auto *load_balance = OptionalScalar(list, "LOAD_BALANCE")) {
        result.load_balance = ParseSwitch(*load_balance);
    }
    return result;
}

void ParseConnectData(const Node &connect_data, ParsedConnectDescriptor &result) {
    for (const auto &child : connect_data.children) {
        const auto &key = child.key;
        if (key == "SERVICE_NAME" || key == "INSTANCE_NAME" || key == "SERVER") {
            continue;
        }
        if (key == "SID") {
            throw ProtocolError(ProtocolErrorKind::UNSUPPORTED,
                                "Oracle descriptor SID is not supported; connect by SERVICE_NAME");
        }
        if (key == "FAILOVER_MODE") {
            // Transparent Application Failover. This client does not replay
            // anything after a lost session, so accepting the setting would
            // promise a recovery that never happens.
            throw ProtocolError(ProtocolErrorKind::UNSUPPORTED,
                                "Oracle descriptor FAILOVER_MODE (TAF) is not supported; a lost session is not "
                                "recovered, only new connections fail over");
        }
        throw ProtocolError(ProtocolErrorKind::UNSUPPORTED,
                            "Oracle descriptor CONNECT_DATA element " + key + " is not supported");
    }
    result.service_name = RequiredChild(connect_data, "SERVICE_NAME").value;
    if (const auto *instance = OptionalScalar(connect_data, "INSTANCE_NAME")) {
        result.instance_name = instance->value;
    }
    if (const auto *server = OptionalScalar(connect_data, "SERVER")) {
        const auto value = Upper(server->value);
        if (value == "POOLED") {
            throw ProtocolError(ProtocolErrorKind::UNSUPPORTED,
                                "Oracle descriptor SERVER=POOLED (DRCP) is not supported");
        }
        if (value != "DEDICATED" && value != "SHARED") {
            throw ProtocolError(ProtocolErrorKind::UNSUPPORTED, "Oracle SERVER must be DEDICATED or SHARED");
        }
        result.server_type = value;
    }
}

void CheckRoot(const Node &root) {
    if (root.key == "DESCRIPTION_LIST") {
        throw ProtocolError(ProtocolErrorKind::UNSUPPORTED,
                            "Oracle DESCRIPTION_LIST is not supported; give a single DESCRIPTION with an "
                            "ADDRESS_LIST instead");
    }
    if (root.key != "DESCRIPTION" || !root.value.empty()) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle descriptor root must be DESCRIPTION");
    }
}

} // namespace

ParsedConnectDescriptor ParseConnectDescriptor(const std::string &descriptor) {
    auto root = Parser(descriptor).Parse();
    CheckRoot(root);
    ParsedConnectDescriptor result;
    // Direct ADDRESS children form one implicit list, placed where the first
    // of them is and governed by the DESCRIPTION's own FAILOVER and
    // LOAD_BALANCE, as python-oracledb does.
    std::optional<size_t> implicit_list;
    for (const auto &child : root.children) {
        const auto &key = child.key;
        if (key == "ADDRESS") {
            if (!implicit_list) {
                implicit_list = result.address_lists.size();
                result.address_lists.emplace_back();
            }
            result.address_lists[*implicit_list].addresses.push_back(ParseAddress(child));
        } else if (key == "ADDRESS_LIST") {
            result.address_lists.push_back(ParseAddressList(child));
        } else if (key == "CONNECT_DATA" || key == "SECURITY" || key == "FAILOVER" || key == "LOAD_BALANCE" ||
                   key == "RETRY_COUNT" || key == "RETRY_DELAY" || key == "CONNECT_TIMEOUT" ||
                   key == "TRANSPORT_CONNECT_TIMEOUT" || key == "SOURCE_ROUTE" || IsIgnoredDescriptionKey(key)) {
            continue;
        } else {
            throw ProtocolError(ProtocolErrorKind::UNSUPPORTED,
                                "Oracle descriptor element " + key + " is not supported");
        }
    }
    size_t total = 0;
    for (const auto &list : result.address_lists) {
        total += list.addresses.size();
    }
    if (total == 0 || total > MAX_CONNECT_ADDRESSES) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle descriptor has an invalid number of addresses");
    }
    RefuseSourceRoute(root);
    if (const auto *failover = OptionalScalar(root, "FAILOVER")) {
        result.failover = ParseSwitch(*failover);
    }
    if (const auto *load_balance = OptionalScalar(root, "LOAD_BALANCE")) {
        result.load_balance = ParseSwitch(*load_balance);
    }
    if (implicit_list) {
        result.address_lists[*implicit_list].failover = result.failover;
        result.address_lists[*implicit_list].load_balance = result.load_balance;
    }
    if (const auto *retry_count = OptionalScalar(root, "RETRY_COUNT")) {
        result.retry_count = ParseSeconds(*retry_count, MAX_CONNECT_RETRY_COUNT);
    }
    if (const auto *retry_delay = OptionalScalar(root, "RETRY_DELAY")) {
        result.retry_delay_seconds = ParseSeconds(*retry_delay, MAX_CONNECT_RETRY_DELAY_SECONDS);
    }
    if (const auto *connect_timeout = OptionalScalar(root, "CONNECT_TIMEOUT")) {
        result.connect_timeout_seconds = ParseSeconds(*connect_timeout, MAX_CONNECT_BUDGET_SECONDS);
        if (*result.connect_timeout_seconds == 0) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle descriptor CONNECT_TIMEOUT must be positive");
        }
    }
    if (const auto *transport_timeout = OptionalScalar(root, "TRANSPORT_CONNECT_TIMEOUT")) {
        result.transport_connect_timeout_seconds = ParseSeconds(*transport_timeout, 3600);
        if (*result.transport_connect_timeout_seconds == 0) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED,
                                "Oracle descriptor TRANSPORT_CONNECT_TIMEOUT must be positive");
        }
    }
    for (const auto &list : result.address_lists) {
        for (const auto &address : list.addresses) {
            result.endpoints.push_back({address.host, address.port, address.protocol});
        }
    }
    ParseConnectData(*RequiredContainer(root, "CONNECT_DATA"), result);
    // (security=(ssl_server_dn_match=yes)(ssl_server_cert_dn="...")). The DN is
    // an extra check on top of hostname verification, not a replacement for it,
    // and ssl_server_dn_match=no does not turn verification off here: this
    // client has no insecure mode to fall back to.
    for (const auto &child : root.children) {
        if (child.key != "SECURITY") {
            continue;
        }
        for (const auto &setting : child.children) {
            if (setting.key == "SSL_SERVER_CERT_DN") {
                if (!result.server_cert_dn.empty()) {
                    throw ProtocolError(ProtocolErrorKind::MALFORMED,
                                        "Oracle descriptor contains more than one SSL_SERVER_CERT_DN");
                }
                result.server_cert_dn = setting.value;
            } else if (setting.key == "SSL_SERVER_DN_MATCH") {
                result.server_dn_match = Upper(setting.value) != "NO" && Upper(setting.value) != "FALSE";
            }
        }
    }
    for (const auto &endpoint : result.endpoints) {
        ConnectionConfig config;
        config.host = endpoint.host;
        config.port = endpoint.port;
        config.service_name = result.service_name;
        config.instance_name = result.instance_name;
        config.protocol = endpoint.protocol;
        ValidateConnectionConfig(config);
    }
    return result;
}

std::vector<RedirectAddress> ParseRedirectAddresses(const std::string &text) {
    auto root = Parser(text, ValueGrammar::LISTENER_SUPPLIED).Parse();
    std::vector<const Node *> addresses;
    if (root.key == "ADDRESS") {
        addresses.push_back(&root);
    } else if (root.key == "ADDRESS_LIST" || root.key == "DESCRIPTION") {
        // What a listener writes is its own business beyond the addresses, so
        // other keys are passed over here — unlike in a user's descriptor,
        // where an unknown key could be a setting the user expects to work.
        for (const auto &child : root.children) {
            if (child.key == "ADDRESS") {
                addresses.push_back(&child);
            } else if (child.key == "ADDRESS_LIST" && root.key == "DESCRIPTION") {
                for (const auto &nested : child.children) {
                    if (nested.key == "ADDRESS") {
                        addresses.push_back(&nested);
                    }
                }
            }
        }
    } else if (root.key == "DESCRIPTION_LIST") {
        throw ProtocolError(ProtocolErrorKind::UNSUPPORTED, "Oracle redirect to a DESCRIPTION_LIST is not supported");
    } else {
        throw ProtocolError(ProtocolErrorKind::MALFORMED,
                            "Oracle redirect address must be a DESCRIPTION, ADDRESS_LIST or ADDRESS");
    }
    if (addresses.empty() || addresses.size() > MAX_CONNECT_ADDRESSES) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle redirect has an invalid number of addresses");
    }
    std::vector<RedirectAddress> result;
    for (const auto *address : addresses) {
        RedirectAddress redirect;
        const auto *protocol = OptionalScalar(*address, "PROTOCOL");
        redirect.protocol_given = protocol != nullptr;
        if (protocol) {
            redirect.address.protocol =
                ParseProtocolName(protocol->value) == "TCPS" ? TransportProtocol::TCPS : TransportProtocol::TCP;
        }
        redirect.address.host = RequiredChild(*address, "HOST").value;
        redirect.address.port = ParsePort(RequiredChild(*address, "PORT").value);
        ConnectionConfig check;
        check.host = redirect.address.host;
        check.port = redirect.address.port;
        check.service_name = "redirect";
        ValidateConnectionConfig(check);
        result.push_back(std::move(redirect));
    }
    return result;
}

void ValidateRedirectReconnectData(const std::string &text) {
    if (text.size() > MAX_RECONNECT_DATA_BYTES) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "Oracle redirect reconnect data is too large");
    }
    auto root = Parser(text, ValueGrammar::LISTENER_SUPPLIED).Parse();
    if (root.key != "DESCRIPTION" || !root.value.empty()) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle redirect reconnect data is not a DESCRIPTION");
    }
    (void)RequiredContainer(root, "CONNECT_DATA");
}

std::string FindTnsAliasDescriptor(const std::string &tnsnames, const std::string &alias) {
    if (alias.empty() || alias.size() > 128 || tnsnames.empty() || tnsnames.size() > (1U << 20U)) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle TNS alias input has invalid bounds");
    }
    for (const auto character : alias) {
        const auto byte = static_cast<unsigned char>(character);
        if (!(std::isalnum(byte) || character == '_' || character == '-' || character == '.')) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle TNS alias contains invalid characters");
        }
    }
    const auto expected = Upper(alias);
    size_t position = 0;
    std::string result;
    while (position < tnsnames.size()) {
        const auto line_end = tnsnames.find_first_of("\r\n", position);
        const auto end = line_end == std::string::npos ? tnsnames.size() : line_end;
        size_t cursor = position;
        while (cursor < end && std::isspace(static_cast<unsigned char>(tnsnames[cursor]))) {
            cursor++;
        }
        if (cursor < end && tnsnames[cursor] != '#' && tnsnames[cursor] != ';') {
            const auto name_begin = cursor;
            while (cursor < end && !std::isspace(static_cast<unsigned char>(tnsnames[cursor])) && tnsnames[cursor] != '=') {
                cursor++;
            }
            const auto name = tnsnames.substr(name_begin, cursor - name_begin);
            while (cursor < end && std::isspace(static_cast<unsigned char>(tnsnames[cursor]))) {
                cursor++;
            }
            if (Upper(name) == expected && cursor < end && tnsnames[cursor] == '=') {
                cursor++;
                while (cursor < tnsnames.size() && std::isspace(static_cast<unsigned char>(tnsnames[cursor]))) {
                    cursor++;
                }
                if (cursor == tnsnames.size() || tnsnames[cursor] != '(') {
                    throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle TNS alias has no descriptor");
                }
                const auto descriptor_begin = cursor;
                size_t depth = 0;
                for (; cursor < tnsnames.size(); cursor++) {
                    const auto byte = static_cast<unsigned char>(tnsnames[cursor]);
                    if (byte < 0x20 && !std::isspace(byte)) {
                        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle TNS alias descriptor contains control bytes");
                    }
                    if (tnsnames[cursor] == '(') {
                        if (++depth > 16) {
                            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle TNS alias descriptor nesting is invalid");
                        }
                    } else if (tnsnames[cursor] == ')' && --depth == 0) {
                        if (!result.empty()) {
                            throw ProtocolError(ProtocolErrorKind::MALFORMED,
                                                "Oracle TNS alias is defined more than once in wallet");
                        }
                        result = tnsnames.substr(descriptor_begin, cursor - descriptor_begin + 1);
                        const auto descriptor_line_end = tnsnames.find_first_of("\r\n", cursor + 1);
                        position = descriptor_line_end == std::string::npos ? tnsnames.size() : descriptor_line_end + 1;
                        break;
                    }
                }
                if (!result.empty()) {
                    continue;
                }
                throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle TNS alias descriptor is unterminated");
            }
        }
        position = line_end == std::string::npos ? tnsnames.size() : line_end + 1;
    }
    if (result.empty()) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle TNS alias was not found in wallet");
    }
    return result;
}

} // namespace oracle_scanner
