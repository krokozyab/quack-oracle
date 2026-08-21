#include "oracle_scanner/descriptor_parser.hpp"
#include "oracle_scanner/protocol_error.hpp"

#include <algorithm>
#include <cctype>
#include <limits>
#include <map>
#include <utility>

namespace oracle_scanner {

namespace {

struct Node {
    std::string key;
    std::string value;
    std::vector<Node> children;
};

class Parser {
public:
    explicit Parser(const std::string &input_p) : input(input_p) {
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
        if (depth > 16 || position >= input.size() || input[position++] != '(') {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle descriptor nesting is invalid");
        }
        SkipWhitespace();
        auto key = ParseAtom('=');
        SkipWhitespace();
        if (position >= input.size() || input[position++] != '=') {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle descriptor key has no value");
        }
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
        if (position >= input.size() || input[position++] != ')') {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle descriptor node is unterminated");
        }
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

void CollectAddresses(const Node &description, std::vector<const Node *> &result) {
    for (const auto &child : description.children) {
        if (child.key == "ADDRESS") {
            result.push_back(&child);
            continue;
        }
        if (child.key != "ADDRESS_LIST") {
            continue;
        }
        for (const auto &address_list_child : child.children) {
            if (address_list_child.key == "ADDRESS") {
                result.push_back(&address_list_child);
            }
        }
    }
}

uint16_t ParsePort(const std::string &value) {
    uint32_t result = 0;
    for (const auto character : value) {
        if (!std::isdigit(static_cast<unsigned char>(character))) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle descriptor port is not numeric");
        }
        result = result * 10 + static_cast<uint32_t>(character - '0');
        if (result > std::numeric_limits<uint16_t>::max()) {
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

} // namespace

ParsedConnectDescriptor ParseConnectDescriptor(const std::string &descriptor) {
    auto root = Parser(descriptor).Parse();
    if (root.key != "DESCRIPTION" || !root.value.empty()) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle descriptor root must be DESCRIPTION");
    }
    std::vector<const Node *> addresses;
    CollectAddresses(root, addresses);
    if (addresses.empty() || addresses.size() > 16) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle descriptor has an invalid number of addresses");
    }
    ParsedConnectDescriptor result;
    for (const auto *address : addresses) {
        const auto protocol = Upper(RequiredChild(*address, "PROTOCOL").value);
        DescriptorEndpoint endpoint;
        if (protocol == "TCP") {
            endpoint.protocol = TransportProtocol::TCP;
        } else if (protocol == "TCPS") {
            endpoint.protocol = TransportProtocol::TCPS;
        } else {
            throw ProtocolError(ProtocolErrorKind::UNSUPPORTED, "Oracle descriptor address protocol is unsupported");
        }
        endpoint.host = RequiredChild(*address, "HOST").value;
        endpoint.port = ParsePort(RequiredChild(*address, "PORT").value);
        result.endpoints.push_back(std::move(endpoint));
    }
    const Node *connect_data = RequiredContainer(root, "CONNECT_DATA");
    result.service_name = RequiredChild(*connect_data, "SERVICE_NAME").value;
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
        config.protocol = endpoint.protocol;
        ValidateConnectionConfig(config);
    }
    return result;
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
            if (Upper(name) == expected && cursor < end && tnsnames[cursor++] == '=') {
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
