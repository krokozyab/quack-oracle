#include "oracle_scanner/call_builder.hpp"
#include "oracle_scanner/bind_validation.hpp"
#include "oracle_scanner/protocol_error.hpp"

#include <algorithm>
#include <cctype>
#include <set>

namespace oracle_scanner {

namespace {

constexpr size_t MAX_CALLABLE_COMPONENTS = 3;
constexpr size_t MAX_IDENTIFIER_BYTES = 128;
constexpr size_t MAX_ARGUMENTS = 256;

bool IsIdentifierStart(char character) {
    const auto value = static_cast<unsigned char>(character);
    return std::isalpha(value) || character == '_';
}

bool IsIdentifierPart(char character) {
    const auto value = static_cast<unsigned char>(character);
    return std::isalnum(value) || character == '_' || character == '$' || character == '#';
}

void ValidateCallableArgumentName(const std::string &value) {
    if (value.empty() || value.size() > MAX_IDENTIFIER_BYTES || !IsIdentifierStart(value.front()) ||
        !std::all_of(value.begin() + 1, value.end(), IsIdentifierPart)) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle procedure argument name is invalid");
    }
}

std::string ParseComponent(const std::string &value, size_t &offset) {
    const auto begin = offset;
    if (offset == value.size()) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle callable name has an empty component");
    }
    if (value[offset] == '"') {
        offset++;
        const auto content_begin = offset;
        bool closed = false;
        while (offset < value.size()) {
            if (value[offset] == '"') {
                if (offset + 1 < value.size() && value[offset + 1] == '"') {
                    offset += 2;
                    continue;
                }
                if (offset == content_begin) {
                    throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle quoted identifier is empty");
                }
                offset++;
                closed = true;
                break;
            }
            const auto character = static_cast<unsigned char>(value[offset++]);
            if (character < 0x20 || character == 0x7f) {
                throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle quoted identifier contains a control character");
            }
        }
        if (!closed) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle quoted identifier is not terminated");
        }
    } else {
        if (!IsIdentifierStart(value[offset])) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle identifier begins with an invalid character");
        }
        do {
            offset++;
        } while (offset < value.size() && IsIdentifierPart(value[offset]));
    }
    const auto component = value.substr(begin, offset - begin);
    if (component.size() > MAX_IDENTIFIER_BYTES) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "Oracle identifier exceeds supported length");
    }
    return component;
}

} // namespace

std::string ParseOracleCallableName(const std::string &value) {
    if (value.empty()) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle callable name is empty");
    }
    size_t offset = 0;
    size_t components = 0;
    while (offset < value.size()) {
        ParseComponent(value, offset);
        components++;
        if (components > MAX_CALLABLE_COMPONENTS) {
            throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "Oracle callable name has too many components");
        }
        if (offset == value.size()) {
            break;
        }
        if (value[offset++] != '.') {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle callable name has invalid separator");
        }
    }
    return value;
}

std::vector<std::string> SplitOracleCallableName(const std::string &value) {
    if (value.empty()) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle callable name is empty");
    }
    std::vector<std::string> components;
    size_t offset = 0;
    while (offset < value.size()) {
        const auto component = ParseComponent(value, offset);
        if (components.size() == MAX_CALLABLE_COMPONENTS) {
            throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "Oracle callable name has too many components");
        }
        if (component.front() == '"') {
            // Quoted: the stored name is the text between the quotes, with a
            // doubled quote standing for one.
            std::string stored;
            for (size_t index = 1; index + 1 < component.size(); index++) {
                stored.push_back(component[index]);
                if (component[index] == '"') {
                    index++;
                }
            }
            components.push_back(std::move(stored));
        } else {
            std::string stored;
            stored.reserve(component.size());
            for (const auto character : component) {
                stored.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(character))));
            }
            components.push_back(std::move(stored));
        }
        if (offset == value.size()) {
            break;
        }
        if (value[offset++] != '.') {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle callable name has invalid separator");
        }
    }
    return components;
}

std::string BuildOracleProcedureCallBlock(const std::string &qualified_name,
                                          const std::vector<OracleBind> &arguments) {
    const auto callable = ParseOracleCallableName(qualified_name);
    if (arguments.size() > MAX_ARGUMENTS) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "Oracle procedure has too many arguments");
    }
    std::set<std::string> bind_names;
    std::string result = "BEGIN " + callable;
    if (!arguments.empty()) {
        result += "(";
        for (size_t index = 0; index < arguments.size(); index++) {
            ValidateCallableArgumentName(arguments[index].name);
            const auto folded = CanonicalOracleBindName(arguments[index].name);
            if (!bind_names.emplace(folded).second) {
                throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle procedure bind names must be unique");
            }
            if (index != 0) {
                result += ", ";
            }
            result += arguments[index].name + " => :" + arguments[index].name;
        }
        result += ")";
    }
    result += "; END;";
    return result;
}

std::string BuildOracleFunctionCallBlock(const std::string &qualified_name, const OracleBind &return_bind,
                                         const std::vector<OracleBind> &arguments) {
    const auto callable = ParseOracleCallableName(qualified_name);
    if (return_bind.direction == BindDirection::IN) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle function return bind must be OUT or IN OUT");
    }
    if (arguments.size() > MAX_ARGUMENTS) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "Oracle function has too many arguments");
    }
    ValidateCallableArgumentName(return_bind.name);
    std::set<std::string> bind_names;
    bind_names.emplace(CanonicalOracleBindName(return_bind.name));
    std::string result = "BEGIN :" + return_bind.name + " := " + callable;
    if (!arguments.empty()) {
        result += "(";
        for (size_t index = 0; index < arguments.size(); index++) {
            ValidateCallableArgumentName(arguments[index].name);
            const auto folded = CanonicalOracleBindName(arguments[index].name);
            if (!bind_names.emplace(folded).second) {
                throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle function bind names must be unique");
            }
            if (index != 0) {
                result += ", ";
            }
            result += arguments[index].name + " => :" + arguments[index].name;
        }
        result += ")";
    }
    result += "; END;";
    return result;
}

std::string BuildOracleCallBlock(const OracleCallRequest &request) {
    switch (request.kind) {
    case OracleCallableKind::PROCEDURE:
        if (request.return_bind.has_value()) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle procedure request must not include a return bind");
        }
        return BuildOracleProcedureCallBlock(request.qualified_name, request.arguments);
    case OracleCallableKind::FUNCTION:
        if (!request.return_bind.has_value()) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle function request requires a return bind");
        }
        return BuildOracleFunctionCallBlock(request.qualified_name, *request.return_bind, request.arguments);
    }
    throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle call request has an unknown callable kind");
}

} // namespace oracle_scanner
