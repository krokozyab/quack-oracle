#pragma once

#include <stdexcept>
#include <string>

namespace oracle_scanner {

enum class ProtocolErrorKind {
    TRUNCATED,
    MALFORMED,
    LIMIT_EXCEEDED,
    INVALID_STATE,
    UNSUPPORTED
};

class ProtocolError : public std::runtime_error {
public:
    ProtocolError(ProtocolErrorKind kind, const std::string &message) : std::runtime_error(message), kind(kind) {
    }

    ProtocolErrorKind Kind() const {
        return kind;
    }

private:
    ProtocolErrorKind kind;
};

} // namespace oracle_scanner
