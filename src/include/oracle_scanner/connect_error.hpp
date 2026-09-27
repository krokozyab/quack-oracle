#pragma once

#include "oracle_scanner/protocol_error.hpp"

#include <cstdint>
#include <string>

namespace oracle_scanner {

// Why one attempt to reach a listener failed. The connect loop decides from
// this alone whether the next address is worth trying, so each value is a
// statement about where the fault lies, not about how it was noticed.
enum class ConnectFailure {
    // No TCP connection: the name did not resolve, the port refused, or the
    // per-attempt timeout ran out. Another address may well answer.
    UNREACHABLE,
    // A TCP connection existed and then went away, or stopped answering,
    // before the listener accepted.
    TRANSPORT_LOST,
    // The listener answered with REFUSE. Oracle's own code, when the listener
    // sent one, is kept beside it.
    LISTENER_REFUSED,
    // A redirect chain could not be followed: too many hops, a cycle, or every
    // address it named was unreachable.
    REDIRECT_FAILED,
    // The TLS handshake failed for a reason other than the certificate.
    TLS_HANDSHAKE,
    // The certificate did not verify, did not carry the expected name, or did
    // not carry the expected DN. A configuration or security fault: another
    // address would only repeat it, so the loop stops.
    TLS_VERIFICATION,
    // The listener said something this client cannot parse, or asked for
    // something it refuses to do (a redirect that changes protocol).
    PROTOCOL,
    // The caller interrupted the connect.
    CANCELLED,
    // The overall connect budget ran out before an attempt could start.
    BUDGET_EXHAUSTED,
    // A local resource the connect needs could not be had — a name-resolution
    // worker could not be started. Not a fact about any address.
    RESOURCE_EXHAUSTED,
};

inline const char *ConnectFailureName(ConnectFailure failure) {
    switch (failure) {
    case ConnectFailure::UNREACHABLE:
        return "unreachable";
    case ConnectFailure::TRANSPORT_LOST:
        return "transport lost";
    case ConnectFailure::LISTENER_REFUSED:
        return "listener refused";
    case ConnectFailure::REDIRECT_FAILED:
        return "redirect failed";
    case ConnectFailure::TLS_HANDSHAKE:
        return "TLS handshake failed";
    case ConnectFailure::TLS_VERIFICATION:
        return "TLS verification failed";
    case ConnectFailure::PROTOCOL:
        return "protocol error";
    case ConnectFailure::CANCELLED:
        return "cancelled";
    case ConnectFailure::BUDGET_EXHAUSTED:
        return "connect budget exhausted";
    case ConnectFailure::RESOURCE_EXHAUSTED:
        return "local resources exhausted";
    }
    return "unknown";
}

// Whether a failure of this kind lets the loop move on to another address.
// Everything else ends the connect at once: a certificate that does not verify
// or a listener speaking nonsense is not improved by asking a different one.
inline bool ConnectFailureAllowsFailover(ConnectFailure failure) {
    switch (failure) {
    case ConnectFailure::UNREACHABLE:
    case ConnectFailure::TRANSPORT_LOST:
    case ConnectFailure::LISTENER_REFUSED:
    case ConnectFailure::REDIRECT_FAILED:
    case ConnectFailure::TLS_HANDSHAKE:
        return true;
    default:
        return false;
    }
}

// A ProtocolError that also says which ConnectFailure it is. The kind is kept
// as it always was — callers and tests that look only at the kind see no
// change — and the failure is what the connect loop reads.
class OracleConnectError : public ProtocolError {
public:
    OracleConnectError(ProtocolErrorKind kind, ConnectFailure failure_p, const std::string &message,
                       uint32_t oracle_error_p = 0)
        : ProtocolError(kind, message), failure(failure_p), oracle_error(oracle_error_p) {
    }

    ConnectFailure Failure() const {
        return failure;
    }
    // The ORA- number a listener refusal carried, or 0.
    uint32_t OracleErrorCode() const {
        return oracle_error;
    }

private:
    ConnectFailure failure;
    uint32_t oracle_error;
};

} // namespace oracle_scanner
