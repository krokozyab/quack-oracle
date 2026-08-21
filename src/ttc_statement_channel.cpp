#include "oracle_scanner/ttc_statement_channel.hpp"

#include <optional>
#include "oracle_scanner/ttc_error.hpp"
#include "oracle_scanner/ttc_execute_response.hpp"
#include "oracle_scanner/ttc_fetch.hpp"
#include "oracle_scanner/protocol_error.hpp"

#include <string>

namespace oracle_scanner {

namespace {

// Bounds on joining one response out of several DATA fragments. A response is
// normally one packet and a large fetch a handful; these exist so a server that
// never terminates a response cannot make this loop run forever.
constexpr size_t MAX_RESPONSE_FRAGMENTS = 4096;
constexpr size_t MAX_RESPONSE_BYTES = 64U << 20U;

} // namespace

TtcStatementChannel::TtcStatementChannel(TtcChannel &channel_p, OracleStatementRegistry &statements_p)
    : channel(channel_p), statements(statements_p) {
}

TtcLobResponse TtcStatementChannel::LobOperation(const TtcLobRequest &request, uint8_t server_field_version) {
    const auto call = channel.LockCall();
    channel.Send(EncodeTtcLobRequest(request));
    auto response = channel.Receive();
    // A refused read answers with the end-of-call and nothing else, so this has
    // to be looked for before the data is decoded. Decoding first turns the
    // server's own reason into a complaint about the shape of its refusal.
    if (IsTtcErrorMessage(response)) {
        const auto completion = DecodeTtcErrorPrefix(response, server_field_version);
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE,
                            completion.message.empty() ? "Oracle refused a LOB read" : completion.message);
    }
    // A LOB large enough to outgrow one packet arrives as several, and the
    // return parameter that says how much was served is in the last of them.
    // Decoding what has arrived so far would read the tail of the data as a
    // parameter, so an incomplete response is a reason to read more rather
    // than an error. The bound is the transport's, not a guess: each pass
    // consumes one message, and a server that stops sending ends the call.
    constexpr size_t MAX_LOB_RESPONSE_MESSAGES = 4096;
    TtcLobResponse decoded;
    for (size_t pass = 0;; pass++) {
        try {
            decoded = DecodeTtcLobResponse(response, request.locator.size());
            break;
        } catch (const ProtocolError &error) {
            if (error.Kind() != ProtocolErrorKind::TRUNCATED || pass + 1 >= MAX_LOB_RESPONSE_MESSAGES) {
                throw;
            }
        }
        const auto more = channel.Receive();
        if (more.empty()) {
            throw ProtocolError(ProtocolErrorKind::TRUNCATED, "Oracle stopped mid-way through a LOB response");
        }
        response.insert(response.end(), more.begin(), more.end());
    }
    // Whatever follows the return parameter is the end of the call. An error
    // there is the server refusing the read — a stale locator, a missing
    // privilege — and it has to reach the caller rather than be skipped.
    const std::vector<uint8_t> tail(response.begin() + static_cast<std::ptrdiff_t>(decoded.bytes_consumed),
                                    response.end());
    if (!tail.empty() && IsTtcErrorMessage(tail)) {
        const auto completion = DecodeTtcErrorPrefix(tail, server_field_version);
        if (completion.error_number != 0) {
            throw ProtocolError(ProtocolErrorKind::INVALID_STATE,
                                completion.message.empty() ? "Oracle refused a LOB read" : completion.message);
        }
    }
    return decoded;
}

std::unique_lock<std::recursive_mutex> TtcStatementChannel::LockCall() {
    return channel.LockCall();
}

void TtcStatementChannel::ExecuteNoBinds(OracleStatementHandle handle, const TtcExecuteNoBindsRequest &request) {
    if (statements.State(handle) != OracleStatementState::OPEN) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "Oracle statement is not ready for initial execute");
    }
    try {
        channel.Send(EncodeTtcExecuteNoBindsRequest(request));
    } catch (...) {
        statements.Poison(handle);
        throw;
    }
}

void TtcStatementChannel::ExecuteBinds(OracleStatementHandle handle, const TtcExecuteBindsRequest &request) {
    if (statements.State(handle) != OracleStatementState::OPEN) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "Oracle statement is not ready for initial bound execute");
    }
    try {
        channel.Send(EncodeTtcExecuteBindsRequest(request));
    } catch (...) {
        statements.Poison(handle);
        throw;
    }
}

std::vector<uint8_t> TtcStatementChannel::ReceiveExecuteResponse(OracleStatementHandle handle) {
    try {
        auto response = channel.Receive();
        if (IsTtcErrorMessage(response)) {
            statements.Poison(handle);
            ThrowTtcServerError(response);
        }
        return response;
    } catch (...) {
        if (statements.State(handle) != OracleStatementState::POISONED) {
            statements.Poison(handle);
        }
        throw;
    }
}

TtcErrorInfo TtcStatementChannel::ReceiveDmlResponse(OracleStatementHandle handle, uint8_t server_field_version) {
    try {
        const auto response = channel.Receive();
        const auto completion = DecodeTtcExecuteCompletion(response, server_field_version);
        if (completion.error_number != 0) {
            statements.Poison(handle);
            throw OracleDmlError(completion.current_row,
                                 completion.message.empty() ? "Oracle DML execution failed" : completion.message);
        }
        return completion;
    } catch (...) {
        if (statements.State(handle) != OracleStatementState::POISONED) {
            statements.Poison(handle);
        }
        throw;
    }
}

TtcPlsqlOutBindsResponse TtcStatementChannel::ReceivePlsqlOutBindsResponse(OracleStatementHandle handle,
                                                                             const std::vector<OracleBind> &binds,
                                                                             uint8_t ttc_field_version) {
    try {
        auto response = channel.Receive();
        if (IsTtcErrorMessage(response)) {
            statements.Poison(handle);
            ThrowTtcServerError(response);
        }
        return DecodeTtcPlsqlOutBindsResponse(response, binds, ttc_field_version);
    } catch (...) {
        if (statements.State(handle) != OracleStatementState::POISONED) {
            statements.Poison(handle);
        }
        throw;
    }
}

TtcCallResponse TtcStatementChannel::ReceiveCallResponse(OracleStatementHandle handle, const std::vector<OracleBind> &binds,
                                                          uint8_t ttc_field_version, uint8_t server_field_version) {
    try {
        auto response = channel.Receive();
        if (IsTtcErrorMessage(response)) {
            statements.Poison(handle);
            ThrowTtcServerError(response);
        }
        return DecodeTtcCallResponse(response, binds, ttc_field_version, server_field_version);
    } catch (...) {
        if (statements.State(handle) != OracleStatementState::POISONED) {
            statements.Poison(handle);
        }
        throw;
    }
}

void TtcStatementChannel::CompleteExecute(OracleStatementHandle handle, bool is_query, uint32_t remote_cursor_id) {
    if (is_query) {
        if (remote_cursor_id == 0) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle query execute response has no cursor id");
        }
        statements.BindRemoteCursor(handle, remote_cursor_id);
    } else if (remote_cursor_id != 0) {
        statements.BindRemoteCursor(handle, remote_cursor_id);
    }
    statements.MarkExecuted(handle, is_query);
}

void TtcStatementChannel::Fetch(OracleStatementHandle handle, uint8_t sequence, uint32_t requested_rows) {
    const auto remote_cursor_id = statements.RemoteCursorId(handle);
    statements.BeginFetch(handle);
    try {
        channel.Send(EncodeTtcFetchRequest({sequence, remote_cursor_id, requested_rows}));
    } catch (...) {
        statements.Poison(handle);
        throw;
    }
}

void TtcStatementChannel::Cancel(OracleStatementHandle handle) {
    // State validation ensures a cursor cannot interrupt an unrelated or
    // already terminal statement; the reader consumes the resulting TTIOER.
    (void)statements.RemoteCursorId(handle);
    channel.Cancel();
}

std::vector<uint8_t> TtcStatementChannel::ReceiveFetchResponse(OracleStatementHandle handle) {
    try {
        return channel.Receive();
    } catch (...) {
        if (statements.State(handle) != OracleStatementState::POISONED) {
            statements.Poison(handle);
        }
        throw;
    }
}

TtcFetchResponse TtcStatementChannel::ReceiveDecodedFetchResponse(OracleStatementHandle handle,
                                                                   const std::vector<OracleColumn> &columns,
                                                                   uint8_t server_field_version,
                                                                   const std::optional<TtcRowData> &preceding_row) {
    try {
        // Oracle does not delimit a data response for this client: on a legacy
        // 19c session it never sets END_OF_RESPONSE, and a response too large
        // for one packet is split into fragments that are not padded to the
        // SDU, so no packet boundary says "this is the end". The decoder is the
        // only thing that knows, so read a fragment, try to decode, and read
        // another only when the decode says it ran out — either by reporting
        // TRUNCATED or by finishing the buffer without a terminator.
        auto accumulated = channel.Receive();
        for (size_t fragments = 1;; fragments++) {
            std::optional<TtcFetchResponse> decoded;
            try {
                decoded = DecodeTtcFetchResponse(accumulated, columns, server_field_version, preceding_row);
            } catch (const ProtocolError &error) {
                if (error.Kind() != ProtocolErrorKind::TRUNCATED) {
                    throw;
                }
            }
            if (decoded && decoded->completed) {
                return std::move(*decoded);
            }
            if (fragments == MAX_RESPONSE_FRAGMENTS) {
                throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED,
                                    "Oracle response spans more fragments than this client will join");
            }
            // The whole accumulated buffer is decoded again rather than resumed
            // from an offset: a fragment can split any field, so there is no
            // safe point to resume from, and a response is a handful of packets.
            const auto next = channel.Receive();
            if (accumulated.size() > MAX_RESPONSE_BYTES - next.size()) {
                throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED,
                                    "Oracle response exceeds the configured reassembly limit");
            }
            accumulated.insert(accumulated.end(), next.begin(), next.end());
        }
    } catch (...) {
        if (statements.State(handle) != OracleStatementState::POISONED) {
            statements.Poison(handle);
        }
        throw;
    }
}

void TtcStatementChannel::MarkFetchExhausted(OracleStatementHandle handle) {
    statements.MarkExhausted(handle);
}

bool TtcStatementChannel::Close(OracleStatementHandle handle) {
    const auto remote_cursor_id = statements.TryRemoteCursorId(handle);
    if (!statements.Close(handle)) {
        return false;
    }
    if (remote_cursor_id) {
        channel.QueueCloseCursor(*remote_cursor_id);
    }
    return true;
}

} // namespace oracle_scanner
