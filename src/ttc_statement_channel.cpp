#include "oracle_scanner/ttc_statement_channel.hpp"
#include "oracle_scanner/ttc_define.hpp"

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

// Reads a response that Oracle may split across DATA fragments, which it does
// not delimit for this client: a legacy 19c session never sets
// END_OF_RESPONSE, and an oversized response is not padded to the SDU, so no
// packet boundary says "this is the end". The decoder is the only thing that
// knows, so decode what has arrived and read more only when it says it ran
// out — either by reporting TRUNCATED or by finishing without a terminator.
//
// A consequence worth knowing: a genuinely malformed response also decodes as
// TRUNCATED, and this then waits for a fragment that never comes, so it
// surfaces as a read timeout rather than immediately. The alternative — give
// up on the first TRUNCATED — is what made every wide table unreadable, since
// a DESCRIBE_INFO past ~120 columns simply does not fit one packet.
//
// The whole accumulated buffer is decoded again on each round rather than
// resumed from an offset: a fragment can split any field, so there is no safe
// point to resume from, and a response is a handful of packets.
template <typename Decoder>
std::vector<uint8_t> ReceiveResponseFragments(TtcChannel &channel, Decoder decoder) {
    auto accumulated = channel.Receive();
    for (size_t fragments = 1;; fragments++) {
        bool complete = false;
        try {
            complete = decoder(accumulated);
        } catch (const ProtocolError &error) {
            if (error.Kind() != ProtocolErrorKind::TRUNCATED) {
                throw;
            }
        }
        if (complete) {
            return accumulated;
        }
        if (fragments == MAX_RESPONSE_FRAGMENTS) {
            throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED,
                                "Oracle response spans more fragments than this client will join");
        }
        const auto next = channel.Receive();
        if (next.size() > MAX_RESPONSE_BYTES || accumulated.size() > MAX_RESPONSE_BYTES - next.size()) {
            throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED,
                                "Oracle response exceeds the configured reassembly limit");
        }
        accumulated.insert(accumulated.end(), next.begin(), next.end());
    }
}

} // namespace

TtcStatementChannel::TtcStatementChannel(TtcChannel &channel_p, OracleStatementRegistry &statements_p)
    : channel(channel_p), statements(statements_p) {
}

TtcLobResponse TtcStatementChannel::LobOperation(const TtcLobRequest &request, uint8_t server_field_version) {
    TtcLobResponse result;
    LobExchange(EncodeTtcLobRequest(request), [&](const std::vector<uint8_t> &response) {
        result = DecodeCompleteTtcLobCall(response, request.locator.size(), server_field_version);
    });
    return result;
}

std::vector<uint8_t> TtcStatementChannel::LocatorOperation(const std::vector<uint8_t> &request, size_t locator_count,
                                                           bool created, uint8_t server_field_version) {
    std::vector<uint8_t> locator;
    LobExchange(request, [&](const std::vector<uint8_t> &response) {
        locator = DecodeCompleteTtcLocatorCall(response, locator_count, created, server_field_version);
    });
    return locator;
}

void TtcStatementChannel::LobExchange(const std::vector<uint8_t> &request,
                                      const std::function<void(const std::vector<uint8_t> &)> &decode) {
    const auto call = channel.LockCall();
    channel.Send(request);
    // A LOB large enough to outgrow one packet arrives as several, and so can
    // the end-of-call behind it: a response is complete only when the data,
    // the return parameter AND the end-of-call all decode. Until then the
    // decoder answers TRUNCATED, which is the one reason to read another
    // message; anything else it reports is final. Nothing is resent: a
    // failure ends the operation, and the caller poisons the session.
    constexpr size_t MAX_LOB_RESPONSE_MESSAGES = 4096;
    // The largest read is one chunk of data plus a locator and an
    // end-of-call; a response growing past that is not a LOB response.
    constexpr size_t MAX_LOB_RESPONSE_BYTES = (16U << 20U) + (64U << 10U);
    auto response = channel.Receive();
    for (size_t pass = 0;; pass++) {
        try {
            decode(response);
            return;
        } catch (const ProtocolError &error) {
            if (error.Kind() != ProtocolErrorKind::TRUNCATED) {
                throw;
            }
            if (pass + 1 >= MAX_LOB_RESPONSE_MESSAGES) {
                throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED,
                                    "Oracle LOB response spans more messages than supported");
            }
        }
        const auto more = channel.Receive();
        if (more.empty()) {
            throw ProtocolError(ProtocolErrorKind::TRUNCATED, "Oracle stopped mid-way through a LOB response");
        }
        if (response.size() > MAX_LOB_RESPONSE_BYTES || more.size() > MAX_LOB_RESPONSE_BYTES - response.size()) {
            throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "Oracle LOB response exceeds supported size");
        }
        response.insert(response.end(), more.begin(), more.end());
    }
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

TtcExecuteResponse TtcStatementChannel::ReceiveDecodedExecuteResponse(OracleStatementHandle handle,
                                                                        uint8_t ttc_field_version,
                                                                        uint8_t server_field_version) {
    try {
        std::optional<TtcExecuteResponse> decoded;
        (void)ReceiveResponseFragments(channel, [&](const std::vector<uint8_t> &message) {
            decoded.reset();
            if (IsTtcErrorMessage(message)) {
                const auto completion = DecodeTtcErrorPrefix(message, server_field_version);
                if (completion.error_number != 0) {
                    throw ProtocolError(ProtocolErrorKind::INVALID_STATE,
                                        completion.message.empty() ? "Oracle query failed" : completion.message,
                                        completion.error_number);
                }
            }
            decoded = DecodeTtcExecuteResponse(message, ttc_field_version, server_field_version);
            return decoded->completed;
        });
        return std::move(*decoded);
    } catch (...) {
        if (statements.State(handle) != OracleStatementState::POISONED) {
            statements.Poison(handle);
        }
        throw;
    }
}

TtcErrorInfo TtcStatementChannel::ReceiveDmlResponse(OracleStatementHandle handle, uint8_t server_field_version) {
    try {
        TtcErrorInfo completion;
        (void)ReceiveResponseFragments(channel, [&](const std::vector<uint8_t> &message) {
            completion = DecodeTtcExecuteCompletion(message, server_field_version);
            return true;
        });
        if (completion.error_number != 0) {
            statements.Poison(handle);
            throw OracleDmlError(completion.current_row,
                                 completion.message.empty() ? "Oracle DML execution failed" : completion.message,
                                 completion.error_number);
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
        std::optional<TtcCallResponse> decoded;
        (void)ReceiveResponseFragments(channel, [&](const std::vector<uint8_t> &message) {
            decoded = DecodeTtcCallResponse(message, binds, ttc_field_version, server_field_version);
            return decoded->completed;
        });
        return std::move(*decoded);
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

void TtcStatementChannel::FetchOpenedCursor(OracleStatementHandle handle, uint8_t sequence, uint32_t requested_rows,
                                            uint8_t field_version) {
    const auto request = EncodeTtcCursorFetchRequest(sequence, statements.RemoteCursorId(handle), requested_rows,
                                                     field_version);
    statements.BeginFetch(handle);
    try {
        channel.Send(request);
    } catch (...) {
        statements.Poison(handle);
        throw;
    }
}

void TtcStatementChannel::DefineInlineLobs(OracleStatementHandle handle, uint8_t sequence,
                                           const std::vector<OracleColumn> &columns, uint32_t rows) {
    const auto cursor = statements.RemoteCursorId(handle);
    const auto request = EncodeInlineLobDefine(sequence, cursor, columns, rows);
    statements.BeginFetch(handle);
    try {
        channel.Send(request);
    } catch (...) {
        statements.Poison(handle);
        throw;
    }
}

void TtcStatementChannel::DefineLobPrefetch(OracleStatementHandle handle,uint8_t sequence,
    const std::vector<OracleColumn> &columns,uint32_t rows,uint8_t field_version,const OracleLobPrefetchLimits &limits) {
    const auto cursor=statements.RemoteCursorId(handle);
    const auto request=EncodeLobPrefetchDefine(sequence,cursor,columns,rows,field_version,limits);
    statements.BeginFetch(handle);
    try { channel.Send(request); }
    catch (...) { statements.Poison(handle);throw; }
}

TtcFetchResponse TtcStatementChannel::ReceiveDecodedLobPrefetchFetchResponse(OracleStatementHandle handle,
    const std::vector<OracleColumn> &columns,const OracleLobPrefetchLimits &limits,uint8_t server_field_version,
    const std::optional<TtcRowData> &preceding_row) {
    try {
        // A prefetched batch can be megabytes, so like a scalar fetch it is
        // decoded once, resuming after the last finished row on each fragment.
        std::optional<LobPrefetchFetchResponseDecoder> decoder;
        (void)ReceiveResponseFragments(channel,[&](const std::vector<uint8_t> &message) {
            if (!decoder) { decoder.emplace(columns,limits,server_field_version,preceding_row); }
            return decoder->Decode(message);
        });
        return decoder->Take();
    } catch (...) {
        if (statements.State(handle)!=OracleStatementState::POISONED) { statements.Poison(handle); }
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
        // A fetch of a few thousand rows spans dozens of fragments, so the
        // decoder resumes after the last row it finished instead of decoding
        // the whole response again for each one. A fragment can split any
        // field, but never a row that has already decoded completely.
        TtcFetchResponseDecoder decoder(columns, server_field_version, preceding_row);
        for (size_t fragments = 1;; fragments++) {
            bool complete = false;
            try {
                complete = decoder.Decode(accumulated);
            } catch (const ProtocolError &error) {
                if (error.Kind() != ProtocolErrorKind::TRUNCATED) {
                    throw;
                }
            }
            if (complete) {
                return decoder.Take();
            }
            if (fragments == MAX_RESPONSE_FRAGMENTS) {
                throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED,
                                    "Oracle response spans more fragments than this client will join");
            }
            const auto next = channel.Receive();
            if (next.size() > MAX_RESPONSE_BYTES || accumulated.size() > MAX_RESPONSE_BYTES - next.size()) {
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
