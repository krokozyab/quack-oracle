#include "oracle_scanner/native_session.hpp"

#include "oracle_scanner/bind_validation.hpp"
#include "oracle_scanner/call_builder.hpp"
#include "oracle_scanner/protocol_error.hpp"
#include "oracle_scanner/sql_binds.hpp"
#include "oracle_scanner/sql_statement.hpp"
#include "oracle_scanner/ttc_execute_response.hpp"
#include "oracle_scanner/ttc_lob.hpp"
#include "oracle_scanner/value_codec.hpp"
#include "oracle_scanner/wallet_archive.hpp"

#include <algorithm>
#include <cstdlib>
#include <limits>
#include <utility>

namespace oracle_scanner {

struct NativeSessionLifetime {
    bool open = true;
};

namespace {

class NativeOracleCursor final : public OracleCursor {
public:
    NativeOracleCursor(TtcStatementChannel &channel_p, uint8_t &next_sequence_p, std::shared_ptr<NativeSessionLifetime> lifetime_p,
                       OracleStatementHandle handle_p,
                       std::vector<OracleColumn> columns_p, std::vector<TtcRowData> prefetched_p, bool exhausted_p,
                       uint8_t server_field_version_p)
        : channel(channel_p), next_sequence(next_sequence_p), lifetime(std::move(lifetime_p)), handle(handle_p),
          columns(std::move(columns_p)), pending(std::move(prefetched_p)), server_field_version(server_field_version_p),
          exhausted(exhausted_p) {
        if (!pending.empty()) {
            previous_row = pending.back();
        }
    }

    ~NativeOracleCursor() override {
        try {
            Close();
        } catch (...) {
        }
    }

    const std::vector<OracleColumn> &Columns() const override { return columns; }

    // A LOB column's row data is a locator, not a value. Reading the content is
    // a separate call per value, which is why this is the only place it can
    // happen: above the session nothing has a channel, and below it nothing
    // knows which columns are LOBs. Everything upstream then sees plain bytes
    // and needs no notion of a locator at all.
    void ResolveLobs(OracleBatch &batch) {
        bool any = false;
        for (const auto &column : columns) {
            any = any || IsOracleLobType(column.oracle_type);
        }
        if (!any) {
            return;
        }
        for (auto &row : batch.rows) {
            for (size_t index = 0; index < row.size() && index < columns.size(); index++) {
                if (!IsOracleLobType(columns[index].oracle_type) || !row[index]) {
                    continue;
                }
                row[index] = ReadWholeLob(*row[index], columns[index].oracle_type == ORACLE_WIRE_TYPE_CLOB);
            }
        }
    }

    std::vector<uint8_t> ReadWholeLob(const std::vector<uint8_t> &locator, bool is_character) {
        TtcLobRequest length_request;
        length_request.sequence = NextCursorSequence();
        length_request.locator = locator;
        length_request.operation = LOB_OP_GET_LENGTH;
        const auto total = channel.LobOperation(length_request, server_field_version).amount;
        std::vector<uint8_t> content;
        // The unit is Oracle's: characters for a CLOB, bytes for a BLOB. The
        // offset advances by what the server says it served, so a multi-byte
        // character never splits the count.
        uint64_t served = 0;
        while (served < total) {
            TtcLobRequest read_request;
            read_request.sequence = NextCursorSequence();
            read_request.locator = locator;
            read_request.operation = LOB_OP_READ;
            read_request.offset = served + 1;
            read_request.amount = std::min<uint64_t>(total - served, is_character ? 32767 : 65536);
            const auto response = channel.LobOperation(read_request, server_field_version);
            if (response.amount == 0 && response.data.empty()) {
                // The server has nothing more to give. Stopping here is the
                // only alternative to looping on an unchanging offset.
                break;
            }
            content.insert(content.end(), response.data.begin(), response.data.end());
            served += response.amount != 0 ? response.amount : response.data.size();
        }
        return is_character ? DecodeUtf16BeToUtf8(content) : content;
    }

    uint8_t NextCursorSequence() {
        const auto result = next_sequence++;
        if (next_sequence == 0) {
            next_sequence = 1;
        }
        return result;
    }

    OracleBatch Fetch(size_t requested_rows) override {
        if (closed || !lifetime->open || requested_rows == 0) {
            throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "Oracle cursor is closed or fetch size is zero");
        }
        OracleBatch result;
        result.columns = columns;
        const auto take_pending = [&] {
            const auto count = (std::min)(requested_rows - result.rows.size(), pending.size());
            result.rows.insert(result.rows.end(), std::make_move_iterator(pending.begin()),
                               std::make_move_iterator(pending.begin() + static_cast<std::ptrdiff_t>(count)));
            pending.erase(pending.begin(), pending.begin() + static_cast<std::ptrdiff_t>(count));
        };
        take_pending();
        if (result.rows.size() < requested_rows && !exhausted) {
            // The fetch and the response that answers it are one call, and a
            // shared session may have another pipeline waiting to make its own.
            const auto call = channel.LockCall();
            const auto sequence = next_sequence++;
            if (next_sequence == 0) {
                next_sequence = 1;
            }
            channel.Fetch(handle, sequence, static_cast<uint32_t>(requested_rows - result.rows.size()));
            const auto response = channel.ReceiveDecodedFetchResponse(handle, columns, server_field_version, previous_row);
            result.rows.insert(result.rows.end(), response.rows.begin(), response.rows.end());
            previous_row = response.last_row;
            exhausted = response.exhausted;
            if (exhausted) {
                channel.MarkFetchExhausted(handle);
            }
        }
        result.exhausted = exhausted && pending.empty();
        ResolveLobs(result);
        return result;
    }

    void Cancel() override {
        if (closed || !lifetime->open) {
            throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "Oracle cursor is closed");
        }
        channel.Cancel(handle);
    }

    void Close() override {
        if (!closed) {
            // A caller may close the session before releasing a cursor. Do
            // not dereference the channel reference after that point: closing
            // the transport already releases its server-side state.
            if (lifetime->open) {
                const auto call = channel.LockCall();
                channel.Close(handle);
            }
            closed = true;
        }
    }

private:
    TtcStatementChannel &channel;
    uint8_t &next_sequence;
    std::shared_ptr<NativeSessionLifetime> lifetime;
    OracleStatementHandle handle;
    std::vector<OracleColumn> columns;
    std::vector<TtcRowData> pending;
    std::optional<TtcRowData> previous_row;
    uint8_t server_field_version = ORACLE_CLIENT_TTC_FIELD_VERSION;
    bool exhausted = false;
    bool closed = false;
};

} // namespace

NativeOracleSession::NativeOracleSession(std::unique_ptr<TnsClientConnection> connection_p)
    : connection(std::move(connection_p)), channel(std::make_unique<TtcStatementChannel>(connection->Ttc(), statements)),
      lifetime(std::make_shared<NativeSessionLifetime>()) {
}

NativeOracleSession::~NativeOracleSession() { Close(); }

std::unique_ptr<NativeOracleSession> NativeOracleSession::Connect(const ConnectionConfig &config, const std::string &password) {
    if (config.user.empty() || password.empty()) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "native Oracle session requires a user and password");
    }
    TlsConfiguration tls;
    if (config.protocol == TransportProtocol::TCPS) {
        tls.server_name = config.tls_server_name;
        tls.sni_name = config.tls_sni_name.empty() ? config.host : config.tls_sni_name;
        if (!config.tls_ca_file.empty()) {
            tls.ca_pem_contents = ReadPemFile(config.tls_ca_file);
        }
        if (!config.wallet_pem_file.empty()) {
            tls.client_pem_contents = ReadWalletPemFile(config.wallet_pem_file);
        }
        tls.client_pem_password = config.wallet_password;
        tls.expected_server_dn = config.tls_server_cert_dn;
    }
    auto connection = TnsClientConnection::Connect(config, tls);
    connection->Negotiate();
    connection->AuthenticateO5Logon(config.user, password);
    return std::unique_ptr<NativeOracleSession>(new NativeOracleSession(std::move(connection)));
}

uint8_t NativeOracleSession::NextSequence() {
    const auto result = next_sequence++;
    if (next_sequence == 0) {
        next_sequence = 1;
    }
    return result;
}

void NativeOracleSession::RequireOpen() const {
    if (!connection || connection->State() != OracleConnectionState::AUTHENTICATED) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "native Oracle session is closed");
    }
}

std::unique_ptr<OracleCursor> NativeOracleSession::Query(const std::string &sql, const std::vector<OracleBind> &binds) {
    RequireOpen();
    const auto call = channel->LockCall();
    const auto ordered_binds = OrderOracleStatementBinds(sql, binds, OracleBindUse::QUERY);
    const auto handle = statements.Open(OracleSqlKind::QUERY);
    if (ordered_binds.empty()) {
        TtcExecuteNoBindsRequest request;
        request.sequence = NextSequence();
        request.sql = sql;
        request.is_query = true;
        channel->ExecuteNoBinds(handle, request);
    } else {
        TtcExecuteBindsRequest request;
        request.sequence = NextSequence();
        request.sql = sql;
        request.binds = ordered_binds;
        request.is_query = true;
        channel->ExecuteBinds(handle, request);
    }
    const auto response = DecodeTtcExecuteResponse(channel->ReceiveExecuteResponse(handle), connection->TtcFieldVersion(),
                                 connection->TtcServerFieldVersion());
    if (!response.completion || response.completion->cursor_id == 0) {
        statements.Poison(handle);
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle query response has no cursor completion");
    }
    channel->CompleteExecute(handle, true, response.completion->cursor_id);
    return std::make_unique<NativeOracleCursor>(*channel, next_sequence, lifetime, handle, response.columns, response.rows,
                                                response.exhausted, connection->TtcServerFieldVersion());
}

uint64_t NativeOracleSession::Execute(const std::string &sql, const std::vector<OracleBind> &binds) {
    RequireOpen();
    const auto call = channel->LockCall();
    const auto ordered_binds = OrderOracleStatementBinds(sql, binds, OracleBindUse::DML);
    const auto handle = statements.Open(OracleSqlKind::DML);
    if (ordered_binds.empty()) {
        TtcExecuteNoBindsRequest request;
        request.sequence = NextSequence();
        request.sql = sql;
        channel->ExecuteNoBinds(handle, request);
    } else {
        TtcExecuteBindsRequest request;
        request.sequence = NextSequence();
        request.sql = sql;
        request.binds = ordered_binds;
        channel->ExecuteBinds(handle, request);
    }
    const auto completion = channel->ReceiveDmlResponse(handle, connection->TtcServerFieldVersion());
    // The TTIOER completion names the server cursor this statement opened.
    // Recording it is what lets Close queue the piggybacked close; without it
    // the server keeps the cursor and a long run of statements on one session
    // ends in ORA-01000.
    channel->CompleteExecute(handle, false, completion.cursor_id);
    channel->Close(handle);
    return completion.row_count;
}

uint64_t NativeOracleSession::ExecuteWithRowCount(const std::string &sql, const std::vector<OracleBind> &binds) {
    RequireOpen();
    const auto call = channel->LockCall();
    auto ordered_binds = OrderOracleStatementBinds(sql, binds, OracleBindUse::DML);
    // PL/SQL bind variables are stricter than SQL placeholders: begin the
    // generated name with a letter even though the SQL scanner also permits
    // an underscore there.
    std::string count_name = "oracle_scanner_row_count";
    for (;;) {
        const auto canonical = CanonicalOracleBindName(count_name);
        bool collides = false;
        for (const auto &bind : ordered_binds) {
            if (CanonicalOracleBindName(bind.name) == canonical) {
                collides = true;
                break;
            }
        }
        if (!collides) {
            break;
        }
        count_name += "_";
    }
    ordered_binds.push_back({count_name, 2, BindDirection::BIND_OUT, std::nullopt, 22});
    const auto block = "BEGIN " + sql + "; :" + count_name + " := SQL%ROWCOUNT; END;";

    const auto handle = statements.Open(OracleSqlKind::PLSQL);
    TtcExecuteBindsRequest execute;
    execute.sequence = NextSequence();
    execute.sql = block;
    execute.binds = ordered_binds;
    execute.is_plsql = true;
    channel->ExecuteBinds(handle, execute);
    const auto decoded = channel->ReceiveCallResponse(handle, ordered_binds, connection->TtcFieldVersion(),
                                                    connection->TtcServerFieldVersion());
    channel->CompleteExecute(handle, false, decoded.completion ? decoded.completion->cursor_id : 0);
    channel->Close(handle);
    if (!decoded.out_binds || decoded.out_binds->scalar_values.size() != 1 ||
        decoded.out_binds->cursor_values.size() != 1 || !decoded.out_binds->scalar_values[0]) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle DML row-count OUT bind is missing");
    }
    const auto text = DecodeOracleNumber(*decoded.out_binds->scalar_values[0]);
    size_t parsed = 0;
    uint64_t result = 0;
    try {
        result = std::stoull(text, &parsed);
    } catch (const std::exception &) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle DML row count is not an unsigned integer");
    }
    if (parsed != text.size()) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle DML row count is not an unsigned integer");
    }
    return result;
}

// One OALL8 per group of rows rather than one per row: Oracle parses the
// statement once, receives the bind metadata once, and runs it as many times as
// there are ROW_DATA messages. The batch is split into groups only so that one
// request stays a bounded message; the row counts are summed across groups.
uint64_t NativeOracleSession::ExecuteBatch(const std::string &sql, const std::vector<std::vector<OracleBind>> &rows) {
    RequireOpen();
    if (rows.empty()) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "native Oracle DML batch cannot be empty");
    }
    constexpr size_t maximum_iterations_per_execute = 1024;
    uint64_t affected_rows = 0;
    for (size_t start = 0; start < rows.size(); start += maximum_iterations_per_execute) {
        const auto call = channel->LockCall();
        const auto end = (std::min)(rows.size(), start + maximum_iterations_per_execute);
        auto ordered_first = OrderOracleStatementBinds(sql, rows[start], OracleBindUse::DML);
        const auto handle = statements.Open(OracleSqlKind::DML);
        TtcExecuteBindsRequest execute;
        execute.sequence = NextSequence();
        execute.sql = sql;
        execute.binds = std::move(ordered_first);
        execute.additional_iterations.reserve(end - start - 1);
        for (size_t index = start + 1; index < end; index++) {
            execute.additional_iterations.push_back(OrderOracleStatementBinds(sql, rows[index], OracleBindUse::DML));
        }
        channel->ExecuteBinds(handle, execute);
        TtcErrorInfo completion;
        try {
            completion = channel->ReceiveDmlResponse(handle, connection->TtcServerFieldVersion());
        } catch (const OracleDmlError &error) {
            // The server reports the iteration it was on, zero-based and
            // relative to this request; the caller counts from the start of the
            // batch it handed over.
            // The row goes first: Oracle's own text is what a reader looks
            // for, and anything appended after it competes with the newline
            // Oracle ends it with.
            throw ProtocolError(error.Kind(), "row " + std::to_string(start + error.FailedRow() + 1) +
                                                  " of the batch failed: " + error.what());
        }
        channel->CompleteExecute(handle, false, completion.cursor_id);
        channel->Close(handle);
        if ((std::numeric_limits<uint64_t>::max)() - affected_rows < completion.row_count) {
            throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "native Oracle DML batch row count overflows uint64");
        }
        affected_rows += completion.row_count;
    }
    return affected_rows;
}

std::vector<OracleBind> NativeOracleSession::ExecuteReturning(const std::string &sql,
                                                              const std::vector<OracleBind> &binds) {
    RequireOpen();
    const auto call = channel->LockCall();
    // The statement already names its own OUT binds — `RETURNING x INTO :y` —
    // so unlike ExecuteWithRowCount nothing is appended to it. Wrapping it in a
    // PL/SQL block is what puts it on the out-bind wire path, which is the one
    // that carries values back.
    auto ordered_binds = OrderOracleStatementBinds(sql, binds, OracleBindUse::CALL);
    const auto block = "BEGIN " + sql + "; END;";

    const auto handle = statements.Open(OracleSqlKind::PLSQL);
    TtcExecuteBindsRequest execute;
    execute.sequence = NextSequence();
    execute.sql = block;
    execute.binds = ordered_binds;
    execute.is_plsql = true;
    channel->ExecuteBinds(handle, execute);
    const auto decoded = channel->ReceiveCallResponse(handle, ordered_binds, connection->TtcFieldVersion(),
                                                      connection->TtcServerFieldVersion());
    channel->CompleteExecute(handle, false, decoded.completion ? decoded.completion->cursor_id : 0);
    channel->Close(handle);

    std::vector<OracleBind> outputs;
    for (const auto &bind : ordered_binds) {
        if (bind.direction != BindDirection::BIND_IN) {
            outputs.push_back(bind);
        }
    }
    if (!decoded.out_binds || decoded.out_binds->scalar_values.size() != outputs.size()) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED,
                            "Oracle RETURNING produced a different number of values than the statement declared");
    }
    for (size_t index = 0; index < outputs.size(); index++) {
        outputs[index].value = decoded.out_binds->scalar_values[index];
    }
    return outputs;
}

OracleCallResult NativeOracleSession::Call(const OracleCallRequest &request) {
    RequireOpen();
    const auto call = channel->LockCall();
    const auto sql = BuildOracleCallBlock(request);
    std::vector<OracleBind> binds;
    if (request.return_bind) {
        binds.push_back(*request.return_bind);
    }
    binds.insert(binds.end(), request.arguments.begin(), request.arguments.end());
    ValidateOracleBinds(binds, OracleBindUse::CALL);

    const auto handle = statements.Open(OracleSqlKind::PLSQL);
    if (binds.empty()) {
        TtcExecuteNoBindsRequest execute;
        execute.sequence = NextSequence();
        execute.sql = sql;
        execute.is_plsql = true;
        channel->ExecuteNoBinds(handle, execute);
    } else {
        TtcExecuteBindsRequest execute;
        execute.sequence = NextSequence();
        execute.sql = sql;
        execute.binds = binds;
        execute.is_plsql = true;
        channel->ExecuteBinds(handle, execute);
    }
    const auto decoded = channel->ReceiveCallResponse(handle, binds, connection->TtcFieldVersion(),
                                                connection->TtcServerFieldVersion());
    channel->CompleteExecute(handle, false, decoded.completion ? decoded.completion->cursor_id : 0);
    channel->Close(handle);

    OracleCallResult result;
    std::vector<size_t> output_indexes;
    for (size_t index = 0; index < binds.size(); index++) {
        if (binds[index].direction != BindDirection::BIND_IN) {
            output_indexes.push_back(index);
        }
    }
    if (decoded.out_binds) {
        if (decoded.out_binds->scalar_values.size() != output_indexes.size() ||
            decoded.out_binds->cursor_values.size() != output_indexes.size()) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle call OUT-bind result count disagrees with request");
        }
        for (size_t output_position = 0; output_position < output_indexes.size(); output_position++) {
            auto output = binds[output_indexes[output_position]];
            if (output.oracle_type == ORACLE_WIRE_TYPE_CURSOR) {
                const auto &descriptor = decoded.out_binds->cursor_values[output_position];
                if (!descriptor) {
                    continue;
                }
                const auto cursor_handle = statements.Open(OracleSqlKind::QUERY);
                channel->CompleteExecute(cursor_handle, true, descriptor->cursor_id);
                result.explicit_cursors.push_back(std::make_unique<NativeOracleCursor>(
                    *channel, next_sequence, lifetime, cursor_handle, descriptor->columns, std::vector<TtcRowData> {}, false,
                    connection->TtcServerFieldVersion()));
            } else {
                output.value = decoded.out_binds->scalar_values[output_position];
                result.outputs.push_back(std::move(output));
            }
        }
    }
    for (const auto &descriptor : decoded.implicit_cursors) {
        const auto cursor_handle = statements.Open(OracleSqlKind::QUERY);
        channel->CompleteExecute(cursor_handle, true, descriptor.cursor_id);
        result.implicit_cursors.push_back(std::make_unique<NativeOracleCursor>(
            *channel, next_sequence, lifetime, cursor_handle, descriptor.columns, std::vector<TtcRowData> {}, false,
            connection->TtcServerFieldVersion()));
    }
    return result;
}

void NativeOracleSession::Commit() {
    RequireOpen();
    const auto call = channel->LockCall();
    (void)connection->Ttc().Commit(NextSequence());
}

void NativeOracleSession::Rollback() {
    RequireOpen();
    const auto call = channel->LockCall();
    (void)connection->Ttc().Rollback(NextSequence());
}

void NativeOracleSession::Cancel() {
    RequireOpen();
    connection->Ttc().Cancel();
}

void NativeOracleSession::Close() {
    if (connection) {
        lifetime->open = false;
        statements.CloseAll();
        connection->Close();
        channel.reset();
        connection.reset();
    }
}

} // namespace oracle_scanner
