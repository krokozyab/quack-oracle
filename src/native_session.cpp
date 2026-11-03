#include "oracle_scanner/native_session.hpp"
#include "oracle_scanner/native_fetch_cancellation.hpp"

#include "oracle_scanner/bind_validation.hpp"
#include "oracle_scanner/call_builder.hpp"
#include "oracle_scanner/protocol_error.hpp"
#include "oracle_scanner/sql_binds.hpp"
#include "oracle_scanner/sql_statement.hpp"
#include "oracle_scanner/ttc_execute_response.hpp"
#include "oracle_scanner/ttc_lob.hpp"
#include "oracle_scanner/temp_lob.hpp"
#include "oracle_scanner/lob_reader.hpp"
#include "oracle_scanner/io_deadline_binding.hpp"
#include "oracle_scanner/lob_prefetch_cursor.hpp"
#include "oracle_scanner/ttc_define.hpp"
#include "oracle_scanner/value_codec.hpp"
#include "oracle_scanner/wallet_archive.hpp"

#include <algorithm>
#include <cstdlib>
#include <functional>
#include <limits>
#include <utility>

namespace oracle_scanner {

struct NativeSessionLifetime {
    bool open = true;
    // Set by any operation or fetch that failed. The exchange may have left a
    // response unread, so the session is never handed to another caller.
    bool exchange_failed = false;
    NativeFetchCancellation fetch_cancellation;
};

namespace {

class NativeOracleCursor final : public OracleCursor {
public:
    NativeOracleCursor(TtcStatementChannel &channel_p, uint8_t &next_sequence_p, std::shared_ptr<NativeSessionLifetime> lifetime_p,
                       OracleStatementHandle handle_p,
                       std::vector<OracleColumn> columns_p, std::vector<TtcRowData> prefetched_p, bool exhausted_p,
                       uint8_t server_field_version_p,uint8_t field_version_p=0)
        : channel(channel_p), next_sequence(next_sequence_p), lifetime(std::move(lifetime_p)), handle(handle_p),
          columns(std::move(columns_p)), pending(std::move(prefetched_p)), server_field_version(server_field_version_p),
          exhausted(exhausted_p),field_version(field_version_p) {
        prefetch_eligible=SupportsLobPrefetchColumns(columns,field_version);
        if (prefetch_eligible) {
            try { (void)BoundedLobPrefetchRows(columns,1,prefetch_limits); }
            catch (const ProtocolError &error) {
                if (error.Kind()!=ProtocolErrorKind::LIMIT_EXCEEDED) { throw; }
                prefetch_eligible=false;
            }
        }
        inline_eligible = !prefetch_eligible && SupportsInlineLobDefine(columns, field_version);
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
    void ResolveLobs(OracleBatch &batch,bool prefetched=false) {
        bool any = false;
        for (const auto &column : columns) {
            any = any || IsOracleLocatorType(column.oracle_type);
        }
        if (!any) {
            return;
        }
        for (auto &row : batch.rows) {
            for (size_t index = 0; index < row.size() && index < columns.size(); index++) {
                if (!IsOracleLocatorType(columns[index].oracle_type) || !row[index]) {
                    continue;
                }
                const bool character=columns[index].oracle_type==ORACLE_WIRE_TYPE_CLOB;
                if (columns[index].inline_lob_cells && !prefetched) {
                    row[index]=ResolveInlineLob(*row[index],character);
                    continue;
                }
                if (!prefetched) { row[index]=ReadWholeLob(*row[index],character);continue; }
                const auto call=channel.LockCall();
                const auto cell=DecodeStoredLobPrefetch(*row[index],character,prefetch_limits);
                const auto content=MaterializePrefetchedOracleLob(cell,65536,prefetch_limits.maximum_content_bytes,
                    [&](const std::vector<uint8_t> &locator,uint64_t offset,uint64_t amount) {
                        TtcLobRequest request;request.sequence=NextCursorSequence();request.locator=locator;
                        request.operation=LOB_OP_READ;request.offset=offset;request.amount=amount;
                        return channel.LobOperation(request,server_field_version);
                    });
                if (!content) { throw ProtocolError(ProtocolErrorKind::MALFORMED,"non-NULL prefetched LOB became NULL"); }
                row[index]=character ? DecodeUtf16BeToUtf8(*content) : *content;
            }
        }
    }

    // A value that came with its row: whole, when what the server sent covers
    // it, and otherwise the rest of it is read from the locator. A CLOB or BLOB
    // came with only its size, so the size spares the length request.
    std::vector<uint8_t> ResolveInlineLob(const std::vector<uint8_t> &cell, bool character) {
        const auto lob = DecodeTtcInlineLob(cell);
        if (!character && lob.prefix.size() == lob.total) {
            return lob.prefix;
        }
        OracleLobPrefetch prefetch;
        prefetch.character = character;
        prefetch.total_units = lob.total;
        prefetch.prefix_units = lob.prefix.size();
        prefetch.prefix = lob.prefix;
        prefetch.locator = lob.locator;
        const auto call = channel.LockCall();
        const auto content = MaterializePrefetchedOracleLob(
            std::optional<OracleLobPrefetch>(std::move(prefetch)), 65536, prefetch_limits.maximum_content_bytes,
            [&](const std::vector<uint8_t> &locator, uint64_t offset, uint64_t amount) {
                TtcLobRequest request;
                request.sequence = NextCursorSequence();
                request.locator = locator;
                request.operation = LOB_OP_READ;
                request.offset = offset;
                request.amount = amount;
                return channel.LobOperation(request, server_field_version);
            });
        return character ? DecodeUtf16BeToUtf8(*content) : *content;
    }

    std::vector<uint8_t> ReadWholeLob(const std::vector<uint8_t> &locator, bool is_character) {
        // Sequence allocation and every request/response share the session call lock.
        const auto call = channel.LockCall();
        auto content = ReadOracleLobContent(is_character,
            [&](uint64_t offset, uint64_t amount) {
                TtcLobRequest request;
                request.sequence = NextCursorSequence();
                request.locator = locator;
                request.operation = LOB_OP_READ;
                request.offset = offset;
                request.amount = amount;
                return channel.LobOperation(request, server_field_version);
            }, [&] {
                TtcLobRequest request;
                request.sequence = NextCursorSequence();
                request.locator = locator;
                request.operation = LOB_OP_GET_LENGTH;
                return channel.LobOperation(request, server_field_version).amount;
            });
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
        const auto fetch_call = channel.LockCall();
        lifetime->fetch_cancellation.RequireUsable();
        try {
        OracleBatch result;
        result.columns = columns;
        const auto take_pending = [&] {
            const auto count = (std::min)(requested_rows - result.rows.size(), pending.size());
            result.rows.insert(result.rows.end(), std::make_move_iterator(pending.begin()),
                               std::make_move_iterator(pending.begin() + static_cast<std::ptrdiff_t>(count)));
            pending.erase(pending.begin(), pending.begin() + static_cast<std::ptrdiff_t>(count));
        };
        take_pending();
        // Initial execute rows always retain the old locator representation.
        // Resolve them before DEFINE, separately from prefetched rows.
        ResolveLobs(result,false);
        if (result.rows.size() < requested_rows && !exhausted) {
            // The fetch and the response that answers it are one call, and a
            // shared session may have another pipeline waiting to make its own.
            const auto call = channel.LockCall();
            const auto desired=requested_rows-result.rows.size();
            const auto count=prefetch_eligible ? BoundedLobPrefetchRows(columns,desired,prefetch_limits) :
                inline_eligible ? InlineLobRows(columns,desired) :
                static_cast<uint32_t>((std::min)(desired,size_t((std::numeric_limits<uint32_t>::max)())));
            const auto sequence=NextCursorSequence();
            if (prefetch_eligible && !prefetch_active) {
                channel.DefineLobPrefetch(handle,sequence,columns,count,field_version,prefetch_limits);
                // Never interpret an old locator as a prefetched descriptor.
                previous_row.reset();prefetch_active=true;
            } else if (inline_eligible && !inline_active) {
                channel.DefineInlineLobs(handle,sequence,columns,count);
                for (auto &column : columns) { column.inline_lob_cells = IsOracleLocatorType(column.oracle_type); }
                // The rows before the define carry locators only.
                previous_row.reset();inline_active=true;
            } else { channel.Fetch(handle,sequence,count); }
            auto response_limits=prefetch_limits;
            response_limits.maximum_rows=count;
            auto response=prefetch_active ?
                channel.ReceiveDecodedLobPrefetchFetchResponse(handle,columns,response_limits,server_field_version,previous_row) :
                channel.ReceiveDecodedFetchResponse(handle,columns,server_field_version,previous_row);
            previous_row = response.last_row;
            exhausted = response.exhausted;
            OracleBatch decoded;decoded.rows=std::move(response.rows);ResolveLobs(decoded,prefetch_active);
            result.rows.insert(result.rows.end(),std::make_move_iterator(decoded.rows.begin()),std::make_move_iterator(decoded.rows.end()));
            if (exhausted) {
                channel.MarkFetchExhausted(handle);
            }
        }
        result.exhausted = exhausted && pending.empty();
        lifetime->fetch_cancellation.CompleteFetch();
        return result;
        } catch (const ProtocolError &error) {
            lifetime->exchange_failed = true;
            lifetime->fetch_cancellation.ObserveError(error);
            throw;
        } catch (...) {
            lifetime->exchange_failed = true;
            lifetime->fetch_cancellation.ObserveUnknownError();
            throw;
        }
    }

    void Cancel() override {
        if (closed || !lifetime->open) {
            throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "Oracle cursor is closed");
        }
        lifetime->fetch_cancellation.Request([&] { channel.Cancel(handle); });
    }

    void Close() override {
        if (!closed) {
            // A caller may close the session before releasing a cursor. Do
            // not dereference the channel reference after that point: closing
            // the transport already releases its server-side state.
            if (lifetime->open && lifetime->fetch_cancellation.CanUseConnection()) {
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
    uint8_t field_version=0;
    bool prefetch_eligible=false;
    bool prefetch_active=false;
    bool inline_eligible=false;
    bool inline_active=false;
    OracleLobPrefetchLimits prefetch_limits;
};

// Temporary LOB operations on the session's own channel.
class SessionTemporaryLobWriter final : public TemporaryLobWriter {
public:
    SessionTemporaryLobWriter(TtcStatementChannel &channel_p, std::function<uint8_t()> next_sequence_p,
                              uint8_t server_field_version_p)
        : channel(channel_p), next_sequence(std::move(next_sequence_p)), server_field_version(server_field_version_p) {
    }

    std::vector<uint8_t> Create(TtcTempLobKind kind) override {
        return channel.LocatorOperation(EncodeTtcCreateTempLob(next_sequence(), kind), 1, true, server_field_version);
    }

    std::vector<uint8_t> Write(const std::vector<uint8_t> &locator, uint64_t offset,
                               const std::vector<uint8_t> &data) override {
        return channel.LocatorOperation(EncodeTtcWriteLob(next_sequence(), locator, offset, data), 1, false,
                                        server_field_version);
    }

    void Free(const std::vector<std::vector<uint8_t>> &locators) override {
        (void)channel.LocatorOperation(EncodeTtcFreeTempLobs(next_sequence(), locators), locators.size(), false,
                                       server_field_version);
    }

private:
    TtcStatementChannel &channel;
    std::function<uint8_t()> next_sequence;
    uint8_t server_field_version;
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
        // The names checked and sent are settled per attempt by the connect
        // loop, from these or from the address being dialed.
        tls.server_name = config.tls_server_name;
        tls.sni_name = config.tls_sni_name;
        if (!config.tls_ca_file.empty()) {
            tls.ca_pem_contents = ReadPemFile(config.tls_ca_file);
        }
        if (!config.wallet_pem_file.empty()) {
            tls.client_pem_contents = ReadWalletIdentityPem(config.wallet_pem_file, !config.wallet_password.empty());
        }
        tls.client_pem_password = config.wallet_password;
        tls.expected_server_dn = config.tls_server_cert_dn;
    }
    auto connection = TnsClientConnection::Connect(config, tls);
    connection->Negotiate();
    connection->AuthenticateO5Logon(config.user, password);
    auto session = std::unique_ptr<NativeOracleSession>(new NativeOracleSession(std::move(connection)));
    session->deadline_binding = config.io_deadline_binding;
    TtcEndToEndAttributes attributes;
    if (!config.client_identifier.empty()) {
        attributes.client_identifier = config.client_identifier;
    }
    if (!config.module.empty()) {
        attributes.module = config.module;
    }
    if (!config.action.empty()) {
        attributes.action = config.action;
    }
    if (!config.client_info.empty()) {
        attributes.client_info = config.client_info;
    }
    if (!attributes.Empty()) {
        // Sent at once, in front of a ping, so the first statement does not
        // have to find the server's report of it in its own response.
        session->connection->Ttc().QueueEndToEndAttributes(attributes);
        session->connection->Ttc().Ping(session->NextSequence(), session->connection->TtcServerFieldVersion());
    }
    return session;
}

// Normal native reader owns the response. This only withholds a result after
// accepted Cancel and records a genuinely decoded error; no drain or replay.
template <class Operation>
static auto RunNativeOperation(NativeSessionLifetime &lifetime, Operation operation)
    -> decltype(operation()) {
    try {
        auto result = operation();
        lifetime.fetch_cancellation.CompleteOperation();
        return result;
    } catch (const ProtocolError &error) {
        lifetime.exchange_failed = true;
        lifetime.fetch_cancellation.ObserveError(error);
        throw;
    } catch (...) {
        lifetime.exchange_failed = true;
        lifetime.fetch_cancellation.ObserveUnknownError();
        throw;
    }
}

uint8_t NativeOracleSession::NextSequence() {
    const auto result = next_sequence++;
    if (next_sequence == 0) {
        next_sequence = 1;
    }
    return result;
}

template <class Operation>
auto NativeOracleSession::WithTemporaryLobs(const std::vector<OracleBind> &binds, Operation operation)
    -> decltype(operation(binds)) {
    if (!TemporaryLobScope::Needed(binds)) {
        return operation(binds);
    }
    const auto call = channel->LockCall();
    SessionTemporaryLobWriter writer(*channel, [this] { return NextSequence(); }, connection->TtcServerFieldVersion());
    TemporaryLobScope scope(writer);
    auto converted = binds;
    try {
        scope.Convert(converted);
        auto result = operation(converted);
        scope.Release();
        return result;
    } catch (...) {
        scope.ReleaseQuietly();
        throw;
    }
}

void NativeOracleSession::RequireOpen() const {
    if (!connection || connection->State() != OracleConnectionState::AUTHENTICATED) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "native Oracle session is closed");
    }
    lifetime->fetch_cancellation.RequireUsable();
}

std::unique_ptr<OracleCursor> NativeOracleSession::Query(const std::string &sql, const std::vector<OracleBind> &binds) {
    // Like every other operation: an ORA-01013 answering an accepted Cancel is
    // observed here, which is what makes the session usable again afterwards.
    return RunNativeOperation(*lifetime, [&]() -> std::unique_ptr<OracleCursor> {
        return OpenQuery(sql, binds);
    });
}

std::unique_ptr<OracleCursor> NativeOracleSession::OpenQuery(const std::string &sql, const std::vector<OracleBind> &binds) {
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
    const auto response = channel->ReceiveDecodedExecuteResponse(handle, connection->TtcFieldVersion(),
                                                                  connection->TtcServerFieldVersion());
    if (!response.completion || response.completion->cursor_id == 0) {
        statements.Poison(handle);
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle query response has no cursor completion");
    }
    channel->CompleteExecute(handle, true, response.completion->cursor_id);
    return std::make_unique<NativeOracleCursor>(*channel, next_sequence, lifetime, handle, response.columns, response.rows,
                                                response.exhausted, connection->TtcServerFieldVersion(),connection->TtcFieldVersion());
}

uint64_t NativeOracleSession::Execute(const std::string &sql, const std::vector<OracleBind> &binds) {
    return RunNativeOperation(*lifetime, [&]() {
        return WithTemporaryLobs(binds, [&](const std::vector<OracleBind> &effective) {
            return ExecuteStatement(sql, effective, OracleSqlKind::DML);
        });
    });
}

void NativeOracleSession::ExecuteAdmin(const std::string &sql) {
    ValidateOracleAdmin(sql);
    (void)ExecuteStatement(sql, {}, OracleSqlKind::ADMIN);
}

uint64_t NativeOracleSession::ExecuteStatement(const std::string &sql, const std::vector<OracleBind> &binds,
                                              OracleSqlKind kind) {
    RequireOpen();
    const auto call = channel->LockCall();
    const auto ordered_binds = OrderOracleStatementBinds(sql, binds, OracleBindUse::DML);
    const auto handle = statements.Open(kind);
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
    return RunNativeOperation(*lifetime, [&]() {
    return WithTemporaryLobs(binds, [&](const std::vector<OracleBind> &binds) {
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
    });
    });
}

// One OALL8 per group of rows rather than one per row: Oracle parses the
// statement once, receives the bind metadata once, and runs it as many times as
// there are ROW_DATA messages. The batch is split into groups only so that one
// request stays a bounded message; the row counts are summed across groups.
uint64_t NativeOracleSession::ExecuteBatch(const std::string &sql, const std::vector<std::vector<OracleBind>> &rows) {
    RequireOpen();
    return RunNativeOperation(*lifetime, [&]() {
        if (rows.empty()) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "native Oracle DML batch cannot be empty");
        }
        constexpr size_t maximum_iterations_per_execute = 1024;
        uint64_t affected_rows = 0;
        for (size_t start = 0; start < rows.size(); start += maximum_iterations_per_execute) {
            RequireOpen();
            const auto call = channel->LockCall();
            const auto end = (std::min)(rows.size(), start + maximum_iterations_per_execute);
            // A LOB value too large for an ordinary bind goes through a
            // temporary LOB, one group at a time so they are released as soon
            // as the group has run.
            SessionTemporaryLobWriter lob_writer(*channel, [this] { return NextSequence(); },
                                                 connection->TtcServerFieldVersion());
            TemporaryLobScope lobs(lob_writer);
            std::vector<std::vector<OracleBind>> converted;
            const bool use_converted = TemporaryLobScope::NeededRows(rows, start, end);
            if (use_converted) {
                converted.assign(rows.begin() + static_cast<std::ptrdiff_t>(start),
                                 rows.begin() + static_cast<std::ptrdiff_t>(end));
            }
            const auto row_at = [&](size_t index) -> const std::vector<OracleBind> & {
                return use_converted ? converted[index - start] : rows[index];
            };
            try {
                if (use_converted) {
                    lobs.ConvertRows(converted);
                }
                // The SQL is parsed for its placeholders once per group; every
                // later row has to carry the first row's names in the same places,
                // so the same order puts it right.
                const auto &first = row_at(start);
                const auto order = OracleStatementBindOrder(sql, first, OracleBindUse::DML);
                const auto ordered = [&](const std::vector<OracleBind> &row) {
                    std::vector<OracleBind> result;
                    result.reserve(order.size());
                    for (const auto index : order) {
                        result.push_back(row[index]);
                    }
                    return result;
                };
                const auto handle = statements.Open(OracleSqlKind::DML);
                TtcExecuteBindsRequest execute;
                execute.sequence = NextSequence();
                execute.sql = sql;
                execute.binds = ordered(first);
                execute.additional_iterations.reserve(end - start - 1);
                for (size_t index = start + 1; index < end; index++) {
                    ValidateOracleBatchRow(first, row_at(index));
                    execute.additional_iterations.push_back(ordered(row_at(index)));
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
                                                          " of the batch failed: " + error.what(), error.OracleCode());
                }
                channel->CompleteExecute(handle, false, completion.cursor_id);
                channel->Close(handle);
                if ((std::numeric_limits<uint64_t>::max)() - affected_rows < completion.row_count) {
                    throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED,
                                        "native Oracle DML batch row count overflows uint64");
                }
                affected_rows += completion.row_count;
                lobs.Release();
            } catch (...) {
                lobs.ReleaseQuietly();
                throw;
            }
        }
        return affected_rows;
    });
}

std::vector<OracleBind> NativeOracleSession::ExecuteReturning(const std::string &sql,
                                                              const std::vector<OracleBind> &binds) {
    RequireOpen();
    return RunNativeOperation(*lifetime, [&]() {
    return WithTemporaryLobs(binds, [&](const std::vector<OracleBind> &binds) {
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
    });
    });
}

OracleCallResult NativeOracleSession::Call(const OracleCallRequest &request) {
    RequireOpen();
    return RunNativeOperation(*lifetime, [&]() {
        const auto call = channel->LockCall();
        const auto sql = BuildOracleCallBlock(request);
        std::vector<OracleBind> binds;
        if (request.return_bind) {
            binds.push_back(*request.return_bind);
        }
        binds.insert(binds.end(), request.arguments.begin(), request.arguments.end());
        if (request.kind == OracleCallableKind::DML_COMPOSITE || request.kind == OracleCallableKind::ANONYMOUS_BLOCK) {
            // A procedure block names its binds in argument order; a composite
            // names them in whatever order its statements do, and PL/SQL binds
            // by first occurrence, so the values follow the block.
            binds = OrderOracleStatementBinds(sql, binds, OracleBindUse::CALL);
        }
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
                    result.explicit_cursors.emplace_back(std::make_unique<NativeOracleCursor>(
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
            result.implicit_cursors.emplace_back(std::make_unique<NativeOracleCursor>(
                *channel, next_sequence, lifetime, cursor_handle, descriptor.columns, std::vector<TtcRowData> {}, false,
                connection->TtcServerFieldVersion()));
        }
        return result;
    });
}

void NativeOracleSession::Commit() {
    RequireOpen();
    const auto call = channel->LockCall();
    try {
        (void)connection->Ttc().Commit(NextSequence(),connection->TtcServerFieldVersion());
    } catch (...) {
        lifetime->exchange_failed = true;
        throw;
    }
}

void NativeOracleSession::Rollback() {
    RequireOpen();
    const auto call = channel->LockCall();
    try {
        (void)connection->Ttc().Rollback(NextSequence(),connection->TtcServerFieldVersion());
    } catch (...) {
        lifetime->exchange_failed = true;
        throw;
    }
}

OracleIoStats NativeOracleSession::IoStats() const {
    if (!connection) {
        return {};
    }
    try {
        const auto statistics = connection->Packets().GetStatistics();
        return {statistics.bytes_sent, statistics.bytes_received, statistics.round_trips};
    } catch (const std::exception &) {
        return {};
    }
}

bool NativeOracleSession::ReadyForReuse() const {
    return connection && connection->State() == OracleConnectionState::AUTHENTICATED && lifetime->open &&
           !lifetime->exchange_failed && lifetime->fetch_cancellation.CanUseConnection() &&
           statements.OpenCount() == 0 && deadline_binding;
}

bool NativeOracleSession::BindIoDeadline(std::shared_ptr<OracleIoDeadline> source) {
    if (!deadline_binding) {
        return false;
    }
    deadline_binding->Bind(std::move(source));
    return true;
}

void NativeOracleSession::Cancel() {
    RequireOpen();
    lifetime->fetch_cancellation.Request([&] { connection->Ttc().Cancel(); });
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
