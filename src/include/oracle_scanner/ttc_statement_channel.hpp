#pragma once

#include "oracle_scanner/statement_registry.hpp"
#include "oracle_scanner/ttc_channel.hpp"
#include "oracle_scanner/ttc_call_response.hpp"
#include "oracle_scanner/ttc_execute.hpp"
#include "oracle_scanner/ttc_execute_response.hpp"
#include "oracle_scanner/ttc_lob.hpp"
#include "oracle_scanner/ttc_fetch_response.hpp"
#include "oracle_scanner/ttc_out_binds.hpp"

#include "oracle_scanner/lob_prefetch_cursor.hpp"
#include <cstdint>
#include <mutex>
#include <functional>
#include <vector>

namespace oracle_scanner {

// Couples TTC request I/O to cursor lifecycle. A transport failure or TTC
// server error poisons the cursor so it cannot be reused after a partial read.
class TtcStatementChannel {
public:
    TtcStatementChannel(TtcChannel &channel, OracleStatementRegistry &statements);

    //! Runs one LOB_OP and returns what it served. The end-of-call that
    //! follows the data is consumed here, so a caller sees a value or an
    //! error and never a half-read channel.
    TtcLobResponse LobOperation(const TtcLobRequest &request, uint8_t server_field_version);

    //! Runs a LOB_OP that returns locators rather than data — creating,
    //! writing or releasing a temporary LOB — from an already encoded request.
    //! Returns the locator(s) the server sent back, concatenated.
    std::vector<uint8_t> LocatorOperation(const std::vector<uint8_t> &request, size_t locator_count, bool created,
                                          uint8_t server_field_version);

    //! Held across a request and the response that answers it. See
    //! TtcChannel::LockCall.
    std::unique_lock<std::recursive_mutex> LockCall();

    void ExecuteNoBinds(OracleStatementHandle handle, const TtcExecuteNoBindsRequest &request);
    void ExecuteBinds(OracleStatementHandle handle, const TtcExecuteBindsRequest &request);
    std::vector<uint8_t> ReceiveExecuteResponse(OracleStatementHandle handle);
    TtcExecuteResponse ReceiveDecodedExecuteResponse(OracleStatementHandle handle, uint8_t ttc_field_version = 12,
                                                     uint8_t server_field_version = 12);
    TtcErrorInfo ReceiveDmlResponse(OracleStatementHandle handle, uint8_t server_field_version = 12);
    TtcPlsqlOutBindsResponse ReceivePlsqlOutBindsResponse(OracleStatementHandle handle,
                                                           const std::vector<OracleBind> &binds,
                                                           uint8_t ttc_field_version = 12);
    TtcCallResponse ReceiveCallResponse(OracleStatementHandle handle, const std::vector<OracleBind> &binds,
                                        uint8_t ttc_field_version = 12, uint8_t server_field_version = 12);
    void CompleteExecute(OracleStatementHandle handle, bool is_query, uint32_t remote_cursor_id);
    void Fetch(OracleStatementHandle handle, uint8_t sequence, uint32_t requested_rows);
    // The next rows of a cursor PL/SQL opened, which take OALL8 and not OFETCH
    // (see EncodeTtcCursorFetchRequest).
    void FetchOpenedCursor(OracleStatementHandle handle, uint8_t sequence, uint32_t requested_rows,
                           uint8_t field_version);
    // Re-executes the described cursor with a define for each column, so JSON
    // and VECTOR values arrive with their rows (see ttc_define.hpp).
    void DefineInlineLobs(OracleStatementHandle handle, uint8_t sequence, const std::vector<OracleColumn> &columns,
                          uint32_t rows);
    void DefineLobPrefetch(OracleStatementHandle handle,uint8_t sequence,
        const std::vector<OracleColumn> &columns,uint32_t rows,uint8_t field_version,const OracleLobPrefetchLimits &limits);
    TtcFetchResponse ReceiveDecodedLobPrefetchFetchResponse(OracleStatementHandle handle,
        const std::vector<OracleColumn> &columns,const OracleLobPrefetchLimits &limits,uint8_t server_field_version,
        const std::optional<TtcRowData> &preceding_row);
    void Cancel(OracleStatementHandle handle);
    std::vector<uint8_t> ReceiveFetchResponse(OracleStatementHandle handle);
    TtcFetchResponse ReceiveDecodedFetchResponse(OracleStatementHandle handle, const std::vector<OracleColumn> &columns,
                                                 uint8_t server_field_version = 12,
                                                 const std::optional<TtcRowData> &preceding_row = std::nullopt);
    void MarkFetchExhausted(OracleStatementHandle handle);
    // Discards the local handle immediately and schedules its server cursor
    // for Oracle's next-call CLOSE_CURSORS piggyback when it has one.
    bool Close(OracleStatementHandle handle);

private:
    void LobExchange(const std::vector<uint8_t> &request, const std::function<void(const std::vector<uint8_t> &)> &decode);

    TtcChannel &channel;
    OracleStatementRegistry &statements;
};

} // namespace oracle_scanner
