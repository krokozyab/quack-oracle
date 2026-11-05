#pragma once

// Internal seam between the DuckDB adapter's translation units. The catalog and
// the table functions both need the scan's bind data and the Oracle-to-DuckDB
// conversions, so those live here rather than in one anonymous namespace.
// Nothing here is part of the extension's public surface.

#include "oracle_scanner/protocol_error.hpp"
#include "oracle_scanner/session.hpp"
#include "oracle_scanner/session_pool.hpp"
#include "oracle_scanner/tns_client.hpp"
#include "oracle_scanner/transaction_session_pool.hpp"
#include "oracle_scanner/value_codec.hpp"

#include "duckdb.hpp"

#include <cstdint>
#include "duckdb/function/table_function.hpp"
#include "duckdb/parser/parsed_data/create_scalar_function_info.hpp"
#include "duckdb/parser/parsed_data/create_table_function_info.hpp"
#include "duckdb/parser/keyword_helper.hpp"
#include "duckdb/planner/table_filter.hpp"

#include <memory>
#include <atomic>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

namespace duckdb {

class LogicalDelete;
class LogicalInsert;
class LogicalUpdate;
class PhysicalOperator;
class PhysicalPlanGenerator;

using oracle_scanner::ConnectionConfig;
using oracle_scanner::OracleColumn;
using oracle_scanner::OracleCursor;
using oracle_scanner::OracleIoStats;
using oracle_scanner::OracleSession;

// ProtocolError is a std::runtime_error from the protocol layer, not a DuckDB
// exception. Letting one escape gives the user `Invalid Error: <text>` with the
// ProtocolErrorKind thrown away, so every call into a session is translated
// here instead: the kind picks the DuckDB exception and the operation name says
// what was being done. UNSUPPORTED means the server sent a shape this client
// does not implement, which is what NotImplementedException is for; every other
// kind is a failure of the connection to Oracle.
inline unordered_map<string, string> OracleErrorInfo(const std::exception &error,
                                                     const string &connection_state = "discarded") {
    auto info = ErrorData(error).ExtraInfo();
    const auto *protocol = dynamic_cast<const oracle_scanner::ProtocolError *>(&error);
    if (protocol) {
        info["oracle_protocol_error_kind"] = std::to_string(static_cast<int>(protocol->Kind()));
        if (protocol->OracleCode()) {
            info["oracle_error_code"] = std::to_string(*protocol->OracleCode());
        }
    }
    info["oracle_connection_state"] = connection_state;
    return info;
}

[[noreturn]] inline void ThrowOracleAdapterError(const char *operation, const std::exception &error) {
    const auto info = OracleErrorInfo(error);
    const auto *protocol = dynamic_cast<const oracle_scanner::ProtocolError *>(&error);
    const auto message = ErrorData(error).RawMessage();
    if (protocol && protocol->Kind() == oracle_scanner::ProtocolErrorKind::UNSUPPORTED) {
        throw NotImplementedException(info, "%s: %s", operation, message);
    }
    throw IOException(info, "%s: %s", operation, message);
}

template <class FUNCTION>
auto TranslatingOracleErrors(const char *operation, FUNCTION function) -> decltype(function()) {
    try {
        return function();
    } catch (const oracle_scanner::ProtocolError &error) {
        ThrowOracleAdapterError(operation, error);
    }
}

//! Refuses any column this client cannot read, then returns its DuckDB type.
LogicalType TypeFor(const OracleColumn &column);
//! The DuckDB type an Oracle column maps to, with no support check.
LogicalType MappedType(const OracleColumn &column);
//! How a NUMBER column is held in DuckDB; see MapNumber in oracle_types.cpp.
struct NumberMapping {
	enum Kind { TEXT, BIGINT, DECIMAL, DOUBLE };
	Kind kind = TEXT;
	uint8_t width = 0;
	uint8_t scale = 0;
};
NumberMapping MapNumber(const OracleColumn &column);
//! True when the column reads as a rounding of the stored value, so nothing that
//! compares its values may be sent to Oracle; see oracle_types.cpp.
bool OracleColumnRoundsOnRead(const OracleColumn &column);
//! Stamps the oracle_unconstrained_number setting onto columns that have no
//! declared precision. Called wherever a statement's or a table's columns are
//! first described, so the type a column gets is settled once.
void ApplyUnconstrainedNumberSetting(ClientContext &context, std::vector<OracleColumn> &columns);
//! Converts one wire value using the column's Oracle type; absent means NULL.
Value ValueFor(const OracleColumn &column, const std::optional<std::vector<uint8_t>> &wire);
//! Stores one wire value in row `row` of a vector of the column's type: the
//! same result as `vector.SetValue(row, ValueFor(column, wire))`, without
//! building the Value in between.
void WriteOracleValue(Vector &vector, idx_t row, const OracleColumn &column,
                      const std::optional<std::vector<uint8_t>> &wire);
//! A unique DuckDB output name for a described column.
std::string OutputName(const OracleColumn &column, idx_t index, std::unordered_set<std::string> &used);
//! Renders one scalar OUT bind value as text for the callable surface.
// `character_set_form` 2 marks a national character value, which arrives as UTF-16BE.
std::string FormatCallScalar(uint16_t oracle_type, const std::vector<uint8_t> &wire, uint8_t character_set_form = 0);
//! Refuses a statement that cannot run inside an explicit DuckDB transaction.
void RequireAutoCommit(ClientContext &context, const char *function_name);
//! Resolves a named Oracle secret into a connection config, validating the
//! endpoint, TLS, and wallet field combinations.
ConnectionConfig ConnectionFromSecret(ClientContext &context, const std::string &secret_name, std::string &password);

//! A session for a read: leased from the connection's pool, or opened outright
//! when the pool is at its cap. Destroying it returns a pooled session for
//! reuse and closes an unpooled one.
class OracleSessionHandle {
public:
    OracleSessionHandle() = default;
    OracleSessionHandle(OracleSessionHandle &&) = default;
    OracleSessionHandle &operator=(OracleSessionHandle &&) = default;
    OracleSessionHandle(const OracleSessionHandle &) = delete;
    OracleSessionHandle &operator=(const OracleSessionHandle &) = delete;

    OracleSession &Get() const;
    OracleSession *operator->() const {
        return &Get();
    }
    explicit operator bool() const {
        return borrowed != nullptr || owned != nullptr || static_cast<bool>(lease);
    }
    //! Keeps a session whose statement failed out of the pool.
    void Poison() noexcept;

    oracle_scanner::OracleSessionLease lease;
    std::unique_ptr<OracleSession> owned;
    //! The session the current DuckDB transaction pinned for writing. Reading
    //! through it is the only way a transaction can see its own uncommitted
    //! rows, since Oracle shows them to nobody else. Shared, not borrowed
    //! outright: a write that fails discards its session, and this scan may
    //! still have a cursor open on it.
    std::shared_ptr<OracleSession> borrowed;
};

//! What duckdb_functions() shows for one SQL function: argument names for the
//! positional and named parameters, in that order, a one-sentence description,
//! one example and its categories.
struct OracleFunctionDocumentation {
    vector<string> parameter_names;
    string description;
    string example;
    vector<string> categories;
};

//! The registration of an already configured table function with its
//! documentation. Taking the finished TableFunction keeps its varargs, named
//! parameters and callbacks exactly as they were; the conflict mode is
//! ALTER_ON_CONFLICT, the same the bare RegisterFunction(TableFunction) overload
//! sets.
CreateTableFunctionInfo DocumentedTableFunctionInfo(TableFunction function, OracleFunctionDocumentation documentation);

//! What each documented registration registers, built apart from registering
//! it so that a test can inspect every info — its conflict mode and its
//! description — directly. The Register* functions register exactly these.
CreateScalarFunctionInfo OracleScannerVersionFunctionInfo();
CreateScalarFunctionInfo OracleIoDeadlineVersionFunctionInfo();
vector<CreateTableFunctionInfo> OracleQueryFunctionInfos();
CreateTableFunctionInfo OracleParallelScanFunctionInfo();
vector<CreateTableFunctionInfo> OracleSnapshotFunctionInfos();
//! The Oracle database's current change number, read through the catalog's own connection details.
std::string OracleCurrentScn(ClientContext &context, const std::string &catalog_name);
//! Makes every scan of `catalog_name` made on this context read AS OF `scn`.
void OraclePinSnapshot(ClientContext &context, const std::string &catalog_name, const std::string &scn);

//! A read session for this connection and secret, pooled when
//! oracle_session_pool_size allows it.
//! `catalog_name` is the ATTACH alias whose transaction may already hold a
//! session to borrow; empty for oracle_query, which is not inside one.
OracleSessionHandle AcquireOracleReadSession(ClientContext &context, const std::string &secret_name,
                                             const std::string &catalog_name, const ConnectionConfig &config,
                                             const std::string &password);

void RegisterOracleSessionPool(ExtensionLoader &loader);

struct OracleTransactionStatus {
    std::string commit_outcome = "not_attempted";
    std::string connection_state = "idle";
    std::optional<uint32_t> oracle_code;
    std::optional<int> protocol_kind;
};

OracleTransactionStatus GetOracleTransactionStatus(ClientContext &context, const std::string &catalog_name);

//! The heavy columns of a scan whose filter DuckDB applies itself: they are not
//! fetched with the rows, only for the rows that pass, by ROWID and at the same
//! change number. `light_vectors[k]` is the output vector of the k-th fetched
//! column (the ROWID comes after them); `heavy_vectors[h]` that of heavy column h.
struct OracleDeferredColumns {
    std::vector<idx_t> light_vectors;
    std::vector<idx_t> heavy_vectors;
    std::vector<OracleColumn> heavy_columns;
    std::string heavy_select; // "ROWIDTOCHAR(ROWID), <heavy columns>"
    std::string source;       // "<table> AS OF SCN n"
};

//! One sort key of a Top-N pushed into a scan: a column of the table.
struct OracleTopNKey {
    column_t column;
    bool descending;
    bool nulls_first;
};

struct OracleQueryBindData final : TableFunctionData {
    // oracle_query has to run its statement while binding, because only the
    // Oracle describe can tell DuckDB what the result columns are.
    OracleSessionHandle session;
    std::unique_ptr<OracleCursor> cursor;
    std::vector<OracleColumn> columns;
    std::vector<LogicalType> types;
    bool transactional_query = false;
    // oracle_query_transaction_typed: the columns were declared by the caller,
    // not described by Oracle, so bind ran nothing and init checks the
    // statement's describe against them by name as well as by type.
    bool declared_schema = false;
    std::string query_sql;
    std::vector<oracle_scanner::OracleBind> query_binds;

    // An attached table already knows its columns from the dictionary, so its
    // statement is deferred to init, where the requested column ids are known
    // and can be pushed into the Oracle select list instead of being applied
    // after fetching every column.
    bool deferred_scan = false;
    //! NUM_ROWS from Oracle's statistics when the dictionary has it; the optimizer's
    //! only idea of how large the table is.
    std::optional<uint64_t> estimated_rows;
    //! NUM_DISTINCT per column of the table, in column order, where the statistics have one.
    std::vector<std::optional<uint64_t>> distinct_counts;
    // Predicates translated from the pushed-down filter set, empty when nothing
    // was pushed. Built at init, where the filters and the read columns are
    // both known.
    std::string where_clause;
    //! ` SAMPLE BLOCK (p) [SEED (n)]` when DuckDB handed the scan a system sample, else empty.
    std::string sample_clause;
    //! The sort keys of a TOP_N the optimizer found over this scan, and how many
    //! rows it keeps (limit plus offset), or none. Set at plan time by
    //! OptimizeOraclePlan; used only when every filter went to Oracle.
    vector<OracleTopNKey> top_n;
    idx_t top_n_rows = 0;
    //! ` ORDER BY ... FETCH FIRST n ROWS ONLY` when the scan applies it, built at init.
    std::string order_clause;
    //! A scan of one statement the optimizer wrote — an AGGREGATE or a JOIN of
    //! attached tables that Oracle computes. `columns` and `types` are its result
    //! columns as the plan expects them, declared rather than described.
    bool statement_scan = false;
    //! A change number every statement of this scan reads at, or empty. Set when the
    //! scan reads in two steps (see OracleDeferredColumns).
    std::string flashback_scn;
    std::string statement_sql;
    ConnectionConfig config;
    std::string password;
    std::string object_name;
    //! The schema that owns the table when the catalog was attached to another
    //! user's, empty for the connected user's own.
    std::string schema_name;
    //! The secret this scan came from, which is half of the pool's key.
    std::string secret_name;
    //! The ATTACH alias this scan belongs to, empty for oracle_query. It is
    //! what decides whether the scan can read a transaction's own writes.
    std::string catalog_name;
    // The attached table this scan belongs to, so the scan function can answer
    // LogicalGet::GetTable. Without that answer DuckDB does not treat the scan
    // as a base table: UPDATE and DELETE refuse to bind, and the table's
    // virtual ROWID column is never registered. Null for oracle_query, which
    // scans a statement rather than a table.
    optional_ptr<TableCatalogEntry> table_entry;
};

//! Counters a scan keeps for EXPLAIN ANALYZE. Atomic, because the threads of a
//! parallel scan add to them together.
struct OracleScanMetrics {
    std::atomic<uint64_t> rows_fetched {0};
    std::atomic<uint64_t> bytes_received {0};
    std::atomic<uint64_t> bytes_sent {0};
    std::atomic<uint64_t> round_trips {0};
    std::atomic<uint64_t> fetch_nanoseconds {0};
    std::atomic<uint64_t> convert_nanoseconds {0};
    std::atomic<uint64_t> sessions {0};
    std::atomic<uint64_t> chunks_read {0};
    std::atomic<uint64_t> deferred_rows {0};
    void Add(const OracleIoStats &io) {
        bytes_sent += io.bytes_sent;
        bytes_received += io.bytes_received;
        round_trips += io.round_trips;
    }
};

struct OracleQueryGlobalState final : GlobalTableFunctionState {
    OracleQueryGlobalState(OracleSessionHandle session_p, std::unique_ptr<OracleCursor> cursor_p,
                           std::vector<OracleColumn> columns_p, std::vector<LogicalType> types_p,
                           std::vector<column_t> output_columns_p, size_t chunk_columns_p)
        : session(std::move(session_p)), cursor(std::move(cursor_p)), columns(std::move(columns_p)),
          types(std::move(types_p)), output_columns(std::move(output_columns_p)), chunk_columns(chunk_columns_p) {
    }

    // Keep the session before the cursor: member destruction is reverse order,
    // so the cursor can queue its remote close while its session is still live,
    // and the session only goes back to the pool once the cursor is gone.
    OracleSessionHandle session;
    std::unique_ptr<OracleCursor> cursor;
    std::vector<OracleColumn> columns;
    std::vector<LogicalType> types;
    std::vector<column_t> output_columns;
    // How many vectors DuckDB sized this chunk to. Each one is the described
    // column beside it: oracle_query fetches every column and DuckDB sizes the
    // chunk to all of them, while an attached scan fetches only the projected
    // columns and gets a chunk of exactly those.
    size_t chunk_columns = 0;
    std::string catalog_name;
    //! Filters Oracle was not sent, applied to each fetched chunk (see SplitOracleFilters).
    unique_ptr<Expression> local_filter;

    //! What the scan did, for EXPLAIN ANALYZE (see OracleScanMetrics).
    OracleScanMetrics metrics;
    //! The statement(s) the scan sent, and the filters it applied itself.
    std::string sent_sql;
    std::string local_filter_text;
    //! The connection's counters when this scan last looked, for the serial scan.
    OracleIoStats last_io;
    //! Set when heavy columns are fetched for the rows that pass the local filter only.
    std::unique_ptr<OracleDeferredColumns> deferred;

    //! A table read in chunks through several sessions: each thread takes the next
    //! statement and reads it on a session of its own. The session and cursor above
    //! are then unused.
    bool parallel = false;
    std::vector<std::string> chunk_sql;
    std::atomic<idx_t> next_chunk {0};
    idx_t thread_count = 1;
    std::string secret_name;
    ConnectionConfig config;
    std::string password;

    idx_t MaxThreads() const override {
        return parallel ? thread_count : 1;
    }
};

//! What one thread of a parallel scan is reading.
struct OracleQueryLocalState final : LocalTableFunctionState {
    OracleSessionHandle session;
    std::unique_ptr<OracleCursor> cursor;
    OracleIoStats last_io;
};
unique_ptr<LocalTableFunctionState> OracleQueryInitLocal(ExecutionContext &context, TableFunctionInitInput &input,
                                                         GlobalTableFunctionState *global_state);
void OracleQueryMetrics(TableFunctionGetMetricsInput &input);

unique_ptr<GlobalTableFunctionState> OracleQueryInit(ClientContext &context, TableFunctionInitInput &input);
void OracleQueryFunction(ClientContext &context, TableFunctionInput &input, DataChunk &output);

//! Refuses any column this client cannot read.
void RequireReadableColumn(const OracleColumn &column);

//! Splits a pushed-down filter set. What can be translated into an Oracle WHERE
//! clause with a provably identical meaning goes there; every other filter comes
//! back as an expression over the scan's output chunk, for the scan to apply to
//! the rows Oracle returns, because DuckDB has already dropped it from its plan.
//! `scanned_columns` maps a filter's index to a described column.
struct OracleFilterSplit {
    std::string where;
    vector<unique_ptr<Expression>> local;
};
bool OraclePushdownExpression(ClientContext &context, const LogicalGet &get, Expression &expression);
OracleFilterSplit SplitOracleFilters(const TableFilterSet &filters, const std::vector<OracleColumn> &columns,
                                     const std::vector<column_t> &scanned_columns);
//! The strict form of the same translation: a filter that cannot be translated
//! throws NotImplementedException instead of being left for the scan.
std::string OracleWhereClause(const TableFilterSet &filters, const std::vector<OracleColumn> &columns,
                              const std::vector<column_t> &scanned_columns);

//! One argument of an Oracle procedure or function, as the data dictionary
//! describes it. `unsupported_reason` is empty exactly when this client can
//! bind the argument; otherwise it names why it cannot, and `oracle_type` is 0.
struct OracleCallableArgument {
    int32_t position = 0; //!< 0 is a function's return value.
    std::string name;
    std::string dictionary_type; //!< ALL_ARGUMENTS.DATA_TYPE, verbatim.
    oracle_scanner::BindDirection direction = oracle_scanner::BindDirection::BIND_IN;
    uint16_t oracle_type = 0;
    uint32_t maximum_bytes = 0;
    std::string bind_type_name; //!< The oracle_call_named spelling of the type.
    std::string unsupported_reason;
};

struct OracleCallableSignature {
    std::string owner;
    std::string package;
    std::string object;
    //! ALL_ARGUMENTS.OVERLOAD, empty when the callable is not overloaded.
    std::string overload;
    bool is_function = false;
    std::vector<OracleCallableArgument> arguments;

    //! How many values a caller supplies: every argument but a function's
    //! return, which comes back rather than going in.
    size_t InputCount() const {
        return arguments.size() - (is_function ? 1 : 0);
    }
};

//! One callable argument's wire form. `value` is absent for an OUT argument and
//! for an explicit NULL.
struct OracleCallableBind {
    uint16_t oracle_type = 0;
    uint32_t maximum_bytes = 0;
    std::optional<std::vector<uint8_t>> value;
    uint8_t character_set_form = 0;
};

//! Encodes one callable argument from its text spelling. Shared by the
//! hand-written argument list and the signature-driven one, so the two cannot
//! disagree about what a value means.
OracleCallableBind EncodeOracleCallableArgument(const std::string &type_name, oracle_scanner::BindDirection direction,
                                                const Value &value, const std::string &name,
                                                const char *function_name);

//! Every overload of a callable, from ALL_ARGUMENTS, ordered as the dictionary
//! numbers them. A name that matches more than one *object* is still refused —
//! that is an ambiguity the caller can fix by qualifying the name, where an
//! overload is a choice only the argument list can settle.
std::vector<OracleCallableSignature> ResolveOracleCallables(OracleSession &session,
                                                            const std::string &qualified_name);

//! The single overload that takes `input_count` values. Refuses when none does,
//! and when more than one does, naming what was available either way.
const OracleCallableSignature &SelectOracleCallableOverload(const std::vector<OracleCallableSignature> &overloads,
                                                            size_t input_count, const std::string &qualified_name);

//! Everything the write path needs about one attached Oracle table. It carries
//! its own connection material because a write opens its own session, pinned to
//! the DuckDB transaction rather than to the statement.
struct OracleWriteTarget {
    std::string catalog_name;
    std::string object_name;
    //! The owning schema when it is not the connected user's, else empty.
    std::string schema_name;
    ConnectionConfig config;
    std::string password;
    // The attached catalog's pool of transaction sessions, or null when the
    // pool is disabled. Every session in it was opened from config and password.
    std::shared_ptr<oracle_scanner::OracleTransactionSessionPool> pool;
};

//! The name a statement uses for a table: quoted, and qualified by its owner when
//! the catalog was attached to a schema other than the connected user's.
std::string OracleObjectReference(const std::string &schema_name, const std::string &object_name);
// The select-list item that reads one column: its quoted name, or for an XMLTYPE
// column the serialization of it as a CLOB under the same name.
std::string OracleSelectExpression(const OracleColumn &column);
// The value expression a write puts a bind in: the placeholder itself, wrapped
// in XMLTYPE(...) for an XMLTYPE column.
std::string OracleBindExpression(const OracleColumn &column, size_t bind_position);

OracleWriteTarget ResolveOracleWriteTarget(ClientContext &context, const std::string &catalog_name);
void CommitOracleTransaction(ClientContext &context, const std::string &catalog_name);
// Marks the pinned session as one that must not be reused: the transaction
// ran something, such as a stored procedure, that can leave session state.
void TaintTransactionSession(ClientContext &context, const std::string &catalog_name);
void RollbackOracleTransaction(ClientContext &context, const std::string &catalog_name) noexcept;

//! Converts one DuckDB value into a bind for a specific Oracle column. The
//! column's Oracle type decides the encoding, never the DuckDB type alone, so
//! no value reaches Oracle as text for it to convert under session NLS.
oracle_scanner::OracleBind OracleBindForColumn(const Value &value, const OracleColumn &column, const std::string &name);

//! The Oracle session pinned to the current DuckDB transaction for this
//! catalog, opening it on first use. Its COMMIT and ROLLBACK follow DuckDB's.
OracleSession &TransactionSession(ClientContext &context, const OracleWriteTarget &target);

//! Discards the pinned session without committing, after a failed write.
void PoisonTransactionSession(ClientContext &context, const std::string &catalog_name) noexcept;

//! The session this transaction already pinned for `catalog_name`, or null when
//! it has not written to that catalog. Unlike TransactionSession this never
//! opens one: pinning a session for a read-only transaction would cost a
//! connection and a COMMIT that has nothing to commit.
std::shared_ptr<OracleSession> TryTransactionSession(ClientContext &context, const std::string &catalog_name);

//! The select-list expression that produces a scannable Oracle ROWID, and the
//! column it is described as. Reading it as text avoids needing a ROWID codec:
//! the value that comes back is an ordinary VARCHAR2 and goes straight back
//! into CHARTOROWID on the way to an UPDATE or DELETE.
extern const char *const ORACLE_ROWID_EXPRESSION;
extern const char *const ORACLE_ROWID_COLUMN_NAME;
OracleColumn OracleRowIdColumn();

//! Plans an INSERT into an attached Oracle table.
PhysicalOperator &PlanOracleInsert(ClientContext &context, PhysicalPlanGenerator &planner, LogicalInsert &op,
                                   optional_ptr<PhysicalOperator> plan, const std::vector<OracleColumn> &columns,
                                   OracleWriteTarget target);

//! Plans a ROWID-addressed UPDATE of an attached Oracle table.
PhysicalOperator &PlanOracleUpdate(ClientContext &context, PhysicalPlanGenerator &planner, LogicalUpdate &op,
                                   PhysicalOperator &plan, const std::vector<OracleColumn> &columns,
                                   OracleWriteTarget target);

//! Plans a ROWID-addressed DELETE from an attached Oracle table.
PhysicalOperator &PlanOracleDelete(ClientContext &context, PhysicalPlanGenerator &planner, LogicalDelete &op,
                                   PhysicalOperator &plan, const std::vector<OracleColumn> &columns,
                                   OracleWriteTarget target);

//! Opens an attached table's scan over exactly the requested columns, pushing
//! the projection into Oracle's select list.
//! What opening a scan sent and moved, for the scan's metrics.
struct OracleScanOpening {
    std::string sql;
    OracleIoStats io;
};
//! Installs the plan rewrites for attached tables (src/oracle_optimizer.cpp).
void RegisterOracleOptimizer(DatabaseInstance &db);
std::string OracleTopNClause(const OracleQueryBindData &bind);
unique_ptr<GlobalTableFunctionState> OracleAggregateInit(ClientContext &context, OracleQueryBindData &bind,
                                                         TableFunctionInitInput &input);

void OverlayDictionaryColumn(OracleColumn &described, const OracleColumn &dictionary);
//! The change number to read a heap table at, or empty when it cannot be pinned
//! (a view, an index-organized, clustered or temporary table, or no flashback).
//! The change number every scan of this statement reads at when oracle_consistent_read is on, else empty.
std::string OracleQuerySnapshot(ClientContext &context, const OracleQueryBindData &bind);
std::string OracleSnapshotOfHeapTable(ClientContext &context, const OracleQueryBindData &bind);

void OpenProjectedScan(ClientContext &context, OracleQueryBindData &bind, const std::vector<column_t> &selected,
                       OracleSessionHandle &session, std::unique_ptr<OracleCursor> &cursor,
                       std::vector<OracleColumn> &columns, bool schema_only = false,
                       OracleScanOpening *opening = nullptr);

//! The statements, one per chunk of the table, that read an attached table through
//! several sessions at one SCN, cut into ROWID ranges at extent boundaries; empty
//! when the scan should be one stream (see the implementation for the reasons).
std::vector<std::string> PlanParallelAttachedScan(ClientContext &context, const OracleQueryBindData &bind,
                                                  const std::vector<column_t> &selected, idx_t sessions);

} // namespace duckdb
