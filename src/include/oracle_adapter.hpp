#pragma once

// Internal seam between the DuckDB adapter's translation units. The catalog and
// the table functions both need the scan's bind data and the Oracle-to-DuckDB
// conversions, so those live here rather than in one anonymous namespace.
// Nothing here is part of the extension's public surface.

#include "oracle_scanner/protocol_error.hpp"
#include "oracle_scanner/session.hpp"
#include "oracle_scanner/session_pool.hpp"
#include "oracle_scanner/tns_client.hpp"
#include "oracle_scanner/value_codec.hpp"

#include "duckdb.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/parser/keyword_helper.hpp"
#include "duckdb/planner/table_filter.hpp"

#include <memory>
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
using oracle_scanner::OracleSession;

// ProtocolError is a std::runtime_error from the protocol layer, not a DuckDB
// exception. Letting one escape gives the user `Invalid Error: <text>` with the
// ProtocolErrorKind thrown away, so every call into a session is translated
// here instead: the kind picks the DuckDB exception and the operation name says
// what was being done. UNSUPPORTED means the server sent a shape this client
// does not implement, which is what NotImplementedException is for; every other
// kind is a failure of the connection to Oracle.
template <class FUNCTION>
auto TranslatingOracleErrors(const char *operation, FUNCTION function) -> decltype(function()) {
    try {
        return function();
    } catch (const oracle_scanner::ProtocolError &error) {
        if (error.Kind() == oracle_scanner::ProtocolErrorKind::UNSUPPORTED) {
            throw NotImplementedException("%s: %s", operation, error.what());
        }
        throw IOException("%s: %s", operation, error.what());
    }
}

//! Refuses any column this client cannot read, then returns its DuckDB type.
LogicalType TypeFor(const OracleColumn &column);
//! The DuckDB type an Oracle column maps to, with no support check.
LogicalType MappedType(const OracleColumn &column);
//! Converts one wire value using the column's Oracle type; absent means NULL.
Value ValueFor(const OracleColumn &column, const std::optional<std::vector<uint8_t>> &wire);
//! A unique DuckDB output name for a described column.
std::string OutputName(const OracleColumn &column, idx_t index, std::unordered_set<std::string> &used);
//! Renders one scalar OUT bind value as text for the callable surface.
std::string FormatCallScalar(uint16_t oracle_type, const std::vector<uint8_t> &wire);
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

//! A read session for this connection and secret, pooled when
//! oracle_session_pool_size allows it.
//! `catalog_name` is the ATTACH alias whose transaction may already hold a
//! session to borrow; empty for oracle_query, which is not inside one.
OracleSessionHandle AcquireOracleReadSession(ClientContext &context, const std::string &secret_name,
                                             const std::string &catalog_name, const ConnectionConfig &config,
                                             const std::string &password);

void RegisterOracleSessionPool(ExtensionLoader &loader);

struct OracleQueryBindData final : TableFunctionData {
    // oracle_query has to run its statement while binding, because only the
    // Oracle describe can tell DuckDB what the result columns are.
    OracleSessionHandle session;
    std::unique_ptr<OracleCursor> cursor;
    std::vector<OracleColumn> columns;
    std::vector<LogicalType> types;

    // An attached table already knows its columns from the dictionary, so its
    // statement is deferred to init, where the requested column ids are known
    // and can be pushed into the Oracle select list instead of being applied
    // after fetching every column.
    bool deferred_scan = false;
    // Predicates translated from the pushed-down filter set, empty when nothing
    // was pushed. Built at init, where the filters and the read columns are
    // both known.
    std::string where_clause;
    ConnectionConfig config;
    std::string password;
    std::string object_name;
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
};

unique_ptr<GlobalTableFunctionState> OracleQueryInit(ClientContext &context, TableFunctionInitInput &input);
void OracleQueryFunction(ClientContext &context, TableFunctionInput &input, DataChunk &output);

//! Refuses any column this client cannot read.
void RequireReadableColumn(const OracleColumn &column);

//! Translates a pushed-down filter set into an Oracle WHERE clause, refusing
//! any filter whose Oracle meaning is not provably identical to DuckDB's.
//! `scanned_columns` maps a filter's index to a described column.
std::string OracleWhereClause(const TableFilterSet &filters, const std::vector<OracleColumn> &columns,
                              const std::vector<column_t> &scanned_columns);

//! One argument of an Oracle procedure or function, as the data dictionary
//! describes it. `unsupported_reason` is empty exactly when this client can
//! bind the argument; otherwise it names why it cannot, and `oracle_type` is 0.
struct OracleCallableArgument {
    int32_t position = 0; //!< 0 is a function's return value.
    std::string name;
    std::string dictionary_type; //!< ALL_ARGUMENTS.DATA_TYPE, verbatim.
    oracle_scanner::BindDirection direction = oracle_scanner::BindDirection::IN;
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
    ConnectionConfig config;
    std::string password;
};

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
                                   PhysicalOperator &plan, OracleWriteTarget target);

//! Opens an attached table's scan over exactly the requested columns, pushing
//! the projection into Oracle's select list.
void OpenProjectedScan(ClientContext &context, OracleQueryBindData &bind, const std::vector<column_t> &selected,
                       OracleSessionHandle &session, std::unique_ptr<OracleCursor> &cursor,
                       std::vector<OracleColumn> &columns);

} // namespace duckdb
