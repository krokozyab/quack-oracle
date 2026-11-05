// Before any include. Windows defines min and max as function-like macros,
// and the headers this pulls in reach <windows.h> — so `(std::min)(...)` is
// rewritten by the preprocessor and the file stops compiling, with the brace
// counting going wrong several lines later as a consequence.
#if defined(_WIN32) && !defined(NOMINMAX)
#define NOMINMAX
#endif

#include "oracle_scanner/oracle_vector.hpp"
#include "oracle_scanner/ttc_lob.hpp"
#include "oracle_scanner/protocol_error.hpp"
#include "oracle_scanner/io_deadline.hpp"
#include "oracle_scanner/session.hpp"
#include "oracle_scanner/session_factory.hpp"
#include "oracle_scanner/value_codec.hpp"
#include "oracle_scanner_extension.hpp"
#include "core_functions_extension.hpp"
#include "oracle_adapter.hpp"
#include "oracle_scanner/ttc_lob.hpp"
#include "oracle_scanner/call_registry.hpp"
#include "oracle_scanner/ttc_execute.hpp"

#include "duckdb/common/exception/conversion_exception.hpp"
#include "duckdb/planner/filter/conjunction_filter.hpp"
#include "duckdb/planner/filter/constant_filter.hpp"
#include "duckdb/planner/filter/expression_filter.hpp"
#include "duckdb/planner/table_filter_set.hpp"
#include "duckdb/planner/filter/in_filter.hpp"
#include "duckdb/planner/filter/null_filter.hpp"
#include "duckdb/planner/filter/optional_filter.hpp"

#include "duckdb.hpp"
#include "duckdb/main/query_result_stream.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/parser/parser.hpp"
#include "duckdb/parser/parsed_data/create_table_function_info.hpp"

#include <chrono>
#include <fstream>
#include <filesystem>
#include <thread>
#include <cassert>
#include <csignal>
#include <cstdlib>
#include <cstdint>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

// A release build defines NDEBUG, and CHECK() then removes not just the check
// but everything inside it — including the call being checked. A suite written
// with assert therefore stops testing the moment it is built for release, which
// is exactly the build nothing here ever ran. CHECK always evaluates its
// expression and always reports, so the two builds test the same thing.
[[noreturn]] static void CheckFailed(const char *expression, const char *file, int line) {
    std::cerr << file << ":" << line << ": check failed: " << expression << std::endl;
    std::abort();
}

#define CHECK(expression)                                                                                              \
    do {                                                                                                               \
        if (!(expression)) {                                                                                           \
            CheckFailed(#expression, __FILE__, __LINE__);                                                              \
        }                                                                                                              \
    } while (0)

using duckdb::Connection;
using duckdb::DuckDB;
using duckdb::OracleScannerExtension;

using oracle_scanner::ConnectionConfig;
using oracle_scanner::OracleBatch;
using oracle_scanner::OracleBind;
using oracle_scanner::OracleCallRequest;
using oracle_scanner::OracleCallResult;
using oracle_scanner::OracleColumn;
using oracle_scanner::OracleCursor;
using oracle_scanner::OracleSession;
using oracle_scanner::ScopedOracleSessionFactory;

namespace {

using WireValue = std::optional<std::vector<uint8_t>>;
using WireRow = std::vector<WireValue>;

WireValue Text(const std::string &value) {
    return std::vector<uint8_t>(value.begin(), value.end());
}

WireValue Number(const std::string &decimal) {
    return oracle_scanner::EncodeOracleNumber(decimal);
}

OracleColumn Column(const std::string &name, uint16_t oracle_type, int16_t precision = 0, int16_t scale = 0) {
    OracleColumn column;
    column.name = name;
    column.oracle_type = oracle_type;
    column.precision = precision;
    column.scale = scale;
    return column;
}

// One scripted answer, and the SQL fragment that selects it. The attached
// catalog asks several different questions during a single ATTACH — the current
// user, the object list, the column dictionary, the primary keys, then the scan
// itself — so a fake that answers every query the same way cannot drive it.
struct FakeResponse {
    std::vector<OracleColumn> columns;
    std::vector<WireRow> rows;
};

// A scripted table, so the fake can answer any projection of it rather than one
// fixed select list. The attached catalog decides the select list itself — a
// scan of two columns, an UPDATE's scan of one column and the ROWID — and a
// test that hard-codes one of them breaks the moment the planner picks another.
struct FakeTable {
    std::vector<OracleColumn> columns;
    std::vector<WireRow> rows;
};

// Everything the adapter asked the session to do, and everything the session is
// scripted to answer with. It outlives the session because the adapter owns and
// destroys the session on its own schedule.
struct FakeScript {
    //! Answer rows on the first Fetch and an empty exhausted batch on the second,
    //! the way a real cursor does.
    bool two_batch_fetch = false;
    // A parallel scan drives several sessions at once, all of them recording
    // into this one script. Unsynchronised, the recording loses entries and the
    // test that reads them back becomes a coin flip — which is how this was
    // found. The routes and tables are set up before any thread starts and are
    // only read afterwards, so only the recording needs the lock.
    std::mutex record_lock;

    // Matched in order, by substring, against the SQL. The first hit answers;
    // anything unmatched falls back to `columns`/`rows` below.
    std::vector<std::pair<std::string, FakeResponse>> routes;
    // Scripted tables, keyed by object name. A query of the form
    // `SELECT ... FROM "NAME"` is answered by projecting this one.
    std::map<std::string, FakeTable> tables;

    std::vector<std::string> queries;
    std::vector<std::vector<OracleBind>> query_binds;
    std::vector<std::string> plain_executes;
    std::vector<std::string> admin_executes;
    std::vector<std::string> counted_executes;
    std::vector<std::vector<OracleBind>> counted_execute_binds;
    std::vector<std::vector<OracleBind>> batch_rows;
    std::vector<std::string> returning_statements;
    std::vector<std::vector<OracleBind>> returning_binds;
    std::map<std::string, WireValue> returning_values;

    std::vector<OracleColumn> columns;
    std::vector<WireRow> rows;
    uint64_t affected_rows = 0;

    std::vector<OracleCallRequest> calls;
    std::vector<OracleBind> call_outputs;
    size_t call_explicit_cursors = 0;
    size_t call_implicit_cursors = 0;
    // When set, a call answers what it was asked rather than call_outputs: the
    // return bind and every OUT or IN OUT scalar argument of the request, in
    // that order, each valued from call_output_values by name (NULL when the
    // script names none). That is the shape a real session returns, so a test
    // does not have to restate the request it is checking.
    bool call_echo_outputs = false;
    std::map<std::string, WireValue> call_output_values;
    // A call that fails the way a composite's row-count check does: Oracle's
    // ORA-20906 after the statements before the failing one have run.
    bool call_should_fail = false;

    // Set to make the scripted cursor fail mid-stream, which is how a protocol
    // failure reaches the adapter after the bind has already succeeded.
    std::optional<oracle_scanner::ProtocolErrorKind> fetch_failure;
    std::string fetch_failure_message;
    bool batch_should_fail = false;
    bool execute_should_fail = false;
    bool commit_should_fail = false;
    // The transaction pool: whether a session reports itself ReadyForReuse
    // (until it fails or closes), and a rollback that fails.
    bool sessions_reusable = false;
    bool rollback_should_fail = false;
    size_t session_closes = 0;
    // USER of the secret each session was opened from, in opening order, and
    // the USER of the session each counted execute ran on.
    std::vector<std::string> session_users;
    std::vector<std::string> execute_users;
    // Every deadline source a session was bound to; null when released.
    std::vector<std::shared_ptr<oracle_scanner::OracleIoDeadline>> bound_sources;
    // A statement containing this fragment waits, the way one waiting on a row
    // lock does, until the deadline of the caller it is bound to expires.
    std::string block_until_deadline;
    size_t blocked_statements = 0;

    size_t sessions_opened = 0;
    size_t sessions_destroyed = 0;
    size_t cursor_closes = 0;
    size_t commits = 0;
    size_t rollbacks = 0;
};

// Projects a scripted table onto the select list the adapter actually wrote.
// Only what the attached scan emits is understood: quoted column names and the
// ROWID expression, comma-separated.
static bool ProjectScriptedTable(const FakeScript &script, const std::string &sql, FakeResponse &result) {
    const auto select_at = sql.find("SELECT ");
    const auto from_at = sql.find(" FROM \"");
    if (select_at != 0 || from_at == std::string::npos) {
        return false;
    }
    auto object = sql.substr(from_at + 7);
    auto object_end = object.find('"');
    if (object_end == std::string::npos) {
        return false;
    }
    if (object.compare(object_end, 3, "\".\"") == 0) {
        // "OWNER"."TABLE": the table is the second name.
        object = object.substr(object_end + 3);
        object_end = object.find('"');
        if (object_end == std::string::npos) {
            return false;
        }
    }
    object.erase(object_end);
    const auto table = script.tables.find(object);
    if (table == script.tables.end()) {
        return false;
    }
    std::vector<size_t> selected;
    const auto select_list = sql.substr(7, from_at - 7);
    size_t position = 0;
    while (position <= select_list.size()) {
        auto end = select_list.find(", ", position);
        const auto item = select_list.substr(position, end == std::string::npos ? std::string::npos : end - position);
        if (item == "ROWIDTOCHAR(ROWID)") {
            // The scan reads the row identity as ordinary text, so the fake
            // answers with one: the row's position is enough to be unique.
            selected.push_back((std::numeric_limits<size_t>::max)());
            result.columns.push_back(Column("rowid", 1));
        } else {
            // An XMLTYPE column is selected as XMLSERIALIZE(CONTENT "X" AS CLOB NO INDENT) "X".
            const std::string serialized = "XMLSERIALIZE(CONTENT ";
            const auto bare = item.compare(0, serialized.size(), serialized) == 0
                                  ? item.substr(serialized.size(), item.find(" AS CLOB") - serialized.size())
                                  : item;
            const auto name = bare.size() >= 2 && bare.front() == '"' ? bare.substr(1, bare.size() - 2) : bare;
            size_t index = 0;
            for (; index < table->second.columns.size(); index++) {
                if (table->second.columns[index].name == name) {
                    break;
                }
            }
            if (index == table->second.columns.size()) {
                return false;
            }
            selected.push_back(index);
            result.columns.push_back(table->second.columns[index]);
        }
        if (end == std::string::npos) {
            break;
        }
        position = end + 2;
    }
    for (size_t row = 0; row < table->second.rows.size(); row++) {
        WireRow projected;
        for (const auto index : selected) {
            if (index == (std::numeric_limits<size_t>::max)()) {
                projected.push_back(Text("AAAROW" + std::to_string(row)));
            } else {
                projected.push_back(table->second.rows[row][index]);
            }
        }
        result.rows.push_back(std::move(projected));
    }
    return true;
}

class FakeCursor final : public OracleCursor {
public:
    FakeCursor(std::shared_ptr<FakeScript> script_p, const std::string &sql = std::string())
        : script(std::move(script_p)) {
        for (const auto &route : script->routes) {
            if (sql.find(route.first) != std::string::npos) {
                answer = &route.second;
                return;
            }
        }
        if (ProjectScriptedTable(*script, sql, projected)) {
            answer = &projected;
        }
    }

    const std::vector<OracleColumn> &Columns() const override {
        return answer ? answer->columns : script->columns;
    }

    OracleBatch Fetch(size_t) override {
        if (script->fetch_failure) {
            throw oracle_scanner::ProtocolError(*script->fetch_failure, script->fetch_failure_message);
        }
        OracleBatch batch;
        batch.columns = Columns();
        if (!drained) {
            batch.rows = answer ? answer->rows : script->rows;
            drained = true;
            // Like a real cursor, which only learns it is exhausted on the
            // fetch that returns nothing: rows now, the empty end-of-data next.
            batch.exhausted = !script->two_batch_fetch;
            return batch;
        }
        batch.exhausted = true;
        return batch;
    }

    void Cancel() override {
    }

    void Close() override {
        std::lock_guard<std::mutex> guard(script->record_lock);
        script->cursor_closes++;
    }

private:
    std::shared_ptr<FakeScript> script;
    FakeResponse projected;
    const FakeResponse *answer = nullptr;
    bool drained = false;
};

class FakeSession final : public OracleSession {
public:
    explicit FakeSession(std::shared_ptr<FakeScript> script_p, std::string user_p = std::string(),
                         std::shared_ptr<oracle_scanner::OracleIoDeadline> deadline_p = nullptr)
        : script(std::move(script_p)), user(std::move(user_p)), deadline(std::move(deadline_p)) {
        std::lock_guard<std::mutex> guard(script->record_lock);
        script->sessions_opened++;
        script->session_users.push_back(user);
    }

    ~FakeSession() override {
        std::lock_guard<std::mutex> guard(script->record_lock);
        script->sessions_destroyed++;
    }

    std::unique_ptr<OracleCursor> Query(const std::string &sql, const std::vector<OracleBind> &binds) override {
        WaitIfBlocked(sql);
        {
            std::lock_guard<std::mutex> guard(script->record_lock);
            script->queries.push_back(sql);
            script->query_binds.push_back(binds);
        }
        return std::make_unique<FakeCursor>(script, sql);
    }

    uint64_t Execute(const std::string &sql, const std::vector<OracleBind> &) override {
        std::lock_guard<std::mutex> guard(script->record_lock);
        script->plain_executes.push_back(sql);
        return script->affected_rows;
    }

    void ExecuteAdmin(const std::string &sql) override {
        std::lock_guard<std::mutex> guard(script->record_lock);
        script->admin_executes.push_back(sql);
    }

    uint64_t ExecuteWithRowCount(const std::string &sql, const std::vector<OracleBind> &binds) override {
        WaitIfBlocked(sql);
        std::lock_guard<std::mutex> guard(script->record_lock);
        script->counted_executes.push_back(sql);
        script->counted_execute_binds.push_back(binds);
        script->execute_users.push_back(user);
        if (script->execute_should_fail) {
            failed = true;
            throw oracle_scanner::ProtocolError(oracle_scanner::ProtocolErrorKind::INVALID_STATE,
                                                 "localized constraint failure", 1);
        }
        return script->affected_rows;
    }

    uint64_t ExecuteBatch(const std::string &sql, const std::vector<std::vector<OracleBind>> &rows) override {
        WaitIfBlocked(sql);
        std::lock_guard<std::mutex> guard(script->record_lock);
        script->counted_executes.push_back(sql);
        script->batch_rows = rows;
        if (script->batch_should_fail) {
            throw oracle_scanner::ProtocolError(*script->fetch_failure, script->fetch_failure_message);
        }
        return script->affected_rows * rows.size();
    }

    std::vector<OracleBind> ExecuteReturning(const std::string &sql, const std::vector<OracleBind> &binds) override {
        std::lock_guard<std::mutex> guard(script->record_lock);
        script->returning_statements.push_back(sql);
        script->returning_binds.push_back(binds);
        std::vector<OracleBind> outputs;
        for (const auto &bind : binds) {
            if (bind.direction == oracle_scanner::BindDirection::BIND_IN) {
                continue;
            }
            auto filled = bind;
            // Answer with what the script says the row became, which is how a
            // DEFAULT or a trigger shows up in a RETURNING result.
            const auto scripted = script->returning_values.find(bind.name);
            filled.value = scripted == script->returning_values.end() ? WireValue() : scripted->second;
            outputs.push_back(std::move(filled));
        }
        return outputs;
    }

    OracleCallResult Call(const OracleCallRequest &request) override {
        for (const auto &operation : request.dml_operations) {
            WaitIfBlocked(operation.sql);
        }
        std::lock_guard<std::mutex> guard(script->record_lock);
        script->calls.push_back(request);
        if (script->call_should_fail) {
            failed = true;
            throw oracle_scanner::ProtocolError(oracle_scanner::ProtocolErrorKind::INVALID_STATE,
                                                "ORA-20906: DML composite operation 2 affected row count mismatch",
                                                20906);
        }
        OracleCallResult result;
        result.outputs = script->call_outputs;
        if (script->call_echo_outputs) {
            result.outputs.clear();
            const auto answer = [&](const OracleBind &bind) {
                auto filled = bind;
                const auto scripted = script->call_output_values.find(bind.name);
                filled.value = scripted == script->call_output_values.end() ? WireValue() : scripted->second;
                result.outputs.push_back(std::move(filled));
            };
            if (request.return_bind && request.return_bind->oracle_type != oracle_scanner::ORACLE_WIRE_TYPE_CURSOR) {
                answer(*request.return_bind);
            }
            for (const auto &argument : request.arguments) {
                if (argument.direction != oracle_scanner::BindDirection::BIND_IN &&
                    argument.oracle_type != oracle_scanner::ORACLE_WIRE_TYPE_CURSOR) {
                    answer(argument);
                }
            }
        }
        for (size_t index = 0; index < script->call_explicit_cursors; index++) {
            result.explicit_cursors.push_back(std::make_unique<FakeCursor>(script));
        }
        for (size_t index = 0; index < script->call_implicit_cursors; index++) {
            result.implicit_cursors.push_back(std::make_unique<FakeCursor>(script));
        }
        return result;
    }

    void Commit() override {
        std::lock_guard<std::mutex> guard(script->record_lock);
        script->commits++;
        if (script->commit_should_fail) {
            failed = true;
            throw oracle_scanner::ProtocolError(oracle_scanner::ProtocolErrorKind::TRUNCATED, "lost COMMIT response");
        }
    }

    void Rollback() override {
        std::lock_guard<std::mutex> guard(script->record_lock);
        script->rollbacks++;
        if (script->rollback_should_fail) {
            failed = true;
            throw oracle_scanner::ProtocolError(oracle_scanner::ProtocolErrorKind::TRUNCATED, "lost ROLLBACK response");
        }
    }

    void Cancel() override {
    }

    void Close() override {
        std::lock_guard<std::mutex> guard(script->record_lock);
        if (!closed) {
            closed = true;
            script->session_closes++;
        }
    }

    bool ReadyForReuse() const override {
        std::lock_guard<std::mutex> guard(script->record_lock);
        return script->sessions_reusable && !closed && !failed;
    }

    bool BindIoDeadline(std::shared_ptr<oracle_scanner::OracleIoDeadline> source) override {
        std::lock_guard<std::mutex> guard(script->record_lock);
        script->bound_sources.push_back(source);
        deadline = source;
        return script->sessions_reusable;
    }

    // Outside the record lock: the wait must not stop anything else.
    void WaitIfBlocked(const std::string &sql) {
        std::shared_ptr<oracle_scanner::OracleIoDeadline> source;
        {
            std::lock_guard<std::mutex> guard(script->record_lock);
            if (script->block_until_deadline.empty() || sql.find(script->block_until_deadline) == std::string::npos) {
                return;
            }
            script->blocked_statements++;
            source = deadline;
        }
        const auto limit = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (std::chrono::steady_clock::now() < limit) {
            const auto current = source ? source->Get() : std::nullopt;
            if (current && std::chrono::steady_clock::now() >= *current) {
                std::lock_guard<std::mutex> guard(script->record_lock);
                failed = true;
                throw oracle_scanner::ProtocolError(oracle_scanner::ProtocolErrorKind::TRUNCATED,
                                                    "Oracle publication IO deadline expired");
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        std::lock_guard<std::mutex> guard(script->record_lock);
        failed = true;
        throw oracle_scanner::ProtocolError(oracle_scanner::ProtocolErrorKind::TRUNCATED, "never interrupted");
    }

private:
    std::shared_ptr<FakeScript> script;
    std::string user;
    std::shared_ptr<oracle_scanner::OracleIoDeadline> deadline;
    bool closed = false;
    bool failed = false;
};

ScopedOracleSessionFactory InstallFake(const std::shared_ptr<FakeScript> &script) {
    return ScopedOracleSessionFactory([script](const ConnectionConfig &config, const std::string &) {
        return std::unique_ptr<OracleSession>(new FakeSession(script, config.user, config.io_deadline));
    });
}

// DuckDB 2.0 returns a QueryResult read unit by unit, with no (column, row)
// access. These tests read results that way after the fact, so this collects
// one up front: every row as Values, or the error, whether it surfaced when the
// query was submitted or while its rows were fetched.
class MaterializedQueryResult {
public:
    explicit MaterializedQueryResult(duckdb::unique_ptr<duckdb::QueryResult> result) {
        if (result->HasError()) {
            error_object = result->GetErrorObject();
            error = result->GetError();
            return;
        }
        column_count = result->ColumnCount();
        types = result->GetTypes();
        for (const auto &name : result->GetNames()) {
            names.push_back(static_cast<const std::string &>(name));
        }
        try {
            while (auto chunk = result->Fetch()) {
                if (chunk->size() == 0) {
                    break;
                }
                for (duckdb::idx_t row = 0; row < chunk->size(); row++) {
                    std::vector<duckdb::Value> values;
                    for (duckdb::idx_t column = 0; column < column_count; column++) {
                        values.push_back(chunk->GetValue(column, row));
                    }
                    rows.push_back(std::move(values));
                }
            }
        } catch (const std::exception &exception) {
            error_object = duckdb::ErrorData(exception);
            error = error_object.Message();
            rows.clear();
        }
        if (result->HasError() && error.empty()) {
            error_object = result->GetErrorObject();
            error = result->GetError();
        }
    }
    bool HasError() const {
        return !error.empty();
    }
    const std::string &GetError() const {
        return error;
    }
    // Extra fields such as oracle_error_code, carried by the error itself.
    const duckdb::ErrorData &GetErrorObject() const {
        return error_object;
    }
    duckdb::idx_t RowCount() const {
        return rows.size();
    }
    duckdb::idx_t ColumnCount() const {
        return column_count;
    }
    duckdb::Value GetValue(duckdb::idx_t column, duckdb::idx_t row) const {
        return rows.at(row).at(column);
    }
    const std::vector<duckdb::LogicalType> &GetTypes() const {
        return types;
    }
    const std::vector<std::string> &GetNames() const {
        return names;
    }

private:
    std::string error;
    duckdb::ErrorData error_object;
    duckdb::idx_t column_count = 0;
    std::vector<duckdb::LogicalType> types;
    std::vector<std::string> names;
    std::vector<std::vector<duckdb::Value>> rows;
};

struct TestDatabase {
    TestDatabase() : db(nullptr), con(db) {
        // DuckDB 2.0 keeps list_value and the other core functions in an
        // extension that is no longer linked by default.
        db.LoadStaticExtension<duckdb::CoreFunctionsExtension>();
        db.LoadStaticExtension<OracleScannerExtension>();
        // The endpoint is never contacted: the installed factory answers before
        // any transport work, so these are placeholders, not credentials.
        Run("CREATE SECRET ora (TYPE oracle, HOST '127.0.0.1', PORT 1521, "
            "SERVICE_NAME 'service', USER 'app_user', PASSWORD 'placeholder');");
        // The fake answers plain scans; the one test of aggregate pushdown turns it on.
        Run("SET oracle_aggregate_pushdown = false;");
        Run("SET oracle_join_pushdown = false;");
    }

    std::unique_ptr<MaterializedQueryResult> Query(const std::string &sql) {
        // ORACLE_TEST_TRACE=1 names each statement before it runs, so a hang says where.
        if (std::getenv("ORACLE_TEST_TRACE")) {
            std::cout << "  > " << sql.substr(0, 160) << std::endl;
        }
        return std::make_unique<MaterializedQueryResult>(con.Query(sql));
    }

    void Run(const std::string &sql) {
        auto result = Query(sql);
        if (result->HasError()) {
            std::cerr << "adapter test setup failed: " << result->GetError() << "\n";
            CHECK(false && "setup statement failed");
        }
    }

    DuckDB db;
    Connection con;
};

std::string ErrorOf(const std::string &sql, const std::shared_ptr<FakeScript> &script) {
    auto factory = InstallFake(script);
    TestDatabase database;
    auto result = database.Query(sql);
    CHECK(result->HasError());
    return result->GetError();
}

// Oracle describe metadata drives the DuckDB column types, and the wire values
// are converted by the same codecs the native session feeds. This is the whole
// oracle_query path with the transport removed.
void TestQueryTypeMappingAndValues() {
    auto script = std::make_shared<FakeScript>();
    script->columns = {Column("id", 2, 6, 0),        // NUMBER(6) -> BIGINT
                       Column("label", 1),           // VARCHAR2  -> VARCHAR
                       Column("amount", 2, 10, 2),   // NUMBER(10,2) -> DECIMAL
                       Column("unbounded", 2),       // NUMBER     -> VARCHAR text
                       Column("payload", 23),        // RAW        -> BLOB
                       Column("ratio", 101)};        // BINARY_DOUBLE -> DOUBLE
    script->rows = {{Number("42"), Text("first"), Number("10.25"), Number("123456789012345678901234567890"),
                     std::vector<uint8_t> {0xDE, 0xAD}, oracle_scanner::EncodeOracleBinaryDouble(0.5)},
                    // A NULL in every column is the other half of the contract:
                    // no codec is asked to decode an absent value.
                    {std::nullopt, std::nullopt, std::nullopt, std::nullopt, std::nullopt, std::nullopt}};

    auto factory = InstallFake(script);
    TestDatabase database;
    auto result = database.Query("SELECT * FROM oracle_query('ora', 'SELECT * FROM app.items')");
    CHECK(!result->HasError());
    CHECK(result->RowCount() == 2);
    CHECK(result->ColumnCount() == 6);

    CHECK(result->GetTypes()[0] == duckdb::LogicalType::BIGINT);
    CHECK(result->GetTypes()[1] == duckdb::LogicalType::VARCHAR);
    CHECK(result->GetTypes()[2] == duckdb::LogicalType::DECIMAL(10, 2));
    CHECK(result->GetTypes()[3] == duckdb::LogicalType::VARCHAR);
    CHECK(result->GetTypes()[4] == duckdb::LogicalType::BLOB);
    CHECK(result->GetTypes()[5] == duckdb::LogicalType::DOUBLE);
    CHECK(result->GetNames()[0] == "id" && result->GetNames()[5] == "ratio");

    CHECK(result->GetValue(0, 0).ToString() == "42");
    CHECK(result->GetValue(1, 0).ToString() == "first");
    CHECK(result->GetValue(2, 0).ToString() == "10.25");
    // An unconstrained NUMBER keeps every digit instead of being narrowed.
    CHECK(result->GetValue(3, 0).ToString() == "123456789012345678901234567890");
    CHECK(result->GetValue(5, 0).GetValue<double>() == 0.5);

    for (duckdb::idx_t column = 0; column < result->ColumnCount(); column++) {
        CHECK(result->GetValue(column, 1).IsNull());
    }

    CHECK(script->queries.size() == 1);
    CHECK(script->queries[0] == "SELECT * FROM app.items");
    CHECK(script->sessions_opened == 1);
}

// A scan stores values with WriteOracleValue rather than SetValue(ValueFor(...)).
// For every mapped type, and for the values each must refuse, the two have to
// store the same thing or raise the same error.
void TestWriteOracleValueMatchesValueFor() {
    using Wire = std::optional<std::vector<uint8_t>>;
    auto timestamp_column = Column("ts", 180);
    timestamp_column.scale = 9;
    oracle_scanner::OracleDateTime moment;
    moment.year = 2026;
    moment.month = 10;
    moment.day = 21;
    moment.hour = 13;
    moment.second = 5;
    moment.nanosecond = 123456789;
    auto micro_moment = moment;
    micro_moment.nanosecond = 123456000;
    auto national_label = Column("n_label", 1);
    national_label.character_set_form = 2;
    auto national_fixed = Column("n_fixed", 96);
    national_fixed.character_set_form = 2;
    auto interval_column = Column("elapsed", 183, 2, 9);
    auto local_zone_column = Column("seen_at", 231);
    local_zone_column.scale = 6;
    const std::vector<std::pair<OracleColumn, std::vector<Wire>>> cases = {
        {Column("id", 2, 10, 0),
         {std::nullopt, Number("0"), Number("-1"), Number("9999999999"), Number("100000000000000000000")}},
        {Column("small", 2, 4, 2), {Number("12.34"), Number("-0.01"), Number("123.45"), Number("1.005")}},
        {Column("medium", 2, 9, 3), {Number("123456.789"), Number("-0.5")}},
        {Column("amount", 2, 12, 2), {Number("1000122856.29"), Number("0.1"), Number("-99999999.99")}},
        {Column("wide", 2, 38, 10),
         {Number("1234567890123456789012345678.0123456789"), Number("-0.0000000001"),
          Number("1234567890123456789012345678901")}},
        {Column("unbounded", 2), {Number("123456789012345678901234567890"), Number("-0.000000000000000000000000000015")}},
        {national_label,
         {std::vector<uint8_t> {0x00, 0x68, 0x00, 0xE9, 0x04, 0x1F, 0xD8, 0x3D, 0xDE, 0x00}, std::vector<uint8_t> {},
          std::vector<uint8_t> {0x00}, std::vector<uint8_t> {0xD8, 0x3D}}},
        {national_fixed, {std::vector<uint8_t> {0x00, 0x61, 0x00, 0x20}}},
        {Column("span", 182),
         {oracle_scanner::EncodeOracleIntervalYearMonth(2, 3), oracle_scanner::EncodeOracleIntervalYearMonth(-5, -11),
          oracle_scanner::EncodeOracleIntervalYearMonth(200000000, 0)}},
        {interval_column,
         {oracle_scanner::EncodeOracleIntervalDaySecond(3, 4, 5, 6, 789012000),
          oracle_scanner::EncodeOracleIntervalDaySecond(-12, -23, -59, -59, -500000000),
          oracle_scanner::EncodeOracleIntervalDaySecond(0, 0, 0, 0, 1)}},
        {Column("legacy", 8), {Text("a long text"), Text(""), std::vector<uint8_t> {0xFF}}},
        {Column("legacy_raw", 24), {std::vector<uint8_t> {0xDE, 0xAD}}},
        {Column("address", 11), {std::vector<uint8_t> {0x00, 0x08, 0x35, 0xB4, 0x00, 0x01, 0x00, 0x00, 0x89, 0x89, 0x00, 0x00}}},
        {Column("universal", 208),
         {std::vector<uint8_t> {0x01, 0x00, 0x08, 0x35, 0xB4, 0x00, 0x01, 0x00, 0x00, 0x89, 0x89, 0x00, 0x00},
          std::vector<uint8_t> {0x02, 0x04, 0x00, 0x40, 0x89, 0xA1, 0x05, 0x61}}},
        {Column("label", 1), {Text(""), Text("plain"), Text("\xD0\xBF\xD1\x80\xD0\xB8\xD0\xB2\xD0\xB5\xD1\x82"),
                              std::vector<uint8_t> {'o', 'k', 0xFF}, std::vector<uint8_t> {0xC3}}},
        {Column("fixed", 96), {Text("ab  ")}},
        {Column("doc", 112), {Text("a clob value")}},
        {Column("payload", 23), {std::vector<uint8_t> {}, std::vector<uint8_t> {0x00, 0xFF, 0x10}}},
        {Column("image", 113), {std::vector<uint8_t> {0xDE, 0xAD, 0xBE, 0xEF}}},
        {Column("ratio", 100), {oracle_scanner::EncodeOracleBinaryFloat(0.25F)}},
        {Column("score", 101), {oracle_scanner::EncodeOracleBinaryDouble(-1.0 / 3.0)}},
        {Column("day", 12), {oracle_scanner::EncodeOracleDate(moment)}},
        {timestamp_column, {oracle_scanner::EncodeOracleTimestamp(moment, false)}},
        {Column("ts_us", 180), {oracle_scanner::EncodeOracleTimestamp(micro_moment, false),
                                oracle_scanner::EncodeOracleTimestamp(moment, false)}},
        {Column("flag", 252), {std::vector<uint8_t> {1}, std::vector<uint8_t> {0}, std::vector<uint8_t> {}}},
        {local_zone_column, {oracle_scanner::EncodeOracleTimestamp(micro_moment, false),
                             oracle_scanner::EncodeOracleTimestamp(moment, false)}},
    };
    const auto store = [](const auto &write) -> std::string {
        try {
            write();
            return "";
        } catch (const std::exception &error) {
            const auto message = std::string(error.what());
            return message.empty() ? std::string("<empty error>") : message;
        }
    };
    size_t refusals = 0;
    for (const auto &entry : cases) {
        const auto &column = entry.first;
        const auto type = duckdb::TypeFor(column);
        for (const auto &wire : entry.second) {
            for (const duckdb::idx_t row : {duckdb::idx_t {0}, duckdb::idx_t {7}}) {
                duckdb::Vector expected(type, STANDARD_VECTOR_SIZE);
                duckdb::Vector written(type, STANDARD_VECTOR_SIZE);
                const auto expected_error =
                    store([&] { expected.SetValue(row, duckdb::ValueFor(column, wire)); });
                const auto written_error =
                    store([&] { duckdb::WriteOracleValue(written, row, column, wire); });
                CHECK(expected_error == written_error);
                if (!expected_error.empty()) {
                    refusals++;
                    continue;
                }
                CHECK(duckdb::Value::NotDistinctFrom(expected.GetValue(row), written.GetValue(row)));
            }
        }
    }
    // The cases include refusals, so the comparison above covers errors too:
    // an out-of-range BIGINT, two DECIMAL overflows, two strings that are not
    // UTF-8 and a timestamp finer than its column, then an odd and a lone
    // surrogate UTF-16 value, a year-month span past int32, a day-second span
    // finer than a microsecond, a LONG that is not UTF-8, a logical UROWID, an
    // empty BOOLEAN and a local-zone time finer than a microsecond, each at two rows.
    CHECK(refusals == 2 * 14);
}

// The types added in 0.6.0 reach SQL as the DuckDB types they map to, with the
// values Oracle holds. A national column is UTF-16 in the row and comes out
// UTF-8; an INTERVAL YEAR TO MONTH is months, an INTERVAL DAY TO SECOND is
// days and microseconds; a ROWID and a UROWID are the text Oracle prints; LONG
// reads as VARCHAR and LONG RAW as BLOB.
void TestNewTypesReadThroughSql() {
	auto script = std::make_shared<FakeScript>();
	auto national = Column("N_LABEL", 1);
	national.character_set_form = 2;
	auto national_fixed = Column("N_FIXED", 96);
	national_fixed.character_set_form = 2;
	auto legacy = Column("LEGACY", 8);
	legacy.character_set_form = 1;
	script->columns = {national, national_fixed, Column("SPAN", 182),         Column("ELAPSED", 183, 2, 6),
	                   legacy,   Column("LEGACY_RAW", 24), Column("ADDRESS", 11), Column("UNIVERSAL", 208)};
	const std::vector<uint8_t> physical = {0x00, 0x08, 0x35, 0xB4, 0x00, 0x01, 0x00, 0x00, 0x89, 0x89, 0x00, 0x00};
	auto universal = physical;
	universal.insert(universal.begin(), 0x01);
	script->rows = {{std::vector<uint8_t> {0x00, 0x68, 0x00, 0xE9, 0xD8, 0x3D, 0xDE, 0x00},
	                 std::vector<uint8_t> {0x00, 0x61, 0x00, 0x20, 0x00, 0x20},
	                 oracle_scanner::EncodeOracleIntervalYearMonth(-5, -11),
	                 oracle_scanner::EncodeOracleIntervalDaySecond(3, 4, 5, 6, 789012000), Text("long text"),
	                 std::vector<uint8_t> {0xDE, 0xAD}, physical, universal},
	                {std::nullopt, std::nullopt, std::nullopt, std::nullopt, std::nullopt, std::nullopt, std::nullopt,
	                 std::nullopt}};

	auto factory = InstallFake(script);
	TestDatabase database;
	auto result = database.Query("SELECT * FROM oracle_query('ora', 'SELECT * FROM app.items')");
	CHECK(!result->HasError());
	const std::vector<duckdb::LogicalType> expected_types = {
	    duckdb::LogicalType::VARCHAR, duckdb::LogicalType::VARCHAR, duckdb::LogicalType::INTERVAL,
	    duckdb::LogicalType::INTERVAL, duckdb::LogicalType::VARCHAR, duckdb::LogicalType::BLOB,
	    duckdb::LogicalType::VARCHAR, duckdb::LogicalType::VARCHAR};
	CHECK(result->GetTypes() == expected_types);
	CHECK(result->GetValue(0, 0).ToString() == "h\xC3\xA9\xF0\x9F\x98\x80");
	// CHAR is blank-padded, and the padding is part of the value.
	CHECK(result->GetValue(1, 0).ToString() == "a  ");
	CHECK(result->GetValue(2, 0) == duckdb::Value::INTERVAL(-71, 0, 0));
	CHECK(result->GetValue(3, 0) == duckdb::Value::INTERVAL(0, 3, ((4 * 60 + 5) * 60 + 6) * 1000000LL + 789012));
	CHECK(result->GetValue(4, 0).ToString() == "long text");
	CHECK(result->GetValue(5, 0).ToString() == "\\xDE\\xAD");
	CHECK(result->GetValue(6, 0).ToString() == "AACDW0AABAAAImJAAA");
	CHECK(result->GetValue(7, 0).ToString() == "AACDW0AABAAAImJAAA");
	for (duckdb::idx_t column = 0; column < 8; column++) {
		CHECK(result->GetValue(column, 1).IsNull());
	}
}

// Projecting a subset of the columns must emit exactly the requested ones, in
// the requested order, with every row initialized.
void TestProjectedColumns() {
    auto script = std::make_shared<FakeScript>();
    script->columns = {Column("lv", 2, 6, 0), Column("a", 1), Column("b", 1)};
    script->rows = {{Number("1"), Text("a"), Text("b")}, {Number("2"), Text("a"), Text("b")}};

    auto factory = InstallFake(script);
    TestDatabase database;

    auto single = database.Query("SELECT lv FROM oracle_query('ora', 'SELECT lv, a, b FROM app.items')");
    CHECK(!single->HasError());
    CHECK(single->ColumnCount() == 1 && single->RowCount() == 2);
    CHECK(single->GetValue(0, 0).ToString() == "1" && single->GetValue(0, 1).ToString() == "2");

    auto middle = database.Query("SELECT a FROM oracle_query('ora', 'SELECT lv, a, b FROM app.items')");
    CHECK(!middle->HasError());
    CHECK(middle->GetValue(0, 0).ToString() == "a");

    auto reordered = database.Query("SELECT b, lv FROM oracle_query('ora', 'SELECT lv, a, b FROM app.items')");
    CHECK(!reordered->HasError());
    CHECK(reordered->GetValue(0, 0).ToString() == "b" && reordered->GetValue(1, 0).ToString() == "1");

    auto counted = database.Query("SELECT count(*) AS c FROM oracle_query('ora', 'SELECT lv, a, b FROM app.items')");
    CHECK(!counted->HasError());
    CHECK(counted->GetValue(0, 0).ToString() == "2");
}

// A ProtocolError raised after the bind succeeded reaches DuckDB through the
// streaming path. It must arrive as a typed DuckDB exception naming the
// operation, not as the untyped `Invalid Error` an escaped std::runtime_error
// produces with its ProtocolErrorKind discarded.
void TestProtocolFailuresBecomeTypedDuckDbErrors() {
    const auto run = [](oracle_scanner::ProtocolErrorKind kind, const std::string &message) {
        auto script = std::make_shared<FakeScript>();
        script->columns = {Column("label", 1)};
        script->fetch_failure = kind;
        script->fetch_failure_message = message;

        auto factory = InstallFake(script);
        TestDatabase database;
        auto result = database.Query("SELECT * FROM oracle_query('ora', 'SELECT label FROM app.items')");
        CHECK(result->HasError());
        return result->GetError();
    };

    const auto malformed = run(oracle_scanner::ProtocolErrorKind::MALFORMED, "unknown TTC message 247");
    CHECK(malformed.find("IO Error") != std::string::npos);
    CHECK(malformed.find("Invalid Error") == std::string::npos);
    CHECK(malformed.find("oracle_query could not fetch from Oracle") != std::string::npos);
    CHECK(malformed.find("unknown TTC message 247") != std::string::npos);

    // UNSUPPORTED is the one kind that is not a connection failure: the server
    // sent a shape this client does not implement.
    const auto unsupported =
        run(oracle_scanner::ProtocolErrorKind::UNSUPPORTED, "TTC describe annotations are not yet supported");
    CHECK(unsupported.find("Not implemented Error") != std::string::npos);
    CHECK(unsupported.find("TTC describe annotations are not yet supported") != std::string::npos);

    for (const auto kind : {oracle_scanner::ProtocolErrorKind::TRUNCATED,
                            oracle_scanner::ProtocolErrorKind::LIMIT_EXCEEDED,
                            oracle_scanner::ProtocolErrorKind::INVALID_STATE}) {
        const auto error = run(kind, "boundary case");
        CHECK(error.find("IO Error") != std::string::npos);
        CHECK(error.find("boundary case") != std::string::npos);
    }
}

// The adapter turns DuckDB parameters into ordered Oracle binds before any
// transport work, so the fake sees exactly what would have gone on the wire.
void TestQueryParametersReachTheSessionAsBinds() {
    auto script = std::make_shared<FakeScript>();
    script->columns = {Column("label", 1)};
    script->rows = {{Text("only")}};

    auto factory = InstallFake(script);
    TestDatabase database;
    auto result = database.Query("SELECT * FROM oracle_query('ora', "
                                 "'SELECT label FROM app.items WHERE id = :id AND label = :label', "
                                 "{id: 7, label: 'seven'})");
    CHECK(!result->HasError());
    CHECK(result->RowCount() == 1);

    CHECK(script->query_binds.size() == 1);
    const auto &binds = script->query_binds[0];
    CHECK(binds.size() == 2);
    CHECK(binds[0].name == "id" && binds[0].oracle_type == 2);
    CHECK(binds[0].direction == oracle_scanner::BindDirection::BIND_IN);
    CHECK(binds[0].value.has_value());
    CHECK(oracle_scanner::DecodeOracleNumber(*binds[0].value) == "7");
    CHECK(binds[1].name == "label" && binds[1].oracle_type == 1);
    CHECK(binds[1].value.has_value());
    CHECK(std::string(binds[1].value->begin(), binds[1].value->end()) == "seven");

    // Oracle treats '' as NULL, and the bind carries that decision unchanged.
    auto empty = database.Query("SELECT * FROM oracle_query('ora', "
                                "'SELECT label FROM app.items WHERE label = :label', {label: ''})");
    CHECK(!empty->HasError());
    CHECK(script->query_binds.size() == 2);
    CHECK(script->query_binds[1][0].value.has_value());
    CHECK(script->query_binds[1][0].value->empty());
}

// Parameters of the types an attached INSERT can write reach oracle_query and
// oracle_execute too, through the same encoder, and a NULL of each says what it is.
void TestParametersOfEveryWritableType() {
    auto script = std::make_shared<FakeScript>();
    script->columns = {Column("label", 1)};
    script->rows = {{Text("only")}};
    script->affected_rows = 1;
    auto factory = InstallFake(script);
    TestDatabase database;
    const auto binds_of = [&](const std::string &list) {
        const auto before = script->query_binds.size();
        auto result = database.Query("SELECT * FROM oracle_query('ora', 'SELECT label FROM app.items WHERE a = :1', " +
                                     list + ")");
        CHECK(!result->HasError());
        CHECK(script->query_binds.size() == before + 1);
        return script->query_binds.back();
    };
    CHECK(binds_of("[true]")[0].oracle_type == 252 &&
          binds_of("[true]")[0].value == std::vector<uint8_t>({1, 1}));
    CHECK(binds_of("[INTERVAL 3 DAY]")[0].oracle_type == 183);
    CHECK(binds_of("[INTERVAL 14 MONTH]")[0].oracle_type == 182);
    // An instant is bound as the TIMESTAMP of its UTC wall time.
    const auto instant = binds_of("[TIMESTAMPTZ '2026-01-01 10:00:00+02']")[0];
    CHECK(instant.oracle_type == 180 && instant.value &&
          oracle_scanner::DecodeOracleTimestamp(*instant.value).hour == 8);
    CHECK(binds_of("[TIMESTAMP_NS '2026-01-01 10:00:00.123456789']")[0].oracle_type == 180);
    CHECK(binds_of("[TIMESTAMP_MS '2026-01-01 10:00:00.5']")[0].oracle_type == 180);
    CHECK(oracle_scanner::DecodeOracleNumber(*binds_of("[170141183460469231731687303715884105727::HUGEINT]")[0].value) ==
          "170141183460469231731687303715884105727");
    CHECK(binds_of("[NULL::HUGEINT]")[0].oracle_type == 2 && !binds_of("[NULL::HUGEINT]")[0].value);
    CHECK(binds_of("[NULL::BOOLEAN]")[0].oracle_type == 252);
    CHECK(binds_of("[NULL::INTERVAL]")[0].oracle_type == 183);
    // Named, as well as positional.
    auto named = database.Query("SELECT * FROM oracle_query('ora', 'SELECT label FROM app.items WHERE a = :flag', "
                                "{flag: false})");
    CHECK(!named->HasError() && script->query_binds.back()[0].oracle_type == 252);
    // A month beside days has no single Oracle interval type.
    auto mixed = database.Query("SELECT * FROM oracle_query('ora', 'SELECT label FROM app.items WHERE a = :1', "
                                "[INTERVAL '1 month 2 days'])");
    CHECK(mixed->HasError() && mixed->GetError().find("cannot hold months") != std::string::npos);
    auto executed = database.Query("SELECT * FROM oracle_execute('ora', 'UPDATE app.items SET a = :1', [true])");
    CHECK(!executed->HasError() && script->counted_execute_binds.back()[0].oracle_type == 252);
    std::cout << "parameters cover BOOLEAN, INTERVAL, TIMESTAMPTZ, TIMESTAMP_NS and HUGEINT" << std::endl;
}

// How NUMBER is held, by declared precision and scale, and what the
// oracle_unconstrained_number setting does for the ones with none.
void TestNumberMappings() {
    const auto number = [](int16_t precision, int16_t scale) {
        auto column = Column("N", 2, precision, scale);
        return duckdb::MappedType(column);
    };
    CHECK(number(10, 0) == duckdb::LogicalType::BIGINT && number(18, 0) == duckdb::LogicalType::BIGINT);
    CHECK(number(19, 0) == duckdb::LogicalType::VARCHAR);
    // Rounded to hundreds: whole numbers, so an integer.
    CHECK(number(10, -2) == duckdb::LogicalType::BIGINT && number(16, -2) == duckdb::LogicalType::BIGINT);
    CHECK(number(17, -2) == duckdb::LogicalType::VARCHAR);
    CHECK(number(5, 2) == duckdb::LogicalType::DECIMAL(5, 2));
    // More digits after the point than the precision: 0.0012 is NUMBER(2,4).
    CHECK(number(2, 4) == duckdb::LogicalType::DECIMAL(4, 4));
    CHECK(number(1, 38) == duckdb::LogicalType::DECIMAL(38, 38) && number(1, 39) == duckdb::LogicalType::VARCHAR);
    CHECK(number(0, 0) == duckdb::LogicalType::VARCHAR && number(126, -127) == duckdb::LogicalType::VARCHAR);

    auto script = std::make_shared<FakeScript>();
    script->columns = {Column("total", 2, 0, 0), Column("price", 2, 8, 2)};
    script->rows = {{Number("1.5"), Number("3.14")}};
    auto factory = InstallFake(script);
    TestDatabase database;
    const auto types = [&] {
        auto result = database.Query("SELECT * FROM oracle_query('ora', 'SELECT total, price FROM t')");
        CHECK(!result->HasError());
        return std::vector<duckdb::LogicalType> {result->GetTypes()[0], result->GetTypes()[1]};
    };
    CHECK(types()[0] == duckdb::LogicalType::VARCHAR);
    database.Run("SET oracle_unconstrained_number = 'double';");
    CHECK(types()[0] == duckdb::LogicalType::DOUBLE && types()[1] == duckdb::LogicalType::DECIMAL(8, 2));
    auto doubled = database.Query("SELECT total FROM oracle_query('ora', 'SELECT total, price FROM t')");
    CHECK(!doubled->HasError() && doubled->GetValue(0, 0).GetValue<double>() == 1.5);
    database.Run("SET oracle_unconstrained_number = 'Decimal(38, 9)';");
    CHECK(types()[0] == duckdb::LogicalType::DECIMAL(38, 9));
    auto decimal = database.Query("SELECT total FROM oracle_query('ora', 'SELECT total, price FROM t')");
    CHECK(!decimal->HasError() && decimal->GetValue(0, 0).ToString() == "1.500000000");
    database.Run("SET oracle_unconstrained_number = 'varchar';");
    CHECK(types()[0] == duckdb::LogicalType::VARCHAR);
    database.Run("SET oracle_unconstrained_number = 'decimal(40,2)';");
    auto bad = database.Query("SELECT * FROM oracle_query('ora', 'SELECT total, price FROM t')");
    CHECK(bad->HasError() && bad->GetError().find("precision <= 38") != std::string::npos);
    database.Run("SET oracle_unconstrained_number = 'real';");
    auto unknown = database.Query("SELECT * FROM oracle_query('ora', 'SELECT total, price FROM t')");
    CHECK(unknown->HasError() && unknown->GetError().find("must be 'varchar', 'double'") != std::string::npos);
    std::cout << "NUMBER maps by precision and scale, and the unconstrained setting picks a type" << std::endl;
}

// oracle_execute promises Oracle's own SQL%ROWCOUNT, which is the operation the
// adapter must call — not the plain Execute whose count comes from the DML
// response.
void TestExecuteUsesTheCountedOperation() {
    auto script = std::make_shared<FakeScript>();
    script->affected_rows = 3;

    auto factory = InstallFake(script);
    TestDatabase database;
    auto result = database.Query("SELECT * FROM oracle_execute('ora', "
                                 "'UPDATE app.items SET label = :label WHERE id = :id', {label: 'x', id: 1})");
    CHECK(!result->HasError());
    CHECK(result->RowCount() == 1);
    CHECK(result->GetValue(0, 0).ToString() == "3");

    CHECK(script->counted_executes.size() == 1);
    CHECK(script->plain_executes.empty());
    CHECK(script->counted_execute_binds[0].size() == 2);
}

// An explicit DuckDB transaction cannot give the isolated Oracle transaction
// oracle_execute runs in, so it is refused before a session is ever opened.
void TestExecuteRefusesAnExplicitTransaction() {
    auto script = std::make_shared<FakeScript>();
    auto factory = InstallFake(script);
    TestDatabase database;
    database.Run("BEGIN TRANSACTION;");
    auto result = database.Query("SELECT * FROM oracle_execute('ora', 'DELETE FROM app.items')");
    CHECK(result->HasError());
    CHECK(result->GetError().find("explicit DuckDB transaction") != std::string::npos);
    CHECK(script->sessions_opened == 0);
    database.Run("ROLLBACK;");
}

// Statement-class and bind validation happen before a session is opened, so a
// rejected statement never reaches the wire.
void TestValidationRunsBeforeAnySession() {
    auto script = std::make_shared<FakeScript>();
    const auto dml_as_query = ErrorOf("SELECT * FROM oracle_query('ora', 'DELETE FROM app.items')", script);
    CHECK(dml_as_query.find("SELECT or WITH") != std::string::npos);
    CHECK(script->sessions_opened == 0);
    CHECK(script->queries.empty());

    auto second = std::make_shared<FakeScript>();
    const auto query_as_dml = ErrorOf("SELECT * FROM oracle_execute('ora', 'SELECT 1 FROM dual')", second);
    CHECK(query_as_dml.find("INSERT, UPDATE, or DELETE") != std::string::npos);
    CHECK(second->sessions_opened == 0);
}

// A missing secret is a bind-time error, and it too must not open a session.
void TestUnknownSecretIsRejected() {
    auto script = std::make_shared<FakeScript>();
    auto factory = InstallFake(script);
    TestDatabase database;
    auto result = database.Query("SELECT * FROM oracle_query('nope', 'SELECT 1 FROM dual')");
    CHECK(result->HasError());
    CHECK(result->GetError().find("was not found") != std::string::npos);
    CHECK(script->sessions_opened == 0);
}

// A column this client cannot read is refused while binding, with a message
// that names the reason. The type codes and character set forms below are the
// ones a live Oracle 19c describe reports for each of these declarations.
void TestUnsupportedColumnTypesAreRefusedAtBind() {
    const auto bind_error = [](uint16_t oracle_type, uint8_t character_set_form) {
        auto script = std::make_shared<FakeScript>();
        auto column = Column("v", oracle_type);
        column.character_set_form = character_set_form;
        script->columns = {column};

        auto factory = InstallFake(script);
        TestDatabase database;
        auto result = database.Query("SELECT * FROM oracle_query('ora', 'SELECT v FROM app.items')");
        CHECK(result->HasError());
        return result->GetError();
    };

    // NVARCHAR2 and NCHAR carry the VARCHAR2 and CHAR type codes; only the
    // character set form separates them. They are readable now (UTF-16 in the
    // row, converted), but a national form on any other type is a shape this
    // version has not seen.
    const auto national_number = bind_error(2, 2);
    CHECK(national_number.find("Not implemented Error") != std::string::npos);
    CHECK(national_number.find("national character set form on Oracle type 2") != std::string::npos);

    // BFILE has no read path and is refused by name, unlike the three LOB
    // types beside it.
    CHECK(bind_error(114, 0).find("Oracle type 114") != std::string::npos);

    // TIMESTAMP WITH LOCAL TIME ZONE and BOOLEAN are readable (see
    // TestBooleanAndLocalZoneReadThroughSql); the refusals above are what is left.

    // Anything with no mapping at all still fails by name rather than falling
    // through to the textual default.
    const auto unmapped = bind_error(108, 0);
    CHECK(unmapped.find("Oracle type 108") != std::string::npos);

    // TIMESTAMP WITH TIME ZONE stays readable: the value carries its own
    // offset, so nothing has to be assumed about a session zone.
    auto script = std::make_shared<FakeScript>();
    script->columns = {Column("v", 181)};
    // The wire carries UTC beside the offset, and the value reads on the wall
    // clock of that offset: 10:42 UTC at +02:00 is 12:42, the late evening of
    // New Year's Eve at +01:30 is already the next year, and 01:00 UTC at
    // -05:00 is still the previous day, the last of a non-leap February.
    script->rows = {{oracle_scanner::EncodeOracleTimestamp({2026, 8, 20, 10, 42, 55, 0, 120, true}, true)},
                    {oracle_scanner::EncodeOracleTimestamp({2026, 12, 31, 23, 30, 0, 500000000, 90, true}, true)},
                    {oracle_scanner::EncodeOracleTimestamp({2026, 3, 1, 1, 0, 0, 0, -300, true}, true)}};
    auto factory = InstallFake(script);
    TestDatabase database;
    auto accepted = database.Query("SELECT * FROM oracle_query('ora', 'SELECT v FROM app.items')");
    CHECK(!accepted->HasError());
    CHECK(accepted->RowCount() == 3);
    CHECK(accepted->GetValue(0, 0).ToString() == "2026-08-20 12:42:55+02:00");
    CHECK(accepted->GetValue(0, 1).ToString() == "2027-01-01 01:00:00.500000000+01:30");
    CHECK(accepted->GetValue(0, 2).ToString() == "2026-02-28 20:00:00-05:00");
}

// BOOLEAN (type 252, one byte) and TIMESTAMP WITH LOCAL TIME ZONE (type 231, a
// wall-clock time in the session's zone, which this client fixes at UTC) read
// as DuckDB's own types.
void TestBooleanAndLocalZoneReadThroughSql() {
    auto script = std::make_shared<FakeScript>();
    script->columns = {Column("B", 252), Column("L", 231)};
    script->columns[1].scale = 6;
    script->rows = {
        {std::vector<uint8_t> {1}, oracle_scanner::EncodeOracleTimestamp({2026, 3, 4, 5, 6, 7, 123456000, 0, false}, false)},
        {std::vector<uint8_t> {0}, oracle_scanner::EncodeOracleTimestamp({1969, 12, 31, 23, 59, 59, 0, 0, false}, false)},
        {std::nullopt, std::nullopt}};
    auto factory = InstallFake(script);
    TestDatabase database;
    auto result = database.Query("SELECT b, l, typeof(b), typeof(l) FROM oracle_query('ora', 'SELECT b, l FROM app.items')");
    CHECK(!result->HasError());
    CHECK(result->RowCount() == 3);
    CHECK(result->GetValue(0, 0) == duckdb::Value::BOOLEAN(true) && result->GetValue(0, 1) == duckdb::Value::BOOLEAN(false));
    CHECK(result->GetValue(0, 2).IsNull());
    CHECK(result->GetValue(2, 0).ToString() == "BOOLEAN" && result->GetValue(3, 0).ToString() == "TIMESTAMP WITH TIME ZONE");
    CHECK(result->GetValue(1, 0) == duckdb::Value::TIMESTAMPTZ(duckdb::timestamp_tz_t(1772600767123456LL)));
    CHECK(result->GetValue(1, 1) == duckdb::Value::TIMESTAMPTZ(duckdb::timestamp_tz_t(-1000000LL)));

    // A TIMESTAMP(9) with a finer fraction than a microsecond is reported.
    auto fine = std::make_shared<FakeScript>();
    fine->columns = {Column("L", 231)};
    fine->rows = {{oracle_scanner::EncodeOracleTimestamp({2026, 3, 4, 5, 6, 7, 123456789, 0, false}, false)}};
    auto fine_factory = InstallFake(fine);
    TestDatabase fine_database;
    auto refused = fine_database.Query("SELECT * FROM oracle_query('ora', 'SELECT l FROM app.items')");
    CHECK(refused->HasError() && refused->GetError().find("sub-microsecond") != std::string::npos);
    std::cout << "BOOLEAN and local-zone columns read as DuckDB types" << std::endl;
}

// A LOB column reaches this layer as plain bytes: the session resolves the
// locator and converts a character LOB out of AL16UTF16 before a row is handed
// up, so the adapter only has to know which DuckDB type each maps to. CLOB and
// NCLOB become VARCHAR, BLOB becomes BLOB.
void TestLobColumnsMapToTextAndBlob() {
    auto script = std::make_shared<FakeScript>();
    auto clob = Column("DOC", 112);
    clob.character_set_form = 1;
    auto nclob = Column("NDOC", 112);
    nclob.character_set_form = 2;
    script->columns = {clob, nclob, Column("BIN", 113)};
    script->rows = {{std::vector<uint8_t>({'h', 'i'}), std::vector<uint8_t>({0xd0, 0xbf}),
                     std::vector<uint8_t>({0x00, 0xff})}};

    auto factory = InstallFake(script);
    TestDatabase database;
    auto result = database.Query("SELECT * FROM oracle_query('ora', 'SELECT doc, ndoc, bin FROM app.items')");
    CHECK(!result->HasError());
    CHECK(result->GetTypes()[0] == duckdb::LogicalType::VARCHAR);
    CHECK(result->GetTypes()[1] == duckdb::LogicalType::VARCHAR);
    CHECK(result->GetTypes()[2] == duckdb::LogicalType::BLOB);
    CHECK(result->GetValue(0, 0).ToString() == "hi");
    CHECK(result->GetValue(1, 0).ToString() == "\xd0\xbf");
}

// A NULL has to survive from the wire to whatever DuckDB evaluates on top of
// the scan. In 2.0 every vector carries its own size and SetValue does not
// advance it, so a scan that set only the chunk's cardinality emitted vectors
// of size zero. VectorOperations::IsNull sizes its loop from the vector, not
// from the chunk's count, and so evaluated over nothing: `label IS NULL` read
// false on every row, including the NULL one.
//
// The form matters, and the first version of this test was vacuous because of
// it. A query that is *only* `label IS NULL`, or a count(*) over a WHERE, passed
// with the bug in place: the projection's ExpressionExecutor re-sizes its own
// output from the chunk's count, and a materialized result is copied by that
// count too, so both repaired the sizes before anything read them. What does
// not get repaired is a reference to the scan's vector used inside a wider
// projection — exactly what `SELECT id, label, label IS NULL FROM ...` does,
// and what the shell showed against a live database. So that is what this
// reads, from a streaming result, which is what the shell and every pipeline
// operator consume.
void TestNullsSurviveAboveTheScan() {
    auto script = std::make_shared<FakeScript>();
    script->two_batch_fetch = true;
    script->columns = {Column("ID", 2, 10, 0), Column("LABEL", 1)};
    script->rows = {{oracle_scanner::EncodeOracleNumber("1"), std::vector<uint8_t>({'a'})},
                    {oracle_scanner::EncodeOracleNumber("2"), std::nullopt},
                    {oracle_scanner::EncodeOracleNumber("3"), std::vector<uint8_t>({'c'})}};
    auto factory = InstallFake(script);
    TestDatabase database;
    const std::string scan = "oracle_query('ora', 'SELECT id, label FROM app.items')";

    // Submitted and read as a stream, chunk by chunk, which is what the shell
    // and every pipeline operator consume in DuckDB 2.0.
    // The stream is closed before the next query: DuckDB 2.0 refuses a new
    // query while the connection still has an open result.
    {
        auto submitted = database.con.Submit("SELECT id, label, label IS NULL AS n FROM " + scan);
        CHECK(!submitted->HasError());
        duckdb::QueryResultStream<> streamed(std::move(submitted));
        auto chunk = streamed.Fetch();
        CHECK(chunk != nullptr && chunk->size() == 3);
        CHECK(chunk->GetValue(1, 1).IsNull());
        CHECK(chunk->GetValue(2, 0).GetValue<bool>() == false);
        CHECK(chunk->GetValue(2, 1).GetValue<bool>() == true);
        CHECK(chunk->GetValue(2, 2).GetValue<bool>() == false);
    }

    // And the aggregate, which counts non-NULLs by the same validity.
    auto counted = database.Query("SELECT count(label) FROM " + scan);
    CHECK(!counted->HasError() && counted->GetValue(0, 0).GetValue<int64_t>() == 2);
}

// Filter pushdown translates only what is provably identical in Oracle, and
// refuses the rest. Refusing matters: DuckDB removes a filter from the plan once
// it hands it to the scan, so a filter that is accepted and then approximated
// changes the answer rather than merely slowing it down.
void TestFilterPushdownTranslatesOnlyTheProvenSubset() {
    std::vector<OracleColumn> columns = {Column("ID", 2), Column("LABEL", 1), Column("TAG", 96)};
    const std::vector<duckdb::column_t> scanned = {0, 1, 2};

    // DuckDB 2.0 hands a scan ExpressionFilters only: LogicalGet converts every
    // legacy filter with ExpressionFilter::FromTableFilter before the scan
    // sees it. The fixtures below still build the legacy shapes, because they
    // are the clearest way to say what is being tested, and go through that
    // same conversion — so this exercises the translator on exactly the input
    // the planner produces.
    const auto as_pushed = [&](const std::vector<OracleColumn> &cols, duckdb::idx_t column,
                               duckdb::unique_ptr<duckdb::TableFilter> filter) {
        duckdb::TableFilterSet filters;
        filters.PushFilter(duckdb::ProjectionIndex(column),
                           duckdb::ExpressionFilter::FromTableFilter(*filter, duckdb::MappedType(cols[column])));
        return filters;
    };
    const auto translate = [&](duckdb::idx_t column, duckdb::unique_ptr<duckdb::TableFilter> filter) {
        return duckdb::OracleWhereClause(as_pushed(columns, column, std::move(filter)), columns, scanned);
    };
    const auto constant = [](duckdb::ExpressionType comparison, duckdb::Value value) {
        return duckdb::make_uniq<duckdb::LegacyConstantFilter>(comparison, std::move(value));
    };

    // NUMBER is exact decimal on both sides, so every comparison round-trips.
    CHECK(translate(0, constant(duckdb::ExpressionType::COMPARE_EQUAL, duckdb::Value::BIGINT(7))) == "\"ID\" = 7");
    CHECK(translate(0, constant(duckdb::ExpressionType::COMPARE_GREATERTHANOREQUALTO, duckdb::Value::BIGINT(2))) ==
           "\"ID\" >= 2");

    // VARCHAR2 equality does not depend on collation; the literal is escaped.
    CHECK(translate(1, constant(duckdb::ExpressionType::COMPARE_EQUAL, duckdb::Value("beta"))) ==
           "\"LABEL\" = 'beta'");
    CHECK(translate(1, constant(duckdb::ExpressionType::COMPARE_EQUAL, duckdb::Value("O'Hara"))) ==
           "\"LABEL\" = 'O''Hara'");

    // Null tests mean the same thing in both engines.
    CHECK(translate(1, duckdb::make_uniq<duckdb::LegacyIsNullFilter>()) == "\"LABEL\" IS NULL");
    CHECK(translate(1, duckdb::make_uniq<duckdb::LegacyIsNotNullFilter>()) == "\"LABEL\" IS NOT NULL");

    const auto refused = [&](duckdb::idx_t column, duckdb::unique_ptr<duckdb::TableFilter> filter,
                             const std::string &reason) {
        try {
            (void)translate(column, std::move(filter));
        } catch (const duckdb::NotImplementedException &error) {
            CHECK(std::string(error.what()).find(reason) != std::string::npos);
            return;
        }
        CHECK(false && "filter should have been refused");
    };

    // Oracle stores '' as NULL, so `col = ''` matches nothing there while
    // DuckDB matches empty strings.
    refused(1, constant(duckdb::ExpressionType::COMPARE_EQUAL, duckdb::Value("")), "empty string");
    // CHAR comparison is blank-padded in Oracle but not in the value handed to
    // DuckDB, so the two predicates are not the same.
    refused(2, constant(duckdb::ExpressionType::COMPARE_EQUAL, duckdb::Value("aa")), "not VARCHAR2");
    // Character ordering follows NLS_SORT and NLS_COMP, which are never
    // negotiated, so a range comparison on text has no provable meaning.
    refused(1, constant(duckdb::ExpressionType::COMPARE_LESSTHAN, duckdb::Value("m")), "not NUMBER");

    // A date reads back as a real TIMESTAMP now, so its filters are timestamp
    // comparisons and can be pushed: TO_DATE and TO_TIMESTAMP with an explicit
    // format carry no session dependence, which is what a bare string literal
    // could never promise.
    const auto date_column = Column("WHEN_DATE", 12);
    const auto timestamp_column = Column("WHEN_TS", 180, 0, 9);
    {
        std::vector<OracleColumn> time_columns = {date_column, timestamp_column};
        const auto translate_time = [&](idx_t index, duckdb::unique_ptr<duckdb::TableFilter> filter) {
            return duckdb::OracleWhereClause(as_pushed(time_columns, index, std::move(filter)), time_columns, {0, 1});
        };
        CHECK(translate_time(0, duckdb::make_uniq<duckdb::LegacyConstantFilter>(
                                     duckdb::ExpressionType::COMPARE_EQUAL,
                                     duckdb::Value::TIMESTAMP(duckdb::Timestamp::FromString("2024-03-05 06:07:08", false)))) ==
               "\"WHEN_DATE\" = TO_DATE('2024-03-05 06:07:08', 'YYYY-MM-DD HH24:MI:SS')");
        // Chronological order depends on nothing a session sets, unlike the
        // collation that keeps ordered text comparisons off this list.
        CHECK(translate_time(0, duckdb::make_uniq<duckdb::LegacyConstantFilter>(
                                     duckdb::ExpressionType::COMPARE_GREATERTHAN,
                                     duckdb::Value::TIMESTAMP(duckdb::Timestamp::FromString("2024-01-01 00:00:00", false)))) ==
               "\"WHEN_DATE\" > TO_DATE('2024-01-01 00:00:00', 'YYYY-MM-DD HH24:MI:SS')");
        CHECK(translate_time(1, duckdb::make_uniq<duckdb::LegacyConstantFilter>(
                                     duckdb::ExpressionType::COMPARE_EQUAL,
                                     duckdb::Value::TIMESTAMPNS(duckdb::timestamp_ns_t(1709618828123456789LL)))) ==
               "\"WHEN_TS\" = TO_TIMESTAMP('2024-03-05 06:07:08.123456789', 'YYYY-MM-DD HH24:MI:SS.FF9')");
        // An Oracle DATE holds whole seconds, so no value in the column can
        // equal a sub-second constant and no boundary sits where it says.
        bool sub_second_refused = false;
        try {
            translate_time(0, duckdb::make_uniq<duckdb::LegacyConstantFilter>(
                                  duckdb::ExpressionType::COMPARE_EQUAL,
                                  duckdb::Value::TIMESTAMP(duckdb::Timestamp::FromString("2024-03-05 06:07:08.5", false))));
        } catch (const duckdb::NotImplementedException &error) {
            sub_second_refused = std::string(error.what()).find("whole seconds") != std::string::npos;
        }
        CHECK(sub_second_refused);
        // Text against a date column is the comparison that would have made
        // Oracle convert through NLS_DATE_FORMAT.
        bool text_refused = false;
        try {
            translate_time(0, duckdb::make_uniq<duckdb::LegacyConstantFilter>(duckdb::ExpressionType::COMPARE_EQUAL,
                                                                        duckdb::Value("2024-03-05")));
        } catch (const duckdb::NotImplementedException &error) {
            text_refused = std::string(error.what()).find("text comparison") != std::string::npos;
        }
        CHECK(text_refused);
    }

    // An IN list is a disjunction of equalities and carries the same proof.
    duckdb::vector<duckdb::Value> numbers = {duckdb::Value::BIGINT(1), duckdb::Value::BIGINT(3)};
    CHECK(translate(0, duckdb::make_uniq<duckdb::LegacyInFilter>(std::move(numbers))) == "\"ID\" IN (1, 3)");
    duckdb::vector<duckdb::Value> labels = {duckdb::Value("beta"), duckdb::Value("gamma")};
    CHECK(translate(1, duckdb::make_uniq<duckdb::LegacyInFilter>(std::move(labels))) == "\"LABEL\" IN ('beta', 'gamma')");

    // One unprovable value refuses the whole list rather than dropping it, which
    // would apply a weaker predicate than the query asked for.
    duckdb::vector<duckdb::Value> with_empty = {duckdb::Value("beta"), duckdb::Value("")};
    refused(1, duckdb::make_uniq<duckdb::LegacyInFilter>(std::move(with_empty)), "empty string");

    // An optional filter is a hint DuckDB does not need for correctness, so one
    // that cannot be translated is dropped instead of raising — while the same
    // filter arriving as required still raises.
    duckdb::vector<duckdb::Value> optional_values = {duckdb::Value("beta"), duckdb::Value("")};
    auto optional = duckdb::make_uniq<duckdb::LegacyOptionalFilter>(
        duckdb::make_uniq<duckdb::LegacyInFilter>(std::move(optional_values)));
    CHECK(translate(1, std::move(optional)).empty());
    auto translatable = duckdb::make_uniq<duckdb::LegacyOptionalFilter>(duckdb::make_uniq<duckdb::LegacyIsNullFilter>());
    CHECK(translate(1, std::move(translatable)) == "\"LABEL\" IS NULL");

    // A conjunction is only as pushable as its children.
    auto conjunction = duckdb::make_uniq<duckdb::LegacyConjunctionAndFilter>();
    conjunction->child_filters.push_back(constant(duckdb::ExpressionType::COMPARE_EQUAL, duckdb::Value::BIGINT(1)));
    conjunction->child_filters.push_back(
        constant(duckdb::ExpressionType::COMPARE_GREATERTHAN, duckdb::Value::BIGINT(0)));
    // A top-level AND is taken a conjunct at a time, so the parentheses go.
    CHECK(translate(0, std::move(conjunction)) == "\"ID\" = 1 AND \"ID\" > 0");
}

// oracle_execute_many builds one Oracle batch out of the supplied rows, runs it
// on a single session, and commits it as a whole. The count it reports is the
// session's, not a count of the rows it was handed.
void TestExecuteManyBatchesAndCommits() {
    auto script = std::make_shared<FakeScript>();
    script->affected_rows = 1;

    auto factory = InstallFake(script);
    TestDatabase database;
    auto result = database.Query("SELECT * FROM oracle_execute_many('ora', "
                                 "'INSERT INTO app.items (id, label) VALUES (:id, :label)', "
                                 "[{id: 1, label: 'one'}, {id: 2, label: 'two'}])");
    CHECK(!result->HasError());
    CHECK(result->GetValue(0, 0).ToString() == "2");

    CHECK(script->batch_rows.size() == 2);
    CHECK(script->batch_rows[0].size() == 2);
    CHECK(script->batch_rows[0][0].name == "id" && script->batch_rows[0][1].name == "label");
    CHECK(oracle_scanner::DecodeOracleNumber(*script->batch_rows[0][0].value) == "1");
    CHECK(oracle_scanner::DecodeOracleNumber(*script->batch_rows[1][0].value) == "2");
    CHECK(script->commits == 1 && script->rollbacks == 0);

    // A failing batch rolls back rather than leaving the Oracle transaction
    // open, and the failure is reported as such.
    auto failing = std::make_shared<FakeScript>();
    failing->fetch_failure = oracle_scanner::ProtocolErrorKind::INVALID_STATE;
    failing->fetch_failure_message = "injected batch failure";
    failing->batch_should_fail = true;
    auto failing_factory = InstallFake(failing);
    TestDatabase failing_database;
    auto failed = failing_database.Query("SELECT * FROM oracle_execute_many('ora', "
                                         "'INSERT INTO app.items (id) VALUES (:id)', [{id: 1}])");
    CHECK(failed->HasError());
    CHECK(failed->GetError().find("oracle_execute_many failed") != std::string::npos);
    CHECK(failing->rollbacks == 1 && failing->commits == 0);
}

// oracle_call_named turns the typed argument list into one OracleCallRequest and
// maps the session's outputs back onto the declared argument names.
void TestNamedCallRequestAndOutputs() {
    auto script = std::make_shared<FakeScript>();
    script->call_outputs = {{"n", 2, oracle_scanner::BindDirection::BIND_OUT, oracle_scanner::EncodeOracleNumber("7"), 22},
                            {"t", 1, oracle_scanner::BindDirection::BIND_OUT, Text("seven"), 32}};

    auto factory = InstallFake(script);
    TestDatabase database;
    auto result = database.Query("SELECT * FROM oracle_call_named('ora', 'app.compute', ["
                                 "{name: 'i', direction: 'in', type: 'number', value: '3'},"
                                 "{name: 'n', direction: 'out', type: 'number', value: NULL},"
                                 "{name: 't', direction: 'out', type: 'varchar', value: NULL}])");
    CHECK(!result->HasError());
    CHECK(result->RowCount() == 2);
    CHECK(result->GetValue(0, 0).ToString() == "n" && result->GetValue(1, 0).ToString() == "7");
    CHECK(result->GetValue(0, 1).ToString() == "t" && result->GetValue(1, 1).ToString() == "seven");

    CHECK(script->calls.size() == 1);
    const auto &request = script->calls[0];
    CHECK(request.kind == oracle_scanner::OracleCallableKind::PROCEDURE);
    CHECK(request.qualified_name == "app.compute");
    CHECK(request.arguments.size() == 3);
    CHECK(request.arguments[0].direction == oracle_scanner::BindDirection::BIND_IN);
    CHECK(request.arguments[1].direction == oracle_scanner::BindDirection::BIND_OUT);
    CHECK(request.arguments[1].oracle_type == 2 && request.arguments[2].oracle_type == 1);
}

// A REF CURSOR result becomes a connection-local handle that oracle_cursor
// consumes exactly once.
void TestCursorHandlesAreConsumedOnce() {
    auto script = std::make_shared<FakeScript>();
    script->columns = {Column("label", 1)};
    script->rows = {{Text("from cursor")}};
    script->call_explicit_cursors = 1;

    auto factory = InstallFake(script);
    TestDatabase database;
    auto handles = database.Query("SELECT * FROM oracle_call_cursors('ora', 'app.open_one', ['c'])");
    CHECK(!handles->HasError());
    CHECK(handles->RowCount() == 1);
    const auto handle = handles->GetValue(0, 0).ToString();
    CHECK(handle.rfind("oracle:", 0) == 0);

    auto rows = database.Query("SELECT * FROM oracle_cursor('" + handle + "')");
    CHECK(!rows->HasError());
    CHECK(rows->RowCount() == 1 && rows->GetValue(0, 0).ToString() == "from cursor");

    // The handle is spent: a second read of the same one is refused rather than
    // silently reopening or reusing a closed cursor.
    auto again = database.Query("SELECT * FROM oracle_cursor('" + handle + "')");
    CHECK(again->HasError());
}

// The scan owns its session: once the query result is gone the session is gone
// too, and the cursor was closed while its session was still alive.
void TestScanReleasesItsSession() {
    auto script = std::make_shared<FakeScript>();
    script->columns = {Column("label", 1)};
    script->rows = {{Text("only")}};

    {
        auto factory = InstallFake(script);
        TestDatabase database;
        auto result = database.Query("SELECT * FROM oracle_query('ora', 'SELECT label FROM app.items')");
        CHECK(!result->HasError());
        CHECK(script->sessions_opened == 1);
    }
    CHECK(script->sessions_destroyed == 1);
}

} // namespace

// The write path encodes by the Oracle column type, never by the DuckDB type
// alone, so no value reaches Oracle as text for it to convert under a session
// NLS setting. These run with no session at all: the conversion is pure.
void TestWriteBindsFollowTheOracleColumnType() {
    const auto bind_for = [](const OracleColumn &column, const duckdb::Value &value) {
        return duckdb::OracleBindForColumn(value, column, "1");
    };
    // A shape this version does not support and a value that cannot be this
    // Oracle type are different answers, and the tests keep them apart.
    const auto unsupported = [&](const OracleColumn &column, const duckdb::Value &value, const std::string &fragment) {
        try {
            bind_for(column, value);
        } catch (const duckdb::NotImplementedException &error) {
            CHECK(std::string(error.what()).find(fragment) != std::string::npos);
            return;
        }
        CHECK(false && "expected the bind to be refused as unsupported");
    };
    const auto unconvertible = [&](const OracleColumn &column, const duckdb::Value &value,
                                   const std::string &fragment) {
        try {
            bind_for(column, value);
        } catch (const duckdb::ConversionException &error) {
            CHECK(std::string(error.what()).find(fragment) != std::string::npos);
            return;
        }
        CHECK(false && "expected the value to be refused as unconvertible");
    };

    // An exact NUMBER goes through decimal text, so the wire value is the one
    // the codec produces and never a rounded binary float.
    const auto number_column = Column("AMOUNT", 2, 12, 2);
    const auto number_bind = bind_for(number_column, duckdb::Value::DECIMAL(int64_t(1234), 12, 2));
    CHECK(number_bind.oracle_type == 2);
    CHECK(number_bind.value == oracle_scanner::EncodeOracleNumber("12.34"));
    // Decimal text round-trips through the same encoder, which is what reading
    // an unconstrained NUMBER and writing it back does.
    CHECK(bind_for(number_column, duckdb::Value("12.34")).value == number_bind.value);
    unsupported(number_column, duckdb::Value::DOUBLE(1.5), "not exact");
    unconvertible(number_column, duckdb::Value("twelve"), "invalid character in Oracle NUMBER text");

    // Oracle stores an empty string as NULL and this client reads one back as
    // NULL, so binding it says the same thing rather than leaving it to the
    // server to substitute.
    const auto text_column = Column("LABEL", 1);
    CHECK(bind_for(text_column, duckdb::Value("beta")).value ==
           std::vector<uint8_t>({'b', 'e', 't', 'a'}));
    CHECK(!bind_for(text_column, duckdb::Value("")).value.has_value());
    CHECK(!bind_for(text_column, duckdb::Value(duckdb::LogicalType::VARCHAR)).value.has_value());
    unsupported(text_column, duckdb::Value::BIGINT(1), "character column");

    // A date read as text is parsed back by DuckDB's ISO parser, and the
    // sub-microsecond digits Oracle keeps survive the round trip.
    const auto date_column = Column("WHEN_DATE", 12);
    oracle_scanner::OracleDateTime expected_date;
    expected_date.year = 2024;
    expected_date.month = 3;
    expected_date.day = 5;
    CHECK(bind_for(date_column, duckdb::Value("2024-03-05")).value ==
           oracle_scanner::EncodeOracleDate(expected_date));
    unconvertible(date_column, duckdb::Value("the fifth of March"), "not an ISO date");

    const auto timestamp_column = Column("WHEN_TS", 180);
    oracle_scanner::OracleDateTime expected_timestamp;
    expected_timestamp.year = 2024;
    expected_timestamp.month = 3;
    expected_timestamp.day = 5;
    expected_timestamp.hour = 6;
    expected_timestamp.minute = 7;
    expected_timestamp.second = 8;
    expected_timestamp.nanosecond = 123456789;
    CHECK(bind_for(timestamp_column, duckdb::Value("2024-03-05 06:07:08.123456789")).value ==
           oracle_scanner::EncodeOracleTimestamp(expected_timestamp, false));
    // The type a TIMESTAMP(7..9) column reads back as, so a row copied out and
    // written back keeps every digit it started with.
    CHECK(bind_for(timestamp_column, duckdb::Value::TIMESTAMPNS(duckdb::timestamp_ns_t(1709618828123456789LL)))
               .value == oracle_scanner::EncodeOracleTimestamp(expected_timestamp, false));

    // A column this client cannot read is one it cannot reason about writing.
    auto national = Column("N_LABEL", 1);
    national.character_set_form = 2;
    // A national column is written as UTF-16BE behind the national form.
    national.character_set_form = 2;
    const auto national_bind = bind_for(national, duckdb::Value("h\xC3\xA9\xF0\x9F\x98\x80"));
    CHECK(national_bind.oracle_type == 1 && national_bind.character_set_form == 2);
    CHECK(national_bind.value == std::vector<uint8_t>({0x00, 0x68, 0x00, 0xE9, 0xD8, 0x3D, 0xDE, 0x00}));
    CHECK(!bind_for(national, duckdb::Value("")).value.has_value());
    auto national_fixed_column = Column("N_FIXED", 96);
    national_fixed_column.character_set_form = 2;
    CHECK(bind_for(national_fixed_column, duckdb::Value("ab")).character_set_form == 2);
    CHECK(bind_for(text_column, duckdb::Value("ab")).character_set_form == 0);
    unsupported(national, duckdb::Value::BIGINT(1), "character column");
    // A NULL row describes its column exactly as a row with a value does, which
    // a batch needs because its bind metadata is declared once.
    CHECK(bind_for(national, duckdb::Value(duckdb::LogicalType::VARCHAR)).character_set_form == 2);
    CHECK(bind_for(Column("SEEN_AT", 231), duckdb::Value(duckdb::LogicalType::TIMESTAMP_TZ)).oracle_type == 180);

    // LOBs: the content as a VARCHAR2 or RAW bind, empty as NULL, and a limit.
    const auto clob = Column("DOC", 112);
    CHECK(bind_for(clob, duckdb::Value("text")).oracle_type == 1);
    CHECK(bind_for(clob, duckdb::Value("text")).value == std::vector<uint8_t>({'t', 'e', 'x', 't'}));
    CHECK(!bind_for(clob, duckdb::Value("")).value.has_value() && bind_for(clob, duckdb::Value("")).oracle_type == 1);
    auto nclob = Column("NDOC", 112);
    nclob.character_set_form = 2;
    CHECK(bind_for(nclob, duckdb::Value("h\xC3\xA9")).character_set_form == 0);
    const auto blob = Column("IMG", 113);
    CHECK(bind_for(blob, duckdb::Value::BLOB("\x01\x02")).oracle_type == 23);
    CHECK(bind_for(blob, duckdb::Value(duckdb::LogicalType::BLOB)).oracle_type == 23);
    unsupported(clob, duckdb::Value::BIGINT(1), "takes VARCHAR");
    unsupported(blob, duckdb::Value("text"), "takes BLOB");
    // A LOB bind says it stands for LOB content, in every row including a NULL
    // one, so the session can send a large value through a temporary LOB and
    // keep an array DML's bind metadata the same for all rows.
    CHECK(bind_for(clob, duckdb::Value("text")).lob_content == 112);
    CHECK(bind_for(clob, duckdb::Value(duckdb::LogicalType::VARCHAR)).lob_content == 112);
    CHECK(bind_for(clob, duckdb::Value("")).lob_content == 112);
    CHECK(bind_for(blob, duckdb::Value::BLOB("\x01")).lob_content == 113);
    CHECK(bind_for(Column("J", 119), duckdb::Value("{}")).lob_content == 112);
    CHECK(bind_for(Column("N", 1), duckdb::Value("x")).lob_content == 0);
    // Past the old 16 MiB limit, which the temporary LOB lifted.
    CHECK(bind_for(clob, duckdb::Value(std::string((16U << 20U) + 1, 'x'))).value->size() == (16U << 20U) + 1);

    // BOOLEAN is the two bytes python-oracledb sends.
    const auto boolean_column = Column("FLAG", 252);
    CHECK(bind_for(boolean_column, duckdb::Value::BOOLEAN(true)).value == std::vector<uint8_t>({1, 1}));
    CHECK(bind_for(boolean_column, duckdb::Value::BOOLEAN(false)).value == std::vector<uint8_t>({1, 0}));
    CHECK(bind_for(boolean_column, duckdb::Value::BOOLEAN(true)).oracle_type == 252);
    CHECK(!bind_for(boolean_column, duckdb::Value(duckdb::LogicalType::BOOLEAN)).value.has_value());
    unsupported(boolean_column, duckdb::Value::BIGINT(1), "takes BOOLEAN");

    // A local-zone column takes a TIMESTAMPTZ, which goes to Oracle as the
    // TIMESTAMP of its UTC wall time because the session zone is UTC.
    auto local_zone = Column("SEEN_AT", 231);
    local_zone.scale = 6;
    oracle_scanner::OracleDateTime utc_moment;
    utc_moment.year = 2026;
    utc_moment.month = 3;
    utc_moment.day = 4;
    utc_moment.hour = 5;
    utc_moment.minute = 6;
    utc_moment.second = 7;
    utc_moment.nanosecond = 123456000;
    const auto local_zone_bind = bind_for(
        local_zone, duckdb::Value::TIMESTAMPTZ(duckdb::timestamp_tz_t(1772600767123456LL)));
    CHECK(local_zone_bind.oracle_type == 180);
    CHECK(local_zone_bind.value == oracle_scanner::EncodeOracleTimestamp(utc_moment, false));
    unsupported(local_zone, duckdb::Value("2026-03-04 05:06:07"), "takes TIMESTAMPTZ");

    // Intervals: whole months for YEAR TO MONTH, days and time for DAY TO SECOND.
    const auto year_month = Column("SPAN", 182);
    CHECK(bind_for(year_month, duckdb::Value::INTERVAL(27, 0, 0)).value == oracle_scanner::EncodeOracleIntervalYearMonth(2, 3));
    CHECK(bind_for(year_month, duckdb::Value::INTERVAL(-71, 0, 0)).value ==
          oracle_scanner::EncodeOracleIntervalYearMonth(-5, -11));
    unconvertible(year_month, duckdb::Value::INTERVAL(1, 1, 0), "whole months");
    unsupported(year_month, duckdb::Value("1-2"), "takes INTERVAL");
    const auto day_second = Column("ELAPSED", 183);
    CHECK(bind_for(day_second, duckdb::Value::INTERVAL(0, 3, 4 * 3600000000LL + 5 * 60000000LL + 6000007LL)).value ==
          oracle_scanner::EncodeOracleIntervalDaySecond(3, 4, 5, 6, 7000));
    // Whole days in the time part move to the day count; a negative span keeps one sign.
    CHECK(bind_for(day_second, duckdb::Value::INTERVAL(0, 1, 25 * 3600000000LL)).value ==
          oracle_scanner::EncodeOracleIntervalDaySecond(2, 1, 0, 0, 0));
    CHECK(bind_for(day_second, duckdb::Value::INTERVAL(0, -2, -3600000000LL)).value ==
          oracle_scanner::EncodeOracleIntervalDaySecond(-2, -1, 0, 0, 0));
    CHECK(bind_for(day_second, duckdb::Value::INTERVAL(0, 0, -500000LL)).value ==
          oracle_scanner::EncodeOracleIntervalDaySecond(0, 0, 0, 0, -500000000));
    unconvertible(day_second, duckdb::Value::INTERVAL(0, 1, -1000000LL), "opposite signs");
    unconvertible(day_second, duckdb::Value::INTERVAL(1, 0, 0), "cannot hold months");
    unsupported(Column("WHEN_TZ", 181), duckdb::Value("2024-03-05 06:07:08+02:00"), "TIMESTAMP WITH TIME ZONE");

    std::cout << "write binds follow the Oracle column type" << std::endl;
}

// Resolving a callable's signature from ALL_ARGUMENTS, driven entirely by
// scripted dictionary rows: no database, no network. The support policy is the
// interesting half — an argument this client cannot bind has to be named as
// unsupported with the reason rather than mapped to whatever is closest.
void TestCallableSignatureResolution() {
    const auto argument_row = [](const std::string &package, const std::string &object, const std::string &overload,
                                 const std::string &position, const std::string &name, const std::string &type,
                                 const std::string &in_out, const std::string &level) {
        WireRow row;
        row.push_back(Text("APP"));
        row.push_back(package.empty() ? WireValue() : Text(package));
        row.push_back(Text(object));
        row.push_back(overload.empty() ? WireValue() : Text(overload));
        row.push_back(Number(position));
        row.push_back(name.empty() ? WireValue() : Text(name));
        row.push_back(Text(type));
        row.push_back(Text(in_out));
        row.push_back(Number(level));
        return row;
    };
    auto script = std::make_shared<FakeScript>();
    script->columns = {Column("OWNER", 1),        Column("PACKAGE_NAME", 1), Column("OBJECT_NAME", 1),
                       Column("OVERLOAD", 1),     Column("POSITION", 2),     Column("ARGUMENT_NAME", 1),
                       Column("DATA_TYPE", 1),    Column("IN_OUT", 1),       Column("DATA_LEVEL", 2)};
    script->rows = {
        argument_row("PKG", "MIXED", "", "1", "P_IN", "NUMBER", "IN", "0"),
        argument_row("PKG", "MIXED", "", "2", "P_BOTH", "VARCHAR2", "IN/OUT", "0"),
        argument_row("PKG", "MIXED", "", "3", "P_ROWS", "REF CURSOR", "OUT", "0"),
        argument_row("PKG", "MIXED", "", "4", "P_DOC", "CLOB", "IN", "0"),
        argument_row("PKG", "MIXED", "", "5", "P_ITEMS", "TABLE", "IN", "0"),
        // A collection contributes its element as a row one level down. It is
        // not an argument, and counting it as one would shift every position
        // after it.
        argument_row("PKG", "MIXED", "", "5", "", "NUMBER", "IN", "1"),
    };
    FakeSession session(script);
    const auto resolved = duckdb::ResolveOracleCallables(session, "pkg.mixed");
    CHECK(resolved.size() == 1);
    const auto &signature = resolved[0];
    CHECK(signature.owner == "APP" && signature.package == "PKG" && signature.object == "MIXED");
    CHECK(!signature.is_function);
    CHECK(signature.arguments.size() == 5);

    // The dictionary is queried by the stored, upper-case form of the name.
    CHECK(script->queries.size() == 1);
    CHECK(script->query_binds.size() == 1 && script->query_binds[0].size() == 4);
    const auto first_bind = script->query_binds[0][0].value;
    CHECK(first_bind.has_value() && std::string(first_bind->begin(), first_bind->end()) == "PKG");

    CHECK(signature.arguments[0].name == "P_IN" && signature.arguments[0].bind_type_name == "number" &&
           signature.arguments[0].direction == oracle_scanner::BindDirection::BIND_IN);
    CHECK(signature.arguments[1].direction == oracle_scanner::BindDirection::BIND_IN_OUT &&
           signature.arguments[1].bind_type_name == "varchar");
    CHECK(signature.arguments[2].direction == oracle_scanner::BindDirection::BIND_OUT &&
           signature.arguments[2].bind_type_name == "cursor");
    CHECK(signature.arguments[3].bind_type_name.empty() &&
           signature.arguments[3].unsupported_reason.find("LOB") != std::string::npos);
    CHECK(signature.arguments[4].bind_type_name.empty() &&
           signature.arguments[4].unsupported_reason.find("collection") != std::string::npos);
    CHECK(signature.arguments[4].position == 5);

    // Position zero is a function's return value: always OUT, and named so it
    // can be bound like any other.
    auto function_script = std::make_shared<FakeScript>();
    function_script->columns = script->columns;
    function_script->rows = {argument_row("PKG", "DOUBLED", "", "0", "", "NUMBER", "OUT", "0"),
                             argument_row("PKG", "DOUBLED", "", "1", "P_IN", "NUMBER", "IN", "0")};
    FakeSession function_session(function_script);
    const auto function_resolved = duckdb::ResolveOracleCallables(function_session, "pkg.doubled");
    CHECK(function_resolved.size() == 1);
    const auto &function_signature = function_resolved[0];
    CHECK(function_signature.is_function);
    CHECK(function_signature.arguments[0].position == 0 && function_signature.arguments[0].name == "return_value" &&
           function_signature.arguments[0].direction == oracle_scanner::BindDirection::BIND_OUT);

    // Overloads all come back: which one the caller means is decided by how
    // many values they pass, and refusing outright would leave them no way to
    // say. Here one takes a single argument and the other takes two.
    auto overloaded_script = std::make_shared<FakeScript>();
    overloaded_script->columns = script->columns;
    overloaded_script->rows = {argument_row("PKG", "EITHER", "1", "1", "P_A", "NUMBER", "IN", "0"),
                               argument_row("PKG", "EITHER", "2", "1", "P_A", "NUMBER", "IN", "0"),
                               argument_row("PKG", "EITHER", "2", "2", "P_B", "VARCHAR2", "IN", "0")};
    FakeSession overloaded_session(overloaded_script);
    const auto overloads = duckdb::ResolveOracleCallables(overloaded_session, "pkg.either");
    CHECK(overloads.size() == 2);
    CHECK(overloads[0].overload == "1" && overloads[0].InputCount() == 1);
    CHECK(overloads[1].overload == "2" && overloads[1].InputCount() == 2);
    CHECK(&duckdb::SelectOracleCallableOverload(overloads, 2, "pkg.either") == &overloads[1]);
    bool arity_refused = false;
    try {
        duckdb::SelectOracleCallableOverload(overloads, 3, "pkg.either");
    } catch (const duckdb::BinderException &error) {
        // The message names what the callable does take, which is the only way
        // the caller can correct the call.
        arity_refused = std::string(error.what()).find("takes 1, 2 arguments, not 3") != std::string::npos;
    }
    CHECK(arity_refused);

    // Two overloads of the same arity differ only in their argument types, and
    // nothing in a list of values says which was meant.
    auto ambiguous_script = std::make_shared<FakeScript>();
    ambiguous_script->columns = script->columns;
    ambiguous_script->rows = {argument_row("PKG", "EITHER", "1", "1", "P_A", "NUMBER", "IN", "0"),
                              argument_row("PKG", "EITHER", "2", "1", "P_A", "VARCHAR2", "IN", "0")};
    FakeSession ambiguous_session(ambiguous_script);
    const auto ambiguous = duckdb::ResolveOracleCallables(ambiguous_session, "pkg.either");
    bool ambiguity_refused = false;
    try {
        duckdb::SelectOracleCallableOverload(ambiguous, 1, "pkg.either");
    } catch (const duckdb::BinderException &error) {
        ambiguity_refused = std::string(error.what()).find("more than one overload") != std::string::npos;
    }
    CHECK(ambiguity_refused);

    // Nothing in the dictionary and nothing behind a synonym either.
    auto empty_script = std::make_shared<FakeScript>();
    empty_script->columns = script->columns;
    FakeSession empty_session(empty_script);
    bool missing_refused = false;
    try {
        duckdb::ResolveOracleCallables(empty_session, "nowhere");
    } catch (const duckdb::BinderException &error) {
        missing_refused = std::string(error.what()).find("was not found") != std::string::npos;
    }
    CHECK(missing_refused);
    // The synonym lookup is the second query, and only because the first found
    // nothing.
    CHECK(empty_script->queries.size() == 2);

    std::cout << "callable signatures resolve from the dictionary" << std::endl;
}

// The signature-driven call: the caller supplies values, and the directions,
// types and buffer sizes come from the dictionary. What matters is that the
// binds it builds are the same binds a hand-written oracle_call_named would
// have produced, so this asserts on the request the session actually received.
void TestAutomaticCallBindsFromTheSignature() {
    const auto argument_row = [](const std::string &position, const std::string &name, const std::string &type,
                                 const std::string &in_out) {
        WireRow row;
        row.push_back(Text("APP"));
        row.push_back(Text("PKG"));
        row.push_back(Text("MIXED"));
        row.push_back(WireValue());
        row.push_back(Number(position));
        row.push_back(Text(name));
        row.push_back(Text(type));
        row.push_back(Text(in_out));
        row.push_back(Number("0"));
        return row;
    };
    auto script = std::make_shared<FakeScript>();
    script->columns = {Column("OWNER", 1),     Column("PACKAGE_NAME", 1), Column("OBJECT_NAME", 1),
                       Column("OVERLOAD", 1),  Column("POSITION", 2),     Column("ARGUMENT_NAME", 1),
                       Column("DATA_TYPE", 1), Column("IN_OUT", 1),       Column("DATA_LEVEL", 2)};
    script->rows = {argument_row("1", "P_IN", "NUMBER", "IN"), argument_row("2", "P_OUT", "NUMBER", "OUT"),
                    argument_row("3", "P_BOTH", "VARCHAR2", "IN/OUT")};
    script->call_outputs = {{"P_OUT", 2, oracle_scanner::BindDirection::BIND_OUT, Number("70")},
                            {"P_BOTH", 1, oracle_scanner::BindDirection::BIND_IN_OUT, Text("head/tail")}};

    auto factory = InstallFake(script);
    TestDatabase database;
    auto result = database.Query("SELECT * FROM oracle_call_auto('ora', 'pkg.mixed', ['7', NULL, 'head']);");
    CHECK(!result->HasError());

    // The call went to the name the dictionary matched, every component quoted,
    // rather than to whatever the caller happened to type.
    CHECK(script->calls.size() == 1);
    const auto &request = script->calls[0];
    CHECK(request.qualified_name == "\"APP\".\"PKG\".\"MIXED\"");
    CHECK(request.kind == oracle_scanner::OracleCallableKind::PROCEDURE);
    CHECK(!request.return_bind.has_value());
    CHECK(request.arguments.size() == 3);
    CHECK(request.arguments[0].name == "P_IN" && request.arguments[0].oracle_type == 2 &&
           request.arguments[0].direction == oracle_scanner::BindDirection::BIND_IN &&
           request.arguments[0].value == oracle_scanner::EncodeOracleNumber("7"));
    // An OUT bind carries no value but must declare the buffer Oracle writes
    // into; taking that from the dictionary is the whole point of this path.
    CHECK(request.arguments[1].name == "P_OUT" && request.arguments[1].direction == oracle_scanner::BindDirection::BIND_OUT &&
           !request.arguments[1].value.has_value() && request.arguments[1].maximum_bytes == 22);
    CHECK(request.arguments[2].direction == oracle_scanner::BindDirection::BIND_IN_OUT &&
           request.arguments[2].oracle_type == 1 &&
           request.arguments[2].value == std::vector<uint8_t>({'h', 'e', 'a', 'd'}));

    // Only the arguments that come back are rows, in declaration order.
    CHECK(result->RowCount() == 2);
    CHECK(result->GetValue(0, 0).ToString() == "P_OUT" && result->GetValue(1, 0).ToString() == "70");
    CHECK(result->GetValue(0, 1).ToString() == "P_BOTH" && result->GetValue(1, 1).ToString() == "head/tail");

    // A value count that does not match the signature is caught before any call.
    auto wrong_arity = database.Query("SELECT * FROM oracle_call_auto('ora', 'pkg.mixed', ['7']);");
    CHECK(wrong_arity->HasError());
    // The message names the arities the callable does take, which is what a
    // caller needs to correct the call — and with overloads there may be
    // several.
    CHECK(wrong_arity->GetError().find("takes 3 arguments, not 1") != std::string::npos);
    CHECK(script->calls.size() == 1);

    std::cout << "automatic calls bind from the resolved signature" << std::endl;
}

// Opening a session costs a TCP connect, a TLS handshake and an authentication
// round trip, so a statement that can reuse one should. The fake counts them,
// which is the only thing that distinguishes a pool that works from one that
// quietly opens a session every time anyway.
void TestReadSessionsArePooledPerConnection() {
    auto script = std::make_shared<FakeScript>();
    script->columns = {Column("label", 1)};
    script->rows = {{Text("only")}};

    {
        auto factory = InstallFake(script);
        TestDatabase database;
        database.Run("SET oracle_session_pool_size = 0;");
        for (int index = 0; index < 3; index++) {
            CHECK(!database.Query("SELECT * FROM oracle_query('ora', 'SELECT label FROM app.items')")->HasError());
        }
        CHECK(script->sessions_opened == 3);

        script->sessions_opened = 0;
        database.Run("SET oracle_session_pool_size = 2;");
        for (int index = 0; index < 3; index++) {
            CHECK(!database.Query("SELECT * FROM oracle_query('ora', 'SELECT label FROM app.items')")->HasError());
        }
        CHECK(script->sessions_opened == 1);

        // A statement that failed leaves the channel in a state this side
        // cannot describe, so its session is not the one the next statement
        // gets. The fake fails at fetch, after the session is already in hand.
        script->sessions_opened = 0;
        script->fetch_failure = oracle_scanner::ProtocolErrorKind::TRUNCATED;
        script->fetch_failure_message = "connection closed mid-row";
        CHECK(database.Query("SELECT * FROM oracle_query('ora', 'SELECT label FROM app.items')")->HasError());
        script->fetch_failure.reset();
        CHECK(!database.Query("SELECT * FROM oracle_query('ora', 'SELECT label FROM app.items')")->HasError());
        // The failing statement reuses the one idle session and poisons it, so
        // the statement after it finds the pool empty and opens one. Without
        // poisoning the failed session would go back and this would be zero,
        // which is what makes the number the check.
        CHECK(script->sessions_opened == 1);
    }

    std::cout << "read sessions are pooled per connection" << std::endl;
}

// The attached catalog, end to end, with no database. Every path here —
// enumeration, one-name lookup, the whole-schema dictionary read, constraints,
// projection pushdown and filter pushdown — was verified only against a live
// Oracle until now, which meant nothing caught a regression in them before a
// release.
void TestAttachedCatalogAgainstAFakeSession() {
    const auto text_columns = [](std::initializer_list<const char *> names) {
        std::vector<OracleColumn> result;
        for (const auto *name : names) {
            result.push_back(Column(name, 1));
        }
        return result;
    };
    auto script = std::make_shared<FakeScript>();
    script->routes.push_back({"SELECT USER FROM DUAL", {text_columns({"USER"}), {{Text("APP")}}}});
    script->routes.push_back({"FROM user_tables", {text_columns({"TABLE_NAME"}), {{Text("ITEMS")}}}});
    script->routes.push_back({"FROM user_views", {text_columns({"VIEW_NAME"}), {{Text("ITEM_VIEW")}}}});
    // table_name, column_name, data_type, data_length, data_precision, data_scale, nullable
    script->routes.push_back(
        {"FROM user_tab_columns",
         {{Column("TABLE_NAME", 1), Column("COLUMN_NAME", 1), Column("DATA_TYPE", 1), Column("DATA_LENGTH", 2),
           Column("DATA_PRECISION", 2), Column("DATA_SCALE", 2), Column("NULLABLE", 1)},
          {{Text("ITEMS"), Text("ID"), Text("NUMBER"), Number("22"), Number("10"), Number("0"), Text("N")},
           {Text("ITEMS"), Text("LABEL"), Text("VARCHAR2"), Number("20"), WireValue(), WireValue(), Text("Y")},
           {Text("ITEM_VIEW"), Text("ID"), Text("NUMBER"), Number("22"), Number("10"), Number("0"), Text("Y")}}}});
    script->routes.push_back({"FROM user_constraints",
                              {text_columns({"TABLE_NAME", "COLUMN_NAME"}), {{Text("ITEMS"), Text("ID")}}}});
    // The scan itself. Its describe has to agree with the dictionary, because
    // the adapter checks that the names line up before it reads a value.
    // Ordered most specific first: a projected scan selects fewer columns and
    // its describe has to match that select list, not the whole table.
    script->routes.push_back({"SELECT \"LABEL\" FROM", {{Column("LABEL", 1)}, {{Text("first")}, {Text("second")}}}});
    script->routes.push_back({"FROM \"ITEMS\"",
                              {{Column("ID", 2, 10, 0), Column("LABEL", 1)},
                               {{Number("1"), Text("first")}, {Number("2"), Text("second")}}}});

    auto factory = InstallFake(script);
    TestDatabase database;
    database.Run("ATTACH 'ora' AS ora (TYPE oracle_scanner);");

    // Enumeration: both tables and views, from the two dictionary queries.
    auto listed = database.Query("SELECT table_name FROM duckdb_tables() WHERE database_name = 'ora' ORDER BY 1;");
    CHECK(!listed->HasError() && listed->RowCount() == 2);
    CHECK(listed->GetValue(0, 0).ToString() == "ITEMS");
    CHECK(listed->GetValue(0, 1).ToString() == "ITEM_VIEW");

    // The dictionary decides the DuckDB types: an integral NUMBER(10) widens to
    // BIGINT, a VARCHAR2 stays text.
    auto scanned = database.Query("SELECT ID, LABEL FROM ora.main.ITEMS ORDER BY ID;");
    CHECK(!scanned->HasError() && scanned->RowCount() == 2);
    CHECK(scanned->GetTypes()[0] == duckdb::LogicalType::BIGINT && scanned->GetTypes()[1] == duckdb::LogicalType::VARCHAR);
    CHECK(scanned->GetValue(0, 0).ToString() == "1" && scanned->GetValue(1, 1).ToString() == "second");

    // NOT NULL and the primary key both come from the dictionary.
    auto constraints = database.Query(
        "SELECT constraint_type FROM duckdb_constraints() WHERE table_name = 'ITEMS' ORDER BY constraint_type;");
    CHECK(!constraints->HasError() && constraints->RowCount() == 2);
    CHECK(constraints->GetValue(0, 0).ToString() == "NOT NULL");
    CHECK(constraints->GetValue(0, 1).ToString() == "PRIMARY KEY");

    // Projection pushdown: the statement Oracle receives selects only what the
    // query reads. Without it the scan would fetch every column and drop most.
    const auto sent_before = script->queries.size();
    auto projected = database.Query("SELECT LABEL FROM ora.main.ITEMS;");
    CHECK(!projected->HasError() && projected->RowCount() == 2);
    CHECK(script->queries.size() > sent_before);
    const auto projection_sql = script->queries.back();
    CHECK(projection_sql.find("SELECT \"LABEL\" FROM \"ITEMS\"") == 0);
    CHECK(projection_sql.find("\"ID\"") == std::string::npos);

    // Filter pushdown is on by default; switched off, nothing reaches Oracle.
    database.Run("SET oracle_filter_pushdown = false;");
    auto unpushed = database.Query("SELECT LABEL FROM ora.main.ITEMS WHERE ID = 1;");
    CHECK(!unpushed->HasError());
    CHECK(script->queries.back().find("WHERE") == std::string::npos);

    database.Run("SET oracle_filter_pushdown = true;");
    auto pushed = database.Query("SELECT LABEL FROM ora.main.ITEMS WHERE ID = 1;");
    CHECK(!pushed->HasError());
    CHECK(script->queries.back().find("WHERE \"ID\" = 1") != std::string::npos);

    std::cout << "the attached catalog runs against a fake session" << std::endl;
}

// Writing through an attached table, with no database: the statements the
// adapter builds, the binds it sends, and the session it sends them on. Until
// the fake could answer a projection of a scripted table, none of this could be
// reached without a live Oracle.
// INSERT reads the common column types straight from DuckDB's vectors instead
// of one Value at a time. Each bind it sends must be the one OracleBindForColumn
// makes from the same value, which stays the statement of the conversion rules.
void TestInsertBindsMatchTheValuePath() {
    const auto text_columns = [](std::initializer_list<const char *> names) {
        std::vector<OracleColumn> result;
        for (const auto *name : names) {
            result.push_back(Column(name, 1));
        }
        return result;
    };
    auto script = std::make_shared<FakeScript>();
    script->routes.push_back({"SELECT USER FROM DUAL", {text_columns({"USER"}), {{Text("APP")}}}});
    script->routes.push_back({"FROM user_tables", {text_columns({"TABLE_NAME"}), {{Text("T")}}}});
    script->routes.push_back({"FROM user_views", {text_columns({"VIEW_NAME"}), {}}});
    const auto row = [](const char *name, const char *type, const char *precision, const char *scale) {
        return std::vector<WireValue>{Text("T"),   Text(name), Text(type), Number("22"),
                                       precision ? Number(precision) : WireValue(),
                                       scale ? Number(scale) : WireValue(), Text("Y")};
    };
    script->routes.push_back(
        {"FROM user_tab_columns",
         {{Column("TABLE_NAME", 1), Column("COLUMN_NAME", 1), Column("DATA_TYPE", 1), Column("DATA_LENGTH", 2),
           Column("DATA_PRECISION", 2), Column("DATA_SCALE", 2), Column("NULLABLE", 1)},
          {row("N", "NUMBER", "18", "0"), row("D", "NUMBER", "15", "2"), row("W", "NUMBER", "38", "10"),
           row("S", "VARCHAR2", nullptr, nullptr), row("C", "CHAR", nullptr, nullptr),
           row("DT", "DATE", nullptr, nullptr),
           row("TS", "TIMESTAMP(6)", nullptr, "6"), row("BD", "BINARY_DOUBLE", nullptr, nullptr),
           row("BF", "BINARY_FLOAT", nullptr, nullptr), row("FLAG", "BOOLEAN", nullptr, nullptr)}}});
    script->routes.push_back({"FROM user_constraints", {text_columns({"TABLE_NAME", "COLUMN_NAME"}), {}}});
    const std::vector<OracleColumn> columns = {Column("N", 2, 18, 0), Column("D", 2, 15, 2), Column("W", 2, 38, 10),
                                               Column("S", 1),         Column("C", 96),        Column("DT", 12),
                                               Column("TS", 180, 0, 6), Column("BD", 101),     Column("BF", 100),
                                               Column("FLAG", 252)};
    script->tables["T"] = {columns, {}};
    script->affected_rows = 3;
    auto factory = InstallFake(script);
    TestDatabase database;
    database.Run("ATTACH 'ora' AS ora (TYPE oracle_scanner);");

    const std::string values =
        "(-999999999999999999, -9999999999999.99, 1234567890123456789012345678.0123456789, 'h\xC3\xA9', 'ab', "
        "TIMESTAMP '0001-01-01 00:00:00', TIMESTAMP '1969-12-31 23:59:59.999999', -1.5e300, 3.4e38, true), "
        "(0, 0.01, -0.0000000001, '', ' ', TIMESTAMP '9999-12-31 23:59:59', TIMESTAMP '2024-02-29 00:00:00.5', "
        "-0.0, -1.17e-38, false), "
        "(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)";
    database.Run("INSERT INTO ora.main.T VALUES " + values + ";");
    // The values as the attached table's own types, which is what the insert
    // casts them to before it binds them.
    auto typed = database.Query(
        "SELECT N::BIGINT, D::DECIMAL(15,2), W::DECIMAL(38,10), S::VARCHAR, C::VARCHAR, DT::TIMESTAMP, TS::TIMESTAMP, "
        "BD::DOUBLE, BF::FLOAT, FLAG::BOOLEAN FROM (VALUES " + values + ") v(N, D, W, S, C, DT, TS, BD, BF, FLAG)");
    CHECK(!typed->HasError());
    CHECK(script->batch_rows.size() == 3 && typed->RowCount() == 3);
    for (duckdb::idx_t row_index = 0; row_index < 3 && script->batch_rows.size() == 3; row_index++) {
        CHECK(script->batch_rows[row_index].size() == columns.size());
        for (duckdb::idx_t column_index = 0; column_index < columns.size(); column_index++) {
            const auto &actual = script->batch_rows[row_index][column_index];
            const auto wanted = duckdb::OracleBindForColumn(typed->GetValue(column_index, row_index),
                                                            columns[column_index], std::to_string(column_index + 1));
            CHECK(actual.name == wanted.name && actual.oracle_type == wanted.oracle_type &&
                  actual.character_set_form == wanted.character_set_form && actual.lob_content == wanted.lob_content &&
                  actual.direction == wanted.direction && actual.value == wanted.value);
        }
    }
}

// The dictionary names a column's type in words, and the attached catalog's
// write and filter paths work from that, not from the describe. Types it did
// not name used to arrive as "Oracle type 0 has no mapping". These now map, so
// a national column is bound as one, an interval and a BOOLEAN are written, and
// what still cannot be written is named for what it is.
void TestAttachedCatalogNamesTheNewTypes() {
    const auto text_columns = [](std::initializer_list<const char *> names) {
        std::vector<OracleColumn> result;
        for (const auto *name : names) {
            result.push_back(Column(name, 1));
        }
        return result;
    };
    auto script = std::make_shared<FakeScript>();
    script->routes.push_back({"SELECT USER FROM DUAL", {text_columns({"USER"}), {{Text("APP")}}}});
    script->routes.push_back({"FROM user_tables", {text_columns({"TABLE_NAME"}), {{Text("T")}}}});
    script->routes.push_back({"FROM user_views", {text_columns({"VIEW_NAME"}), {}}});
    const auto row = [](const char *name, const char *type, const char *scale) {
        return std::vector<WireValue>{Text("T"), Text(name), Text(type), Number("22"), WireValue(),
                                       scale ? Number(scale) : WireValue(), Text("Y")};
    };
    script->routes.push_back(
        {"FROM user_tab_columns",
         {{Column("TABLE_NAME", 1), Column("COLUMN_NAME", 1), Column("DATA_TYPE", 1), Column("DATA_LENGTH", 2),
           Column("DATA_PRECISION", 2), Column("DATA_SCALE", 2), Column("NULLABLE", 1)},
          {row("NV", "NVARCHAR2", nullptr), row("NC", "NCHAR", nullptr), row("YM", "INTERVAL YEAR(2) TO MONTH", "0"),
           row("DS", "INTERVAL DAY(2) TO SECOND(6)", "6"), row("FLAG", "BOOLEAN", nullptr),
           row("SEEN", "TIMESTAMP(6) WITH LOCAL TIME ZONE", "6"), row("ADDR", "ROWID", nullptr),
           row("OLD", "LONG", nullptr), row("DOC", "CLOB", nullptr), row("NDOC", "NCLOB", nullptr),
           row("IMG", "BLOB", nullptr)}}});
    script->routes.push_back({"FROM user_constraints", {text_columns({"TABLE_NAME", "COLUMN_NAME"}), {}}});
    auto national = Column("NV", 1);
    national.character_set_form = 2;
    auto national_fixed = Column("NC", 96);
    national_fixed.character_set_form = 2;
    auto national_doc = Column("NDOC", 112);
    national_doc.character_set_form = 2;
    script->tables["T"] = {{national, national_fixed, Column("YM", 182), Column("DS", 183), Column("FLAG", 252),
                            Column("SEEN", 231), Column("ADDR", 11), Column("OLD", 8), Column("DOC", 112),
                            national_doc, Column("IMG", 113)},
                           {}};
    script->affected_rows = 1;
    auto factory = InstallFake(script);
    TestDatabase database;
    database.Run("ATTACH 'ora' AS ora (TYPE oracle_scanner);");

    auto described = database.Query("SELECT column_name, data_type FROM duckdb_columns() WHERE table_name = 'T' "
                                    "ORDER BY column_index");
    CHECK(!described->HasError());
    const std::vector<std::string> expected_types = {"VARCHAR", "VARCHAR", "INTERVAL", "INTERVAL",
                                                     "BOOLEAN", "TIMESTAMP WITH TIME ZONE", "VARCHAR", "VARCHAR",
                                                     "VARCHAR", "VARCHAR", "BLOB"};
    CHECK(described->RowCount() == expected_types.size());
    for (duckdb::idx_t index = 0; index < expected_types.size(); index++) {
        CHECK(described->GetValue(1, index).ToString() == expected_types[index]);
    }

    database.Run("INSERT INTO ora.main.T (NV, NC, YM, DS, FLAG, SEEN) VALUES ('h\xC3\xA9', 'ab', INTERVAL 14 MONTHS, "
                 "INTERVAL '2 days 03:04:05', true, TIMESTAMPTZ '2026-03-04 05:06:07+00');");
    CHECK(script->batch_rows.size() == 1 && script->batch_rows[0].size() == 6);
    const auto &binds = script->batch_rows[0];
    CHECK(binds[0].oracle_type == 1 && binds[0].character_set_form == 2);
    CHECK(binds[0].value == std::vector<uint8_t>({0x00, 0x68, 0x00, 0xE9}));
    CHECK(binds[1].oracle_type == 96 && binds[1].character_set_form == 2);
    CHECK(binds[2].oracle_type == 182 && binds[2].value == oracle_scanner::EncodeOracleIntervalYearMonth(1, 2));
    CHECK(binds[3].oracle_type == 183 && binds[3].value == oracle_scanner::EncodeOracleIntervalDaySecond(2, 3, 4, 5, 0));
    CHECK(binds[4].oracle_type == 252 && binds[4].value == std::vector<uint8_t>({1, 1}));
    CHECK(binds[5].oracle_type == 180);

    // A LOB is written as the ordinary bind of its content: VARCHAR2 for a CLOB
    // or NCLOB, RAW for a BLOB.
    database.Run("INSERT INTO ora.main.T (DOC, NDOC, IMG) VALUES ('doc', 'ndoc', '\\x01\\x02'::BLOB), (NULL, NULL, NULL), "
                 "('', '', ''::BLOB);");
    CHECK(script->batch_rows.size() == 3 && script->batch_rows[0].size() == 3);
    CHECK(script->batch_rows[0][0].oracle_type == 1 && script->batch_rows[0][0].character_set_form == 0 &&
          script->batch_rows[0][0].value == std::vector<uint8_t>({'d', 'o', 'c'}));
    CHECK(script->batch_rows[0][1].oracle_type == 1 && script->batch_rows[0][1].character_set_form == 0);
    CHECK(script->batch_rows[0][2].oracle_type == 23 && script->batch_rows[0][2].value == std::vector<uint8_t>({1, 2}));
    for (size_t row = 1; row < 3; row++) {
        CHECK(script->batch_rows[row][0].oracle_type == 1 && !script->batch_rows[row][0].value.has_value());
        CHECK(script->batch_rows[row][2].oracle_type == 23 && !script->batch_rows[row][2].value.has_value());
    }
    // RETURNING cannot carry a LOB, and says so.
    auto returning_lob = database.Query("INSERT INTO ora.main.T (DOC) VALUES ('x') RETURNING DOC;");
    CHECK(returning_lob->HasError() && returning_lob->GetError().find("cannot return the LOB, JSON or VECTOR column") != std::string::npos);

    // What cannot be written is refused by name, not as "type 0".
    auto refused = database.Query("INSERT INTO ora.main.T (OLD) VALUES ('x');");
    CHECK(refused->HasError() && refused->GetError().find("Oracle type 8 cannot be written") != std::string::npos);
    refused = database.Query("INSERT INTO ora.main.T (ADDR) VALUES ('AAAAAAAAAAAAAAAAAA');");
    CHECK(refused->HasError() && refused->GetError().find("Oracle type 11 cannot be written") != std::string::npos);
    std::cout << "the attached catalog names national, interval, boolean and local-zone columns" << std::endl;
}

// JSON and VECTOR through SQL, with no database: the DuckDB types a describe
// maps to, the values, the catalog that reads a VECTOR's shape from the
// dictionary, the text they are written as, and an INSERT whose columns the
// optimizer turns into constants. The images are built here from the layout
// oson.cpp and oracle_vector.cpp document and the live tests check against a
// server; the captured ones are in protocol_test.cpp.
std::vector<uint8_t> VectorImage(uint8_t format, uint32_t dimensions, const std::vector<uint8_t> &elements) {
    std::vector<uint8_t> image {0xDB, 0x00, 0x00, 0x12, format};
    for (int shift = 24; shift >= 0; shift -= 8) {
        image.push_back(static_cast<uint8_t>(dimensions >> shift));
    }
    image.insert(image.end(), 8, 0);
    image.insert(image.end(), elements.begin(), elements.end());
    return image;
}

std::vector<uint8_t> Float32Elements(const std::vector<float> &values) {
    std::vector<uint8_t> result;
    for (const auto value : values) {
        const auto sortable = oracle_scanner::EncodeOracleBinaryFloat(value);
        result.insert(result.end(), sortable.begin(), sortable.end());
    }
    return result;
}

std::vector<uint8_t> Utf8(const std::string &text) {
    return std::vector<uint8_t>(text.begin(), text.end());
}

void TestJsonAndVectorColumnsThroughSql() {
    // A scalar JSON document is the smallest image: header, tree size, then a
    // string node (its length in the type byte).
    std::vector<uint8_t> scalar_string {0xff, 0x4a, 0x5a, 0x01, 0x00, 0x16, 0x00, 0x07, 0x06};
    for (const auto character : std::string("scalar")) {
        scalar_string.push_back(static_cast<uint8_t>(character));
    }
    const std::vector<uint8_t> object_a_is_1 {0xff, 0x4a, 0x5a, 0x01, 0x21, 0x06, 0x01, 0x00, 0x02, 0x00, 0x08, 0x00, 0x00, 0x2c,
                                              0x00, 0x00, 0x01, 0x61, 0x84, 0x01, 0x01, 0x00, 0x05, 0x21, 0xc1, 0x02};

    // oracle_query: the describe carries the vector's shape.
    {
        auto script = std::make_shared<FakeScript>();
        auto json = Column("J", 119);
        auto fixed = Column("F", 127);
        fixed.vector_dimensions = 3;
        fixed.vector_format = oracle_scanner::ORACLE_VECTOR_FLOAT32;
        auto open_ended = Column("O", 127);
        open_ended.vector_flags = oracle_scanner::ORACLE_VECTOR_COLUMN_FLEXIBLE_DIMENSIONS;
        auto small = Column("S", 127);
        small.vector_dimensions = 4;
        small.vector_format = oracle_scanner::ORACLE_VECTOR_INT8;
        auto packed = Column("B", 127);
        packed.vector_dimensions = 16;
        packed.vector_format = oracle_scanner::ORACLE_VECTOR_BINARY;
        script->columns = {json, fixed, open_ended, small, packed};
        script->rows = {{object_a_is_1, VectorImage(oracle_scanner::ORACLE_VECTOR_FLOAT32, 3, Float32Elements({1.5F, 2.0F, 3.0F})),
                         VectorImage(oracle_scanner::ORACLE_VECTOR_FLOAT32, 2, Float32Elements({0.5F, -1.0F})),
                         VectorImage(oracle_scanner::ORACLE_VECTOR_INT8, 4, {1, 0xFE, 3, 127}),
                         VectorImage(oracle_scanner::ORACLE_VECTOR_BINARY, 16, {0x05, 0xFF})},
                        {scalar_string, std::nullopt, std::nullopt, std::nullopt, std::nullopt},
                        {std::nullopt, std::nullopt, std::nullopt, std::nullopt, std::nullopt}};
        auto factory = InstallFake(script);
        TestDatabase database;
        auto result = database.Query("SELECT * FROM oracle_query('ora', 'SELECT * FROM app.docs')");
        CHECK(!result->HasError());
        CHECK(result->GetTypes()[0].IsJSONType());
        CHECK(result->GetTypes()[1].ToString() == "FLOAT[3]");
        CHECK(result->GetTypes()[2].ToString() == "DOUBLE[]");
        CHECK(result->GetTypes()[3].ToString() == "TINYINT[4]");
        CHECK(result->GetTypes()[4].ToString() == "UTINYINT[2]");
        CHECK(result->RowCount() == 3);
        CHECK(result->GetValue(0, 0).ToString() == "{\"a\":1}");
        CHECK(result->GetValue(1, 0).ToString() == "[1.5, 2.0, 3.0]");
        CHECK(result->GetValue(2, 0).ToString() == "[0.5, -1.0]");
        CHECK(result->GetValue(3, 0).ToString() == "[1, -2, 3, 127]");
        CHECK(result->GetValue(4, 0).ToString() == "[5, 255]");
        CHECK(result->GetValue(0, 1).ToString() == "\"scalar\"");
        CHECK(result->GetValue(1, 1).IsNull() && result->GetValue(0, 2).IsNull());
        // The JSON column is queryable as JSON.
        auto extracted = database.Query("SELECT json_extract(J, '$.a') FROM oracle_query('ora', 'SELECT * FROM app.docs') WHERE J IS NOT NULL ORDER BY 1");
        CHECK(!extracted->HasError());
        // A vector of a different storage format than its column declared is refused, not reinterpreted.
        script->rows = {{object_a_is_1, VectorImage(oracle_scanner::ORACLE_VECTOR_INT8, 3, {1, 2, 3}), std::nullopt, std::nullopt,
                         std::nullopt}};
        auto mismatched = database.Query("SELECT F FROM oracle_query('ora', 'SELECT * FROM app.docs')");
        CHECK(mismatched->HasError() && mismatched->GetError().find("storage format") != std::string::npos);
        // A BINARY vector in a column that may hold any format cannot be a list of DOUBLE.
        script->rows = {{object_a_is_1, std::nullopt, VectorImage(oracle_scanner::ORACLE_VECTOR_BINARY, 8, {1}), std::nullopt,
                         std::nullopt}};
        auto binary_in_flexible = database.Query("SELECT O FROM oracle_query('ora', 'SELECT * FROM app.docs')");
        CHECK(binary_in_flexible->HasError() && binary_in_flexible->GetError().find("BINARY vector") != std::string::npos);
    }

    // The attached catalog: the dictionary names the types and VECTOR_INFO the shapes.
    auto script = std::make_shared<FakeScript>();
    const auto text_columns = [](std::initializer_list<const char *> names) {
        std::vector<OracleColumn> result;
        for (const auto *name : names) {
            result.push_back(Column(name, 1));
        }
        return result;
    };
    script->routes.push_back({"SELECT USER FROM DUAL", {text_columns({"USER"}), {{Text("APP")}}}});
    script->routes.push_back({"FROM user_tables", {text_columns({"TABLE_NAME"}), {{Text("DOCS")}, {Text("PERF")}}}});
    script->routes.push_back({"FROM user_views", {text_columns({"VIEW_NAME"}), {}}});
    script->routes.push_back(
        {"vector_info FROM user_tab_columns",
         {text_columns({"TABLE_NAME", "COLUMN_NAME", "VECTOR_INFO"}),
          {{Text("DOCS"), Text("EMB"), Text("VECTOR(3,FLOAT32,DENSE)")},
           {Text("DOCS"), Text("FLEX"), Text("VECTOR(*,*,DENSE)")},
           {Text("DOCS"), Text("SPARSE"), Text("VECTOR(8,FLOAT64,SPARSE)")},
           {Text("PERF"), Text("V"), Text("VECTOR(3,FLOAT32,DENSE)")}}}});
    const auto row = [](const char *name, const char *type, const char *table = "DOCS") {
        return std::vector<WireValue> {Text(table), Text(name), Text(type), Number("22"), WireValue(), WireValue(), Text("Y")};
    };
    script->routes.push_back(
        {"FROM user_tab_columns",
         {{Column("TABLE_NAME", 1), Column("COLUMN_NAME", 1), Column("DATA_TYPE", 1), Column("DATA_LENGTH", 2),
           Column("DATA_PRECISION", 2), Column("DATA_SCALE", 2), Column("NULLABLE", 1)},
          {row("ID", "NUMBER"), row("DOC", "JSON"), row("EMB", "VECTOR"), row("FLEX", "VECTOR"), row("SPARSE", "VECTOR"),
           {Text("PERF"), Text("ID"), Text("NUMBER"), Number("22"), Number("9"), Number("0"), Text("N")},
           row("V", "VECTOR", "PERF"), row("J", "JSON", "PERF")}}});
    script->routes.push_back({"FROM user_constraints", {text_columns({"TABLE_NAME", "COLUMN_NAME"}), {{Text("PERF"), Text("ID")}}}});
    auto id_column = Column("ID", 2);
    auto embedding = Column("EMB", 127);
    auto flex = Column("FLEX", 127);
    auto sparse = Column("SPARSE", 127);
    script->tables["DOCS"] = {{id_column, Column("DOC", 119), embedding, flex, sparse}, {}};
    script->tables["PERF"] = {{Column("ID", 2, 9, 0), embedding, Column("J", 119)}, {}};
    script->affected_rows = 1;
    auto factory = InstallFake(script);
    TestDatabase database;
    database.Run("ATTACH 'ora' AS ora (TYPE oracle_scanner);");
    auto described = database.Query(
        "SELECT column_name, data_type FROM duckdb_columns() WHERE table_name = 'DOCS' ORDER BY column_index");
    CHECK(!described->HasError() && described->RowCount() == 5);
    CHECK(described->GetValue(1, 1).ToString() == "JSON");
    CHECK(described->GetValue(1, 2).ToString() == "FLOAT[3]");
    CHECK(described->GetValue(1, 3).ToString() == "DOUBLE[]");
    CHECK(described->GetValue(1, 4).ToString() == "STRUCT(dimensions UINTEGER, indices UINTEGER[], \"values\" DOUBLE[])");

    // JSON is written as its text, which the server converts; a VECTOR as its image.
    database.Run("INSERT INTO ora.main.DOCS (ID, DOC, EMB, FLEX, SPARSE) VALUES (1, '{\"k\":[1,2]}', [0.1, 2, -3.5], "
                 "[1.0, 2.0], {'dimensions': 8, 'indices': [1, 6], 'values': [0.5, 4.0]});");
    CHECK(script->batch_rows.size() == 1 && script->batch_rows[0].size() == 5);
    const auto &binds = script->batch_rows[0];
    CHECK(binds[1].oracle_type == 1 && binds[1].value == Utf8("{\"k\":[1,2]}"));
    // A vector is bound as its image, in the storage format its column has;
    // a column of any format is written as FLOAT64 and the server converts.
    const auto written = [&](size_t position) { return oracle_scanner::DecodeOracleVector(*binds[position].value); };
    CHECK(binds[2].oracle_type == 127 && written(2).format == oracle_scanner::ORACLE_VECTOR_FLOAT32 &&
          written(2).float32 == std::vector<float>({0.1F, 2.0F, -3.5F}));
    CHECK(binds[3].oracle_type == 127 && written(3).format == oracle_scanner::ORACLE_VECTOR_FLOAT64 &&
          written(3).float64 == std::vector<double>({1.0, 2.0}));
    CHECK(binds[4].oracle_type == 127 && written(4).sparse && written(4).dimensions == 8 &&
          written(4).indices == std::vector<uint32_t>({1, 6}) && written(4).float64 == std::vector<double>({0.5, 4.0}));
    // NULL carries the same wire type as a value, as a batch needs.
    database.Run("INSERT INTO ora.main.DOCS (ID, DOC, EMB) VALUES (2, NULL, NULL), (3, '{}', [1, 2, 3]);");
    CHECK(script->batch_rows.size() == 2);
    CHECK(script->batch_rows[0][1].oracle_type == 1 && !script->batch_rows[0][1].value.has_value());
    CHECK(script->batch_rows[0][2].oracle_type == 127 && !script->batch_rows[0][2].value.has_value());

    // A column the statement names is written whatever the optimizer makes of
    // the expression that fills it: here two columns are constants the
    // optimizer folds, and they used to be mistaken for columns left out, so
    // Oracle received a row of NULLs, or no columns at all.
    database.Run("INSERT INTO ora.main.PERF (ID, V, J) SELECT i, list_transform(range(3), lambda x: x / 2.0)::FLOAT[3], "
                 "'{\"folded\":true}'::JSON FROM range(2) t(i);");
    CHECK(script->batch_rows.size() == 2 && script->batch_rows[0].size() == 3);
    CHECK(oracle_scanner::DecodeOracleVector(*script->batch_rows[0][1].value).float32 == std::vector<float>({0.0F, 0.5F, 1.0F}));
    CHECK(script->batch_rows[0][2].value == Utf8("{\"folded\":true}"));
    database.Run("INSERT INTO ora.main.PERF (ID, V, J) SELECT 10 + i, list_transform(range(3), lambda x: x / 2.0)::FLOAT[3], "
                 "'{\"folded\":true}'::JSON FROM range(2) t(i);");
    CHECK(script->batch_rows.size() == 2 && script->batch_rows[0].size() == 3);
    CHECK(oracle_scanner::DecodeOracleVector(*script->batch_rows[0][1].value).float32 == std::vector<float>({0.0F, 0.5F, 1.0F}));
    // A column the statement leaves out stays out.
    database.Run("INSERT INTO ora.main.PERF (ID) SELECT i FROM range(2) t(i);");
    CHECK(script->batch_rows.size() == 2 && script->batch_rows[0].size() == 1);

    auto returning = database.Query("INSERT INTO ora.main.DOCS (ID) VALUES (4) RETURNING ID;");
    CHECK(returning->HasError() && returning->GetError().find("cannot return the LOB, JSON or VECTOR column") != std::string::npos);

    auto wrong_shape = database.Query("INSERT INTO ora.main.DOCS (ID, EMB) VALUES (5, [1, 2]);");
    CHECK(wrong_shape->HasError());
    // A test of a JSON path is narrowed in Oracle (JSON_VALUE / JSON_EXISTS) and still applied by DuckDB.
    CHECK(!database.Query("SELECT ID FROM ora.main.DOCS WHERE DOC->>'$.name' = 'abc';")->HasError());
    CHECK(script->queries.back().find("JSON_VALUE(\"DOC\", '$.name' RETURNING VARCHAR2(4000) NULL ON ERROR) = 'abc'") !=
          std::string::npos);
    // A constant that could be a number is not narrowed: Oracle writes numbers its own way.
    CHECK(!database.Query("SELECT ID FROM ora.main.DOCS WHERE DOC->>'$.name' = '5';")->HasError());
    CHECK(script->queries.back().find("JSON_VALUE") == std::string::npos);
    CHECK(!database.Query("SELECT ID FROM ora.main.DOCS WHERE DOC->>'$.a[0]' IS NOT NULL;")->HasError());
    CHECK(script->queries.back().find("JSON_EXISTS(\"DOC\", '$.a[0]')") != std::string::npos);
    std::cout << "JSON and VECTOR columns read, write and attach against a fake session" << std::endl;
}

// With filter pushdown on, a filter Oracle is not sent is applied to the rows
// that come back rather than refused. The fake answers every WHERE with all the
// rows, so only the local evaluation can narrow them.
void TestUntranslatableFiltersRunLocally() {
    const auto text_columns = [](std::initializer_list<const char *> names) {
        std::vector<OracleColumn> result;
        for (const auto *name : names) {
            result.push_back(Column(name, 1));
        }
        return result;
    };
    auto script = std::make_shared<FakeScript>();
    script->two_batch_fetch = true;
    script->routes.push_back({"SELECT USER FROM DUAL", {text_columns({"USER"}), {{Text("APP")}}}});
    script->routes.push_back({"FROM user_tables", {text_columns({"TABLE_NAME"}), {{Text("ITEMS")}}}});
    script->routes.push_back({"FROM user_views", {text_columns({"VIEW_NAME"}), {}}});
    script->routes.push_back(
        {"FROM user_tab_columns",
         {{Column("TABLE_NAME", 1), Column("COLUMN_NAME", 1), Column("DATA_TYPE", 1), Column("DATA_LENGTH", 2),
           Column("DATA_PRECISION", 2), Column("DATA_SCALE", 2), Column("NULLABLE", 1)},
          {{Text("ITEMS"), Text("ID"), Text("NUMBER"), Number("22"), Number("10"), Number("0"), Text("N")},
           {Text("ITEMS"), Text("LABEL"), Text("VARCHAR2"), Number("20"), WireValue(), WireValue(), Text("Y")}}}});
    script->routes.push_back({"FROM user_constraints", {text_columns({"TABLE_NAME", "COLUMN_NAME"}), {}}});
    script->tables["ITEMS"] = {{Column("ID", 2, 10, 0), Column("LABEL", 1)},
                               {{Number("1"), Text("first")}, {Number("2"), Text("second")}, {Number("3"), Text("third")}}};
    auto factory = InstallFake(script);
    TestDatabase database;
    database.Run("ATTACH 'ora' AS ora (TYPE oracle_scanner);");
    database.Run("SET oracle_filter_pushdown = true;");

    const auto ids = [&](const std::string &where) {
        auto result = database.Query("SELECT ID FROM ora.main.ITEMS WHERE " + where + " ORDER BY ID;");
        CHECK(!result->HasError());
        std::string joined;
        for (duckdb::idx_t row = 0; row < result->RowCount(); row++) {
            joined += (joined.empty() ? "" : ",") + result->GetValue(0, row).ToString();
        }
        return joined;
    };
    // LIKE is not translated: Oracle's LIKE, escape and collation rules differ.
    CHECK(ids("LABEL LIKE 'sec%'") == "2");
    CHECK(script->queries.back().find("WHERE") == std::string::npos);
    // One filter sent and one kept: both hold.
    CHECK(ids("ID >= 2 AND LABEL LIKE 'th%'") == "3");
    CHECK(script->queries.back().find("WHERE \"ID\" >= 2") != std::string::npos);
    // A predicate across two columns.
    CHECK(ids("ID = 1 OR LABEL = 'third'") == "1,3");
    // Every row dropped by the local filter in the first batch must not end the scan.
    CHECK(ids("LABEL LIKE 'zzz%'").empty());
    std::cout << "filters Oracle is not sent are applied locally" << std::endl;
}

// A CLOB the local filter never looks at is read for the rows that pass the filter,
// by ROWID and at the change number the rows were read at.
void TestHeavyColumnsAreReadAfterTheFilter() {
    const auto text_columns = [](std::initializer_list<const char *> names) {
        std::vector<OracleColumn> result;
        for (const auto *name : names) {
            result.push_back(Column(name, 1));
        }
        return result;
    };
    auto script = std::make_shared<FakeScript>();
    script->routes.push_back({"SELECT USER FROM DUAL", {text_columns({"USER"}), {{Text("APP")}}}});
    script->routes.push_back({"dbms_flashback", {{Column("SCN", 2)}, {{Number("100")}}}});
    script->routes.push_back({"iot_type", {text_columns({"IOT_TYPE", "TEMPORARY", "CLUSTER_NAME"}), {{WireValue(), Text("N"), WireValue()}}}});
    script->routes.push_back({"WHERE ROWID IN", {{Column("rowid", 1), Column("BODY", 112)}, {{Text("AAAROW1"), Text("second body")}}}});
    script->routes.push_back({"FROM user_tables", {text_columns({"TABLE_NAME"}), {{Text("DOCS")}}}});
    script->routes.push_back({"FROM user_views", {text_columns({"VIEW_NAME"}), {}}});
    script->routes.push_back(
        {"FROM user_tab_columns",
         {{Column("TABLE_NAME", 1), Column("COLUMN_NAME", 1), Column("DATA_TYPE", 1), Column("DATA_LENGTH", 2),
           Column("DATA_PRECISION", 2), Column("DATA_SCALE", 2), Column("NULLABLE", 1)},
          {{Text("DOCS"), Text("ID"), Text("NUMBER"), Number("22"), Number("10"), Number("0"), Text("N")},
           {Text("DOCS"), Text("LABEL"), Text("VARCHAR2"), Number("20"), WireValue(), WireValue(), Text("Y")},
           {Text("DOCS"), Text("BODY"), Text("CLOB"), Number("4000"), WireValue(), WireValue(), Text("Y")}}}});
    script->routes.push_back({"FROM user_constraints", {text_columns({"TABLE_NAME", "COLUMN_NAME"}), {}}});
    script->tables["DOCS"] = {{Column("ID", 2, 10, 0), Column("LABEL", 1), Column("BODY", 112)},
                              {{Number("1"), Text("first"), Text("first body")},
                               {Number("2"), Text("second"), Text("second body")},
                               {Number("3"), Text("third"), Text("third body")}}};
    auto factory = InstallFake(script);
    TestDatabase database;
    database.Run("ATTACH 'ora' AS ora (TYPE oracle_scanner);");
    // LIKE is a filter Oracle is not sent, so DuckDB applies it, and BODY is not part of it.
    auto result = database.Query("SELECT ID, BODY FROM ora.main.DOCS WHERE LABEL LIKE 'sec%';");
    CHECK(!result->HasError() && result->RowCount() == 1);
    CHECK(result->GetValue(0, 0).ToString() == "2" && result->GetValue(1, 0).ToString() == "second body");
    bool light = false;
    bool heavy = false;
    for (const auto &query : script->queries) {
        light = light || (query.find("AS OF SCN 100") != std::string::npos && query.find("ROWIDTOCHAR(ROWID)") != std::string::npos &&
                          query.find("\"BODY\"") == std::string::npos);
        heavy = heavy || query.find("WHERE ROWID IN (CHARTOROWID('AAAROW1'))") != std::string::npos;
    }
    CHECK(light && heavy);
    // A filter that reads the column is applied to the whole row, which is read at once.
    script->queries.clear();
    CHECK(!database.Query("SELECT ID FROM ora.main.DOCS WHERE LABEL LIKE 'sec%' AND BODY LIKE 'x%';")->HasError());
    for (const auto &query : script->queries) {
        CHECK(query.find("WHERE ROWID IN") == std::string::npos);
    }
    // And the setting turns it off.
    database.Run("SET oracle_deferred_columns = false;");
    script->queries.clear();
    CHECK(!database.Query("SELECT ID, BODY FROM ora.main.DOCS WHERE LABEL LIKE 'sec%';")->HasError());
    for (const auto &query : script->queries) {
        CHECK(query.find("WHERE ROWID IN") == std::string::npos && query.find("AS OF SCN") == std::string::npos);
    }
    // With oracle_consistent_read a statement's scans all read at one change number.
    database.Run("SET oracle_consistent_read = true;");
    script->queries.clear();
    CHECK(!database.Query("SELECT a.ID FROM ora.main.DOCS a JOIN ora.main.DOCS b ON a.LABEL = b.LABEL;")->HasError());
    size_t pinned = 0;
    for (const auto &query : script->queries) {
        pinned += query.find("FROM \"DOCS\" AS OF SCN 100") != std::string::npos ? 1 : 0;
    }
    CHECK(pinned == 2);
    // A sample is read at that change number too. It used to drop it, so the
    // statement read now instead of at the moment it promised. Oracle takes the
    // sample clause only ahead of AS OF.
    script->queries.clear();
    CHECK(!database.Query("SELECT count(*) FROM ora.main.DOCS TABLESAMPLE SYSTEM (10%) REPEATABLE (3);")->HasError());
    CHECK(!script->queries.empty() &&
          script->queries.back().find("FROM \"DOCS\" SAMPLE (10.000000) SEED (3) AS OF SCN 100") != std::string::npos);
    database.Run("SET oracle_consistent_read = false;");
    std::cout << "heavy columns are read after the filter" << std::endl;
}

// ATTACH ... (SCHEMA 'x') lists another user's tables through the ALL_ views,
// qualifies every statement with the owner, and settles the name against
// ALL_USERS. The connected user's own schema, named or not, stays on USER_.
void TestAttachToAnotherSchema() {
    const auto text_columns = [](std::initializer_list<const char *> names) {
        std::vector<OracleColumn> result;
        for (const auto *name : names) {
            result.push_back(Column(name, 1));
        }
        return result;
    };
    auto script = std::make_shared<FakeScript>();
    script->routes.push_back({"SELECT USER FROM DUAL", {text_columns({"USER"}), {{Text("READER")}}}});
    script->routes.push_back({"username = 'hr'", {text_columns({"USERNAME"}), {}}});
    script->routes.push_back({"UPPER(username) = UPPER('hr')", {text_columns({"USERNAME"}), {{Text("HR")}}}});
    script->routes.push_back({"username = 'HR'", {text_columns({"USERNAME"}), {{Text("HR")}}}});
    script->routes.push_back({"username = 'READER'", {text_columns({"USERNAME"}), {{Text("READER")}}}});
    script->routes.push_back({"username = 'NOBODY'", {text_columns({"USERNAME"}), {}}});
    script->routes.push_back({"UPPER(username) = UPPER('NOBODY')", {text_columns({"USERNAME"}), {}}});
    script->routes.push_back({"FROM all_tables", {text_columns({"TABLE_NAME"}), {{Text("ITEMS")}}}});
    script->routes.push_back({"FROM all_views", {text_columns({"VIEW_NAME"}), {}}});
    script->routes.push_back({"FROM user_tables", {text_columns({"TABLE_NAME"}), {{Text("OWN_TABLE")}}}});
    script->routes.push_back({"FROM user_views", {text_columns({"VIEW_NAME"}), {}}});
    const std::vector<OracleColumn> dictionary = {Column("TABLE_NAME", 1), Column("COLUMN_NAME", 1), Column("DATA_TYPE", 1),
                                                  Column("DATA_LENGTH", 2), Column("DATA_PRECISION", 2),
                                                  Column("DATA_SCALE", 2), Column("NULLABLE", 1)};
    script->routes.push_back(
        {"FROM all_tab_columns",
         {dictionary, {{Text("ITEMS"), Text("ID"), Text("NUMBER"), Number("22"), Number("10"), Number("0"), Text("N")}}}});
    script->routes.push_back(
        {"FROM user_tab_columns",
         {dictionary, {{Text("OWN_TABLE"), Text("ID"), Text("NUMBER"), Number("22"), Number("10"), Number("0"), Text("N")}}}});
    script->routes.push_back({"FROM all_constraints", {text_columns({"TABLE_NAME", "COLUMN_NAME"}), {{Text("ITEMS"), Text("ID")}}}});
    script->routes.push_back({"FROM user_constraints", {text_columns({"TABLE_NAME", "COLUMN_NAME"}), {}}});
    script->tables["ITEMS"] = {{Column("ID", 2, 10, 0)}, {{Number("1")}}};
    script->tables["OWN_TABLE"] = {{Column("ID", 2, 10, 0)}, {{Number("1")}}};
    script->affected_rows = 1;
    auto factory = InstallFake(script);
    TestDatabase database;

    // Written in lower case, resolved to the one user it matches.
    database.Run("ATTACH 'ora' AS other (TYPE oracle_scanner, SCHEMA 'hr');");
    auto listed = database.Query("SELECT table_name FROM duckdb_tables() WHERE database_name = 'other';");
    CHECK(!listed->HasError() && listed->RowCount() == 1 && listed->GetValue(0, 0).ToString() == "ITEMS");
    CHECK(!database.Query("SELECT * FROM other.main.ITEMS;")->HasError());
    CHECK(script->queries.back().find("FROM \"HR\".\"ITEMS\"") != std::string::npos);
    // The owner's key constraint came from ALL_CONSTRAINTS for this owner.
    auto keys = database.Query("SELECT constraint_type FROM duckdb_constraints() WHERE table_name = 'ITEMS' "
                               "AND constraint_type = 'PRIMARY KEY';");
    CHECK(!keys->HasError() && keys->RowCount() == 1);
    database.Run("INSERT INTO other.main.ITEMS VALUES (5);");
    CHECK(script->counted_executes.back() == "INSERT INTO \"HR\".\"ITEMS\" (\"ID\") VALUES (:1)");
    database.Run("UPDATE other.main.ITEMS SET ID = 6;");
    CHECK(script->counted_executes.back().find("UPDATE \"HR\".\"ITEMS\" SET") == 0);
    database.Run("DELETE FROM other.main.ITEMS;");
    CHECK(script->counted_executes.back().find("DELETE FROM \"HR\".\"ITEMS\" WHERE ROWID") == 0);

    // The connected user's own name reads the USER_ views, unqualified.
    database.Run("ATTACH 'ora' AS own (TYPE oracle_scanner, SCHEMA 'READER');");
    CHECK(!database.Query("SELECT * FROM own.main.OWN_TABLE;")->HasError());
    CHECK(script->queries.back().find("FROM \"OWN_TABLE\"") != std::string::npos);

    auto unknown = database.Query("ATTACH 'ora' AS nobody (TYPE oracle_scanner, SCHEMA 'NOBODY');");
    CHECK(unknown->HasError() && unknown->GetError().find("no schema \"NOBODY\"") != std::string::npos);
    auto not_text = database.Query("ATTACH 'ora' AS bad (TYPE oracle_scanner, SCHEMA 5);");
    CHECK(not_text->HasError() && not_text->GetError().find("SCHEMA takes a schema name") != std::string::npos);
    std::cout << "an attached catalog can read another user's schema" << std::endl;
}

void TestXmlTypeColumnsAreText() {
    const auto text_columns = [](std::initializer_list<const char *> names) {
        std::vector<OracleColumn> result;
        for (const auto *name : names) {
            result.push_back(Column(name, 1));
        }
        return result;
    };
    auto script = std::make_shared<FakeScript>();
    script->routes.push_back({"SELECT USER FROM DUAL", {text_columns({"USER"}), {{Text("APP")}}}});
    script->routes.push_back({"FROM user_tables", {text_columns({"TABLE_NAME"}), {{Text("DOCS")}}}});
    script->routes.push_back({"FROM user_views", {text_columns({"VIEW_NAME"}), {}}});
    const std::vector<OracleColumn> dictionary = {Column("TABLE_NAME", 1), Column("COLUMN_NAME", 1), Column("DATA_TYPE", 1),
                                                  Column("DATA_LENGTH", 2), Column("DATA_PRECISION", 2),
                                                  Column("DATA_SCALE", 2), Column("NULLABLE", 1)};
    script->routes.push_back(
        {"FROM user_tab_columns",
         {dictionary,
          {{Text("DOCS"), Text("ID"), Text("NUMBER"), Number("22"), Number("10"), Number("0"), Text("N")},
           {Text("DOCS"), Text("BODY"), Text("XMLTYPE"), Number("2000"), std::nullopt, std::nullopt, Text("Y")}}}});
    script->routes.push_back({"FROM user_constraints", {text_columns({"TABLE_NAME", "COLUMN_NAME"}), {}}});
    script->tables["DOCS"] = {{Column("ID", 2, 10, 0), Column("BODY", 112)}, {{Number("1"), Text("<a/>")}}};
    script->affected_rows = 1;
    auto factory = InstallFake(script);
    TestDatabase database;
    database.Run("ATTACH 'ora' AS o (TYPE oracle_scanner);");

    // The column is text on the DuckDB side, and the scan asks Oracle to serialize it.
    auto described = database.Query("SELECT data_type FROM duckdb_columns() WHERE column_name = 'BODY';");
    CHECK(!described->HasError() && described->GetValue(0, 0).ToString() == "VARCHAR");
    // A name typed in lower case finds the one object that matches ignoring case,
    // and the statement Oracle gets names it as Oracle stores it.
    auto lower = database.Query("SELECT body FROM o.main.docs;");
    CHECK(!lower->HasError() && lower->GetValue(0, 0).ToString() == "<a/>");
    CHECK(script->queries.back().find("FROM \"DOCS\"") != std::string::npos);
    auto scanned = database.Query("SELECT BODY FROM o.main.DOCS;");
    CHECK(!scanned->HasError() && scanned->GetValue(0, 0).ToString() == "<a/>");
    CHECK(script->queries.back().find("XMLSERIALIZE(CONTENT \"BODY\" AS CLOB NO INDENT) \"BODY\"") != std::string::npos);
    // A write binds the text through XMLPARSE, once per placeholder.
    database.Run("INSERT INTO o.main.DOCS VALUES (2, '<b/>');");
    CHECK(script->counted_executes.back() == "INSERT INTO \"DOCS\" (\"ID\", \"BODY\") VALUES (:1, XMLPARSE(DOCUMENT :2))");
    database.Run("UPDATE o.main.DOCS SET BODY = '<c/>';");
    CHECK(script->counted_executes.back().find("\"BODY\" = XMLPARSE(DOCUMENT :1)") != std::string::npos);
    std::cout << "an XMLTYPE column reads and writes as text" << std::endl;
}

// With Oracle's row count the optimizer puts the attached table on the probe
// side of a join, and the keys the other side holds reach Oracle: as an IN list
// when they are few, as ranges of the key otherwise.
void TestJoinKeysReachOracle() {
    const auto text_columns = [](std::initializer_list<const char *> names) {
        std::vector<OracleColumn> result;
        for (const auto *name : names) {
            result.push_back(Column(name, 1));
        }
        return result;
    };
    auto script = std::make_shared<FakeScript>();
    script->routes.push_back({"SELECT USER FROM DUAL", {text_columns({"USER"}), {{Text("APP")}}}});
    // The statistics query comes before the object listing, which matches the same view.
    script->routes.push_back({"num_distinct IS NOT NULL",
                              {{Column("TABLE_NAME", 1), Column("COLUMN_NAME", 1), Column("NUM_DISTINCT", 2)},
                               {{Text("FACTS"), Text("ID"), Number("4000000")}}}});
    script->routes.push_back({"num_rows IS NOT NULL", {{Column("TABLE_NAME", 1), Column("NUM_ROWS", 2)},
                                                       {{Text("FACTS"), Number("5000000")}}}});
    script->routes.push_back({"FROM user_tables", {text_columns({"TABLE_NAME"}), {{Text("FACTS")}}}});
    script->routes.push_back({"FROM user_views", {text_columns({"VIEW_NAME"}), {}}});
    const std::vector<OracleColumn> dictionary = {Column("TABLE_NAME", 1), Column("COLUMN_NAME", 1), Column("DATA_TYPE", 1),
                                                  Column("DATA_LENGTH", 2), Column("DATA_PRECISION", 2),
                                                  Column("DATA_SCALE", 2), Column("NULLABLE", 1)};
    script->routes.push_back(
        {"FROM user_tab_columns",
         {dictionary, {{Text("FACTS"), Text("ID"), Text("NUMBER"), Number("22"), Number("10"), Number("0"), Text("N")}}}});
    script->routes.push_back({"FROM user_constraints", {text_columns({"TABLE_NAME", "COLUMN_NAME"}), {}}});
    script->tables["FACTS"] = {{Column("ID", 2, 10, 0)}, {{Number("1000")}, {Number("1100")}, {Number("1200")}}};
    auto factory = InstallFake(script);
    TestDatabase database;
    database.Run("ATTACH 'ora' AS o (TYPE oracle_scanner);");

    // The row count and the column's distinct count reach the optimizer, which sizes the grouping from them.
    auto estimated = database.Query("EXPLAIN SELECT ID, count(*) FROM o.main.FACTS GROUP BY ID;");
    CHECK(!estimated->HasError());
    std::string plan;
    for (duckdb::idx_t row = 0; row < estimated->RowCount(); row++) {
        plan += estimated->GetValue(1, row).ToString();
    }
    // The scan is 5,000,000 rows, and the grouping is sized below that because
    // the column is known to hold fewer distinct values.
    size_t at_scan_size = 0;
    for (auto position = plan.find("~5,000,000 rows"); position != std::string::npos;
         position = plan.find("~5,000,000 rows", position + 1)) {
        at_scan_size++;
    }
    CHECK(at_scan_size == 2 && plan.find("~") != std::string::npos);
    // Five keys: an IN list.
    auto few = database.Query("SELECT count(*) FROM o.main.FACTS f JOIN (SELECT unnest([1000, 1100, 1200, 9999]) k) v "
                              "ON f.ID = v.k;");
    CHECK(!few->HasError() && few->GetValue(0, 0).ToString() == "3");
    CHECK(script->queries.back().find("WHERE") != std::string::npos &&
          script->queries.back().find("1000") != std::string::npos);
    // Many keys: the ranges they fall in, and the answer is the same.
    auto many = database.Query("SELECT count(*) FROM o.main.FACTS f JOIN (SELECT 1000 + i * 100 AS k FROM range(300) t(i)) v "
                               "ON f.ID = v.k;");
    CHECK(!many->HasError() && many->GetValue(0, 0).ToString() == "3");
    CHECK(script->queries.back().find("WHERE") != std::string::npos &&
          (script->queries.back().find("BETWEEN") != std::string::npos ||
           script->queries.back().find("IN (") != std::string::npos));
    // ORDER BY ... LIMIT over a number is ranked by Oracle, which returns only the first rows; DuckDB's
    // own TOP_N stays above it. The setting turns it off.
    auto top = database.Query("SELECT ID FROM o.main.FACTS ORDER BY ID DESC NULLS FIRST LIMIT 5 OFFSET 2;");
    CHECK(!top->HasError());
    CHECK(script->queries.back().find("ORDER BY \"ID\" DESC NULLS FIRST FETCH FIRST 7 ROWS ONLY") != std::string::npos);
    database.Run("SET oracle_top_n_pushdown = false;");
    CHECK(!database.Query("SELECT ID FROM o.main.FACTS ORDER BY ID DESC LIMIT 5;")->HasError());
    CHECK(script->queries.back().find("ORDER BY") == std::string::npos);
    database.Run("SET oracle_top_n_pushdown = true;");
    // A grouped COUNT/SUM/MIN/MAX is computed by Oracle: the scan runs one GROUP BY statement and its columns
    // reach the plan in the types the AGGREGATE had (a sum of integers arrives as text and is a HUGEINT).
    database.Run("SET oracle_aggregate_pushdown = true;");
    script->routes.insert(script->routes.begin(),
                          {"GROUP BY", {{Column("C0", 2, 10, 0), Column("C1", 2, 18, 0), Column("C2", 1), Column("C3", 2, 10, 0)},
                                        {{Number("1000"), Number("2"), Text("2100"), Number("1000")},
                                         {Number("1100"), Number("1"), Text("1100"), Number("1100")}}}});
    auto grouped = database.Query("SELECT ID, count(*), sum(ID), min(ID) FROM o.main.FACTS WHERE ID > 5 GROUP BY ID ORDER BY ID;");
    CHECK(!grouped->HasError() && grouped->RowCount() == 2);
    CHECK(grouped->GetValue(2, 0).ToString() == "2100" && grouped->GetValue(2, 0).type() == duckdb::LogicalType::HUGEINT &&
          grouped->GetValue(1, 0).ToString() == "2");
    CHECK(script->queries.back().find("GROUP BY \"ID\"") != std::string::npos &&
          script->queries.back().find("SUM(\"ID\")") != std::string::npos &&
          script->queries.back().find("WHERE \"ID\" > 5") != std::string::npos);
    // An IN list over Oracle's 1000-entry limit is sent as several lists joined by OR.
    std::string many_keys = "SELECT ID FROM o.main.FACTS WHERE ID IN (1";
    for (int key = 3; key < 5000; key += 2) {
        many_keys += ", " + std::to_string(key);
    }
    CHECK(!database.Query(many_keys + ");")->HasError());
    CHECK(script->queries.back().find("\"ID\" IN (") != std::string::npos &&
          script->queries.back().find(") OR \"ID\" IN (") != std::string::npos);
    // An inner join of two attached tables is one statement, each side an inline view with its own filters.
    database.Run("SET oracle_join_pushdown = true;");
    script->routes.insert(script->routes.begin(),
                          {"JOIN (SELECT", {{Column("C0", 2, 10, 0), Column("C1", 2, 10, 0)},
                                            {{Number("1000"), Number("1100")}, {Number("1100"), Number("1100")}}}});
    auto joined = database.Query("SELECT a.ID, b.ID FROM o.main.FACTS a JOIN o.main.FACTS b ON a.ID <= b.ID "
                                 "WHERE a.ID > 5 AND b.ID < 9000 ORDER BY 1, 2;");
    CHECK(!joined->HasError() && joined->RowCount() == 2 && joined->GetValue(0, 0).ToString() == "1000");
    CHECK(script->queries.back().find("FROM (SELECT \"ID\" FROM \"FACTS\" WHERE \"ID\" > 5") !=
              std::string::npos &&
          script->queries.back().find("a.\"ID\" <= b.\"ID\"") != std::string::npos);
    database.Run("SET oracle_join_pushdown = false;");
    // An aggregate with a FILTER is left to DuckDB.
    CHECK(!database.Query("SELECT count(*) FILTER (WHERE ID > 1050) FROM o.main.FACTS;")->HasError());
    CHECK(script->queries.back().find("GROUP BY") == std::string::npos);
    // The rest of this test counts rows the fake serves for plain scans.
    database.Run("SET oracle_aggregate_pushdown = false;");
    // EXPLAIN ANALYZE says what was sent to Oracle and what came back.
    auto analyzed = database.Query("EXPLAIN ANALYZE SELECT ID FROM o.main.FACTS WHERE ID > 1000;");
    CHECK(!analyzed->HasError());
    std::string analysis;
    for (duckdb::idx_t row = 0; row < analyzed->RowCount(); row++) {
        analysis += analyzed->GetValue(1, row).ToString();
    }
    CHECK(analysis.find("Oracle SQL") != std::string::npos && analysis.find("WHERE \"ID\" > 1000") != std::string::npos &&
          analysis.find("Oracle rows returned") != std::string::npos &&
          analysis.find("Oracle network") != std::string::npos && analysis.find("Oracle sessions") != std::string::npos);
    // A system sample of a table is taken by Oracle, not by reading every row. A filter
    // above the sample stays above it, in DuckDB; a filter below it is part of the scan,
    // and the sample then stays in DuckDB, after the filter.
    auto sampled = database.Query("SELECT count(*) FROM o.main.FACTS TABLESAMPLE SYSTEM (10%) REPEATABLE (7);");
    CHECK(!sampled->HasError());
    CHECK(script->queries.back().find("FROM \"FACTS\" SAMPLE (10.000000) SEED (7)") != std::string::npos);
    auto after = database.Query("SELECT count(*) FROM o.main.FACTS TABLESAMPLE SYSTEM (10%) WHERE ID > 0;");
    CHECK(!after->HasError() && script->queries.back().find("SAMPLE (10.000000)") != std::string::npos &&
          script->queries.back().find("WHERE") == std::string::npos);
    auto before = database.Query("SELECT count(*) FROM (SELECT * FROM o.main.FACTS WHERE ID > 0) TABLESAMPLE SYSTEM (10%);");
    CHECK(!before->HasError() && script->queries.back().find("SAMPLE") == std::string::npos &&
          script->queries.back().find("WHERE") != std::string::npos);
    std::cout << "a join's keys reach Oracle as a WHERE clause" << std::endl;
}

// oracle_vector_search puts nothing from the caller into its statement but
// identifiers, a number and a word from a fixed list, and refuses the rest.
void TestVectorSearchArguments() {
    auto script = std::make_shared<FakeScript>();
    script->columns = {Column("ID", 2, 6, 0)};
    script->rows = {{Number("1")}};
    auto factory = InstallFake(script);
    TestDatabase database;
    const auto error_of = [&](const std::string &arguments) {
        auto result = database.Query("SELECT * FROM oracle_vector_search('ora', " + arguments + ")");
        CHECK(result->HasError());
        return result->GetError();
    };
    CHECK(error_of("'T', 'E', [1.0], metric := 'x; DROP TABLE t'").find("metric must be COSINE") != std::string::npos);
    CHECK(error_of("'T', 'E', [1.0], k := 0").find("k must be between 1 and 100000") != std::string::npos);
    CHECK(error_of("'T', 'E', 5").find("list or array of numbers") != std::string::npos);
    CHECK(error_of("'', 'E', [1.0]").find("table cannot be empty") != std::string::npos);
    // Unquoted names are read as Oracle reads them; a quoted one is kept, and quotes inside are doubled.
    auto quoted = database.Query("SELECT * FROM oracle_vector_search('ora', 'sales.\"MixedCase\"', 'e\"mb', [1.0]::FLOAT[1])");
    CHECK(!quoted->HasError());
    CHECK(script->queries.back().find("FROM \"SALES\".\"MixedCase\" t") != std::string::npos);
    CHECK(script->queries.back().find("t.\"E\"\"MB\"") != std::string::npos);
    std::cout << "oracle_vector_search refuses what it cannot put in a statement safely" << std::endl;
}

// With oracle_parallel_scan a big table is read as ROWID ranges cut at extent
// boundaries, all at one SCN, and every ROWID belongs to exactly one range.
void TestAttachedScanReadsInRowidRanges() {
    const auto text_columns = [](std::initializer_list<const char *> names) {
        std::vector<OracleColumn> result;
        for (const auto *name : names) {
            result.push_back(Column(name, 1));
        }
        return result;
    };
    auto script = std::make_shared<FakeScript>();
    script->routes.push_back({"SELECT USER FROM DUAL", {text_columns({"USER"}), {{Text("APP")}}}});
    script->routes.push_back({"dbms_flashback", {{Column("SCN", 2)}, {{Number("424242")}}}});
    script->routes.push_back({"iot_type", {text_columns({"IOT_TYPE", "TEMPORARY", "CLUSTER_NAME"}),
                                           {{std::nullopt, Text("N"), std::nullopt}}}});
    // Ten extents of 1,000 blocks, in ROWID order.
    std::vector<std::vector<std::optional<std::vector<uint8_t>>>> extents;
    for (int index = 0; index < 10; index++) {
        extents.push_back({Text("EXTENT" + std::to_string(index)), Number("1000")});
    }
    script->routes.push_back({"dba_extents", {{Column("LOW", 1), Column("BLOCKS", 2)}, extents}});
    script->routes.push_back({"FROM user_tables", {text_columns({"TABLE_NAME"}), {{Text("FACTS")}}}});
    script->routes.push_back({"FROM user_views", {text_columns({"VIEW_NAME"}), {}}});
    const std::vector<OracleColumn> dictionary = {Column("TABLE_NAME", 1), Column("COLUMN_NAME", 1), Column("DATA_TYPE", 1),
                                                  Column("DATA_LENGTH", 2), Column("DATA_PRECISION", 2),
                                                  Column("DATA_SCALE", 2), Column("NULLABLE", 1)};
    script->routes.push_back(
        {"FROM user_tab_columns",
         {dictionary, {{Text("FACTS"), Text("ID"), Text("NUMBER"), Number("22"), Number("10"), Number("0"), Text("N")}}}});
    script->routes.push_back({"FROM user_constraints", {text_columns({"TABLE_NAME", "COLUMN_NAME"}), {}}});
    script->tables["FACTS"] = {{Column("ID", 2, 10, 0)}, {{Number("1")}}};
    auto factory = InstallFake(script);
    TestDatabase database;
    database.Run("ATTACH 'ora' AS o (TYPE oracle_scanner);");

    // Automatic, and this table has no row-count statistics: one statement, no ranges.
    CHECK(!database.Query("SELECT count(*) FROM o.main.FACTS;")->HasError());
    for (const auto &query : script->queries) {
        CHECK(query.find("CHARTOROWID") == std::string::npos);
    }
    script->queries.clear();

    database.Run("SET oracle_parallel_scan = 4;");
    auto result = database.Query("SELECT count(*) FROM o.main.FACTS;");
    CHECK(!result->HasError());
    std::vector<std::string> chunks;
    for (const auto &query : script->queries) {
        if (query.find("AS OF SCN 424242 WHERE ROWID") != std::string::npos) {
            chunks.push_back(query);
        }
    }
    // 10,000 blocks over 16 chunks of about 625: each 1,000-block extent is a chunk.
    CHECK(chunks.size() == 10);
    std::sort(chunks.begin(), chunks.end());
    size_t open_below = 0;
    size_t open_above = 0;
    for (const auto &chunk : chunks) {
        const bool has_lower = chunk.find("ROWID >= CHARTOROWID") != std::string::npos;
        const bool has_upper = chunk.find("ROWID < CHARTOROWID") != std::string::npos;
        open_below += has_lower ? 0 : 1;
        open_above += has_upper ? 0 : 1;
    }
    CHECK(open_below == 1 && open_above == 1);
    bool joined = false;
    for (const auto &chunk : chunks) {
        joined = joined || chunk.find("ROWID >= CHARTOROWID('EXTENT2') AND ROWID < CHARTOROWID('EXTENT3')") != std::string::npos;
    }
    CHECK(joined);
    // Once the transaction has written, the one session that sees its rows reads, as one stream.
    database.Run("BEGIN;");
    database.Run("INSERT INTO o.main.FACTS VALUES (5);");
    script->queries.clear();
    CHECK(!database.Query("SELECT count(*) FROM o.main.FACTS;")->HasError());
    for (const auto &query : script->queries) {
        CHECK(query.find("AS OF SCN") == std::string::npos);
    }
    database.Run("ROLLBACK;");
    std::cout << "an attached scan can read in ROWID ranges at one SCN" << std::endl;
}

void TestCallableArgumentsOfTheNewTypes() {
    using oracle_scanner::BindDirection;
    const auto encode = [](const char *type, const char *text) {
        return duckdb::EncodeOracleCallableArgument(type, BindDirection::BIND_IN, duckdb::Value(text), "P", "test");
    };
    const auto national = encode("nvarchar", "ab");
    CHECK(national.oracle_type == 1 && national.character_set_form == 2);
    CHECK(national.value && *national.value == oracle_scanner::EncodeUtf8ToUtf16Be("ab"));
    CHECK(encode("boolean", "TRUE").value == std::vector<uint8_t>({1, 1}));
    CHECK(encode("boolean", "0").value == std::vector<uint8_t>({1, 0}));
    CHECK(encode("interval_ym", "2 years 3 months").value == oracle_scanner::EncodeOracleIntervalYearMonth(2, 3));
    CHECK(encode("interval_ds", "1 day 02:03:04").oracle_type == 183);
    // A local-zone value is bound as the TIMESTAMP of its UTC wall time.
    const auto local_zone = encode("timestamp_ltz", "2024-03-01 10:00:00+02");
    CHECK(local_zone.oracle_type == 180 && local_zone.value && local_zone.value->size() == 11);
    const auto null_out = duckdb::EncodeOracleCallableArgument("nvarchar", BindDirection::BIND_OUT, duckdb::Value(),
                                                               "P", "test");
    CHECK(!null_out.value && null_out.character_set_form == 2);
    bool refused = false;
    try {
        encode("boolean", "maybe");
    } catch (const duckdb::BinderException &error) {
        refused = std::string(error.what()).find("not a valid BOOLEAN") != std::string::npos;
    }
    CHECK(refused);
    CHECK(duckdb::FormatCallScalar(1, oracle_scanner::EncodeUtf8ToUtf16Be("\xD0\xB0"), 2) == "\xD0\xB0");
    CHECK(duckdb::FormatCallScalar(252, {1, 1}) == "true");
    CHECK(duckdb::FormatCallScalar(182, oracle_scanner::EncodeOracleIntervalYearMonth(2, 3)) == "2 years 3 months");
    std::cout << "callable arguments cover national text, BOOLEAN, intervals and local-zone timestamps" << std::endl;
}

void TestAttachedWritesAgainstAFakeSession() {
    const auto text_columns = [](std::initializer_list<const char *> names) {
        std::vector<OracleColumn> result;
        for (const auto *name : names) {
            result.push_back(Column(name, 1));
        }
        return result;
    };
    auto script = std::make_shared<FakeScript>();
    script->routes.push_back({"SELECT USER FROM DUAL", {text_columns({"USER"}), {{Text("APP")}}}});
    script->routes.push_back({"FROM user_tables", {text_columns({"TABLE_NAME"}), {{Text("ITEMS")}}}});
    script->routes.push_back({"FROM user_views", {text_columns({"VIEW_NAME"}), {}}});
    script->routes.push_back(
        {"FROM user_tab_columns",
         {{Column("TABLE_NAME", 1), Column("COLUMN_NAME", 1), Column("DATA_TYPE", 1), Column("DATA_LENGTH", 2),
           Column("DATA_PRECISION", 2), Column("DATA_SCALE", 2), Column("NULLABLE", 1)},
          {{Text("ITEMS"), Text("ID"), Text("NUMBER"), Number("22"), Number("10"), Number("0"), Text("N")},
           {Text("ITEMS"), Text("LABEL"), Text("VARCHAR2"), Number("20"), WireValue(), WireValue(), Text("Y")}}}});
    script->routes.push_back({"FROM user_constraints", {text_columns({"TABLE_NAME", "COLUMN_NAME"}), {}}});
    script->tables["ITEMS"] = {{Column("ID", 2, 10, 0), Column("LABEL", 1)},
                               {{Number("1"), Text("first")}, {Number("2"), Text("second")}}};
    script->affected_rows = 1;

    auto factory = InstallFake(script);
    TestDatabase database;
    database.Run("ATTACH 'ora' AS ora (TYPE oracle_scanner);");

    // INSERT: one statement, the columns the query named, and one bind row per
    // row of the chunk — array DML, not one statement per row.
    database.Run("INSERT INTO ora.main.ITEMS (ID, LABEL) VALUES (7, 'seven'), (8, 'eight');");
    CHECK(!script->counted_executes.empty());
    CHECK(script->counted_executes.back() == "INSERT INTO \"ITEMS\" (\"ID\", \"LABEL\") VALUES (:1, :2)");
    CHECK(script->batch_rows.size() == 2);
    CHECK(script->batch_rows[0].size() == 2);
    CHECK(script->batch_rows[0][0].value == oracle_scanner::EncodeOracleNumber("7"));
    CHECK(script->batch_rows[0][1].value == std::vector<uint8_t>({'s', 'e', 'v', 'e', 'n'}));
    CHECK(script->batch_rows[1][0].value == oracle_scanner::EncodeOracleNumber("8"));

    // A column the statement does not name is left out of it, so Oracle applies
    // its own DEFAULT rather than receiving an explicit NULL.
    database.Run("INSERT INTO ora.main.ITEMS (ID) VALUES (9);");
    CHECK(script->counted_executes.back() == "INSERT INTO \"ITEMS\" (\"ID\") VALUES (:1)");

    // UPDATE addresses each row by its own ROWID, which the scan read as text.
    database.Run("UPDATE ora.main.ITEMS SET LABEL = 'renamed';");
    CHECK(script->counted_executes.back() ==
           "UPDATE \"ITEMS\" SET \"LABEL\" = :1 WHERE ROWID = CHARTOROWID(:2)");
    CHECK(script->batch_rows.size() == 2);
    CHECK(script->batch_rows[0].size() == 2);
    CHECK(script->batch_rows[0][1].value == std::vector<uint8_t>({'A', 'A', 'A', 'R', 'O', 'W', '0'}));
    CHECK(script->batch_rows[1][1].value == std::vector<uint8_t>({'A', 'A', 'A', 'R', 'O', 'W', '1'}));

    database.Run("DELETE FROM ora.main.ITEMS;");
    CHECK(script->counted_executes.back() == "DELETE FROM \"ITEMS\" WHERE ROWID = CHARTOROWID(:1)");
    CHECK(script->batch_rows[0].size() == 1);

    // RETURNING asks Oracle for the row it actually stored. Echoing back what
    // was sent would be wrong for exactly the cases the clause exists for, so
    // the fake answers with something the caller could not have supplied.
    script->returning_values["r1"] = Number("42");
    script->returning_values["r2"] = Text("from oracle");
    auto returned = database.Query("INSERT INTO ora.main.ITEMS (ID) VALUES (5) RETURNING ID, LABEL;");
    CHECK(!returned->HasError());
    CHECK(returned->RowCount() == 1);
    CHECK(returned->GetValue(0, 0).ToString() == "42");
    CHECK(returned->GetValue(1, 0).ToString() == "from oracle");
    // The statement carries RETURNING for every table column, because that is
    // the shape DuckDB evaluates the RETURNING list over, and one OUT bind per
    // column to receive them.
    CHECK(!script->returning_statements.empty());
    CHECK(script->returning_statements.back() ==
           "INSERT INTO \"ITEMS\" (\"ID\") VALUES (:1) RETURNING \"ID\", \"LABEL\" INTO :r1, :r2");
    CHECK(script->returning_binds.back().size() == 3);
    CHECK(script->returning_binds.back()[1].direction == oracle_scanner::BindDirection::BIND_OUT);

    // Two rows means two statements: the array form of RETURNING has no
    // evidence here, so each row is asked for on its own.
    const auto statements_before = script->returning_statements.size();
    CHECK(!database.Query("INSERT INTO ora.main.ITEMS (ID) VALUES (6), (7) RETURNING ID;")->HasError());
    CHECK(script->returning_statements.size() == statements_before + 2);

    // UPDATE and DELETE ... RETURNING: one statement per row, addressed by that
    // row's ROWID, asking for every column and for the row count, because a row
    // deleted since the scan read it returns nothing.
    script->returning_values["r1"] = Number("1");
    script->returning_values["r2"] = Text("renamed");
    script->returning_values["rc"] = Number("1");
    const auto before_update = script->returning_statements.size();
    auto updated = database.Query("UPDATE ora.main.ITEMS SET LABEL = 'renamed' RETURNING ID, LABEL;");
    CHECK(!updated->HasError() && updated->RowCount() == 2);
    CHECK(updated->GetValue(1, 0).ToString() == "renamed");
    CHECK(script->returning_statements.size() == before_update + 2);
    CHECK(script->returning_statements.back() ==
          "UPDATE \"ITEMS\" SET \"LABEL\" = :1, \"ID\" = :2 WHERE ROWID = CHARTOROWID(:3) RETURNING \"ID\", \"LABEL\" INTO :r1, :r2; "
          ":rc := SQL%ROWCOUNT");
    const auto before_delete = script->returning_statements.size();
    auto deleted = database.Query("DELETE FROM ora.main.ITEMS RETURNING ID, LABEL;");
    CHECK(!deleted->HasError() && deleted->RowCount() == 2);
    CHECK(script->returning_statements.size() == before_delete + 2);
    CHECK(script->returning_statements.back() ==
          "DELETE FROM \"ITEMS\" WHERE ROWID = CHARTOROWID(:1) RETURNING \"ID\", \"LABEL\" INTO :r1, :r2; "
          ":rc := SQL%ROWCOUNT");
    // A row that is gone by the time its statement runs is not reported.
    script->returning_values["rc"] = Number("0");
    auto gone = database.Query("DELETE FROM ora.main.ITEMS RETURNING ID;");
    CHECK(!gone->HasError() && gone->RowCount() == 0);
    script->returning_values.erase("rc");

    // Inside a transaction a read of the same catalog goes on the session the
    // write pinned, because Oracle shows uncommitted rows to that session and
    // to no other. The count is the check: a read that opened its own session
    // would answer from before the write.
    const auto opened_before = script->sessions_opened;
    const auto commits_before = script->commits;
    database.Run("BEGIN TRANSACTION;");
    database.Run("INSERT INTO ora.main.ITEMS (ID) VALUES (11);");
    const auto opened_after_write = script->sessions_opened;
    CHECK(opened_after_write == opened_before + 1);
    CHECK(!database.Query("SELECT ID FROM ora.main.ITEMS;")->HasError());
    CHECK(script->sessions_opened == opened_after_write);
    database.Run("COMMIT;");
    // One COMMIT for the whole transaction, not one per statement in it.
    CHECK(script->commits == commits_before + 1);

    std::cout << "attached writes run against a fake session" << std::endl;
}

// A function returning SYS_REFCURSOR. Its value does not come back as a value
// at all — the server sends a cursor — so the return bind has to be read from
// the cursor list rather than the scalar one, and reading the wrong list is how
// this used to be refused outright.
void TestFunctionsCanReturnARefCursor() {
    auto script = std::make_shared<FakeScript>();
    script->columns = {Column("OWNER", 1),     Column("PACKAGE_NAME", 1), Column("OBJECT_NAME", 1),
                       Column("OVERLOAD", 1),  Column("POSITION", 2),     Column("ARGUMENT_NAME", 1),
                       Column("DATA_TYPE", 1), Column("IN_OUT", 1),       Column("DATA_LEVEL", 2)};
    const auto argument_row = [](const std::string &position, const std::string &name, const std::string &type,
                                 const std::string &in_out) {
        WireRow row;
        row.push_back(Text("APP"));
        row.push_back(WireValue());
        row.push_back(Text("ROWS_OF"));
        row.push_back(WireValue());
        row.push_back(Number(position));
        row.push_back(name.empty() ? WireValue() : Text(name));
        row.push_back(Text(type));
        row.push_back(Text(in_out));
        row.push_back(Number("0"));
        return row;
    };
    script->rows = {argument_row("0", "", "REF CURSOR", "OUT"), argument_row("1", "P_N", "NUMBER", "IN")};
    // The rows the returned cursor will hand out.
    script->call_explicit_cursors = 1;

    auto factory = InstallFake(script);
    TestDatabase database;
    auto result = database.Query("SELECT * FROM oracle_call_auto('ora', 'rows_of', ['3']);");
    CHECK(!result->HasError());
    CHECK(result->RowCount() == 1);
    CHECK(result->GetValue(0, 0).ToString() == "return_value");
    // No scalar value: the result is the cursor, and the handle is how a caller
    // reaches it.
    CHECK(result->GetValue(1, 0).IsNull());
    CHECK(!result->GetValue(2, 0).IsNull());

    // The call carried a cursor return bind, which is what makes the server
    // open one; without it the function would have nowhere to put its result.
    CHECK(script->calls.size() == 1);
    CHECK(script->calls[0].kind == oracle_scanner::OracleCallableKind::FUNCTION);
    CHECK(script->calls[0].return_bind.has_value());
    CHECK(script->calls[0].return_bind->oracle_type == 102);
    CHECK(script->calls[0].return_bind->direction == oracle_scanner::BindDirection::BIND_OUT);

    std::cout << "functions can return a REF CURSOR" << std::endl;
}

// The shard boundaries are computed without overflow whatever the key range:
// each shard starts where the one before it ended, the first at the minimum and
// the last at the maximum, so nothing is lost or read twice.
void TestParallelScanRangesDoNotOverflow() {
    struct Case {
        const char *low;
        const char *high;
        int shards;
    };
    const Case cases[] = {{"-9223372036854775808", "9223372036854775807", 4},
                          {"-9223372036854775808", "9223372036854775807", 7},
                          {"-9000000000000000000", "9000000000000000000", 32},
                          {"0", "1000000000000000000", 32},
                          {"5", "5", 4},
                          {"5", "7", 8},
                          {"-3", "3", 3}};
    for (const auto &item : cases) {
        auto script = std::make_shared<FakeScript>();
        script->routes.push_back({"get_system_change_number", {{Column("SCN", 2)}, {{Number("1")}}}});
        script->routes.push_back({"WHERE 1 = 0", {{Column("ID", 2, 18, 0)}, {}}});
        script->routes.push_back({"MIN(", {{Column("LO", 2), Column("HI", 2), Column("NULLS", 2)},
                                           {{Number(item.low), Number(item.high), Number("0")}}}});
        script->tables["ITEMS"] = {{Column("ID", 2, 18, 0)}, {{Number("1")}}};
        auto factory = InstallFake(script);
        TestDatabase database;
        CHECK(!database.Query("SELECT count(*) FROM oracle_scan_parallel('ora', 'items', 'id', shards => " +
                              std::to_string(item.shards) + ");")
                   ->HasError());
        std::vector<std::pair<long long, long long>> ranges;
        for (const auto &statement : script->queries) {
            const auto low_at = statement.find("\"ID\" >= ");
            const auto high_at = statement.find("\"ID\" <= ");
            if (statement.find("AS OF SCN") != std::string::npos && low_at != std::string::npos && high_at != std::string::npos) {
                ranges.emplace_back(std::stoll(statement.substr(low_at + 8)), std::stoll(statement.substr(high_at + 8)));
            }
        }
        std::sort(ranges.begin(), ranges.end());
        CHECK(!ranges.empty());
        CHECK(ranges.front().first == std::stoll(item.low) && ranges.back().second == std::stoll(item.high));
        for (size_t index = 0; index < ranges.size(); index++) {
            CHECK(ranges[index].first <= ranges[index].second);
            if (index != 0) {
                CHECK(ranges[index].first == ranges[index - 1].second + 1);
            }
        }
    }
    std::cout << "parallel scan ranges cover every key once, at the extremes too" << std::endl;
}

// Sharding a table by key ranges. The parallelism is the easy half; what this
// pins is the half that would be wrong silently — every shard reading the same
// snapshot, and the ranges covering every key exactly once.
void TestParallelScanShardsOneSnapshot() {
    auto script = std::make_shared<FakeScript>();
    script->routes.push_back({"get_system_change_number", {{Column("SCN", 2)}, {{Number("991144")}}}});
    script->routes.push_back({"WHERE 1 = 0", {{Column("ID", 2, 10, 0), Column("LABEL", 1)}, {}}});
    script->routes.push_back({"MIN(", {{Column("LO", 2), Column("HI", 2), Column("NULLS", 2)},
                                       {{Number("1"), Number("100"), Number("0")}}}});
    script->tables["ITEMS"] = {{Column("ID", 2, 10, 0), Column("LABEL", 1)}, {{Number("1"), Text("first")}}};

    auto factory = InstallFake(script);
    TestDatabase database;
    auto result = database.Query("SELECT count(*) FROM oracle_scan_parallel('ora', 'items', 'id', shards => 4);");
    CHECK(!result->HasError());

    // Four shards, and the ranges have to cover 1..100 once each: a gap loses
    // rows and an overlap duplicates them, and both look like a working scan.
    std::vector<std::string> shard_statements;
    for (const auto &statement : script->queries) {
        // The describe also reads AS OF the same SCN, so a shard is recognised
        // by its range predicate rather than by the flashback clause.
        if (statement.find("FROM \"ITEMS\" AS OF SCN") != std::string::npos &&
            statement.find("\"ID\" >= ") != std::string::npos) {
            shard_statements.push_back(statement);
        }
    }
    CHECK(shard_statements.size() == 4);
    std::vector<bool> covered(101, false);
    for (const auto &statement : shard_statements) {
        // Every shard reads the same system change number. Different ones would
        // make this several moments rather than one snapshot.
        CHECK(statement.find("AS OF SCN 991144 ") != std::string::npos);
        const auto low_at = statement.find("\"ID\" >= ");
        const auto high_at = statement.find("\"ID\" <= ");
        CHECK(low_at != std::string::npos && high_at != std::string::npos);
        const auto low = std::stoll(statement.substr(low_at + 8));
        const auto high = std::stoll(statement.substr(high_at + 8));
        CHECK(low <= high);
        for (auto key = low; key <= high; key++) {
            CHECK(key >= 1 && key <= 100);
            CHECK(!covered[static_cast<size_t>(key)]);
            covered[static_cast<size_t>(key)] = true;
        }
    }
    for (size_t key = 1; key <= 100; key++) {
        CHECK(covered[key]);
    }

    // A key that can be NULL is in no range at all, so those rows need a shard
    // of their own or the scan quietly returns fewer rows than the table has.
    auto null_script = std::make_shared<FakeScript>();
    null_script->routes = script->routes;
    null_script->routes[2] = {"MIN(", {{Column("LO", 2), Column("HI", 2), Column("NULLS", 2)},
                                       {{Number("1"), Number("100"), Number("3")}}}};
    null_script->tables = script->tables;
    auto null_factory = InstallFake(null_script);
    TestDatabase null_database;
    CHECK(!null_database.Query("SELECT count(*) FROM oracle_scan_parallel('ora', 'items', 'id', shards => 2);")
                ->HasError());
    size_t null_shards = 0;
    for (const auto &statement : null_script->queries) {
        if (statement.find("\"ID\" IS NULL") != std::string::npos) {
            null_shards++;
        }
    }
    CHECK(null_shards == 1);

    std::cout << "parallel scans shard one snapshot" << std::endl;
}

// CONNECT_DESCRIPTOR: a full descriptor in the secret, with no wallet needed.
// What the adapter hands the session is checked field by field — the address
// lists, the routing policy, the timeouts — since that is everything the
// connect loop plans from. The endpoints are placeholders; nothing connects.
void TestConnectDescriptorSecretReachesTheSession() {
    auto script = std::make_shared<FakeScript>();
    script->columns = {Column("label", 1)};
    script->rows = {{Text("only")}};
    auto configs = std::make_shared<std::vector<ConnectionConfig>>();
    oracle_scanner::ScopedOracleSessionFactory factory([script, configs](const ConnectionConfig &config,
                                                                         const std::string &) {
        configs->push_back(config);
        return std::unique_ptr<OracleSession>(new FakeSession(script));
    });
    TestDatabase database;
    database.Run("CREATE SECRET multi (TYPE oracle, USER 'app_user', PASSWORD 'placeholder', CONNECT_DESCRIPTOR "
                 "'(DESCRIPTION=(CONNECT_TIMEOUT=90)(RETRY_COUNT=20)(RETRY_DELAY=3)(TRANSPORT_CONNECT_TIMEOUT=3)"
                 "(ADDRESS_LIST=(LOAD_BALANCE=on)(ADDRESS=(PROTOCOL=TCP)(HOST=scan.example)(PORT=1521)))"
                 "(ADDRESS_LIST=(ADDRESS=(PROTOCOL=TCP)(HOST=standby.example)(PORT=1522)))"
                 "(CONNECT_DATA=(SERVICE_NAME=sales.example)(INSTANCE_NAME=sales1)))');");
    CHECK(!database.Query("SELECT * FROM oracle_query('multi', 'SELECT label FROM app.items')")->HasError());
    CHECK(configs->size() == 1);
    const auto &config = configs->front();
    CHECK(config.host.empty() && config.service_name == "sales.example" && config.instance_name == "sales1");
    CHECK(config.routing.address_lists.size() == 2);
    CHECK(config.routing.address_lists[0].load_balance && !config.routing.address_lists[1].load_balance);
    CHECK(config.routing.address_lists[1].addresses[0].host == "standby.example" &&
          config.routing.address_lists[1].addresses[0].port == 1522);
    CHECK(config.routing.retry_count == 20 && config.routing.retry_delay_seconds == 3 &&
          config.routing.connect_budget_seconds == 90 && config.connect_timeout_seconds == 3);
    CHECK(config.protocol == oracle_scanner::TransportProtocol::TCP);
    // The query's interrupt flag is wired in, and it is clear.
    CHECK(config.connect_cancelled && !config.connect_cancelled());

    // Conflicts are refused at bind, before any session is asked for.
    const auto refused = [&](const std::string &secret_options, const std::string &expected) {
        database.Run("CREATE OR REPLACE SECRET bad (TYPE oracle, USER 'app_user', PASSWORD 'placeholder', " +
                     secret_options + ");");
        const auto before = configs->size();
        auto result = database.Query("SELECT * FROM oracle_query('bad', 'SELECT label FROM app.items')");
        CHECK(result->HasError());
        if (result->GetError().find(expected) == std::string::npos) {
            std::cerr << "unexpected error: " << result->GetError() << "\n";
            CHECK(false && "wrong error for a refused secret");
        }
        CHECK(configs->size() == before);
    };
    const std::string plain = "'(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=a.example)(PORT=1521))"
                              "(CONNECT_DATA=(SERVICE_NAME=svc)))'";
    refused("HOST 'a.example', CONNECT_DESCRIPTOR " + plain,
            "CONNECT_DESCRIPTOR cannot be combined with HOST, PORT, or SERVICE_NAME");
    refused("TNS_ALIAS 'x', CONNECT_DESCRIPTOR " + plain, "TNS_ALIAS and CONNECT_DESCRIPTOR cannot be combined");
    refused("PROTOCOL 'tcps', CONNECT_DESCRIPTOR " + plain, "CONNECT_DESCRIPTOR protocol does not match PROTOCOL 'tcps'");
    refused("TLS_SERVER_NAME 'a.example', CONNECT_DESCRIPTOR " + plain, "require PROTOCOL 'tcps'");
    refused("CONNECT_TIMEOUT 5, CONNECT_DESCRIPTOR '(DESCRIPTION=(TRANSPORT_CONNECT_TIMEOUT=3)"
            "(ADDRESS=(HOST=a.example)(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=svc)))'",
            "CONNECT_TIMEOUT disagrees with the CONNECT_DESCRIPTOR TRANSPORT_CONNECT_TIMEOUT");
    refused("CONNECT_DESCRIPTOR '(DESCRIPTION_LIST=(DESCRIPTION=(ADDRESS=(HOST=a)(PORT=1))"
            "(CONNECT_DATA=(SERVICE_NAME=svc)))(DESCRIPTION=(ADDRESS=(HOST=b)(PORT=1))"
            "(CONNECT_DATA=(SERVICE_NAME=other))))'",
            "different databases");
    refused("CONNECT_DESCRIPTOR '(DESCRIPTION=(ADDRESS=(HOST=a)(PORT=1))(CONNECT_DATA=(SERVICE_NAME=svc)"
            "(FAILOVER_MODE=(TYPE=select))))'",
            "FAILOVER_MODE (TAF) is not supported");

    // A TCPS descriptor takes TLS settings, and a wallet is not required.
    database.Run("CREATE SECRET secure (TYPE oracle, USER 'app_user', PASSWORD 'placeholder', "
                 "TLS_SERVER_NAME 'cert.example', CONNECT_DESCRIPTOR '(DESCRIPTION=(ADDRESS=(PROTOCOL=TCPS)"
                 "(HOST=a.example)(PORT=2484))(ADDRESS=(PROTOCOL=TCPS)(HOST=b.example)(PORT=2484))"
                 "(CONNECT_DATA=(SERVICE_NAME=svc)))');");
    CHECK(!database.Query("SELECT * FROM oracle_query('secure', 'SELECT label FROM app.items')")->HasError());
    CHECK(configs->back().protocol == oracle_scanner::TransportProtocol::TCPS);
    CHECK(configs->back().tls_server_name == "cert.example" && configs->back().wallet_pem_file.empty());

    // The HOST/PORT/SERVICE_NAME form is untouched: one address, no routing.
    CHECK(!database.Query("SELECT * FROM oracle_query('ora', 'SELECT label FROM app.items')")->HasError());
    CHECK(configs->back().host == "127.0.0.1" && configs->back().routing.address_lists.empty());

    std::cout << "connect descriptor secrets reach the session" << std::endl;
}

// The environment, portably: setenv and unsetenv are POSIX, and MSVC spells them _putenv_s.
void SetEnvironment(const char *name, const std::string &value) {
#if defined(_WIN32)
    CHECK(_putenv_s(name, value.c_str()) == 0);
#else
    CHECK(setenv(name, value.c_str(), 1) == 0);
#endif
}

void UnsetEnvironment(const char *name) {
#if defined(_WIN32)
    CHECK(_putenv_s(name, "") == 0);
#else
    CHECK(unsetenv(name) == 0);
#endif
}

// DSN and CONFIG_DIR: the python-oracledb spellings of the same three sources.
void TestDsnSecretReachesTheSession() {
    auto script = std::make_shared<FakeScript>();
    script->columns = {Column("label", 1)};
    script->rows = {{Text("only")}};
    auto configs = std::make_shared<std::vector<ConnectionConfig>>();
    oracle_scanner::ScopedOracleSessionFactory factory([script, configs](const ConnectionConfig &config,
                                                                         const std::string &) {
        configs->push_back(config);
        return std::unique_ptr<OracleSession>(new FakeSession(script));
    });
    TestDatabase database;
    const auto query = [&](const std::string &secret_options) {
        database.Run("CREATE OR REPLACE SECRET dsn_secret (TYPE oracle, USER 'app_user', PASSWORD 'placeholder', " +
                     secret_options + ");");
        return database.Query("SELECT * FROM oracle_query('dsn_secret', 'SELECT label FROM app.items')");
    };

    // Easy Connect, with a list of hosts and routing parameters.
    CHECK(!query("DSN 'a.example:1521,b.example:1522/sales.example?retry_count=4&transport_connect_timeout=3'")
               ->HasError());
    const auto &easy = configs->back();
    CHECK(easy.host.empty() && easy.service_name == "sales.example" && easy.routing.retry_count == 4 &&
          easy.connect_timeout_seconds == 3);
    CHECK(!easy.routing.address_lists.empty() && easy.protocol == oracle_scanner::TransportProtocol::TCP);
    size_t addresses = 0;
    for (const auto &list : easy.routing.address_lists) {
        addresses += list.addresses.size();
    }
    CHECK(addresses == 2);

    // A SID names the database the older way, from a secret or a descriptor; a
    // list of descriptions that name one database is read as its addresses.
    CHECK(!query("HOST 'h.example', SID 'orcl'")->HasError());
    CHECK(configs->back().sid == "orcl" && configs->back().service_name.empty());
    CHECK(!query("DSN '(DESCRIPTION=(ADDRESS=(HOST=a.example)(PORT=1521))(CONNECT_DATA=(SID=orcl2)))'")->HasError());
    CHECK(configs->back().sid == "orcl2" && configs->back().service_name.empty());
    CHECK(!query("DSN '(DESCRIPTION_LIST=(DESCRIPTION=(ADDRESS=(HOST=p.example)(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=svc)))"
                 "(DESCRIPTION=(ADDRESS=(HOST=q.example)(PORT=1522))(CONNECT_DATA=(SERVICE_NAME=svc))))'")
               ->HasError());
    CHECK(configs->back().service_name == "svc" && configs->back().routing.address_lists.size() == 2);
    {
        // A missing name is a refusal that says so, not an internal error.
        auto neither = query("HOST 'h.example'");
        CHECK(neither->HasError() && neither->GetError().find("requires a non-empty service_name") != std::string::npos);
    }
    {
        auto both = query("HOST 'h.example', SERVICE_NAME 'svc', SID 'orcl'");
        CHECK(both->HasError() && both->GetError().find("both SERVICE_NAME and SID") != std::string::npos);
    }

    // Session attributes ride on the secret.
    CHECK(!query("DSN 'a.example/svc', MODULE 'etl', ACTION 'load', CLIENT_IDENTIFIER 'u1', CLIENT_INFO 'run 7'")->HasError());
    CHECK(configs->back().module == "etl" && configs->back().action == "load" &&
          configs->back().client_identifier == "u1" && configs->back().client_info == "run 7");
    {
        auto too_long = query("DSN 'a.example/svc', ACTION '" + std::string(33, 'x') + "'");
        CHECK(too_long->HasError() && too_long->GetError().find("ACTION is longer than 32 bytes") != std::string::npos);
    }

    // tcps:// selects TLS the way a TCPS descriptor does.
    CHECK(!query("DSN 'tcps://secure.example:2484/svc', TLS_SERVER_NAME 'cert.example'")->HasError());
    CHECK(configs->back().protocol == oracle_scanner::TransportProtocol::TCPS &&
          configs->back().tls_server_name == "cert.example");

    // A descriptor works as a DSN too.
    CHECK(!query("DSN '(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=d.example)(PORT=1521))"
                 "(CONNECT_DATA=(SERVICE_NAME=svc)))'")
               ->HasError());
    CHECK(configs->back().service_name == "svc");

    // A bare name is an alias, looked up in CONFIG_DIR: a folder or the file.
    const auto folder =
        (std::filesystem::temp_directory_path() /
         ("oracle_scanner_config_dir_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count())))
            .string();
    CHECK(std::filesystem::create_directory(folder));
    const auto tnsnames_path = folder + "/tnsnames.ora";
    {
        std::ofstream output(tnsnames_path, std::ios::binary);
        output << "folder_db = (DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=f.example)(PORT=1530))"
                  "(CONNECT_DATA=(SERVICE_NAME=folder.example)))\n";
    }
    CHECK(!query("DSN 'folder_db', CONFIG_DIR '" + folder + "'")->HasError());
    CHECK(configs->back().service_name == "folder.example");
    CHECK(!query("TNS_ALIAS 'FOLDER_DB', CONFIG_DIR '" + tnsnames_path + "'")->HasError());
    CHECK(configs->back().routing.address_lists.at(0).addresses.at(0).port == 1530);

    const auto refused = [&](const std::string &secret_options, const std::string &expected) {
        const auto before = configs->size();
        auto result = query(secret_options);
        CHECK(result->HasError());
        if (result->GetError().find(expected) == std::string::npos) {
            std::cerr << "unexpected error: " << result->GetError() << "\n";
            CHECK(false && "wrong error for a refused secret");
        }
        CHECK(configs->size() == before);
    };
    refused("DSN 'a.example/svc', HOST 'a.example'", "DSN cannot be combined with HOST, PORT, or SERVICE_NAME");
    refused("DSN 'a.example/svc', TNS_ALIAS 'x', CONFIG_DIR '" + folder + "'",
            "DSN cannot be combined with TNS_ALIAS or CONNECT_DESCRIPTOR");
    refused("DSN 'folder_db'", "names an alias, which needs CONFIG_DIR");
    refused("DSN 'a.example/svc', CONFIG_DIR '" + folder + "'", "CONFIG_DIR is only used to look up");
    // TNS_ADMIN is where an alias is looked up when nothing else says, and
    // CONFIG_DIR still wins over it.
    SetEnvironment("TNS_ADMIN", folder);
    CHECK(!query("DSN 'folder_db'")->HasError());
    CHECK(configs->back().service_name == "folder.example");
    CHECK(!query("TNS_ALIAS 'folder_db'")->HasError());
    SetEnvironment("TNS_ADMIN", "/nonexistent_oracle_scanner_dir");
    CHECK(!query("DSN 'folder_db', CONFIG_DIR '" + folder + "'")->HasError());
    refused("DSN 'folder_db'", "could not be resolved");
    UnsetEnvironment("TNS_ADMIN");
    refused("DSN 'missing_alias', CONFIG_DIR '" + folder + "'", "DSN could not be resolved");
    refused("DSN 'a.example:1521'", "DSN could not be resolved");
    refused("DSN 'a.example/svc?https_proxy=p'", "is not supported");
    refused("DSN 'a.example/svc', PROTOCOL 'tcps'", "DSN protocol does not match PROTOCOL 'tcps'");
    refused("DSN 'a.example/svc', WALLET_FILE '/x'", "require PROTOCOL 'tcps'");

    std::filesystem::remove(tnsnames_path);
    std::filesystem::remove(folder);
    std::cout << "DSN and CONFIG_DIR secrets reach the session" << std::endl;
}

// Failover is for new connections only. A statement whose session fails after
// its SQL went out is not sent again — not on the same session, and not on a
// new one — and the next statement starts on a fresh session.
void TestFailedStatementIsNotReplayed() {
    auto script = std::make_shared<FakeScript>();
    script->columns = {Column("label", 1)};
    script->rows = {{Text("only")}};
    auto factory = InstallFake(script);
    TestDatabase database;
    script->fetch_failure = oracle_scanner::ProtocolErrorKind::TRUNCATED;
    script->fetch_failure_message = "connection closed mid-row";
    auto result = database.Query("SELECT * FROM oracle_query('ora', 'SELECT label FROM app.items')");
    CHECK(result->HasError());
    CHECK(result->GetError().find("connection closed mid-row") != std::string::npos);
    CHECK(script->queries.size() == 1 && script->sessions_opened == 1);

    script->fetch_failure.reset();
    CHECK(!database.Query("SELECT * FROM oracle_query('ora', 'SELECT label FROM app.items')")->HasError());
    CHECK(script->queries.size() == 2 && script->sessions_opened == 2);
    std::cout << "failed statements are not replayed" << std::endl;
}

// The dictionary rows ALL_ARGUMENTS gives for QUACK_DEMO_ADD in
// examples/demo_setup.sql: the return value at position 0, then P_A and P_B.
static std::vector<OracleColumn> DictionaryColumns() {
    return {Column("OWNER", 1),     Column("PACKAGE_NAME", 1), Column("OBJECT_NAME", 1),
            Column("OVERLOAD", 1),  Column("POSITION", 2),     Column("ARGUMENT_NAME", 1),
            Column("DATA_TYPE", 1), Column("IN_OUT", 1),       Column("DATA_LEVEL", 2)};
}

static std::vector<WireRow> QuackDemoAddDictionary() {
    const auto row = [](const std::string &position, const std::string &name, const std::string &in_out) {
        return WireRow {Text("DEMO"),         WireValue(),    Text("QUACK_DEMO_ADD"), WireValue(), Number(position),
                        name.empty() ? WireValue() : Text(name), Text("NUMBER"), Text(in_out),  Number("0")};
    };
    return {row("0", "", "OUT"), row("1", "P_A", "IN"), row("2", "P_B", "IN")};
}

// An attached catalog with one table, QUACK_DEMO_DEPARTMENTS, and a change
// number to read it at: what oracle_snapshot needs from Oracle.
static void AddSnapshotRoutes(FakeScript &script) {
    script.routes.push_back({"SELECT USER FROM DUAL", {{Column("USER", 1)}, {{Text("APP")}}}});
    script.routes.push_back({"dbms_flashback", {{Column("SCN", 2)}, {{Number("4242")}}}});
    script.routes.push_back({"FROM user_tables", {{Column("TABLE_NAME", 1)}, {{Text("QUACK_DEMO_DEPARTMENTS")}}}});
    script.routes.push_back({"FROM user_views", {{Column("VIEW_NAME", 1)}, {}}});
    script.routes.push_back(
        {"FROM user_tab_columns",
         {{Column("TABLE_NAME", 1), Column("COLUMN_NAME", 1), Column("DATA_TYPE", 1), Column("DATA_LENGTH", 2),
           Column("DATA_PRECISION", 2), Column("DATA_SCALE", 2), Column("NULLABLE", 1)},
          {{Text("QUACK_DEMO_DEPARTMENTS"), Text("DEPARTMENT_ID"), Text("NUMBER"), Number("22"), Number("6"), Number("0"), Text("Y")}}}});
    script.routes.push_back({"FROM user_constraints", {{Column("TABLE_NAME", 1), Column("COLUMN_NAME", 1)}, {}}});
    script.tables["QUACK_DEMO_DEPARTMENTS"] = {{Column("DEPARTMENT_ID", 2, 6, 0)}, {{Number("20")}, {Number("30")}, {Number("40")}}};
}

// oracle_snapshots lists tables from every attached database, and a refresh
// used to rebuild the snapshot by schema and table name alone, in the default
// database. A snapshot in an attached database file then replaced an ordinary
// table of the same name in the default one and left itself as it was. The
// snapshot is made where this session's USE points, refreshed where it is, and
// a name two snapshots share is refused rather than guessed.
void TestSnapshotRefreshStaysInItsDatabase() {
    auto script = std::make_shared<FakeScript>();
    AddSnapshotRoutes(*script);
    auto factory = InstallFake(script);
    TestDatabase database;
    database.Run("ATTACH 'ora' AS ora (TYPE oracle_scanner);");
    database.Run("ATTACH ':memory:' AS other;");
    const std::string make =
        "SELECT * FROM oracle_snapshot('ora', 'snap', 'SELECT * FROM ora.main.QUACK_DEMO_DEPARTMENTS');";
    database.Run("USE other;");
    database.Run(make);
    database.Run("USE memory;");
    // The first value of a query, or its error, so a check fails by saying so.
    const auto scalar = [&database](const std::string &sql) {
        auto result = database.Query(sql);
        if (result->HasError()) {
            return "error: " + result->GetError();
        }
        return result->RowCount() == 0 ? std::string("no rows") : result->GetValue(0, 0).ToString();
    };
    CHECK(scalar("SELECT count(*) FROM other.main.snap") == "3");
    CHECK(scalar("SELECT count(*) FROM duckdb_tables() WHERE database_name = 'memory' AND table_name = 'snap'") == "0");

    database.Run("CREATE TABLE snap AS SELECT 'mine' AS v;");
    auto listed = database.Query("SELECT database_name, schema_name, table_name FROM oracle_snapshots()");
    CHECK(!listed->HasError() && listed->RowCount() == 1 && listed->GetValue(0, 0).ToString() == "other" &&
          listed->GetValue(1, 0).ToString() == "main" && listed->GetValue(2, 0).ToString() == "snap");
    auto refreshed = database.Query("SELECT * FROM oracle_snapshot_refresh('snap')");
    CHECK(!refreshed->HasError() && refreshed->RowCount() == 1);
    CHECK(scalar("SELECT v FROM memory.main.snap") == "mine");
    CHECK(scalar("SELECT count(*) FROM other.main.snap") == "3");

    // A second snapshot of the same name, in the default database, makes the
    // bare name ambiguous; the qualified one still names exactly one table.
    database.Run("DROP TABLE memory.main.snap;");
    database.Run(make);
    auto ambiguous = database.Query("SELECT * FROM oracle_snapshot_refresh('snap')");
    CHECK(ambiguous->HasError() && ambiguous->GetError().find("more than one") != std::string::npos &&
          ambiguous->GetError().find("other.main.snap") != std::string::npos);
    CHECK(!database.Query("SELECT * FROM oracle_snapshot_refresh('other.main.snap')")->HasError());
    CHECK(!database.Query("SELECT * FROM oracle_snapshot_refresh('memory.main.snap')")->HasError());
    std::cout << "a snapshot refresh rebuilds its own table and no other" << std::endl;
}

// A NUMBER with no declared precision under oracle_unconstrained_number =
// 'decimal(10,1)' reads 1.21 and 1.24 as 1.2. Oracle compares the stored values,
// so a group key, a filter, a join key or a sort key on it sent to Oracle gave a
// different answer from the one DuckDB gives over what it read: GROUP BY x made
// two groups of 1.2, and x > 1.2 kept both rows. All of it now stays in DuckDB,
// and a column with a declared precision is still sent.
void TestRoundedNumberIsComparedInDuckDb() {
    auto script = std::make_shared<FakeScript>();
    script->routes.push_back({"SELECT USER FROM DUAL", {{Column("USER", 1)}, {{Text("APP")}}}});
    script->routes.push_back({"FROM user_tables", {{Column("TABLE_NAME", 1)}, {{Text("R")}}}});
    script->routes.push_back({"FROM user_views", {{Column("VIEW_NAME", 1)}, {}}});
    script->routes.push_back(
        {"FROM user_tab_columns",
         {{Column("TABLE_NAME", 1), Column("COLUMN_NAME", 1), Column("DATA_TYPE", 1), Column("DATA_LENGTH", 2),
           Column("DATA_PRECISION", 2), Column("DATA_SCALE", 2), Column("NULLABLE", 1)},
          {{Text("R"), Text("ID"), Text("NUMBER"), Number("22"), Number("10"), Number("0"), Text("Y")},
           {Text("R"), Text("X"), Text("NUMBER"), Number("22"), WireValue(), WireValue(), Text("Y")}}}});
    script->routes.push_back({"FROM user_constraints", {{Column("TABLE_NAME", 1), Column("COLUMN_NAME", 1)}, {}}});
    script->tables["R"] = {{Column("ID", 2, 10, 0), Column("X", 2)},
                           {{Number("1"), Number("1.21")}, {Number("2"), Number("1.24")}, {Number("3"), Number("2")}}};
    auto factory = InstallFake(script);
    TestDatabase database;
    database.Run("SET oracle_unconstrained_number = 'decimal(10,1)';");
    database.Run("SET oracle_aggregate_pushdown = true;");
    database.Run("SET oracle_join_pushdown = true;");
    database.Run("ATTACH 'ora' AS o (TYPE oracle_scanner);");

    auto grouped = database.Query("SELECT X, count(*) FROM o.main.R GROUP BY X ORDER BY X;");
    CHECK(!grouped->HasError() && grouped->RowCount() == 2);
    CHECK(grouped->GetValue(0, 0).ToString() == "1.2" && grouped->GetValue(1, 0).ToString() == "2");
    CHECK(script->queries.back().find("GROUP BY") == std::string::npos);

    auto filtered = database.Query("SELECT count(*) FROM o.main.R WHERE X > 1.2;");
    CHECK(!filtered->HasError() && filtered->GetValue(0, 0).ToString() == "1");
    CHECK(script->queries.back().find("WHERE") == std::string::npos);

    // Ranked by the rounded value, the two 1.2 rows tie and ID decides.
    auto ranked = database.Query("SELECT ID FROM o.main.R ORDER BY X, ID DESC LIMIT 1;");
    CHECK(!ranked->HasError() && ranked->GetValue(0, 0).ToString() == "2");
    CHECK(script->queries.back().find("FETCH FIRST") == std::string::npos);

    auto joined = database.Query("SELECT count(*) FROM o.main.R a JOIN o.main.R b ON a.X = b.X;");
    CHECK(!joined->HasError() && joined->GetValue(0, 0).ToString() == "5");
    for (const auto &query : script->queries) {
        CHECK(query.find("a.\"X\"") == std::string::npos);
    }

    // The declared column is exact, and its filter still goes to Oracle.
    CHECK(!database.Query("SELECT ID FROM o.main.R WHERE ID > 1;")->HasError());
    CHECK(script->queries.back().find("WHERE \"ID\" > 1") != std::string::npos);
    std::cout << "a rounded NUMBER is compared in DuckDB, not in Oracle" << std::endl;
}

static std::string Decoded(const std::optional<std::vector<uint8_t>> &wire) {
    CHECK(wire.has_value());
    return std::string(wire->begin(), wire->end());
}

// One registered example, and what it has to do against the fake session.
struct FunctionExampleCase {
    std::function<void(FakeScript &)> setup;
    // Statements run first, on the same connection, as the README's function
    // reference tells a reader to.
    std::vector<std::string> prerequisites;
    std::function<void(FakeScript &, MaterializedQueryResult &)> verify;
};

static std::map<std::string, FunctionExampleCase> FunctionExampleCases() {
    using oracle_scanner::BindDirection;
    using oracle_scanner::OracleCallableKind;
    const auto departments = [](FakeScript &script) {
        script.columns = {Column("DEPARTMENT_ID", 2, 6, 0), Column("DEPARTMENT_NAME", 1)};
        script.rows = {{Number("10"), Text("ACCOUNTING")}, {Number("20"), Text("RESEARCH")},
                       {Number("30"), Text("SALES")},      {Number("40"), Text("OPERATIONS")}};
    };
    const auto one_call = [](FakeScript &script) -> const OracleCallRequest & {
        CHECK(script.calls.size() == 1);
        return script.calls[0];
    };
    std::map<std::string, FunctionExampleCase> cases;

    cases["oracle_scanner_version"] = {nullptr, {}, [](FakeScript &, MaterializedQueryResult &result) {
                                           CHECK(result.RowCount() == 1 &&
                                                 !result.GetValue(0, 0).ToString().empty());
                                       }};
    cases["oracle_scanner_io_deadline_version"] = {nullptr, {}, [](FakeScript &, MaterializedQueryResult &result) {
                                                       CHECK(result.RowCount() == 1 &&
                                                             result.GetValue(0, 0).ToString() == "1");
                                                   }};
    cases["oracle_execute_admin"] = {
        [](FakeScript &) {}, {},
        [](FakeScript &script, MaterializedQueryResult &result) {
            CHECK(script.admin_executes.size() == 1);
            CHECK(result.GetValue(0, 0).GetValue<bool>());
        }};
    cases["oracle_transaction_status"] = {
        [](FakeScript &script) {
            script.routes.push_back({"SELECT USER FROM DUAL", {{Column("USER", 1)}, {{Text("APP")}}}});
        }, {"ATTACH 'demo' AS ora (TYPE oracle_scanner);"},
        [](FakeScript &, MaterializedQueryResult &result) {
            CHECK(result.GetValue(0, 0).ToString() == "not_attempted");
        }};
    cases["oracle_query"] = {[](FakeScript &script) {
                                 script.columns = {Column("VALUE", 2)};
                                 script.rows = {{Number("42")}};
                             },
                             {},
                             [](FakeScript &script, MaterializedQueryResult &result) {
                                 CHECK(script.queries.back() == "SELECT :1 AS value FROM dual");
                                 CHECK(script.query_binds.back().size() == 1);
                                 CHECK(result.RowCount() == 1 && result.GetValue(0, 0).ToString() == "42");
                             }};
    cases["oracle_query_transaction"] = {
        [](FakeScript &script) {
            script.routes.push_back({"SELECT USER FROM DUAL", {{Column("USER", 1)}, {{Text("APP")}}}});
            script.columns = {Column("VALUE", 2)};
            script.rows = {{Number("1")}};
        },
        {"ATTACH 'demo' AS ora (TYPE oracle_scanner);"},
        [](FakeScript &script, MaterializedQueryResult &result) {
            CHECK(script.queries.back() == "SELECT 1 FROM dual");
            CHECK(result.RowCount() == 1 && result.GetValue(0, 0).ToString() == "1");
        }};
    cases["oracle_query_transaction_typed"] = {
        [departments](FakeScript &script) {
            script.routes.push_back({"SELECT USER FROM DUAL", {{Column("USER", 1)}, {{Text("APP")}}}});
            departments(script);
        },
        {"ATTACH 'demo' AS ora (TYPE oracle_scanner);"},
        [](FakeScript &script, MaterializedQueryResult &result) {
            const std::string sql =
                "SELECT DEPARTMENT_ID, DEPARTMENT_NAME FROM QUACK_DEMO_DEPARTMENTS ORDER BY DEPARTMENT_ID";
            CHECK(std::count(script.queries.begin(), script.queries.end(), sql) == 1);
            CHECK(result.RowCount() == 4 && result.GetValue(0, 0).GetValue<int64_t>() == 10 &&
                  result.GetValue(1, 3).ToString() == "OPERATIONS");
            CHECK(result.GetTypes()[0] == duckdb::LogicalType::BIGINT);
        }};
    cases["oracle_execute_composite_transaction"] = {
        [](FakeScript &script) {
            script.routes.push_back({"SELECT USER FROM DUAL", {{Column("USER", 1)}, {{Text("APP")}}}});
        },
        {"ATTACH 'demo' AS ora (TYPE oracle_scanner);"},
        [one_call](FakeScript &script, MaterializedQueryResult &result) {
            const auto &call = one_call(script);
            CHECK(call.kind == OracleCallableKind::DML_COMPOSITE && call.qualified_name.empty());
            CHECK(call.dml_operations.size() == 2 && call.dml_operations[0].expected_rows == 1 &&
                  call.dml_operations[1].expected_rows == 1);
            CHECK(call.arguments.size() == 1 && call.arguments[0].name == "label");
            CHECK(result.RowCount() == 1 && result.GetValue(0, 0).GetValue<int64_t>() == 2);
        }};
    cases["oracle_execute_transaction"] = {
        [](FakeScript &script) {
            script.routes.push_back({"SELECT USER FROM DUAL", {{Column("USER", 1)}, {{Text("APP")}}}});
            script.affected_rows = 1;
        },
        {"ATTACH 'demo' AS ora (TYPE oracle_scanner);"},
        [](FakeScript &script, MaterializedQueryResult &result) {
            CHECK(script.counted_executes.size() == 1);
            CHECK(script.counted_execute_binds[0].size() == 1);
            CHECK(result.GetValue(0, 0).GetValue<int64_t>() == 1);
        }};
    cases["oracle_execute_many_transaction"] = {
        [](FakeScript &script) {
            script.routes.push_back({"SELECT USER FROM DUAL", {{Column("USER", 1)}, {{Text("APP")}}}});
            script.affected_rows = 1;
        },
        {"ATTACH 'demo' AS ora (TYPE oracle_scanner);"},
        [](FakeScript &script, MaterializedQueryResult &result) {
            // Exact counts are the default: one scalar execution per row.
            CHECK(script.counted_executes.size() == 1 &&
                  script.counted_executes[0] == "DELETE FROM QUACK_DEMO_LOG WHERE LOG_ID = :id");
            CHECK(script.counted_execute_binds[0].size() == 1);
            CHECK(result.RowCount() == 1 && result.GetValue(0, 0).ToString() == "1" &&
                  result.GetValue(1, 0).ToString() == "1" && result.GetValue(2, 0).GetValue<bool>());
        }};
    cases["oracle_call_named_transaction"] = {
        [](FakeScript &script) {
            script.routes.push_back({"SELECT USER FROM DUAL", {{Column("USER", 1)}, {{Text("APP")}}}});
            script.call_echo_outputs = true;
            script.call_output_values["P_TEXT"] = Text("Quack.");
        },
        {"ATTACH 'demo' AS ora (TYPE oracle_scanner);"},
        [one_call](FakeScript &script, MaterializedQueryResult &result) {
            const auto &call = one_call(script);
            CHECK(call.kind == OracleCallableKind::PROCEDURE && call.qualified_name == "QUACK_DEMO_MOTTO");
            CHECK(call.arguments.size() == 1 && call.arguments[0].name == "P_TEXT" &&
                  call.arguments[0].direction == BindDirection::BIND_OUT);
            CHECK(result.RowCount() == 1 && result.GetValue(0, 0).ToString() == "P_TEXT" &&
                  result.GetValue(1, 0).ToString() == "Quack.");
        }};
    cases["oracle_plsql"] = {
        [](FakeScript &script) {
            script.call_echo_outputs = true;
            script.call_output_values["greeting"] = Text("hello world");
        },
        {},
        [one_call](FakeScript &script, MaterializedQueryResult &result) {
            const auto &call = one_call(script);
            CHECK(call.kind == OracleCallableKind::ANONYMOUS_BLOCK && call.qualified_name.empty());
            CHECK(call.block.find("BEGIN :greeting := 'hello ' || :who; END;") == 0);
            CHECK(call.arguments.size() == 2 && call.arguments[0].name == "greeting" &&
                  call.arguments[0].direction == BindDirection::BIND_OUT && call.arguments[1].name == "who" &&
                  Decoded(call.arguments[1].value) == "world");
            CHECK(script.commits == 1);
            CHECK(result.RowCount() == 1 && result.GetValue(0, 0).ToString() == "greeting" &&
                  result.GetValue(1, 0).ToString() == "hello world");
        }};
    cases["oracle_plsql_transaction"] = {
        [](FakeScript &script) {
            script.routes.push_back({"SELECT USER FROM DUAL", {{Column("USER", 1)}, {{Text("APP")}}}});
            script.call_echo_outputs = true;
            script.call_output_values["n"] = Number("2");
        },
        {"ATTACH 'demo' AS ora (TYPE oracle_scanner);"},
        [one_call](FakeScript &script, MaterializedQueryResult &result) {
            const auto &call = one_call(script);
            CHECK(call.kind == OracleCallableKind::ANONYMOUS_BLOCK && call.block == "BEGIN :n := 1 + 1; END;");
            CHECK(call.arguments.size() == 1 && call.arguments[0].name == "n");
            CHECK(result.RowCount() == 1 && result.GetValue(0, 0).ToString() == "n" &&
                  result.GetValue(1, 0).ToString() == "2");
        }};
    const auto snapshot_setup = [](FakeScript &script) { AddSnapshotRoutes(script); };
    const std::string snapshot_attach = "ATTACH 'demo' AS ora (TYPE oracle_scanner);";
    const std::string snapshot_made =
        "SELECT * FROM oracle_snapshot('ora', 'departments_snapshot', 'SELECT * FROM ora.main.QUACK_DEMO_DEPARTMENTS WHERE department_id > 10');";
    cases["oracle_snapshot"] = {snapshot_setup, {snapshot_attach},
                                [](FakeScript &script, MaterializedQueryResult &result) {
                                    CHECK(result.RowCount() == 1 && result.GetValue(0, 0).ToString() == "departments_snapshot" &&
                                          result.GetValue(1, 0).ToString() == "3" && result.GetValue(2, 0).ToString() == "4242");
                                    // The table was read at the change number the snapshot recorded.
                                    bool pinned = false;
                                    for (const auto &query : script.queries) {
                                        pinned = pinned || query.find("FROM \"QUACK_DEMO_DEPARTMENTS\" AS OF SCN 4242") != std::string::npos;
                                    }
                                    CHECK(pinned);
                                }};
    cases["oracle_snapshot_refresh"] = {snapshot_setup, {snapshot_attach, snapshot_made},
                                        [](FakeScript &, MaterializedQueryResult &result) {
                                            CHECK(result.RowCount() == 1 && result.GetValue(0, 0).ToString() == "departments_snapshot");
                                        }};
    cases["oracle_snapshots"] = {snapshot_setup, {snapshot_attach, snapshot_made},
                                 [](FakeScript &, MaterializedQueryResult &result) {
                                     CHECK(result.RowCount() == 1 && result.GetValue(0, 0).ToString() == "memory" &&
                                           result.GetValue(2, 0).ToString() == "departments_snapshot" &&
                                           result.GetValue(3, 0).ToString() == "ora" &&
                                           result.GetValue(4, 0).ToString() == "4242");
                                 }};
    cases["oracle_vector_search"] = {
        [](FakeScript &script) {
            script.columns = {Column("ID", 2, 6, 0), Column("DISTANCE", 101)};
            script.rows = {{Number("7"), std::nullopt}};
        },
        {},
        [](FakeScript &script, MaterializedQueryResult &) {
            CHECK(!script.queries.empty());
            const auto &sql = script.queries.back();
            CHECK(sql == "SELECT t.*, VECTOR_DISTANCE(t.\"EMBEDDING\", :1, COSINE) AS \"DISTANCE\" FROM \"DOCS\" t "
                         "ORDER BY \"DISTANCE\" FETCH APPROX FIRST 5 ROWS ONLY");
            const auto &binds = script.query_binds.back();
            CHECK(binds.size() == 1 && binds[0].oracle_type == 127 && binds[0].value && !binds[0].value->empty());
        }};
    cases["oracle_execute"] = {[](FakeScript &script) { script.affected_rows = 1; },
                               {},
                               [](FakeScript &script, MaterializedQueryResult &result) {
                                   CHECK(script.counted_executes.size() == 1 &&
                                         script.counted_executes[0].find("INSERT INTO QUACK_DEMO_LOG") == 0);
                                   CHECK(script.counted_execute_binds[0].size() == 2);
                                   CHECK(result.GetValue(0, 0).GetValue<int64_t>() == 1);
                               }};
    cases["oracle_execute_many"] = {[](FakeScript &script) { script.affected_rows = 1; },
                                    {},
                                    [](FakeScript &script, MaterializedQueryResult &result) {
                                        CHECK(script.batch_rows.size() == 2 && script.batch_rows[0].size() == 2);
                                        CHECK(result.GetValue(0, 0).GetValue<int64_t>() == 2);
                                    }};
    cases["oracle_call_number"] = {[](FakeScript &script) {
                                       script.call_echo_outputs = true;
                                       script.call_output_values["r"] = Number("42");
                                   },
                                   {},
                                   [one_call](FakeScript &script, MaterializedQueryResult &result) {
                                       const auto &call = one_call(script);
                                       CHECK(call.kind == OracleCallableKind::FUNCTION &&
                                             call.qualified_name == "QUACK_DEMO_ANSWER" && call.arguments.empty());
                                       CHECK(result.GetValue(0, 0).ToString() == "42");
                                   }};
    cases["oracle_call_number_args"] = {
        [](FakeScript &script) {
            script.call_echo_outputs = true;
            script.call_output_values["r"] = Number("5");
        },
        {},
        [one_call](FakeScript &script, MaterializedQueryResult &result) {
            const auto &call = one_call(script);
            CHECK(call.kind == OracleCallableKind::FUNCTION && call.qualified_name == "QUACK_DEMO_ADD");
            CHECK(call.arguments.size() == 2 && call.arguments[0].name == "P_A" && call.arguments[1].name == "P_B");
            CHECK(call.arguments[0].direction == BindDirection::BIND_IN &&
                  oracle_scanner::DecodeOracleNumber(*call.arguments[0].value) == "2");
            CHECK(result.GetValue(0, 0).ToString() == "5");
        }};
    cases["oracle_call_out_number"] = {
        [](FakeScript &script) {
            script.call_echo_outputs = true;
            script.call_output_values["P_COUNT"] = Number("4");
        },
        {},
        [one_call](FakeScript &script, MaterializedQueryResult &result) {
            const auto &call = one_call(script);
            CHECK(call.kind == OracleCallableKind::PROCEDURE && call.qualified_name == "QUACK_DEMO_COUNT_DEPARTMENTS");
            CHECK(call.arguments.size() == 1 && call.arguments[0].name == "P_COUNT" &&
                  call.arguments[0].direction == BindDirection::BIND_OUT && call.arguments[0].oracle_type == 2);
            CHECK(result.GetValue(0, 0).ToString() == "4");
        }};
    cases["oracle_call_out_varchar"] = {
        [](FakeScript &script) {
            script.call_echo_outputs = true;
            script.call_output_values["P_TEXT"] = Text("no Oracle client required");
        },
        {},
        [one_call](FakeScript &script, MaterializedQueryResult &result) {
            const auto &call = one_call(script);
            CHECK(call.qualified_name == "QUACK_DEMO_MOTTO" && call.arguments.size() == 1 &&
                  call.arguments[0].name == "P_TEXT" && call.arguments[0].direction == BindDirection::BIND_OUT &&
                  call.arguments[0].oracle_type == 1);
            CHECK(result.GetValue(0, 0).ToString() == "no Oracle client required");
        }};
    cases["oracle_call_inout_number"] = {
        [](FakeScript &script) {
            script.call_echo_outputs = true;
            script.call_output_values["P_VALUE"] = Number("42");
        },
        {},
        [one_call](FakeScript &script, MaterializedQueryResult &result) {
            const auto &call = one_call(script);
            CHECK(call.qualified_name == "QUACK_DEMO_DOUBLE" && call.arguments.size() == 1 &&
                  call.arguments[0].name == "P_VALUE" && call.arguments[0].direction == BindDirection::BIND_IN_OUT);
            CHECK(oracle_scanner::DecodeOracleNumber(*call.arguments[0].value) == "21");
            CHECK(result.GetValue(0, 0).ToString() == "42");
        }};
    cases["oracle_call_inout_varchar"] = {
        [](FakeScript &script) {
            script.call_echo_outputs = true;
            script.call_output_values["P_TEXT"] = Text("QUACK");
        },
        {},
        [one_call](FakeScript &script, MaterializedQueryResult &result) {
            const auto &call = one_call(script);
            CHECK(call.qualified_name == "QUACK_DEMO_SHOUT" && call.arguments.size() == 1 &&
                  call.arguments[0].name == "P_TEXT" && call.arguments[0].direction == BindDirection::BIND_IN_OUT);
            CHECK(Decoded(call.arguments[0].value) == "quack");
            CHECK(result.GetValue(0, 0).ToString() == "QUACK");
        }};
    const auto one_handle = [](MaterializedQueryResult &result) {
        CHECK(result.RowCount() == 1);
        (void)oracle_scanner::ParseCursorHandle(result.GetValue(result.ColumnCount() - 1, 0).ToString());
    };
    cases["oracle_call"] = {[](FakeScript &script) { script.call_explicit_cursors = 1; },
                            {},
                            [one_call, one_handle](FakeScript &script, MaterializedQueryResult &result) {
                                const auto &call = one_call(script);
                                CHECK(call.qualified_name == "QUACK_DEMO_LIST" && call.arguments.size() == 1 &&
                                      call.arguments[0].name == "P_ROWS" &&
                                      call.arguments[0].oracle_type == oracle_scanner::ORACLE_WIRE_TYPE_CURSOR);
                                one_handle(result);
                            }};
    cases["oracle_call_implicit"] = {[](FakeScript &script) { script.call_implicit_cursors = 1; },
                                     {},
                                     [one_call, one_handle](FakeScript &script, MaterializedQueryResult &result) {
                                         const auto &call = one_call(script);
                                         CHECK(call.qualified_name == "QUACK_DEMO_IMPLICIT" &&
                                               call.arguments.empty());
                                         one_handle(result);
                                     }};
    cases["oracle_call_cursors"] = {[](FakeScript &script) { script.call_explicit_cursors = 1; },
                                    {},
                                    [one_call, one_handle](FakeScript &script, MaterializedQueryResult &result) {
                                        const auto &call = one_call(script);
                                        CHECK(call.qualified_name == "QUACK_DEMO_LIST" &&
                                              call.arguments.size() == 1 && call.arguments[0].name == "P_ROWS");
                                        one_handle(result);
                                    }};
    cases["oracle_call_named"] = {
        [](FakeScript &script) {
            script.call_echo_outputs = true;
            script.call_output_values["P_GREETING"] = Text("hello, world");
        },
        {},
        [one_call](FakeScript &script, MaterializedQueryResult &result) {
            const auto &call = one_call(script);
            CHECK(call.kind == OracleCallableKind::PROCEDURE && call.qualified_name == "QUACK_DEMO_GREET");
            CHECK(call.arguments.size() == 2 && call.arguments[0].name == "P_NAME" &&
                  call.arguments[0].direction == BindDirection::BIND_IN && Decoded(call.arguments[0].value) == "world");
            CHECK(call.arguments[1].name == "P_GREETING" && call.arguments[1].direction == BindDirection::BIND_OUT);
            CHECK(result.RowCount() == 1 && result.GetValue(0, 0).ToString() == "P_GREETING" &&
                  result.GetValue(1, 0).ToString() == "hello, world");
        }};
    cases["oracle_call_named_function"] = {
        [](FakeScript &script) {
            script.call_echo_outputs = true;
            script.call_output_values["return_value"] = Number("5");
        },
        {},
        [one_call](FakeScript &script, MaterializedQueryResult &result) {
            const auto &call = one_call(script);
            CHECK(call.kind == OracleCallableKind::FUNCTION && call.qualified_name == "QUACK_DEMO_ADD");
            CHECK(call.return_bind && call.return_bind->oracle_type == 2);
            CHECK(call.arguments.size() == 2 && call.arguments[1].name == "P_B" &&
                  oracle_scanner::DecodeOracleNumber(*call.arguments[1].value) == "3");
            CHECK(result.GetValue(0, 0).ToString() == "return_value" && result.GetValue(1, 0).ToString() == "5");
        }};
    cases["oracle_arguments"] = {[](FakeScript &script) {
                                     script.columns = DictionaryColumns();
                                     script.rows = QuackDemoAddDictionary();
                                 },
                                 {},
                                 [](FakeScript &script, MaterializedQueryResult &result) {
                                     CHECK(script.calls.empty());
                                     CHECK(result.RowCount() == 3);
                                     CHECK(result.GetValue(2, 1).ToString() == "P_A" &&
                                           result.GetValue(2, 2).ToString() == "P_B");
                                     for (duckdb::idx_t row = 0; row < 3; row++) {
                                         CHECK(result.GetValue(6, row).IsNull());
                                     }
                                 }};
    cases["oracle_call_auto"] = {
        [](FakeScript &script) {
            script.columns = DictionaryColumns();
            script.rows = QuackDemoAddDictionary();
            script.call_echo_outputs = true;
            script.call_output_values["return_value"] = Number("5");
        },
        {},
        [one_call](FakeScript &script, MaterializedQueryResult &result) {
            const auto &call = one_call(script);
            CHECK(call.kind == OracleCallableKind::FUNCTION &&
                  call.qualified_name.find("QUACK_DEMO_ADD") != std::string::npos);
            CHECK(call.arguments.size() == 2 && oracle_scanner::DecodeOracleNumber(*call.arguments[0].value) == "2" &&
                  oracle_scanner::DecodeOracleNumber(*call.arguments[1].value) == "3");
            CHECK(result.GetValue(0, 0).ToString() == "return_value" && result.GetValue(1, 0).ToString() == "5");
        }};
    // The two cursor examples read a handle from a DuckDB variable, which the
    // README's function reference fills from a fresh call first — one call
    // per example, since a handle is consumed.
    cases["oracle_cursor"] = {
        [departments](FakeScript &script) {
            departments(script);
            script.call_explicit_cursors = 1;
        },
        {"SET VARIABLE oracle_example_handle = (SELECT cursor_handle FROM oracle_call('demo', 'QUACK_DEMO_LIST', "
         "'P_ROWS'));"},
        [](FakeScript &, MaterializedQueryResult &result) {
            CHECK(result.RowCount() == 4 && result.ColumnCount() == 2);
            CHECK(result.GetValue(1, 3).ToString() == "OPERATIONS");
        }};
    cases["oracle_close_call"] = {
        [departments](FakeScript &script) {
            departments(script);
            script.call_explicit_cursors = 1;
        },
        {"SET VARIABLE oracle_close_handle = (SELECT cursor_handle FROM oracle_call('demo', 'QUACK_DEMO_LIST', "
         "'P_ROWS'));"},
        [](FakeScript &script, MaterializedQueryResult &result) {
            CHECK(result.RowCount() == 1 && result.GetValue(0, 0).GetValue<bool>());
            CHECK(script.cursor_closes >= 1);
        }};
    cases["oracle_scan_parallel"] = {
        [](FakeScript &script) {
            script.routes.push_back({"get_system_change_number", {{Column("SCN", 2)}, {{Number("991144")}}}});
            script.routes.push_back(
                {"WHERE 1 = 0", {{Column("DEPARTMENT_ID", 2, 6, 0), Column("DEPARTMENT_NAME", 1)}, {}}});
            script.routes.push_back({"MIN(", {{Column("LO", 2), Column("HI", 2), Column("NULLS", 2)},
                                              {{Number("10"), Number("40"), Number("0")}}}});
            script.tables["QUACK_DEMO_DEPARTMENTS"] = {{Column("DEPARTMENT_ID", 2, 6, 0), Column("DEPARTMENT_NAME", 1)},
                                                     {{Number("10"), Text("ACCOUNTING")}}};
        },
        {},
        [](FakeScript &script, MaterializedQueryResult &) {
            size_t shards = 0;
            for (const auto &statement : script.queries) {
                if (statement.find("FROM \"QUACK_DEMO_DEPARTMENTS\" AS OF SCN 991144") != std::string::npos &&
                    statement.find("\"DEPARTMENT_ID\" >= ") != std::string::npos) {
                    shards++;
                }
            }
            CHECK(shards == 4);
        }};
    return cases;
}

// Every example duckdb_functions() shows is run — the registered string itself,
// not a copy of it — against a fake session in the environment the examples
// promise: the extension loaded, a secret named `demo`, and the demo objects,
// here scripted. Parsing alone would not show that the arguments are right,
// so each case also checks the request the session actually received. Nothing
// here reaches a network.
void TestFunctionExamplesRun() {
    std::vector<std::pair<std::string, std::string>> examples;
    {
        TestDatabase database;
        auto listed = database.Query("SELECT function_name, function_type, examples FROM duckdb_functions() "
                                     "WHERE starts_with(function_name, 'oracle_') ORDER BY function_name");
        CHECK(!listed->HasError());
        for (duckdb::idx_t row = 0; row < listed->RowCount(); row++) {
            const auto list = duckdb::ListValue::GetChildren(listed->GetValue(2, row));
            CHECK(list.size() == 1);
            examples.emplace_back(listed->GetValue(0, row).ToString(), list[0].ToString());
        }
    }
    auto cases = FunctionExampleCases();
    // The same set on both sides: a function added without an executable
    // example, or a case left for a function that is gone, fails here.
    CHECK(examples.size() == cases.size() && examples.size() == 35);
    for (const auto &example : examples) {
        const auto found = cases.find(example.first);
        if (found == cases.end()) {
            std::cerr << "no example case for " << example.first << "\n";
            CHECK(false && "function example without a test case");
        }
        auto script = std::make_shared<FakeScript>();
        if (found->second.setup) {
            found->second.setup(*script);
        }
        auto factory = InstallFake(script);
        TestDatabase database;
        database.Run("CREATE SECRET demo (TYPE oracle, HOST '127.0.0.1', PORT 1521, SERVICE_NAME 'service', "
                     "USER 'app_user', PASSWORD 'placeholder');");
        for (const auto &statement : found->second.prerequisites) {
            database.Run(statement);
        }
        const auto is_scalar =
            example.first == "oracle_scanner_version" || example.first == "oracle_scanner_io_deadline_version";
        // Parsing first, the way each kind of example is meant to be used: a
        // scalar example is an expression, a table example one whole statement.
        if (is_scalar) {
            CHECK(duckdb::Parser::GetBuiltinParser().ParseExpressionList(example.second).size() == 1);
        } else {
            auto parser = duckdb::Parser::GetBuiltinParser();
            parser.ParseQuery(example.second);
            CHECK(parser.statements.size() == 1 &&
                  parser.statements[0]->type == duckdb::StatementType::SELECT_STATEMENT);
        }
        if (!is_scalar) {
            // A table example is exactly one SELECT from its own function.
            CHECK(example.second.rfind("SELECT * FROM " + example.first + "(", 0) == 0);
            CHECK(example.second.back() == ';');
        }
        script->calls.clear();
        auto result = database.Query(is_scalar ? "SELECT " + example.second : example.second);
        if (result->HasError()) {
            std::cerr << example.first << " example failed: " << result->GetError() << "\n";
            CHECK(false && "a documented example does not run");
        }
        found->second.verify(*script, *result);
    }

    // A handle is consumed by its first use, so running the oracle_cursor
    // example twice fails the second time: the reference has to tell readers
    // to make a fresh call for each.
    {
        auto script = std::make_shared<FakeScript>();
        script->columns = {Column("DEPARTMENT_ID", 2, 6, 0)};
        script->rows = {{Number("10")}};
        script->call_explicit_cursors = 1;
        auto factory = InstallFake(script);
        TestDatabase database;
        database.Run("CREATE SECRET demo (TYPE oracle, HOST '127.0.0.1', PORT 1521, SERVICE_NAME 'service', "
                     "USER 'app_user', PASSWORD 'placeholder');");
        database.Run(cases["oracle_cursor"].prerequisites[0]);
        const auto example = "SELECT * FROM oracle_cursor(getvariable('oracle_example_handle'));";
        CHECK(!database.Query(example)->HasError());
        CHECK(database.Query(example)->HasError());
    }
    std::cout << "every documented function example runs" << std::endl;
}

// Every documented registration uses ALTER_ON_CONFLICT, the conflict mode the
// bare RegisterFunction overloads set. Loading the extension twice would not
// show it — DuckDB may skip the second load — and registering the same
// signature again fails under either mode, so the infos the extension
// registers are inspected directly, all thirty-two of them.
void TestDocumentedRegistrationsAlterOnConflict() {
    std::vector<std::string> names;
    const auto check = [&](const duckdb::CreateFunctionInfo &info, const duckdb::Identifier &name) {
        CHECK(info.on_conflict == duckdb::OnCreateConflict::ALTER_ON_CONFLICT);
        CHECK(info.descriptions.size() == 1 && !info.descriptions[0].description.empty() &&
              info.descriptions[0].examples.size() == 1);
        names.push_back(static_cast<const std::string &>(name));
    };
    const auto version = duckdb::OracleScannerVersionFunctionInfo();
    check(version, version.functions.name);
    const auto io_deadline = duckdb::OracleIoDeadlineVersionFunctionInfo();
    check(io_deadline, io_deadline.functions.name);
    for (const auto &info : duckdb::OracleQueryFunctionInfos()) {
        check(info, info.functions.name);
    }
    const auto parallel = duckdb::OracleParallelScanFunctionInfo();
    check(parallel, parallel.functions.name);
    for (const auto &info : duckdb::OracleSnapshotFunctionInfos()) {
        check(info, info.functions.name);
    }
    CHECK(names.size() == 35);

    // And what that mode means on a database that already has the functions:
    // an extra overload under an existing name is added to it, where
    // ERROR_ON_CONFLICT refuses the same thing.
    TestDatabase database;
    duckdb::ExtensionLoader loader(*database.db.instance, "oracle_scanner");
    const auto overload = [] {
        return duckdb::TableFunction("oracle_arguments", {duckdb::LogicalType::INTEGER}, nullptr,
                                     [](duckdb::ClientContext &, duckdb::TableFunctionBindInput &,
                                        duckdb::vector<duckdb::LogicalType> &,
                                        duckdb::vector<duckdb::Identifier> &) -> duckdb::unique_ptr<duckdb::FunctionData> {
                                         return nullptr;
                                     });
    };
    duckdb::CreateTableFunctionInfo strict(overload());
    strict.on_conflict = duckdb::OnCreateConflict::ERROR_ON_CONFLICT;
    bool refused = false;
    try {
        loader.RegisterFunction(std::move(strict));
    } catch (const std::exception &) {
        refused = true;
    }
    CHECK(refused);
    duckdb::CreateTableFunctionInfo altering(overload());
    altering.on_conflict = duckdb::OnCreateConflict::ALTER_ON_CONFLICT;
    loader.RegisterFunction(std::move(altering));
    auto listed = database.Query("SELECT count(*) FROM duckdb_functions() WHERE function_name = 'oracle_arguments'");
    CHECK(!listed->HasError() && listed->GetValue(0, 0).GetValue<int64_t>() == 2);
    std::cout << "documented registrations use ALTER_ON_CONFLICT" << std::endl;
}

void TestReadOnlyHiddenCatalogGuardsWrites() {
    auto script = std::make_shared<FakeScript>();
    script->routes.push_back({"SELECT USER FROM DUAL", {{Column("USER", 1)}, {{Text("APP")}}}});
    script->columns = {Column("VALUE", 2)};
    script->rows = {{Number("42")}};
    script->affected_rows = 1;
    auto factory = InstallFake(script);
    TestDatabase database;
    database.Run("ATTACH 'ora' AS ro (TYPE oracle_scanner, READ_ONLY, HIDDEN true);");
    CHECK(database.Query("SELECT * FROM oracle_query_transaction('ro', 'SELECT 42 FROM dual');")->GetValue(0, 0).ToString() == "42");
    const auto opened = script->sessions_opened;
    auto refused = database.Query("SELECT * FROM oracle_execute_transaction('ro', 'INSERT INTO items VALUES (1)');");
    CHECK(refused->HasError() && refused->GetError().find("read-only") != std::string::npos);
    CHECK(script->sessions_opened == opened);
    database.Run("ATTACH 'ora' AS changed (TYPE oracle_scanner);");
    database.Run("PREPARE stale_write AS SELECT * FROM oracle_execute_transaction('changed', 'INSERT INTO items VALUES (1)');");
    database.Run("DETACH changed;");
    database.Run("ATTACH 'ora' AS changed (TYPE oracle_scanner, READ_ONLY);");
    const auto before_execution = script->sessions_opened;
    auto stale = database.Query("EXECUTE stale_write;");
    CHECK(stale->HasError() && stale->GetError().find("read-only") != std::string::npos);
    CHECK(script->sessions_opened == before_execution);
}

void TestRawCatalogTransactionsPinReadsAndWrites() {
    auto script = std::make_shared<FakeScript>();
    script->routes.push_back({"SELECT USER FROM DUAL", {{Column("USER", 1)}, {{Text("APP")}}}});
    script->columns = {Column("VALUE", 2)};
    script->rows = {{Number("42")}};
    script->affected_rows = 1;
    auto factory = InstallFake(script);
    TestDatabase database;
    database.Run("ATTACH 'ora' AS tx (TYPE oracle_scanner);");
    const auto opened = script->sessions_opened;
    const auto commits = script->commits;
    database.Run("BEGIN;");
    database.Run("SELECT * FROM oracle_query_transaction('tx', 'SELECT :1 FROM dual', [42]);");
    database.Run("SELECT * FROM oracle_execute_transaction('tx', 'INSERT INTO items VALUES (:1)', [1]);");
    database.Run("SELECT * FROM oracle_execute_transaction('tx', 'UPDATE items SET id = :1', [2]);");
    database.Run("SELECT * FROM oracle_query_transaction('tx', 'SELECT 42 FROM dual');");
    CHECK(script->sessions_opened == opened + 1);
    CHECK(script->commits == commits);
    database.Run("ROLLBACK;");
    CHECK(script->rollbacks == 1 && script->commits == commits);
    database.Run("BEGIN;");
    database.Run("SELECT * FROM oracle_execute_transaction('tx', 'DELETE FROM items');");
    database.Run("COMMIT;");
    CHECK(script->sessions_opened == opened + 2 && script->commits == commits + 1);

    // Invalid DDL must fail before opening an Oracle session.
    const auto before_ddl = script->sessions_opened;
    CHECK(database.Query("SELECT * FROM oracle_execute_transaction('tx', 'CREATE TABLE bad(id NUMBER)');")->HasError());
    CHECK(script->sessions_opened == before_ddl);
    CHECK(database.Query("SELECT * FROM oracle_query_transaction('memory', 'SELECT 1');")->HasError());
    database.Run("PREPARE admin_plan AS SELECT * FROM oracle_execute_admin('ora', 'CREATE TABLE ADMIN_PROBE (ID NUMBER)');");
    database.Run("BEGIN;");
    CHECK(database.Query("EXECUTE admin_plan;")->HasError());
    CHECK(database.Query("SELECT * FROM oracle_execute_admin('ora', 'CREATE TABLE ADMIN_PROBE (ID NUMBER)');")->HasError());
    CHECK(script->admin_executes.empty() && script->sessions_opened == before_ddl);
    database.Run("ROLLBACK;");
    database.Run("EXECUTE admin_plan;");
    CHECK(script->admin_executes.size() == 1);

    database.Run("PREPARE lake_read AS SELECT * FROM oracle_query_transaction('tx', 'SELECT 42 FROM dual');");
    database.Run("BEGIN;");
    CHECK(database.Query("EXECUTE lake_read;")->GetValue(0, 0).ToString() == "42");
    CHECK(database.Query("EXECUTE lake_read;")->GetValue(0, 0).ToString() == "42");
    database.Run("COMMIT;");
    database.Run("BEGIN;");
    CHECK(database.Query("EXECUTE lake_read;")->GetValue(0, 0).ToString() == "42");
    database.Run("ROLLBACK;");
    const auto stable_commits = script->commits;

    database.Run("BEGIN;");
    database.Run("SELECT * FROM oracle_execute_transaction('tx', 'INSERT INTO items VALUES (8)');");
    script->fetch_failure = oracle_scanner::ProtocolErrorKind::TRUNCATED;
    script->fetch_failure_message = "injected failed fetch";
    CHECK(database.Query("SELECT * FROM oracle_query_transaction('tx', 'SELECT 42 FROM dual');")->HasError());
    script->fetch_failure.reset();
    const auto after_fetch_failure = script->sessions_opened;
    CHECK(database.Query("SELECT * FROM oracle_execute_transaction('tx', 'INSERT INTO items VALUES (9)');")->HasError());
    CHECK(script->sessions_opened == after_fetch_failure);
    database.Run("ROLLBACK;");

    database.Run("BEGIN;");
    database.Run("SELECT * FROM oracle_execute_transaction('tx', 'INSERT INTO items VALUES (3)');");
    script->execute_should_fail = true;
    const auto rollbacks_before_failure = script->rollbacks;
    auto failed_dml = database.Query("SELECT * FROM oracle_execute_transaction('tx', 'INSERT INTO items VALUES (4)');");
    CHECK(failed_dml->HasError());
    // DRV-012: a session poisoned by a failed exchange is closed without
    // another Rollback, which could only wait on its unread response; closing
    // the connection is what rolls the server transaction back.
    CHECK(script->rollbacks == rollbacks_before_failure);
    CHECK(failed_dml->GetError().find("localized constraint failure") != std::string::npos);
    CHECK(failed_dml->GetErrorObject().ExtraInfo().count("oracle_error_code") == 1);
    CHECK(failed_dml->GetErrorObject().ExtraInfo().at("oracle_error_code") == "1");
    CHECK(failed_dml->GetErrorObject().ExtraInfo().at("oracle_connection_state") == "discarded");
    const auto after_failure = script->sessions_opened;
    CHECK(database.Query("SELECT * FROM oracle_execute_transaction('tx', 'INSERT INTO items VALUES (5)');")->HasError());
    CHECK(script->sessions_opened == after_failure && script->commits == stable_commits);
    database.Run("ROLLBACK;");
    script->execute_should_fail = false;
    database.Run("BEGIN;");
    database.Run("SELECT * FROM oracle_execute_transaction('tx', 'INSERT INTO items VALUES (6)');");
    script->commit_should_fail = true;
    auto failed_commit = database.Query("COMMIT;");
    CHECK(failed_commit->HasError());
    CHECK(failed_commit->GetError().find("outcome is unknown") != std::string::npos);
    auto status = database.Query("SELECT * FROM oracle_transaction_status('tx');");
    CHECK(!status->HasError());
    CHECK(status->GetValue(0, 0).ToString() == "unknown");
    CHECK(status->GetValue(1, 0).ToString() == "discarded");
    CHECK(status->GetValue(3, 0).GetValue<int32_t>() == static_cast<int32_t>(oracle_scanner::ProtocolErrorKind::TRUNCATED));
    script->commit_should_fail = false;
    database.Run("BEGIN;");
    database.Run("SELECT * FROM oracle_execute_transaction('tx', 'INSERT INTO items VALUES (7)');");
    database.Run("ROLLBACK;");
    std::cout << "raw catalog reads and writes follow commit/rollback and reject failed transaction reuse" << std::endl;
}

// The attached catalog's transaction pool, driven the way DuckLake drives it:
// every transaction on a DuckDB connection of its own, destroyed afterwards, so
// nothing a ClientContext owns survives from one transaction to the next.
static std::shared_ptr<FakeScript> PooledScript() {
    auto script = std::make_shared<FakeScript>();
    script->sessions_reusable = true;
    script->routes.push_back({"SELECT USER FROM DUAL", {{Column("USER", 1)}, {{Text("APP")}}}});
    script->routes.push_back({"SELECT 1 FROM DUAL", {{Column("1", 2)}, {{Number("1")}}}});
    script->affected_rows = 1;
    return script;
}

static bool RunOn(duckdb::DuckDB &db, const std::vector<std::string> &statements) {
    duckdb::Connection connection(db);
    bool ok = true;
    for (const auto &sql : statements) {
        ok = !connection.Query(sql)->HasError() && ok;
    }
    return ok;
}

static const std::string POOLED_INSERT = "SELECT * FROM oracle_execute_transaction('tx', 'INSERT INTO items VALUES (:1)', [1]);";

void TestTransactionSessionsAreReusedAcrossConnections() {
    auto script = PooledScript();
    auto factory = InstallFake(script);
    TestDatabase database;
    database.Run("ATTACH 'ora' AS tx (TYPE oracle_scanner);");
    // ATTACH read the current schema on a session it then left idle.
    CHECK(script->sessions_opened == 1 && script->session_closes == 0);
    const auto rollbacks = script->rollbacks;
    for (int round = 0; round < 3; round++) {
        CHECK(RunOn(database.db, {POOLED_INSERT}));
    }
    CHECK(script->sessions_opened == 1 && script->commits == 3 && script->counted_executes.size() == 3);
    // A ROLLBACK the server acknowledged ends a transaction as cleanly.
    CHECK(RunOn(database.db, {"BEGIN;", POOLED_INSERT, "ROLLBACK;"}));
    CHECK(script->sessions_opened == 1 && script->rollbacks == rollbacks + 1);
    CHECK(RunOn(database.db, {POOLED_INSERT}));
    CHECK(script->sessions_opened == 1 && script->session_closes == 0);

    // Each lease follows its own caller's deadline source, and a session put
    // back follows nobody's.
    // The leading entries unbind the dictionary leases ATTACH and the first
    // catalog lookup took with no caller; from then on every binding to a
    // caller is followed by an unbind.
    size_t first = 0;
    while (first < script->bound_sources.size() && !script->bound_sources[first]) {
        first++;
    }
    CHECK(first > 0 && first < script->bound_sources.size());
    std::vector<std::shared_ptr<oracle_scanner::OracleIoDeadline>> callers;
    for (size_t index = first; index < script->bound_sources.size(); index++) {
        if ((index - first) % 2 == 0) {
            CHECK(script->bound_sources[index] != nullptr);
            callers.push_back(script->bound_sources[index]);
        } else {
            CHECK(script->bound_sources[index] == nullptr);
        }
    }
    CHECK(callers.size() >= 5);
    CHECK(callers[1] != callers[2] && callers[2] != callers[3]);
}

// Nothing that may have left a session in an unknown state goes back: a
// failed statement, a COMMIT whose outcome is unknown, a rollback that failed,
// a stored procedure that may have changed the session itself.
void TestTransactionSessionsThatMustNotBeReused() {
    auto script = PooledScript();
    auto factory = InstallFake(script);
    TestDatabase database;
    database.Run("ATTACH 'ora' AS tx (TYPE oracle_scanner);");
    CHECK(RunOn(database.db, {POOLED_INSERT}));
    CHECK(script->sessions_opened == 1);

    script->execute_should_fail = true;
    CHECK(!RunOn(database.db, {POOLED_INSERT}));
    script->execute_should_fail = false;
    CHECK(script->session_closes == 1);
    CHECK(RunOn(database.db, {POOLED_INSERT}));
    CHECK(script->sessions_opened == 2);

    script->commit_should_fail = true;
    CHECK(!RunOn(database.db, {POOLED_INSERT}));
    script->commit_should_fail = false;
    CHECK(script->session_closes == 2);
    CHECK(RunOn(database.db, {POOLED_INSERT}));
    CHECK(script->sessions_opened == 3);

    script->rollback_should_fail = true;
    (void)RunOn(database.db, {"BEGIN;", POOLED_INSERT, "ROLLBACK;"});
    script->rollback_should_fail = false;
    CHECK(script->session_closes == 3);
    CHECK(RunOn(database.db, {POOLED_INSERT}));
    CHECK(script->sessions_opened == 4);

    script->call_echo_outputs = true;
    script->call_output_values["P_TEXT"] = Text("Quack.");
    CHECK(RunOn(database.db, {"SELECT * FROM oracle_call_named_transaction('tx', 'QUACK_DEMO_MOTTO', "
                              "[{name:'P_TEXT',direction:'out',type:'varchar',value:NULL::VARCHAR}]);"}));
    CHECK(script->session_closes == 4);
    CHECK(RunOn(database.db, {POOLED_INSERT}));
    CHECK(script->sessions_opened == 5 && script->session_closes == 4);
}

// The pool is bounded, can be switched off, and gives everything back when the
// catalog goes; a connection destroyed mid-transaction rolls back first.
void TestTransactionPoolSizeDetachAndAbandonedTransactions() {
    {
        auto script = PooledScript();
        auto factory = InstallFake(script);
        TestDatabase database;
        database.Run("SET oracle_transaction_pool_size = 0;");
        database.Run("ATTACH 'ora' AS tx (TYPE oracle_scanner);");
        CHECK(RunOn(database.db, {POOLED_INSERT}));
        const auto opened = script->sessions_opened;
        CHECK(RunOn(database.db, {POOLED_INSERT}) && RunOn(database.db, {POOLED_INSERT}));
        // One fresh session per transaction, none of them bound or reused.
        CHECK(script->sessions_opened == opened + 2 && script->bound_sources.empty());
        database.Run("SET oracle_transaction_pool_size = 65;");
        CHECK(database.Query("ATTACH 'ora' AS refused (TYPE oracle_scanner);")->HasError());
    }
    auto script = PooledScript();
    auto factory = InstallFake(script);
    TestDatabase database;
    database.Run("SET oracle_transaction_pool_size = 1;");
    database.Run("ATTACH 'ora' AS tx (TYPE oracle_scanner);");
    {
        duckdb::Connection first(database.db);
        duckdb::Connection second(database.db);
        CHECK(!first.Query("BEGIN;")->HasError() && !first.Query(POOLED_INSERT)->HasError());
        CHECK(!second.Query("BEGIN;")->HasError() && !second.Query(POOLED_INSERT)->HasError());
        // Two transactions at once hold two sessions, never one between them.
        CHECK(script->sessions_opened == 2);
        CHECK(!first.Query("COMMIT;")->HasError() && !second.Query("COMMIT;")->HasError());
        // Room for one idle session: the other is closed.
        CHECK(script->session_closes == 1);
    }
    {
        duckdb::Connection abandoned(database.db);
        CHECK(!abandoned.Query("BEGIN;")->HasError() && !abandoned.Query(POOLED_INSERT)->HasError());
    }
    // Destroying the connection rolled the transaction back, and that
    // acknowledged rollback let the session go back.
    CHECK(script->sessions_opened == 2 && script->session_closes == 1);
    CHECK(RunOn(database.db, {POOLED_INSERT}));
    CHECK(script->sessions_opened == 2);
    database.Run("DETACH tx;");
    CHECK(script->session_closes == 2);
}

// Two catalogs attached from two secrets keep two pools: each transaction runs
// on a session opened from its own catalog's secret.
void TestTransactionPoolsDoNotMixSecrets() {
    auto script = PooledScript();
    auto factory = InstallFake(script);
    TestDatabase database;
    database.Run("CREATE SECRET other (TYPE oracle, HOST '127.0.0.1', PORT 1521, SERVICE_NAME 'service', "
                 "USER 'other_user', PASSWORD 'placeholder');");
    database.Run("ATTACH 'ora' AS tx (TYPE oracle_scanner);");
    database.Run("ATTACH 'other' AS tx_other (TYPE oracle_scanner);");
    CHECK(script->session_users.size() == 2);
    const std::string other_insert =
        "SELECT * FROM oracle_execute_transaction('tx_other', 'INSERT INTO items VALUES (:1)', [1]);";
    for (int round = 0; round < 2; round++) {
        CHECK(RunOn(database.db, {POOLED_INSERT}) && RunOn(database.db, {other_insert}));
    }
    CHECK(script->sessions_opened == 2);
    CHECK(script->execute_users.size() == 4);
    for (size_t index = 0; index < script->execute_users.size(); index++) {
        CHECK(script->execute_users[index] == (index % 2 == 0 ? "app_user" : "other_user"));
    }
}

// Connection::Interrupt reaches the IO of every transaction path, on a session
// the pool handed out: opening a query (a SELECT FOR UPDATE waits on its lock
// right there, at bind), a scalar statement, and a batch. Each waits until the
// caller's deadline expires, so only the interrupt can end it; the statement
// is sent once, the session is not reused, and the connection goes on.
void TestInterruptReachesEveryTransactionPath() {
    struct Path {
        std::string name;
        std::string fragment;
        std::string sql;
    };
    const std::vector<Path> paths = {
        {"query open", "FOR UPDATE",
         "SELECT * FROM oracle_query_transaction('tx', 'SELECT id FROM items WHERE id = 1 FOR UPDATE');"},
        {"scalar execute", "SET n = n + 1",
         "SELECT * FROM oracle_execute_transaction('tx', 'UPDATE items SET n = n + 1 WHERE id = 1');"},
        {"batch", "SET n = n + 2",
         "SELECT * FROM oracle_execute_many_transaction('tx', 'UPDATE items SET n = n + 2 WHERE id = :id', [{id: 1}]);"},
        {"composite", "SET n = n + 3",
         "SELECT * FROM oracle_execute_composite_transaction('tx', "
         "['UPDATE items SET n = n + 3 WHERE id = :id'], {id: 1}, [1]);"},
        {"typed query open", "FOR UPDATE NOWAIT",
         "SELECT * FROM oracle_query_transaction_typed('tx', 'SELECT id FROM items WHERE id = 1 FOR UPDATE NOWAIT', "
         "['ID'], ['VARCHAR']);"},
    };
    for (const auto &path : paths) {
        auto script = PooledScript();
        script->columns = {Column("ID", 2)};
        script->rows = {{Number("1")}};
        auto factory = InstallFake(script);
        TestDatabase database;
        database.Run("ATTACH 'ora' AS tx (TYPE oracle_scanner);");
        CHECK(RunOn(database.db, {POOLED_INSERT}));
        const auto opened = script->sessions_opened;
        const auto closes = script->session_closes;
        script->block_until_deadline = path.fragment;
        duckdb::Connection connection(database.db);
        bool failed = false;
        std::chrono::steady_clock::time_point returned;
        std::thread runner([&] {
            failed = connection.Query(path.sql)->HasError();
            returned = std::chrono::steady_clock::now();
        });
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
        const auto interrupted = std::chrono::steady_clock::now();
        connection.Interrupt();
        runner.join();
        if (!failed || returned - interrupted >= std::chrono::seconds(1)) {
            std::cerr << "interrupt did not reach " << path.name << "\n";
        }
        CHECK(failed && returned - interrupted < std::chrono::seconds(1));
        // It ran on the session the pool handed out, it was sent once, and
        // that session, its exchange failed, is closed rather than returned.
        CHECK(script->sessions_opened == opened && script->blocked_statements == 1);
        CHECK(script->session_closes == closes + 1);
        script->block_until_deadline.clear();
        // The connection goes on: a new transaction begins and commits.
        CHECK(!connection.Query("BEGIN;")->HasError() && !connection.Query(POOLED_INSERT)->HasError() &&
              !connection.Query("COMMIT;")->HasError());
        CHECK(script->blocked_statements == 1);
    }
}

static size_t CountQueries(const FakeScript &script, const std::string &sql) {
    return static_cast<size_t>(std::count(script.queries.begin(), script.queries.end(), sql));
}

// oracle_query_transaction_typed: binding sends nothing to Oracle, every
// execution sends the statement exactly once in the transaction current then,
// and a describe that does not match the declaration is an error, never a
// silently different result.
void TestTypedTransactionQuery() {
    auto script = std::make_shared<FakeScript>();
    script->routes.push_back({"SELECT USER FROM DUAL", {{Column("USER", 1)}, {{Text("APP")}}}});
    script->routes.push_back({"FROM ITEMS", {{Column("ID", 2, 10, 0), Column("LABEL", 1), Column("PRICE", 2, 10, 2)},
                                              {{Number("7"), Text("seven"), Number("12.5")}}}});
    script->routes.push_back({"FROM WIDE", {{Column("ID", 2, 10, 0), Column("LABEL", 1), Column("EXTRA", 1)}, {}}});
    script->routes.push_back({"FROM RENAMED", {{Column("ID", 2, 10, 0), Column("TITLE", 1)}, {}}});
    script->routes.push_back({"FROM RETYPED", {{Column("ID", 1), Column("LABEL", 1)}, {}}});
    auto factory = InstallFake(script);
    TestDatabase database;
    database.Run("ATTACH 'ora' AS tx (TYPE oracle_scanner);");

    const std::string sql = "SELECT ID, LABEL, PRICE FROM ITEMS WHERE ID = :id";
    const std::string call = "oracle_query_transaction_typed('tx', '" + sql +
                             "', ['id', 'LABEL', 'price'], ['BIGINT', 'varchar', 'DECIMAL(10,2)'], {id: 7})";
    const auto opened = script->sessions_opened;
    const auto sent = script->queries.size();
    database.Run("PREPARE typed AS SELECT * FROM " + call + ";");
    CHECK(script->sessions_opened == opened && script->queries.size() == sent);

    auto first = database.Query("EXECUTE typed;");
    CHECK(!first->HasError() && first->RowCount() == 1);
    CHECK(first->GetNames() == std::vector<std::string>({"id", "LABEL", "price"}));
    CHECK(first->GetTypes()[0] == duckdb::LogicalType::BIGINT && first->GetTypes()[1] == duckdb::LogicalType::VARCHAR &&
          first->GetTypes()[2] == duckdb::LogicalType::DECIMAL(10, 2));
    CHECK(first->GetValue(0, 0).GetValue<int64_t>() == 7 && first->GetValue(1, 0).ToString() == "seven" &&
          first->GetValue(2, 0).ToString() == "12.50");
    CHECK(CountQueries(*script, sql) == 1);
    CHECK(script->query_binds.back().size() == 1 && script->query_binds.back()[0].name == "id");

    // Inside a transaction both executions ride its one session; after COMMIT
    // the same plan runs on the next transaction's, never on a cursor or a
    // session left over from the last.
    database.Run("BEGIN;");
    const auto in_transaction = script->sessions_opened;
    CHECK(!database.Query("EXECUTE typed;")->HasError() && !database.Query("EXECUTE typed;")->HasError());
    CHECK(script->sessions_opened == in_transaction + 1 && CountQueries(*script, sql) == 3);
    database.Run("COMMIT;");
    database.Run("BEGIN;");
    CHECK(database.Query("EXECUTE typed;")->GetValue(1, 0).ToString() == "seven");
    CHECK(script->sessions_opened == in_transaction + 2 && CountQueries(*script, sql) == 4);
    database.Run("ROLLBACK;");
    // Positional binds work as well.
    CHECK(!database.Query("SELECT * FROM oracle_query_transaction_typed('tx', 'SELECT ID, LABEL, PRICE FROM ITEMS "
                          "WHERE ID = :1', ['ID', 'LABEL', 'PRICE'], ['BIGINT', 'VARCHAR', 'DECIMAL(10,2)'], [7]);")
               ->HasError());

    // Each kind of mismatch, reported for what it is; the statement ran once.
    const auto mismatch = [&](const std::string &table, const std::string &expected) {
        const auto statement = "SELECT * FROM oracle_query_transaction_typed('tx', 'SELECT * FROM " + table +
                               "', ['ID', 'LABEL'], ['BIGINT', 'VARCHAR']);";
        auto refused = database.Query(statement);
        if (!refused->HasError() || refused->GetError().find(expected) == std::string::npos) {
            std::cerr << "typed mismatch for " << table << ": " << refused->GetError() << "\n";
        }
        CHECK(refused->HasError() && refused->GetError().find(expected) != std::string::npos);
        CHECK(CountQueries(*script, "SELECT * FROM " + table) == 1);
    };
    mismatch("WIDE", "Oracle returned 3 columns where the declaration has 2");
    mismatch("RENAMED", "Oracle column 2 is TITLE where LABEL was declared");
    mismatch("RETYPED", "Oracle column ID maps to VARCHAR where BIGINT was declared");
    // A table that changes under a prepared plan is caught the same way.
    script->routes[1].second.columns[2] = Column("PRICE", 101);
    auto changed = database.Query("EXECUTE typed;");
    CHECK(changed->HasError() &&
          changed->GetError().find("PRICE maps to DOUBLE where DECIMAL(10,2) was declared") != std::string::npos);
    // ... and a mismatch inside a transaction ends it, without a rollback that
    // would wait on the session.
    database.Run("BEGIN;");
    const auto rollbacks = script->rollbacks;
    CHECK(database.Query("EXECUTE typed;")->HasError());
    CHECK(database.Query("SELECT * FROM oracle_execute_transaction('tx', 'DELETE FROM ITEMS')")->HasError());
    database.Run("ROLLBACK;");
    CHECK(script->rollbacks == rollbacks);

    // Every refusal at bind happens before a session or a statement.
    const auto refused_at_bind = [&](const std::string &arguments, const std::string &expected) {
        const auto before_sessions = script->sessions_opened;
        const auto before_queries = script->queries.size();
        auto refused = database.Query("SELECT * FROM oracle_query_transaction_typed(" + arguments + ");");
        if (!refused->HasError() || refused->GetError().find(expected) == std::string::npos) {
            std::cerr << "typed bind for " << arguments << ": " << refused->GetError() << "\n";
        }
        CHECK(refused->HasError() && refused->GetError().find(expected) != std::string::npos);
        CHECK(script->sessions_opened == before_sessions && script->queries.size() == before_queries);
    };
    refused_at_bind("'tx', 'SELECT D FROM ITEMS', ['D'], ['DATE']", "is not one an Oracle column maps to");
    refused_at_bind("'tx', 'SELECT N FROM ITEMS', ['N'], ['INTEGER']", "is not one an Oracle column maps to");
    refused_at_bind("'tx', 'SELECT N FROM ITEMS', ['N'], ['NOT_A_TYPE']", "is not a DuckDB type");
    refused_at_bind("'tx', 'SELECT A, B FROM ITEMS', ['A', 'a'], ['VARCHAR', 'VARCHAR']", "non-empty and unique");
    refused_at_bind("'tx', 'SELECT A FROM ITEMS', [''], ['VARCHAR']", "non-empty and unique");
    refused_at_bind("'tx', 'SELECT A FROM ITEMS', ['A'], ['VARCHAR', 'BIGINT']", "as many column types");
    refused_at_bind("'tx', 'SELECT A FROM ITEMS', []::VARCHAR[], []::VARCHAR[]", "at least one");
    refused_at_bind("'tx', 'SELECT A FROM ITEMS', ['A', NULL], ['VARCHAR', 'VARCHAR']", "cannot contain NULL");
    refused_at_bind("'tx', NULL, ['A'], ['VARCHAR']", "cannot be NULL");
    refused_at_bind("'tx', 'DELETE FROM ITEMS', ['A'], ['VARCHAR']", "only SELECT or WITH");
    refused_at_bind("'tx', 'SELECT A FROM ITEMS WHERE ID = :id', ['A'], ['VARCHAR']", "do not match");
    refused_at_bind("'tx', 'SELECT A FROM ITEMS', ['A'], ['VARCHAR'], [1], [2]", "at most one params");
    refused_at_bind("'memory', 'SELECT A FROM ITEMS', ['A'], ['VARCHAR']", "attached oracle_scanner catalog");
    std::cout << "typed transaction query binds locally, runs once per execution and refuses a different describe"
              << std::endl;
}

static const std::string COMPOSITE_INSERT_AND_UPDATE =
    "SELECT * FROM oracle_execute_composite_transaction('tx', "
    "['INSERT INTO ITEMS (ID, LABEL) VALUES (:id, :label)', 'UPDATE ITEMS SET N = N + 1 WHERE ID = :id'], "
    "{label: 'x', id: 1}, [1, 1]);";

// oracle_execute_composite_transaction: one request with every statement, its
// expected count and each bind once; no COMMIT of its own; every refusal
// before a session; and a failure that ends the transaction instead of being
// retried or rolled back on a session that may still be answering.
void TestCompositeTransactionDml() {
    auto script = std::make_shared<FakeScript>();
    script->routes.push_back({"SELECT USER FROM DUAL", {{Column("USER", 1)}, {{Text("APP")}}}});
    auto factory = InstallFake(script);
    TestDatabase database;
    database.Run("ATTACH 'ora' AS tx (TYPE oracle_scanner);");
    database.Run("ATTACH 'ora' AS ro (TYPE oracle_scanner, READ_ONLY);");

    database.Run("BEGIN;");
    const auto commits = script->commits;
    auto result = database.Query(COMPOSITE_INSERT_AND_UPDATE);
    CHECK(!result->HasError() && result->RowCount() == 1 && result->GetValue(0, 0).GetValue<int64_t>() == 2);
    CHECK(script->calls.size() == 1 && script->commits == commits);
    const auto &call = script->calls[0];
    CHECK(call.kind == oracle_scanner::OracleCallableKind::DML_COMPOSITE && call.qualified_name.empty() &&
          !call.return_bind);
    CHECK(call.dml_operations.size() == 2 &&
          call.dml_operations[0].sql == "INSERT INTO ITEMS (ID, LABEL) VALUES (:id, :label)" &&
          call.dml_operations[1].sql == "UPDATE ITEMS SET N = N + 1 WHERE ID = :id");
    CHECK(call.dml_operations[0].expected_rows == 1 && call.dml_operations[1].expected_rows == 1);
    // :id is used twice and bound once.
    CHECK(call.arguments.size() == 2);
    // It rides the transaction: a later statement in it uses the same session,
    // and only DuckDB's COMMIT commits.
    const auto opened = script->sessions_opened;
    database.Run("SELECT * FROM oracle_execute_transaction('tx', 'DELETE FROM ITEMS WHERE ID = 2');");
    CHECK(script->sessions_opened == opened && script->commits == commits);
    database.Run("COMMIT;");
    CHECK(script->commits == commits + 1);

    // Positional binds, and a statement with no binds at all.
    CHECK(!database.Query("SELECT * FROM oracle_execute_composite_transaction('tx', "
                          "['DELETE FROM ITEMS WHERE ID = :1', 'UPDATE ITEMS SET N = :2 WHERE ID = :1', "
                          "'DELETE FROM ITEMS WHERE ID < 0'], [3, 4], [1, 0, 0]);")
               ->HasError());
    CHECK(script->calls.back().arguments.size() == 2 && script->calls.back().dml_operations.size() == 3);

    // Every refusal is made at bind, before a session or a call.
    const auto refused_at_bind = [&](const std::string &arguments, const std::string &expected) {
        const auto before_sessions = script->sessions_opened;
        const auto before_calls = script->calls.size();
        auto refused = database.Query("SELECT * FROM oracle_execute_composite_transaction(" + arguments + ");");
        if (!refused->HasError() || refused->GetError().find(expected) == std::string::npos) {
            std::cerr << "composite bind for " << arguments << ": " << refused->GetError() << "\n";
        }
        CHECK(refused->HasError() && refused->GetError().find(expected) != std::string::npos);
        CHECK(script->sessions_opened == before_sessions && script->calls.size() == before_calls);
    };
    refused_at_bind("'tx', ['CREATE TABLE T2 (ID NUMBER)'], [], [0]", "only INSERT, UPDATE, or DELETE");
    refused_at_bind("'tx', ['BEGIN NULL; END;'], [], [0]", "statement terminators");
    refused_at_bind("'tx', ['COMMIT'], [], [0]", "only INSERT, UPDATE, or DELETE");
    refused_at_bind("'tx', ['DELETE FROM ITEMS; COMMIT'], [], [0]", "statement terminators");
    refused_at_bind("'tx', ['DELETE FROM ITEMS WHERE ID = :id'], [], [0]", "has a placeholder with no bind");
    refused_at_bind("'tx', ['DELETE FROM ITEMS'], {id: 1}, [0]", "do not match");
    refused_at_bind("'tx', ['DELETE FROM ITEMS'], 42, [0]", "params must be a STRUCT");
    refused_at_bind("'tx', ['DELETE FROM ITEMS'], [], [0, 1]", "one expected row count per statement");
    refused_at_bind("'tx', []::VARCHAR[], [], []::BIGINT[]", "needs 1..16 statements");
    refused_at_bind("'tx', list_transform(range(17), lambda i: 'DELETE FROM ITEMS'), [], "
                    "list_transform(range(17), lambda i: 0)",
                    "needs 1..16 statements");
    refused_at_bind("'tx', ['DELETE FROM ITEMS'], [], [-1]", "outside 0..1000000");
    refused_at_bind("'tx', ['DELETE FROM ITEMS'], [], [1000001]", "outside 0..1000000");
    refused_at_bind("'tx', [NULL::VARCHAR], [], [0]", "statement 1 or its count is NULL");
    refused_at_bind("'tx', ['DELETE FROM ITEMS'], NULL, [0]", "cannot be NULL");
    refused_at_bind("'memory', ['DELETE FROM ITEMS'], [], [0]", "attached oracle_scanner catalog");
    refused_at_bind("'ro', ['DELETE FROM ITEMS'], [], [0]", "read-only");

    // A failed block: Oracle's error and code reach the caller, the block is
    // not sent again, no rollback is attempted on the failed session, and the
    // transaction cannot go on.
    database.Run("BEGIN;");
    database.Run("SELECT * FROM oracle_execute_transaction('tx', 'DELETE FROM ITEMS WHERE ID = 9');");
    const auto rollbacks = script->rollbacks;
    const auto calls = script->calls.size();
    script->call_should_fail = true;
    auto failed = database.Query(COMPOSITE_INSERT_AND_UPDATE);
    script->call_should_fail = false;
    CHECK(failed->HasError() && failed->GetError().find("affected row count mismatch") != std::string::npos);
    CHECK(failed->GetErrorObject().ExtraInfo().count("oracle_error_code") == 1 &&
          failed->GetErrorObject().ExtraInfo().at("oracle_error_code") == "20906");
    CHECK(script->calls.size() == calls + 1 && script->rollbacks == rollbacks);
    const auto after_failure = script->sessions_opened;
    CHECK(database.Query("SELECT * FROM oracle_execute_transaction('tx', 'DELETE FROM ITEMS WHERE ID = 10');")
              ->HasError());
    CHECK(script->sessions_opened == after_failure);
    database.Run("ROLLBACK;");
    CHECK(!database.Query(COMPOSITE_INSERT_AND_UPDATE)->HasError());
    std::cout << "composite transaction DML is one validated request with exact counts and no COMMIT of its own"
              << std::endl;
}

int main() {
    TestTypedTransactionQuery();
    TestCompositeTransactionDml();
    TestReadOnlyHiddenCatalogGuardsWrites();

    TestRawCatalogTransactionsPinReadsAndWrites();
    TestTransactionSessionsAreReusedAcrossConnections();
    TestTransactionSessionsThatMustNotBeReused();
    TestTransactionPoolSizeDetachAndAbandonedTransactions();
    TestTransactionPoolsDoNotMixSecrets();
    TestInterruptReachesEveryTransactionPath();
    TestQueryTypeMappingAndValues();
    TestWriteOracleValueMatchesValueFor();
    TestNewTypesReadThroughSql();
    TestBooleanAndLocalZoneReadThroughSql();
    TestProjectedColumns();
    TestProtocolFailuresBecomeTypedDuckDbErrors();
    TestUnsupportedColumnTypesAreRefusedAtBind();
    TestLobColumnsMapToTextAndBlob();
    TestNullsSurviveAboveTheScan();
    TestFilterPushdownTranslatesOnlyTheProvenSubset();
    TestExecuteManyBatchesAndCommits();
    TestNamedCallRequestAndOutputs();
    TestCursorHandlesAreConsumedOnce();
    TestQueryParametersReachTheSessionAsBinds();
    TestExecuteUsesTheCountedOperation();
    TestParametersOfEveryWritableType();
    TestNumberMappings();
    TestExecuteRefusesAnExplicitTransaction();
    TestValidationRunsBeforeAnySession();
    TestUnknownSecretIsRejected();
    TestScanReleasesItsSession();
    TestReadSessionsArePooledPerConnection();
    TestAttachedCatalogAgainstAFakeSession();
    TestAttachedWritesAgainstAFakeSession();
    TestAttachedCatalogNamesTheNewTypes();
    TestInsertBindsMatchTheValuePath();
    TestAttachToAnotherSchema();
    TestUntranslatableFiltersRunLocally();
    TestJsonAndVectorColumnsThroughSql();
    TestXmlTypeColumnsAreText();
    TestJoinKeysReachOracle();
    TestHeavyColumnsAreReadAfterTheFilter();
    TestAttachedScanReadsInRowidRanges();
    TestCallableArgumentsOfTheNewTypes();
    TestVectorSearchArguments();
    TestParallelScanShardsOneSnapshot();
    TestParallelScanRangesDoNotOverflow();
    TestWriteBindsFollowTheOracleColumnType();
    TestCallableSignatureResolution();
    TestAutomaticCallBindsFromTheSignature();
    TestFunctionsCanReturnARefCursor();
    TestConnectDescriptorSecretReachesTheSession();
    TestDsnSecretReachesTheSession();
    TestFailedStatementIsNotReplayed();
    TestFunctionExamplesRun();
    TestSnapshotRefreshStaysInItsDatabase();
    TestRoundedNumberIsComparedInDuckDb();
    TestDocumentedRegistrationsAlterOnConflict();
    std::cout << "oracle_scanner adapter tests passed\n";
    return 0;
}
