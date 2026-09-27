// Before any include. Windows defines min and max as function-like macros,
// and the headers this pulls in reach <windows.h> — so `(std::min)(...)` is
// rewritten by the preprocessor and the file stops compiling, with the brace
// counting going wrong several lines later as a consequence.
#if defined(_WIN32) && !defined(NOMINMAX)
#define NOMINMAX
#endif

#include "oracle_scanner/protocol_error.hpp"
#include "oracle_scanner/session.hpp"
#include "oracle_scanner/session_factory.hpp"
#include "oracle_scanner/value_codec.hpp"
#include "oracle_scanner_extension.hpp"
#include "oracle_adapter.hpp"
#include "oracle_scanner/call_registry.hpp"
#include "oracle_scanner/ttc_execute.hpp"

#include "duckdb/common/exception/conversion_exception.hpp"
#include "duckdb/planner/filter/conjunction_filter.hpp"
#include "duckdb/planner/filter/constant_filter.hpp"
#include "duckdb/planner/filter/in_filter.hpp"
#include "duckdb/planner/filter/null_filter.hpp"
#include "duckdb/planner/filter/optional_filter.hpp"

#include "duckdb.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/parser/parser.hpp"
#include "duckdb/parser/parsed_data/create_table_function_info.hpp"

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

    // Set to make the scripted cursor fail mid-stream, which is how a protocol
    // failure reaches the adapter after the bind has already succeeded.
    std::optional<oracle_scanner::ProtocolErrorKind> fetch_failure;
    std::string fetch_failure_message;
    bool batch_should_fail = false;

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
    const auto object_end = object.find('"');
    if (object_end == std::string::npos) {
        return false;
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
            const auto name = item.size() >= 2 && item.front() == '"' ? item.substr(1, item.size() - 2) : item;
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
        }
        batch.exhausted = drained;
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
    explicit FakeSession(std::shared_ptr<FakeScript> script_p) : script(std::move(script_p)) {
        std::lock_guard<std::mutex> guard(script->record_lock);
        script->sessions_opened++;
    }

    ~FakeSession() override {
        std::lock_guard<std::mutex> guard(script->record_lock);
        script->sessions_destroyed++;
    }

    std::unique_ptr<OracleCursor> Query(const std::string &sql, const std::vector<OracleBind> &binds) override {
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

    uint64_t ExecuteWithRowCount(const std::string &sql, const std::vector<OracleBind> &binds) override {
        std::lock_guard<std::mutex> guard(script->record_lock);
        script->counted_executes.push_back(sql);
        script->counted_execute_binds.push_back(binds);
        return script->affected_rows;
    }

    uint64_t ExecuteBatch(const std::string &sql, const std::vector<std::vector<OracleBind>> &rows) override {
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
        std::lock_guard<std::mutex> guard(script->record_lock);
        script->calls.push_back(request);
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
    }

    void Rollback() override {
        std::lock_guard<std::mutex> guard(script->record_lock);
        script->rollbacks++;
    }

    void Cancel() override {
    }

    void Close() override {
    }

private:
    std::shared_ptr<FakeScript> script;
};

ScopedOracleSessionFactory InstallFake(const std::shared_ptr<FakeScript> &script) {
    return ScopedOracleSessionFactory([script](const ConnectionConfig &, const std::string &) {
        return std::unique_ptr<OracleSession>(new FakeSession(script));
    });
}

struct TestDatabase {
    TestDatabase() : db(nullptr), con(db) {
        db.LoadStaticExtension<OracleScannerExtension>();
        // The endpoint is never contacted: the installed factory answers before
        // any transport work, so these are placeholders, not credentials.
        Run("CREATE SECRET ora (TYPE oracle, HOST '127.0.0.1', PORT 1521, "
            "SERVICE_NAME 'service', USER 'app_user', PASSWORD 'placeholder');");
    }

    std::unique_ptr<duckdb::MaterializedQueryResult> Query(const std::string &sql) {
        return con.Query(sql);
    }

    void Run(const std::string &sql) {
        auto result = con.Query(sql);
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

    CHECK(result->types[0] == duckdb::LogicalType::BIGINT);
    CHECK(result->types[1] == duckdb::LogicalType::VARCHAR);
    CHECK(result->types[2] == duckdb::LogicalType::DECIMAL(10, 2));
    CHECK(result->types[3] == duckdb::LogicalType::VARCHAR);
    CHECK(result->types[4] == duckdb::LogicalType::BLOB);
    CHECK(result->types[5] == duckdb::LogicalType::DOUBLE);
    CHECK(result->names[0] == "id" && result->names[5] == "ratio");

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
    // character set form separates them, and their values are UTF-16 in the row
    // itself. NCLOB shares the CLOB type code and is readable, because its
    // content does not travel in the row at all — it is read through LOB_OP,
    // which serves AL16UTF16 for a plain CLOB too.
    for (const uint16_t character_type : {1, 96}) {
        const auto error = bind_error(character_type, 2);
        CHECK(error.find("Not implemented Error") != std::string::npos);
        CHECK(error.find("national character set") != std::string::npos);
    }

    // BFILE has no read path and is refused by name, unlike the three LOB
    // types beside it.
    CHECK(bind_error(114, 0).find("Oracle type 114") != std::string::npos);

    CHECK(bind_error(182, 0).find("INTERVAL") != std::string::npos);
    CHECK(bind_error(183, 0).find("INTERVAL") != std::string::npos);

    const auto local_zone = bind_error(231, 0);
    CHECK(local_zone.find("session time zone") != std::string::npos);

    // Anything with no mapping at all still fails by name rather than falling
    // through to the textual default.
    const auto unmapped = bind_error(8, 0);
    CHECK(unmapped.find("Oracle type 8") != std::string::npos);

    // TIMESTAMP WITH TIME ZONE stays readable: the value carries its own
    // offset, so nothing has to be assumed about a session zone.
    auto script = std::make_shared<FakeScript>();
    script->columns = {Column("v", 181)};
    script->rows = {{oracle_scanner::EncodeOracleTimestamp({2026, 8, 20, 10, 42, 55, 0, 120, true}, true)}};
    auto factory = InstallFake(script);
    TestDatabase database;
    auto accepted = database.Query("SELECT * FROM oracle_query('ora', 'SELECT v FROM app.items')");
    CHECK(!accepted->HasError());
    CHECK(accepted->GetValue(0, 0).ToString().find("+02:00") != std::string::npos);
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
    CHECK(result->types[0] == duckdb::LogicalType::VARCHAR);
    CHECK(result->types[1] == duckdb::LogicalType::VARCHAR);
    CHECK(result->types[2] == duckdb::LogicalType::BLOB);
    CHECK(result->GetValue(0, 0).ToString() == "hi");
    CHECK(result->GetValue(1, 0).ToString() == "\xd0\xbf");
}

// Filter pushdown translates only what is provably identical in Oracle, and
// refuses the rest. Refusing matters: DuckDB removes a filter from the plan once
// it hands it to the scan, so a filter that is accepted and then approximated
// changes the answer rather than merely slowing it down.
void TestFilterPushdownTranslatesOnlyTheProvenSubset() {
    std::vector<OracleColumn> columns = {Column("ID", 2), Column("LABEL", 1), Column("TAG", 96)};
    const std::vector<duckdb::column_t> scanned = {0, 1, 2};

    const auto translate = [&](duckdb::idx_t column, duckdb::unique_ptr<duckdb::TableFilter> filter) {
        duckdb::TableFilterSet filters;
        filters.filters[column] = std::move(filter);
        return duckdb::OracleWhereClause(filters, columns, scanned);
    };
    const auto constant = [](duckdb::ExpressionType comparison, duckdb::Value value) {
        return duckdb::make_uniq<duckdb::ConstantFilter>(comparison, std::move(value));
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
    CHECK(translate(1, duckdb::make_uniq<duckdb::IsNullFilter>()) == "\"LABEL\" IS NULL");
    CHECK(translate(1, duckdb::make_uniq<duckdb::IsNotNullFilter>()) == "\"LABEL\" IS NOT NULL");

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
            duckdb::TableFilterSet filters;
            filters.filters[index] = std::move(filter);
            return duckdb::OracleWhereClause(filters, time_columns, {0, 1});
        };
        CHECK(translate_time(0, duckdb::make_uniq<duckdb::ConstantFilter>(
                                     duckdb::ExpressionType::COMPARE_EQUAL,
                                     duckdb::Value::TIMESTAMP(duckdb::Timestamp::FromString("2024-03-05 06:07:08", false)))) ==
               "\"WHEN_DATE\" = TO_DATE('2024-03-05 06:07:08', 'YYYY-MM-DD HH24:MI:SS')");
        // Chronological order depends on nothing a session sets, unlike the
        // collation that keeps ordered text comparisons off this list.
        CHECK(translate_time(0, duckdb::make_uniq<duckdb::ConstantFilter>(
                                     duckdb::ExpressionType::COMPARE_GREATERTHAN,
                                     duckdb::Value::TIMESTAMP(duckdb::Timestamp::FromString("2024-01-01 00:00:00", false)))) ==
               "\"WHEN_DATE\" > TO_DATE('2024-01-01 00:00:00', 'YYYY-MM-DD HH24:MI:SS')");
        CHECK(translate_time(1, duckdb::make_uniq<duckdb::ConstantFilter>(
                                     duckdb::ExpressionType::COMPARE_EQUAL,
                                     duckdb::Value::TIMESTAMPNS(duckdb::timestamp_ns_t(1709618828123456789LL)))) ==
               "\"WHEN_TS\" = TO_TIMESTAMP('2024-03-05 06:07:08.123456789', 'YYYY-MM-DD HH24:MI:SS.FF9')");
        // An Oracle DATE holds whole seconds, so no value in the column can
        // equal a sub-second constant and no boundary sits where it says.
        bool sub_second_refused = false;
        try {
            translate_time(0, duckdb::make_uniq<duckdb::ConstantFilter>(
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
            translate_time(0, duckdb::make_uniq<duckdb::ConstantFilter>(duckdb::ExpressionType::COMPARE_EQUAL,
                                                                        duckdb::Value("2024-03-05")));
        } catch (const duckdb::NotImplementedException &error) {
            text_refused = std::string(error.what()).find("text comparison") != std::string::npos;
        }
        CHECK(text_refused);
    }

    // An IN list is a disjunction of equalities and carries the same proof.
    duckdb::vector<duckdb::Value> numbers = {duckdb::Value::BIGINT(1), duckdb::Value::BIGINT(3)};
    CHECK(translate(0, duckdb::make_uniq<duckdb::InFilter>(std::move(numbers))) == "\"ID\" IN (1, 3)");
    duckdb::vector<duckdb::Value> labels = {duckdb::Value("beta"), duckdb::Value("gamma")};
    CHECK(translate(1, duckdb::make_uniq<duckdb::InFilter>(std::move(labels))) == "\"LABEL\" IN ('beta', 'gamma')");

    // One unprovable value refuses the whole list rather than dropping it, which
    // would apply a weaker predicate than the query asked for.
    duckdb::vector<duckdb::Value> with_empty = {duckdb::Value("beta"), duckdb::Value("")};
    refused(1, duckdb::make_uniq<duckdb::InFilter>(std::move(with_empty)), "empty string");

    // An optional filter is a hint DuckDB does not need for correctness, so one
    // that cannot be translated is dropped instead of raising — while the same
    // filter arriving as required still raises.
    duckdb::vector<duckdb::Value> optional_values = {duckdb::Value("beta"), duckdb::Value("")};
    auto optional = duckdb::make_uniq<duckdb::OptionalFilter>(
        duckdb::make_uniq<duckdb::InFilter>(std::move(optional_values)));
    CHECK(translate(1, std::move(optional)).empty());
    auto translatable = duckdb::make_uniq<duckdb::OptionalFilter>(duckdb::make_uniq<duckdb::IsNullFilter>());
    CHECK(translate(1, std::move(translatable)) == "\"LABEL\" IS NULL");

    // A conjunction is only as pushable as its children.
    auto conjunction = duckdb::make_uniq<duckdb::ConjunctionAndFilter>();
    conjunction->child_filters.push_back(constant(duckdb::ExpressionType::COMPARE_EQUAL, duckdb::Value::BIGINT(1)));
    conjunction->child_filters.push_back(
        constant(duckdb::ExpressionType::COMPARE_GREATERTHAN, duckdb::Value::BIGINT(0)));
    CHECK(translate(0, std::move(conjunction)) == "(\"ID\" = 1 AND \"ID\" > 0)");
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
    unsupported(national, duckdb::Value("beta"), "national character set");
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
    CHECK(scanned->types[0] == duckdb::LogicalType::BIGINT && scanned->types[1] == duckdb::LogicalType::VARCHAR);
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

    // Filter pushdown is off by default, so nothing reaches Oracle until it is
    // asked for.
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
    database.Run("CREATE SECRET rac (TYPE oracle, USER 'app_user', PASSWORD 'placeholder', CONNECT_DESCRIPTOR "
                 "'(DESCRIPTION=(CONNECT_TIMEOUT=90)(RETRY_COUNT=20)(RETRY_DELAY=3)(TRANSPORT_CONNECT_TIMEOUT=3)"
                 "(ADDRESS_LIST=(LOAD_BALANCE=on)(ADDRESS=(PROTOCOL=TCP)(HOST=scan.example)(PORT=1521)))"
                 "(ADDRESS_LIST=(ADDRESS=(PROTOCOL=TCP)(HOST=standby.example)(PORT=1522)))"
                 "(CONNECT_DATA=(SERVICE_NAME=sales.example)(INSTANCE_NAME=sales1)))');");
    CHECK(!database.Query("SELECT * FROM oracle_query('rac', 'SELECT label FROM app.items')")->HasError());
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
            "(CONNECT_DATA=(SERVICE_NAME=svc))))'",
            "DESCRIPTION_LIST is not supported");
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
    std::function<void(FakeScript &, duckdb::MaterializedQueryResult &)> verify;
};

static std::map<std::string, FunctionExampleCase> FunctionExampleCases() {
    using duckdb::MaterializedQueryResult;
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
    CHECK(examples.size() == cases.size() && examples.size() == 20);
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
        const auto is_scalar = example.first == "oracle_scanner_version";
        // Parsing first, the way each kind of example is meant to be used: a
        // scalar example is an expression, a table example one whole statement.
        if (is_scalar) {
            CHECK(duckdb::Parser::ParseExpressionList(example.second).size() == 1);
        } else {
            duckdb::Parser parser;
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
// registers are inspected directly, all twenty of them.
void TestDocumentedRegistrationsAlterOnConflict() {
    std::vector<std::string> names;
    const auto check = [&](const duckdb::CreateFunctionInfo &info, const std::string &name) {
        CHECK(info.on_conflict == duckdb::OnCreateConflict::ALTER_ON_CONFLICT);
        CHECK(info.descriptions.size() == 1 && !info.descriptions[0].description.empty() &&
              info.descriptions[0].examples.size() == 1);
        names.push_back(name);
    };
    const auto version = duckdb::OracleScannerVersionFunctionInfo();
    check(version, version.functions.name);
    for (const auto &info : duckdb::OracleQueryFunctionInfos()) {
        check(info, info.functions.name);
    }
    const auto parallel = duckdb::OracleParallelScanFunctionInfo();
    check(parallel, parallel.functions.name);
    CHECK(names.size() == 20);

    // And what that mode means on a database that already has the functions:
    // an extra overload under an existing name is added to it, where
    // ERROR_ON_CONFLICT refuses the same thing.
    TestDatabase database;
    duckdb::ExtensionLoader loader(*database.db.instance, "oracle_scanner");
    const auto overload = [] {
        return duckdb::TableFunction("oracle_arguments", {duckdb::LogicalType::INTEGER}, nullptr,
                                     [](duckdb::ClientContext &, duckdb::TableFunctionBindInput &,
                                        duckdb::vector<duckdb::LogicalType> &,
                                        duckdb::vector<std::string> &) -> duckdb::unique_ptr<duckdb::FunctionData> {
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

int main() {

    TestQueryTypeMappingAndValues();
    TestProjectedColumns();
    TestProtocolFailuresBecomeTypedDuckDbErrors();
    TestUnsupportedColumnTypesAreRefusedAtBind();
    TestLobColumnsMapToTextAndBlob();
    TestFilterPushdownTranslatesOnlyTheProvenSubset();
    TestExecuteManyBatchesAndCommits();
    TestNamedCallRequestAndOutputs();
    TestCursorHandlesAreConsumedOnce();
    TestQueryParametersReachTheSessionAsBinds();
    TestExecuteUsesTheCountedOperation();
    TestExecuteRefusesAnExplicitTransaction();
    TestValidationRunsBeforeAnySession();
    TestUnknownSecretIsRejected();
    TestScanReleasesItsSession();
    TestReadSessionsArePooledPerConnection();
    TestAttachedCatalogAgainstAFakeSession();
    TestAttachedWritesAgainstAFakeSession();
    TestParallelScanShardsOneSnapshot();
    TestWriteBindsFollowTheOracleColumnType();
    TestCallableSignatureResolution();
    TestAutomaticCallBindsFromTheSignature();
    TestFunctionsCanReturnARefCursor();
    TestConnectDescriptorSecretReachesTheSession();
    TestFailedStatementIsNotReplayed();
    TestFunctionExamplesRun();
    TestDocumentedRegistrationsAlterOnConflict();
    std::cout << "oracle_scanner adapter tests passed\n";
    return 0;
}
