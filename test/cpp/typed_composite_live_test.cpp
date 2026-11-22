// Opt-in live checks of oracle_query_transaction_typed and
// oracle_execute_composite_transaction.
//
// ORA19C_HOST, ORA19C_PORT, ORA19C_SERVICE, ORA19C_USER and ORA19C_PASSWORD
// name an administrative account that can create users and read V$SQL and
// V$SESSION. The test creates a throwaway user with a random password, runs
// against it, and drops it, checking that none of its sessions is left. How
// often a statement ran is read from V$SQL by a marker in its text, so the
// counts are Oracle's, not the extension's. Only stage names, Oracle error
// codes and timings are printed.
#include "duckdb.hpp"
#include "oracle_scanner_extension.hpp"
#include "core_functions_extension.hpp"
#include "live_query_result.hpp"

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <random>
#include <regex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace duckdb;

namespace {

std::string Env(const char *name) {
    const auto value = std::getenv(name);
    if (!value || !*value) {
        throw std::runtime_error(std::string("missing environment variable: ") + name);
    }
    return value;
}

std::string SqlLiteral(const std::string &value) {
    std::string result = "'";
    for (const auto c : value) {
        result += c == '\'' ? "''" : std::string(1, c);
    }
    return result + "'";
}

std::string Random(size_t length) {
    static const char alphabet[] = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    std::random_device device;
    std::uniform_int_distribution<size_t> pick(0, sizeof(alphabet) - 2);
    std::string result;
    for (size_t index = 0; index < length; index++) {
        result += alphabet[pick(device)];
    }
    return result;
}

std::string OracleCode(const std::string &error) {
    std::smatch code;
    const std::regex ora("ORA-[0-9]{5}");
    return std::regex_search(error, code, ora) ? code.str() : std::string();
}

[[noreturn]] void Fail(const std::string &stage, const std::string &error = std::string()) {
    std::cerr << "FAIL " << stage;
    const auto code = OracleCode(error);
    if (!code.empty()) {
        std::cerr << " " << code;
    }
    std::cerr << "\n";
    throw std::runtime_error("live check failed");
}

void Check(bool condition, const std::string &stage) {
    if (!condition) {
        Fail(stage);
    }
}

unique_ptr<LiveQueryResult> Run(Connection &con, const std::string &sql, const std::string &stage) {
    auto result = make_uniq<LiveQueryResult>(con.Query(sql));
    if (result->HasError()) {
        Fail(stage, result->GetError());
    }
    return result;
}

std::string Scalar(Connection &con, const std::string &sql, const std::string &stage) {
    auto result = Run(con, sql, stage);
    Check(result->RowCount() == 1, stage + ": one row");
    return result->GetValue(0, 0).ToString();
}

// The statement must fail, and its error must contain what is expected.
std::string Refused(Connection &con, const std::string &sql, const std::string &expected, const std::string &stage) {
    auto result = make_uniq<LiveQueryResult>(con.Query(sql));
    Check(result->HasError(), stage + ": refused");
    if (result->GetError().find(expected) == std::string::npos) {
        Fail(stage + ": the expected reason", result->GetError());
    }
    return result->GetError();
}

std::string Secret(const std::string &user, const std::string &password, int read_timeout = 60) {
    return "TYPE oracle, HOST " + SqlLiteral(Env("ORA19C_HOST")) + ", PORT " + Env("ORA19C_PORT") + ", SERVICE_NAME " +
           SqlLiteral(Env("ORA19C_SERVICE")) + ", USER " + SqlLiteral(user) + ", PASSWORD " + SqlLiteral(password) +
           ", CONNECT_TIMEOUT 5, READ_TIMEOUT " + std::to_string(read_timeout);
}

// Executions Oracle counted for statements carrying the marker; with `block`,
// only of the anonymous blocks carrying it, not of the static SQL inside them.
// The query is written so that its own text never contains the marker.
int64_t Executions(Connection &admin, const std::string &marker, bool block = false) {
    return std::stoll(Scalar(admin,
                             "SELECT * FROM oracle_query('admin', 'SELECT NVL(SUM(EXECUTIONS), 0) AS N FROM V$SQL "
                             "WHERE SQL_TEXT LIKE ''%'' || ''" + marker.substr(0, 3) + "'' || ''" + marker.substr(3) +
                                 "%''" + std::string(block ? " AND SQL_TEXT LIKE ''BEGIN%''" : "") + "');",
                             "count executions"));
}

int64_t Sessions(Connection &admin, const std::string &user) {
    return std::stoll(Scalar(admin,
                             "SELECT * FROM oracle_query('admin', 'SELECT COUNT(*) AS N FROM V$SESSION WHERE USERNAME = "
                             "''" + user + "''');",
                             "count sessions"));
}

// The committed state of ITEMS as another session sees it: "id:n" per row.
std::string Observed(Connection &admin, const std::string &user, const std::string &stage) {
    auto rows = Run(admin,
                    "SELECT * FROM oracle_query('admin', 'SELECT ID || '':'' || N AS R FROM " + user +
                        ".ITEMS ORDER BY ID');",
                    stage);
    std::string result;
    for (idx_t row = 0; row < rows->RowCount(); row++) {
        result += (result.empty() ? "" : ",") + rows->GetValue(0, row).ToString();
    }
    return result;
}

// Joins on every way out of a scope, so a failed check cannot leave a thread
// running past the cleanup that drops its user.
struct JoinedThread {
    std::thread thread;
    template <class F>
    explicit JoinedThread(F function) : thread(std::move(function)) {
    }
    ~JoinedThread() {
        if (thread.joinable()) {
            thread.join();
        }
    }
    void Join() {
        thread.join();
    }
};

// Waits until a session of the user is blocked by another, the way a
// statement waiting on a row lock is.
bool BlockedEventually(Connection &admin, const std::string &user) {
    for (int attempt = 0; attempt < 100; attempt++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        const auto blocked = Scalar(admin,
                                    "SELECT * FROM oracle_query('admin', 'SELECT COUNT(*) AS N FROM V$SESSION WHERE "
                                    "USERNAME = ''" + user + "'' AND BLOCKING_SESSION IS NOT NULL');",
                                    "find blocked");
        if (blocked != "0") {
            return true;
        }
    }
    return false;
}

long long Milliseconds(std::chrono::steady_clock::duration duration) {
    return static_cast<long long>(std::chrono::duration_cast<std::chrono::milliseconds>(duration).count());
}

void TypedChecks(DuckDB &db, Connection &admin, const std::string &user, const std::string &suffix) {
    Connection con(db);
    const auto marker = "QTA" + suffix;
    const auto typed = "oracle_query_transaction_typed('tx', 'SELECT /* " + marker +
                       " */ ID, LABEL, PRICE FROM ITEMS WHERE ID = :id', ['ID', 'LABEL', 'PRICE'], "
                       "['BIGINT', 'VARCHAR', 'DECIMAL(10,2)'], {id: 1})";

    // 1. PREPARE runs nothing in Oracle and opens no session.
    const auto sessions = Sessions(admin, user);
    Run(con, "PREPARE typed AS SELECT * FROM " + typed + ";", "prepare typed");
    Check(Executions(admin, marker) == 0, "typed: PREPARE executes nothing");
    Check(Sessions(admin, user) == sessions, "typed: PREPARE opens no session");
    std::cout << "PASS typed: PREPARE is a pure bind\n";

    // 2. Each execution runs the statement once; the untyped function runs
    // its statement at bind and again at init.
    auto first = Run(con, "EXECUTE typed;", "execute typed");
    Check(first->RowCount() == 1 && first->GetValue(0, 0).ToString() == "1" &&
              first->GetValue(1, 0).ToString() == "one" && first->GetValue(2, 0).ToString() == "1.50",
          "typed: values");
    Check(Executions(admin, marker) == 1, "typed: one execution");
    const auto legacy = "QTB" + suffix;
    Run(con, "SELECT * FROM oracle_query_transaction('tx', 'SELECT /* " + legacy + " */ ID FROM ITEMS WHERE ID = 1');",
        "untyped read");
    const auto legacy_executions = Executions(admin, legacy);
    Check(legacy_executions == 2, "untyped: executes at bind and at init");
    std::cout << "PASS typed: 1 Oracle execution per read, untyped: " << legacy_executions << "\n";

    // 3. The same plan in successive transactions: once per execution, on the
    // transaction current then, seeing its own uncommitted writes.
    Run(con, "BEGIN;", "begin");
    Run(con, "SELECT * FROM oracle_execute_transaction('tx', 'UPDATE ITEMS SET LABEL = ''uncommitted'' WHERE ID = 1');",
        "own write");
    Check(Run(con, "EXECUTE typed;", "read own write")->GetValue(1, 0).ToString() == "uncommitted",
          "typed: reads its transaction's own write");
    Run(con, "EXECUTE typed;", "execute again");
    Run(con, "ROLLBACK;", "rollback");
    Run(con, "BEGIN;", "begin again");
    Check(Run(con, "EXECUTE typed;", "after rollback")->GetValue(1, 0).ToString() == "one",
          "typed: the next transaction sees the rolled-back value");
    Run(con, "COMMIT;", "commit");
    Check(Executions(admin, marker) == 4, "typed: one execution each, across COMMIT and ROLLBACK");
    std::cout << "PASS typed: reusable PREPARE across COMMIT and ROLLBACK\n";

    // 4. Oracle's describe must match the declaration.
    Refused(con,
            "SELECT * FROM oracle_query_transaction_typed('tx', 'SELECT ID, LABEL FROM ITEMS', ['ID', 'NAME'], "
            "['BIGINT', 'VARCHAR']);",
            "Oracle column 2 is LABEL where NAME was declared", "typed: name mismatch");
    Refused(con,
            "SELECT * FROM oracle_query_transaction_typed('tx', 'SELECT ID, LABEL FROM ITEMS', ['ID', 'LABEL'], "
            "['VARCHAR', 'VARCHAR']);",
            "Oracle column ID maps to BIGINT where VARCHAR was declared", "typed: type mismatch");
    Refused(con,
            "SELECT * FROM oracle_query_transaction_typed('tx', 'SELECT ID, LABEL FROM ITEMS', ['ID'], ['BIGINT']);",
            "Oracle returned 2 columns where the declaration has 1", "typed: count mismatch");
    // DDL after PREPARE: the plan runs against the changed table and says so.
    Run(con,
        "PREPARE wide AS SELECT * FROM oracle_query_transaction_typed('tx', 'SELECT * FROM SHAPED', ['ID', 'V'], "
        "['BIGINT', 'VARCHAR']);",
        "prepare before DDL");
    Check(Run(con, "EXECUTE wide;", "before DDL")->RowCount() == 1, "typed: before DDL");
    Run(admin, "SELECT * FROM oracle_execute_admin('admin', 'ALTER TABLE " + user + ".SHAPED ADD (EXTRA NUMBER)');",
        "DDL after PREPARE");
    Refused(con, "EXECUTE wide;", "Oracle returned 3 columns where the declaration has 2", "typed: DDL after PREPARE");
    std::cout << "PASS typed: name, type, count and DDL-after-PREPARE mismatches refused\n";

    // 5. Every declarable type, from real Oracle columns.
    auto values = Run(con,
                      "SELECT * FROM oracle_query_transaction_typed('tx', 'SELECT CAST(1.5 AS BINARY_FLOAT) AS F, "
                      "CAST(2.25 AS BINARY_DOUBLE) AS D, CAST(TIMESTAMP ''2026-01-02 03:04:05.123456'' AS TIMESTAMP(6)) "
                      "AS TS, CAST(TIMESTAMP ''2026-01-02 03:04:05.123456789'' AS TIMESTAMP(9)) AS TSN, "
                      "HEXTORAW(''CAFE'') AS B, BIG FROM ITEMS WHERE ID = 1', "
                      "['F', 'D', 'TS', 'TSN', 'B', 'BIG'], "
                      "['FLOAT', 'DOUBLE', 'TIMESTAMP', 'TIMESTAMP_NS', 'BLOB', 'VARCHAR']);",
                      "every type");
    Check(values->RowCount() == 1, "types: one row");
    Check(values->GetValue(0, 0).ToString() == "1.5" && values->GetValue(1, 0).ToString() == "2.25",
          "types: FLOAT and DOUBLE");
    Check(values->GetValue(2, 0).ToString() == "2026-01-02 03:04:05.123456", "types: TIMESTAMP");
    Check(values->GetValue(3, 0).ToString() == "2026-01-02 03:04:05.123456789", "types: TIMESTAMP_NS");
    Check(values->GetValue(4, 0).ToString() == "\\xCA\\xFE", "types: BLOB");
    // NUMBER(19) is wider than BIGINT and arrives as its exact text.
    Check(values->GetValue(5, 0).ToString() == "9223372036854775807", "types: NUMBER(19) as VARCHAR");
    std::cout << "PASS typed: FLOAT, DOUBLE, TIMESTAMP, TIMESTAMP_NS, BLOB, DECIMAL, BIGINT, NUMBER(19) as VARCHAR\n";
}

void CompositeChecks(DuckDB &db, Connection &admin, const std::string &user, const std::string &suffix) {
    Connection con(db);

    // 1. Named binds, one shared by two statements, exact counts, and no
    // COMMIT of its own: another session sees nothing until DuckDB commits.
    const auto marker = "QCA" + suffix;
    Run(con, "BEGIN;", "begin");
    const auto affected =
        Scalar(con,
               "SELECT * FROM oracle_execute_composite_transaction('tx', ["
               "'INSERT /* " + marker + " */ INTO ITEMS (ID, LABEL, PRICE, N) VALUES (:id, :label, 0, 1)', "
               "'UPDATE ITEMS SET N = N + :step WHERE ID = :id', 'DELETE FROM ITEMS WHERE ID = 999'], "
               "{step: 1, label: 'ten', id: 10}, [1, 1, 0]);",
               "composite");
    Check(affected == "2", "composite: affected rows");
    Check(Observed(admin, user, "observer before commit") == "1:0", "composite: nothing committed inside");
    Run(con, "COMMIT;", "commit");
    Check(Observed(admin, user, "observer after commit") == "1:0,10:2", "composite: committed by COMMIT");
    Check(Executions(admin, marker, true) == 1, "composite: one execution");
    // Positional binds, the same value in two statements.
    Check(Scalar(con,
                 "SELECT * FROM oracle_execute_composite_transaction('tx', ["
                 "'UPDATE ITEMS SET N = N + :2 WHERE ID = :1', 'UPDATE ITEMS SET LABEL = ''pos'' WHERE ID = :1'], "
                 "[10, 5], [1, 1]);",
                 "positional") == "2",
          "composite: positional binds");
    Check(Observed(admin, user, "observer positional") == "1:0,10:7", "composite: positional values");
    std::cout << "PASS composite: bind mapping, exact counts, no internal COMMIT\n";

    // 2. A count mismatch late in the block: Oracle's error, the block not
    // sent again, and ROLLBACK takes back every statement of the transaction,
    // including the ones before the block and inside it.
    const auto late = "QCB" + suffix;
    Run(con, "BEGIN;", "begin late");
    Run(con, "SELECT * FROM oracle_execute_transaction('tx', 'INSERT INTO ITEMS (ID, N) VALUES (20, 0)');",
        "before the block");
    const auto mismatch = Refused(con,
                                  "SELECT * FROM oracle_execute_composite_transaction('tx', ["
                                  "'INSERT /* " + late + " */ INTO ITEMS (ID, N) VALUES (21, 0)', "
                                  "'UPDATE ITEMS SET N = N + 1 WHERE ID IN (20, 21)'], [], [1, 1]);",
                                  "affected row count mismatch", "composite: late count mismatch");
    Check(OracleCode(mismatch) == "ORA-20906", "composite: ORA-20906");
    Refused(con, "SELECT * FROM oracle_execute_transaction('tx', 'DELETE FROM ITEMS WHERE ID = 1');", "",
            "composite: the failed transaction cannot go on");
    Run(con, "ROLLBACK;", "rollback late");
    Check(Observed(admin, user, "observer after mismatch") == "1:0,10:7", "composite: everything rolled back");
    Check(Executions(admin, late, true) == 1, "composite: the failed block was not replayed");
    // A constraint violation in a later statement, the same way.
    Run(con, "BEGIN;", "begin constraint");
    const auto constraint = Refused(con,
                                    "SELECT * FROM oracle_execute_composite_transaction('tx', ["
                                    "'INSERT INTO ITEMS (ID, N) VALUES (30, 1)', "
                                    "'UPDATE ITEMS SET N = 500 WHERE ID = 30'], [], [1, 1]);",
                                    "", "composite: late constraint failure");
    Check(OracleCode(constraint) == "ORA-02290", "composite: ORA-02290");
    Run(con, "ROLLBACK;", "rollback constraint");
    Check(Observed(admin, user, "observer after constraint") == "1:0,10:7", "composite: constraint rolled back");
    // And the connection goes on with a new transaction.
    Check(Scalar(con,
                 "SELECT * FROM oracle_execute_composite_transaction('tx', ['UPDATE ITEMS SET N = N + 1 WHERE ID = 1'], "
                 "[], [1]);",
                 "after failures") == "1",
          "composite: usable after failures");
    Check(Observed(admin, user, "observer after recovery") == "1:1,10:7", "composite: recovered");
    std::cout << "PASS composite: late ORA-20906 and ORA-02290 roll back the whole transaction, no replay\n";

    // 3. Interrupted while a statement of the block waits on a row lock.
    Run(admin, "ATTACH 'rt' AS holder (TYPE oracle_scanner);", "attach holder");
    Connection holding(db);
    const auto lock = [&] {
        Run(holding, "BEGIN;", "holder begin");
        Run(holding, "SELECT * FROM oracle_execute_transaction('holder', 'UPDATE ITEMS SET N = N WHERE ID = 10');",
            "holder lock");
    };
    lock();
    {
        std::atomic<bool> failed {false};
        std::atomic<bool> returned {false};
        std::string error;
        std::chrono::steady_clock::time_point returned_at;
        JoinedThread runner([&] {
            auto result = con.Query("SELECT * FROM oracle_execute_composite_transaction('tx', ["
                                    "'UPDATE ITEMS SET N = N + 50 WHERE ID = 1', "
                                    "'UPDATE ITEMS SET N = N + 50 WHERE ID = 10'], [], [1, 1]);");
            returned_at = std::chrono::steady_clock::now();
            failed = result->HasError();
            error = result->HasError() ? result->GetError() : std::string();
            returned = true;
        });
        if (!BlockedEventually(admin, user)) {
            con.Interrupt();
            runner.Join();
            Fail("interrupt: the block waits on the lock", error);
        }
        const auto interrupted_at = std::chrono::steady_clock::now();
        con.Interrupt();
        runner.Join();
        Check(failed, "interrupt: the interrupted block fails");
        Check(returned_at - interrupted_at < std::chrono::seconds(2), "interrupt: ends the wait");
        std::cout << "PASS composite: interrupt under a row lock, " << Milliseconds(returned_at - interrupted_at)
                  << " ms\n";
    }
    Run(holding, "ROLLBACK;", "holder rollback");
    Check(Observed(admin, user, "observer after interrupt") == "1:1,10:7", "interrupt: nothing kept");
    Check(Scalar(con, "SELECT * FROM oracle_execute_composite_transaction('tx', ['UPDATE ITEMS SET N = N WHERE ID = 1'], "
                      "[], [1]);",
                 "after interrupt") == "1",
          "interrupt: the connection goes on");

    // 4. The read deadline of the secret bounds the same wait.
    Run(admin, "ATTACH 'rt_short' AS short_tx (TYPE oracle_scanner);", "attach short");
    lock();
    {
        Connection waiting(db);
        const auto started = std::chrono::steady_clock::now();
        Refused(waiting,
                "SELECT * FROM oracle_execute_composite_transaction('short_tx', "
                "['UPDATE ITEMS SET N = N + 50 WHERE ID = 10'], [], [1]);",
                "", "deadline: the block fails");
        const auto elapsed = std::chrono::steady_clock::now() - started;
        Check(elapsed >= std::chrono::seconds(2) && elapsed < std::chrono::seconds(10), "deadline: READ_TIMEOUT 3");
        std::cout << "PASS composite: READ_TIMEOUT bounds a lock wait, " << Milliseconds(elapsed) << " ms\n";
    }
    Run(holding, "ROLLBACK;", "holder rollback");
    Check(Observed(admin, user, "observer after deadline") == "1:1,10:7", "deadline: nothing kept");
    Run(admin, "DETACH short_tx;", "detach short");
    Run(admin, "DETACH holder;", "detach holder");
}

} // namespace

int main() {
    DuckDB db(nullptr);
    db.LoadStaticExtension<CoreFunctionsExtension>();
    db.LoadStaticExtension<OracleScannerExtension>();
    Connection admin(db);
    const auto suffix = Random(8);
    const auto user = "QO_TC_" + suffix;
    const auto password = "P" + Random(20);
    bool created = false;
    int status = 0;
    try {
        Run(admin, "CREATE SECRET admin (" + Secret(Env("ORA19C_USER"), Env("ORA19C_PASSWORD")) + ");", "admin secret");
        Run(admin,
            "SELECT * FROM oracle_execute_admin('admin', 'CREATE USER " + user + " IDENTIFIED BY \"" + password +
                "\" QUOTA UNLIMITED ON USERS');",
            "create user");
        created = true;
        Run(admin, "SELECT * FROM oracle_execute_admin('admin', 'GRANT CREATE SESSION, CREATE TABLE TO " + user + "');",
            "grant");
        Run(admin,
            "SELECT * FROM oracle_execute_admin('admin', 'CREATE TABLE " + user +
                ".ITEMS (ID NUMBER(10) PRIMARY KEY, LABEL VARCHAR2(40), PRICE NUMBER(10,2), N NUMBER(10) NOT NULL "
                "CHECK (N < 100), BIG NUMBER(19))');",
            "create items");
        Run(admin, "SELECT * FROM oracle_execute_admin('admin', 'CREATE TABLE " + user +
                       ".SHAPED (ID NUMBER(10), V VARCHAR2(10))');",
            "create shaped");
        Run(admin, "CREATE SECRET rt (" + Secret(user, password) + ");", "runtime secret");
        Run(admin, "CREATE SECRET rt_short (" + Secret(user, password, 3) + ");", "short secret");
        Run(admin, "ATTACH 'rt' AS tx (TYPE oracle_scanner);", "attach");
        Run(admin, "SELECT * FROM oracle_execute_transaction('tx', 'INSERT INTO ITEMS VALUES (1, ''one'', 1.5, 0, "
                   "9223372036854775807)');",
            "seed items");
        Run(admin, "SELECT * FROM oracle_execute_transaction('tx', 'INSERT INTO SHAPED VALUES (1, ''v'')');",
            "seed shaped");

        TypedChecks(db, admin, user, suffix);
        CompositeChecks(db, admin, user, suffix);

        // A new database instance, with its own sessions, reads what was
        // committed.
        {
            DuckDB fresh(nullptr);
            fresh.LoadStaticExtension<CoreFunctionsExtension>();
            fresh.LoadStaticExtension<OracleScannerExtension>();
            Connection reader(fresh);
            Run(reader, "CREATE SECRET rt (" + Secret(user, password) + ");", "fresh secret");
            Run(reader, "ATTACH 'rt' AS tx (TYPE oracle_scanner);", "fresh attach");
            auto rows = Run(reader,
                            "SELECT * FROM oracle_query_transaction_typed('tx', 'SELECT ID, N, LABEL FROM ITEMS ORDER "
                            "BY ID', ['ID', 'N', 'LABEL'], ['BIGINT', 'BIGINT', 'VARCHAR']);",
                            "fresh read");
            Check(rows->RowCount() == 2 && rows->GetValue(1, 0).ToString() == "1" &&
                      rows->GetValue(1, 1).ToString() == "7" && rows->GetValue(2, 1).ToString() == "pos",
                  "fresh: the committed rows");
            Run(reader, "DETACH tx;", "fresh detach");
        }
        std::cout << "PASS a fresh database instance reads the committed state\n";
        Run(admin, "DETACH tx;", "detach");
    } catch (const std::exception &error) {
        std::cerr << "live test stopped: " << (std::string(error.what()) == "live check failed" ? "" : "error") << "\n";
        status = 1;
    }
    if (created) {
        try {
            (void)admin.Query("DETACH IF EXISTS tx;");
            (void)admin.Query("DETACH IF EXISTS holder;");
            (void)admin.Query("DETACH IF EXISTS short_tx;");
            auto left = Run(admin,
                            "SELECT * FROM oracle_query('admin', 'SELECT SID || '','' || SERIAL# AS S FROM V$SESSION "
                            "WHERE USERNAME = ''" + user + "''');",
                            "cleanup sessions");
            for (idx_t row = 0; row < left->RowCount(); row++) {
                // A session that ends on its own meanwhile answers ORA-00030;
                // one in a wait, ORA-00031. Either way it is going.
                (void)admin.Query("SELECT * FROM oracle_execute_admin('admin', 'ALTER SYSTEM KILL SESSION ''" +
                                  left->GetValue(0, row).ToString() + "'' IMMEDIATE');");
            }
            auto dropped = admin.Query("SELECT * FROM oracle_execute_admin('admin', 'DROP USER " + user + " CASCADE');");
            if (dropped->HasError()) {
                std::this_thread::sleep_for(std::chrono::seconds(2));
                Run(admin, "SELECT * FROM oracle_execute_admin('admin', 'DROP USER " + user + " CASCADE');",
                    "drop user");
            }
            Check(Scalar(admin,
                         "SELECT * FROM oracle_query('admin', 'SELECT COUNT(*) AS N FROM DBA_USERS WHERE USERNAME = ''" +
                             user + "''');",
                         "cleanup check") == "0",
                  "test user dropped");
            Check(Sessions(admin, user) == 0, "no session of the test user left");
            std::cout << "PASS cleanup: test user and its sessions gone\n";
        } catch (const std::exception &) {
            std::cerr << "FAIL cleanup\n";
            status = 1;
        }
    }
    return status;
}
