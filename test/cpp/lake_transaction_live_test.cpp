#include "duckdb.hpp"
#include "oracle_scanner_extension.hpp"
#include "core_functions_extension.hpp"
#include "oracle_adapter.hpp"

#include <cstdlib>
#include <iostream>
#include <regex>
#include <stdexcept>
#include <string>

using namespace duckdb;

static std::string Env(const char *name) {
    const auto value = std::getenv(name);
    if (!value || !*value) {
        throw std::runtime_error(std::string("missing environment variable: ") + name);
    }
    return value;
}

static std::string SqlLiteral(const std::string &value) {
    std::string result = "'";
    for (const auto c : value) {
        result += c == '\'' ? "''" : std::string(1, c);
    }
    return result + "'";
}

static void Failure(const std::string &stage, const std::string &error) {
    // Report only the stage and Oracle code; query errors can contain SQL,
    // credentials, bind values or private endpoint details.
    std::smatch code;
    const std::regex ora("ORA-[0-9]{5}");
    std::cerr << "FAIL " << stage;
    if (std::regex_search(error, code, ora)) {
        std::cerr << " " << code.str();
    }
    std::cerr << "\n";
    throw std::runtime_error("live check failed");
}

// DuckDB 2.0 results are read unit by unit; these checks only need the first value.
static Value FirstValue(QueryResult &result) {
    auto chunk = result.Fetch();
    if (!chunk || chunk->size() == 0) {
        throw std::runtime_error("live check expected a row");
    }
    return chunk->GetValue(0, 0);
}

static unique_ptr<QueryResult> Run(Connection &con, const std::string &sql, const std::string &stage) {
    auto result = con.Query(sql);
    if (result->HasError()) {
        Failure(stage, result->GetError());
    }
    return result;
}

static std::string Scalar(Connection &con, const std::string &sql, const std::string &stage) {
    auto result = Run(con, "SELECT * FROM oracle_query_transaction('tx', " + SqlLiteral(sql) + ");", stage);
    if (result->RowCount() != 1) {
        Failure(stage, "unexpected row count");
    }
    return FirstValue(*result).ToString();
}

static void Count(Connection &con, const std::string &expected, const std::string &stage) {
    if (Scalar(con, "SELECT COUNT(*) FROM LAKE_TX_PROBE", stage) != expected) {
        Failure(stage, "unexpected count");
    }
}

static void Dml(Connection &con, const std::string &sql, const std::string &stage) {
    Run(con, "SELECT * FROM oracle_execute_transaction('tx', " + SqlLiteral(sql) + ");", stage);
}

static std::string ConnectionOptions() {
        std::string connection;
        if (std::getenv("ODL_WALLET")) {
            connection = "TNS_ALIAS " + SqlLiteral(Env("ODL_ALIAS")) + ", PROTOCOL 'tcps', WALLET_FILE " +
                         SqlLiteral(Env("ODL_WALLET")) + ", TLS_SERVER_NAME " + SqlLiteral(Env("ODL_TLS_SERVER_NAME"));
        } else {
            connection = "HOST " + SqlLiteral(Env("ODL_HOST")) + ", PORT " + Env("ODL_PORT") +
                         ", SERVICE_NAME " + SqlLiteral(Env("ODL_SERVICE"));
        }
        return connection;
}

static void Configure(Connection &con, const std::string &user, const std::string &password) {
    Run(con, "CREATE SECRET live (TYPE oracle, " + ConnectionOptions() + ", USER " + SqlLiteral(user) +
             ", PASSWORD " + SqlLiteral(password) + ", CONNECT_TIMEOUT 5, READ_TIMEOUT 10);", "create_secret");
}

static void TransactionChecks(DuckDB &db, Connection &con) {
        Run(con, "ATTACH 'live' AS tx (TYPE oracle_scanner);", "attach");
        Connection observer(db);
        Count(observer, "0", "initial_count");
        Run(con, "BEGIN;", "begin");
        const auto sid = Scalar(con, "SELECT SYS_CONTEXT('USERENV','SID') FROM DUAL", "first_read");
        Dml(con, "INSERT INTO LAKE_TX_PROBE VALUES (1, 'first')", "first_insert");
        Dml(con, "INSERT INTO LAKE_TX_PROBE VALUES (2, 'second')", "second_insert");
        Count(con, "2", "read_own_writes");
        Count(observer, "0", "uncommitted_hidden");
        if (Scalar(con, "SELECT SYS_CONTEXT('USERENV','SID') FROM DUAL", "second_read") != sid) {
            Failure("same_session", "session changed");
        }
        Run(con, "ROLLBACK;", "rollback");
        Count(observer, "0", "rollback_visibility");
        Run(con, "BEGIN;", "begin_commit");
        Dml(con, "INSERT INTO LAKE_TX_PROBE VALUES (3, 'committed')", "committed_insert");
        Run(con, "COMMIT;", "commit");
        Count(observer, "1", "commit_visibility");
        Run(con, "BEGIN;", "begin_read_committed");
        Count(con, "1", "read_committed_before");
        Dml(observer, "INSERT INTO LAKE_TX_PROBE VALUES (9, 'other writer')", "other_writer_commit");
        Count(con, "2", "read_committed_after");
        Run(con, "ROLLBACK;", "rollback_read_committed");
        Dml(observer, "DELETE FROM LAKE_TX_PROBE WHERE ID = 9", "remove_other_writer");
        Run(con, "BEGIN;", "begin_lock");
        Scalar(con, "SELECT ID FROM LAKE_TX_PROBE WHERE ID = 3 FOR UPDATE", "lock_before_write");
        Run(observer, "BEGIN;", "begin_lock_contender");
        auto locked = observer.Query("SELECT * FROM oracle_query_transaction('tx', "
            "'SELECT ID FROM LAKE_TX_PROBE WHERE ID = 3 FOR UPDATE NOWAIT');");
        if (!locked->HasError() || locked->GetErrorObject().ExtraInfo().find("oracle_error_code") ==
            locked->GetErrorObject().ExtraInfo().end() ||
            locked->GetErrorObject().ExtraInfo().at("oracle_error_code") != "54") {
            Failure("lock_conflict", "expected structured Oracle code 54");
        }
        Run(observer, "ROLLBACK;", "rollback_lock_contender");
        Run(con, "ROLLBACK;", "release_lock");
        Scalar(observer, "SELECT ID FROM LAKE_TX_PROBE WHERE ID = 3 FOR UPDATE NOWAIT", "lock_released");
        Run(con, "BEGIN;", "begin_failure");
        Dml(con, "INSERT INTO LAKE_TX_PROBE VALUES (4, 'must roll back')", "before_failure");
        auto duplicate = con.Query("SELECT * FROM oracle_execute_transaction('tx', "
                                   "'INSERT INTO LAKE_TX_PROBE VALUES (3, ''duplicate'')');");
        if (!duplicate->HasError() || duplicate->GetErrorObject().ExtraInfo().find("oracle_error_code") ==
            duplicate->GetErrorObject().ExtraInfo().end() ||
            duplicate->GetErrorObject().ExtraInfo().at("oracle_error_code") != "1") {
            Failure("duplicate_failure", "expected ORA-00001");
        }
        Run(con, "ROLLBACK;", "rollback_failure");
        Count(observer, "1", "failed_transaction_visibility");
        {
            auto abandoned = std::make_unique<Connection>(db);
            Run(*abandoned, "BEGIN;", "begin_abandoned");
            Dml(*abandoned, "INSERT INTO LAKE_TX_PROBE VALUES (5, 'abandoned')", "abandoned_insert");
        }
        Count(observer, "1", "disconnect_rolls_back");
        Run(con, "BEGIN;", "begin_update");
        Dml(con, "UPDATE LAKE_TX_PROBE SET LABEL = 'updated' WHERE ID = 3", "update");
        Dml(con, "DELETE FROM LAKE_TX_PROBE WHERE ID = 3", "delete");
        Count(con, "0", "own_delete");
        Run(con, "COMMIT;", "commit_delete");
        Count(observer, "0", "delete_visibility");
        Run(con, "PREPARE lake_count AS SELECT * FROM oracle_query_transaction('tx', "
                 "'SELECT COUNT(*) FROM LAKE_TX_PROBE');", "prepare_count");
        Run(con, "BEGIN;", "begin_prepared");
        Dml(con, "INSERT INTO LAKE_TX_PROBE VALUES (6, 'prepared')", "prepared_insert");
        auto prepared = Run(con, "EXECUTE lake_count;", "execute_prepared");
        if (FirstValue(*prepared).ToString() != "1") {
            Failure("prepared_own_write", "unexpected count");
        }
        Run(con, "ROLLBACK;", "rollback_prepared");
        prepared = Run(con, "EXECUTE lake_count;", "execute_prepared_again");
        if (FirstValue(*prepared).ToString() != "0") {
            Failure("prepared_after_rollback", "unexpected count");
        }
        Run(con, "BEGIN;", "begin_borrowed_cursors");
        auto target = ResolveOracleWriteTarget(*con.context, "tx");
        TransactionSession(*con.context, target);
        auto first = AcquireOracleReadSession(*con.context, "", "tx", target.config, target.password);
        auto second = AcquireOracleReadSession(*con.context, "", "tx", target.config, target.password);
        std::weak_ptr<OracleSession> lifetime = first.borrowed;
        auto first_cursor = first->Query("SELECT 1 FROM DUAL", {});
        auto second_cursor = second->Query("SELECT 2 FROM DUAL", {});
        PoisonTransactionSession(*con.context, "tx");
        for (auto *cursor : {first_cursor.get(), second_cursor.get()}) {
            bool rejected = false;
            try {
                cursor->Fetch(1);
            } catch (const oracle_scanner::ProtocolError &error) {
                rejected = error.Kind() == oracle_scanner::ProtocolErrorKind::INVALID_STATE;
            }
            if (!rejected) {
                Failure("poisoned_borrowed_cursor", "closed cursor reused");
            }
            cursor->Close();
        }
        first_cursor.reset();
        second_cursor.reset();
        first = OracleSessionHandle();
        if (lifetime.expired()) {
            Failure("second_borrowed_owner", "session destroyed too early");
        }
        second = OracleSessionHandle();
        if (!lifetime.expired()) {
            Failure("borrowed_session_cleanup", "session retained");
        }
        Run(con, "ROLLBACK;", "rollback_borrowed_cursors");
        std::cout << "PASS transaction session, visibility, commit, rollback, failure, disconnect, update and delete\n";
        std::cout << "PASS prepared query reacquires the current transaction\n";
        std::cout << "PASS READ COMMITTED visibility, FOR UPDATE before DML and structured NOWAIT conflict\n";
        std::cout << "PASS multiple borrowed cursors safely reject access after transaction poisoning\n";
}

static void Admin(Connection &con, const std::string &sql, const std::string &stage) {
    Run(con, "SELECT * FROM oracle_execute_admin('live', " + SqlLiteral(sql) + ");", stage);
}

static void ATPChecks(Connection &admin) {
    const auto user = Env("ODL_RUNTIME_USER");
    const auto password = Env("ODL_RUNTIME_PASSWORD");
    if (!std::regex_match(user, std::regex("ODL_TEST_[A-Z0-9]{12}")) ||
        !std::regex_match(password, std::regex("[A-Za-z0-9_]{8,28}"))) {
        Failure("fixture_configuration", "invalid generated identifier or password");
    }
    auto tablespaces = Run(admin, "SELECT * FROM oracle_query('live', "
        "'SELECT DEFAULT_TABLESPACE FROM USER_USERS');", "default_tablespace");
    const auto tablespace = FirstValue(*tablespaces).ToString();
    if (!std::regex_match(tablespace, std::regex("[A-Za-z][A-Za-z0-9_]{0,29}"))) {
        Failure("tablespace_configuration", "unsupported tablespace identifier");
    }
    bool created = false;
    try {
        Admin(admin, "CREATE USER " + user + " IDENTIFIED BY \"" + password + "\" DEFAULT TABLESPACE " + tablespace,
              "create_test_user");
        created = true;
        Admin(admin, "GRANT CREATE SESSION TO " + user, "grant_runtime_session");
        Admin(admin, "ALTER USER " + user + " QUOTA 10M ON " + tablespace, "runtime_quota");
        Admin(admin, "CREATE TABLE " + user + ".LAKE_TX_PROBE (ID NUMBER(18,0) PRIMARY KEY, LABEL VARCHAR2(100))",
              "create_probe");
        {
            DuckDB runtime(nullptr);
            runtime.LoadStaticExtension<CoreFunctionsExtension>();
            runtime.LoadStaticExtension<OracleScannerExtension>();
            Connection con(runtime);
            Configure(con, user, password);
            TransactionChecks(runtime, con);
            auto before = Run(con, "SELECT * FROM tx.LAKE_TX_PROBE;", "describe_before_ddl");
            if (before->GetTypes().size() != 2) {
                Failure("describe_before_ddl", "unexpected columns");
            }
            Admin(admin, "ALTER TABLE " + user + ".LAKE_TX_PROBE ADD (EXTRA_ID NUMBER(18,0))", "alter_probe");
            // Explicit refresh boundary outside runtime transactions. No stale
            // DuckCatalog entries or prepared plans are reused across reattach.
            Run(con, "DETACH tx;", "detach_for_refresh");
            Run(con, "ATTACH 'live' AS tx (TYPE oracle_scanner);", "reattach_for_refresh");
            auto after = Run(con, "SELECT * FROM tx.LAKE_TX_PROBE;", "describe_after_refresh");
            if (after->GetTypes().size() != 3) {
                Failure("describe_after_refresh", "stale metadata");
            }
            std::cout << "PASS catalog refresh by DETACH/ATTACH after administrative ALTER\n";
        }
        // Do not automatically replay DDL if its acknowledgement is lost.
        created = false;
        Admin(admin, "DROP USER " + user + " CASCADE", "drop_test_user");
        std::cout << "PASS ATP transaction suite with CREATE SESSION runtime user; temporary schema removed\n";
    } catch (...) {
        if (created) {
            try {
                Admin(admin, "DROP USER " + user + " CASCADE", "cleanup_test_user");
                std::cout << "Temporary ATP test schema removed after failure\n";
            } catch (...) {
                std::cerr << "FAIL ATP test schema cleanup; administrator inspection required\n";
            }
        }
        throw;
    }
}

int main(int argc, char **argv) {
    try {
        DuckDB db(nullptr);
        db.LoadStaticExtension<CoreFunctionsExtension>();
        db.LoadStaticExtension<OracleScannerExtension>();
        Connection con(db);
        Configure(con, Env("ODL_USER"), Env("ODL_PASSWORD"));
        Run(con, "SELECT * FROM oracle_query('live', 'SELECT 1 FROM DUAL');", "authenticate_once");
        if (argc > 1 && std::string(argv[1]) == "--preflight") {
            std::cout << "PASS native authentication and query\n";
            return 0;
        }
        if (argc > 1 && std::string(argv[1]) == "--atp-suite") {
            ATPChecks(con);
        } else {
            TransactionChecks(db, con);
        }
        return 0;
    } catch (const std::exception &) {
        return 1;
    }
}
