// Opt-in live checks of the attached catalog's transaction session pool.
//
// Everything comes from the environment: ORA19C_HOST, ORA19C_PORT,
// ORA19C_SERVICE, ORA19C_USER and ORA19C_PASSWORD name an administrative
// account. The test creates two throwaway users with random passwords, runs
// against them, and drops them again, checking that no server session of
// theirs is left. Nothing is printed but stage names and Oracle error codes.
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
#include <set>
#include <vector>
#include <stdexcept>
#include <string>
#include <thread>

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

[[noreturn]] void Fail(const std::string &stage, const std::string &error = std::string()) {
    std::smatch code;
    const std::regex ora("ORA-[0-9]{5}");
    std::cerr << "FAIL " << stage;
    if (std::regex_search(error, code, ora)) {
        std::cerr << " " << code.str();
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
    if (result->RowCount() != 1) {
        Fail(stage + ": row count");
    }
    return result->GetValue(0, 0).ToString();
}

std::string Connection_(const std::string &user, const std::string &password) {
    return "TYPE oracle, HOST " + SqlLiteral(Env("ORA19C_HOST")) + ", PORT " + Env("ORA19C_PORT") + ", SERVICE_NAME " +
           SqlLiteral(Env("ORA19C_SERVICE")) + ", USER " + SqlLiteral(user) + ", PASSWORD " + SqlLiteral(password) +
           ", CONNECT_TIMEOUT 5, READ_TIMEOUT 60";
}

struct Identity {
    std::string session_id;
    std::string sid;
    std::string user;
};

Identity Who(DuckDB &db, const std::string &catalog, const std::string &stage) {
    Connection con(db);
    auto result = Run(con,
                      "SELECT * FROM oracle_query_transaction(" + SqlLiteral(catalog) +
                          ", 'SELECT SYS_CONTEXT(''USERENV'',''SESSIONID'') AS ID, "
                          "SYS_CONTEXT(''USERENV'',''SID'') AS SID, USER AS U FROM DUAL');",
                      stage);
    Check(result->RowCount() == 1, stage + ": identity row");
    return {result->GetValue(0, 0).ToString(), result->GetValue(1, 0).ToString(), result->GetValue(2, 0).ToString()};
}

int64_t Sessions(Connection &admin, const std::string &user) {
    return std::stoll(Scalar(admin,
                             "SELECT * FROM oracle_query('admin', 'SELECT COUNT(*) AS N FROM V$SESSION WHERE USERNAME = "
                             "''" + user + "''');",
                             "count sessions"));
}

int64_t SessionsEventually(Connection &admin, const std::string &user, int64_t expected) {
    auto count = Sessions(admin, user);
    for (int attempt = 0; attempt < 50 && count != expected; attempt++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        count = Sessions(admin, user);
    }
    return count;
}

void Kill(Connection &admin, const std::string &sid_filter, const std::string &stage) {
    auto rows = Run(admin, "SELECT * FROM oracle_query('admin', 'SELECT SID || '','' || SERIAL# AS S FROM V$SESSION WHERE " +
                               sid_filter + "');",
                    stage);
    Check(rows->RowCount() == 1, stage + ": one session to kill");
    auto killed = admin.Query("SELECT * FROM oracle_execute_admin('admin', 'ALTER SYSTEM KILL SESSION ''" +
                              rows->GetValue(0, 0).ToString() + "'' IMMEDIATE');");
    // ORA-00031: marked for kill, which a session in a wait answers; it is
    // killed as soon as the wait lets it, which is what the test needs.
    if (killed->HasError() && killed->GetError().find("ORA-00031") == std::string::npos) {
        Fail(stage, killed->GetError());
    }
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

std::string Items(DuckDB &db, const std::string &catalog, const std::string &stage) {
    Connection con(db);
    return Scalar(con, "SELECT * FROM oracle_query_transaction(" + SqlLiteral(catalog) +
                           ", 'SELECT COUNT(*) || '':'' || NVL(SUM(N), 0) AS S FROM ITEMS');",
                  stage);
}

} // namespace

int main() {
    DuckDB db(nullptr);
    db.LoadStaticExtension<CoreFunctionsExtension>();
    db.LoadStaticExtension<OracleScannerExtension>();
    Connection admin(db);
    const auto suffix = Random(8);
    const auto user_a = "QO_POOL_A_" + suffix;
    const auto user_b = "QO_POOL_B_" + suffix;
    const auto password_a = "P" + Random(20);
    const auto password_b = "P" + Random(20);
    bool created = false;
    int status = 0;
    try {
        Run(admin, "CREATE SECRET admin (" + Connection_(Env("ORA19C_USER"), Env("ORA19C_PASSWORD")) + ");", "admin secret");
        for (const auto &[user, password] : {std::make_pair(user_a, password_a), std::make_pair(user_b, password_b)}) {
            Run(admin,
                "SELECT * FROM oracle_execute_admin('admin', 'CREATE USER " + user + " IDENTIFIED BY \"" + password +
                    "\" QUOTA UNLIMITED ON USERS');",
                "create user");
            created = true;
            Run(admin, "SELECT * FROM oracle_execute_admin('admin', 'GRANT CREATE SESSION, CREATE TABLE TO " + user + "');",
                "grant");
            Run(admin,
                "SELECT * FROM oracle_execute_admin('admin', 'CREATE TABLE " + user +
                    ".ITEMS (ID NUMBER PRIMARY KEY, N NUMBER NOT NULL)');",
                "create table");
        }
        Run(admin, "CREATE SECRET rt_a (" + Connection_(user_a, password_a) + ");", "runtime secret");
        Run(admin, "CREATE SECRET rt_b (" + Connection_(user_b, password_b) + ");", "runtime secret");

        // 1. Reuse across per-transaction connections, after COMMIT and ROLLBACK.
        Run(admin, "ATTACH 'rt_a' AS tx (TYPE oracle_scanner);", "attach");
        Check(Sessions(admin, user_a) == 1, "attach leaves one idle session");
        const auto first = Who(db, "tx", "identity");
        for (int row = 1; row <= 3; row++) {
            Connection con(db);
            Run(con,
                "SELECT * FROM oracle_execute_transaction('tx', 'INSERT INTO ITEMS VALUES (:1, 0)', [" +
                    std::to_string(row) + "]);",
                "insert");
        }
        {
            Connection con(db);
            Run(con, "BEGIN;", "begin");
            Run(con, "SELECT * FROM oracle_execute_transaction('tx', 'INSERT INTO ITEMS VALUES (99, 0)');",
                "rolled back insert");
            Run(con, "ROLLBACK;", "rollback");
        }
        Check(Items(db, "tx", "items") == "3:0", "COMMITs kept, ROLLBACK undone");
        const auto after = Who(db, "tx", "identity");
        Check(after.session_id == first.session_id && after.user == user_a, "one session across transactions");
        Check(Sessions(admin, user_a) == 1, "still one server session");
        std::cout << "PASS reuse after COMMIT and ROLLBACK across connections\n";

        // The control: no pool, a new logon per transaction.
        Run(admin, "SET oracle_transaction_pool_size = 0;", "pool off");
        Run(admin, "ATTACH 'rt_a' AS unpooled (TYPE oracle_scanner);", "attach unpooled");
        Run(admin, "RESET oracle_transaction_pool_size;", "pool default");
        std::set<std::string> logons;
        for (int round = 0; round < 3; round++) {
            logons.insert(Who(db, "unpooled", "identity").session_id);
        }
        Check(logons.size() == 3, "pool size 0 logs on every time");
        Run(admin, "DETACH unpooled;", "detach unpooled");
        std::cout << "PASS pool size 0 opens a session per transaction\n";

        // 2. A session killed while idle is replaced before the next
        // transaction sends anything, and that transaction runs once.
        Kill(admin, "AUDSID = " + after.session_id, "kill idle");
        {
            Connection con(db);
            Run(con, "SELECT * FROM oracle_execute_transaction('tx', 'INSERT INTO ITEMS VALUES (4, 0)');",
                "insert after kill");
        }
        Check(Items(db, "tx", "items") == "4:0", "exactly one row after the kill");
        const auto replaced = Who(db, "tx", "identity");
        Check(replaced.session_id != after.session_id, "a fresh session replaced the killed one");
        std::cout << "PASS killed idle session replaced before any work\n";

        // 3. Killed while its UPDATE waits on a row lock: the failure is the
        // caller's, nothing is retried, and the row keeps its value.
        Run(admin, "ATTACH 'rt_a' AS holder (TYPE oracle_scanner);", "attach holder");
        Connection holding(db);
        Run(holding, "BEGIN;", "holder begin");
        Run(holding, "SELECT * FROM oracle_execute_transaction('holder', 'UPDATE ITEMS SET N = N WHERE ID = 1');",
            "holder lock");
        std::atomic<bool> victim_failed {false};
        JoinedThread victim([&] {
            Connection con(db);
            auto result =
                con.Query("SELECT * FROM oracle_execute_transaction('tx', 'UPDATE ITEMS SET N = N + 1 WHERE ID = 1');");
            victim_failed = result->HasError();
        });
        std::string blocked;
        for (int attempt = 0; attempt < 100 && blocked.empty(); attempt++) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            auto rows = Run(admin,
                            "SELECT * FROM oracle_query('admin', 'SELECT AUDSID FROM V$SESSION WHERE USERNAME = ''" +
                                user_a + "'' AND BLOCKING_SESSION IS NOT NULL');",
                            "find blocked");
            if (rows->RowCount() == 1) {
                blocked = rows->GetValue(0, 0).ToString();
            }
        }
        Check(!blocked.empty(), "the UPDATE waits on the lock");
        Kill(admin, "AUDSID = " + blocked, "kill while waiting");
        victim.Join();
        Check(victim_failed, "the interrupted UPDATE reports its failure");
        Run(holding, "ROLLBACK;", "holder rollback");
        Check(Items(db, "tx", "items") == "4:0", "the UPDATE was not replayed");
        std::cout << "PASS no replay once an operation began\n";

        // 4. A DuckDB interrupt reaches the socket of a reused session on every
        // transaction path: a SELECT FOR UPDATE opened by
        // oracle_query_transaction, a scalar UPDATE, a batch UPDATE. Each waits
        // on a row lock, on the session the pool handed out; the interrupt ends
        // the wait without waiting for the lock or the read timeout, nothing is
        // replayed, and the connection begins and commits a new transaction.
        const std::vector<std::pair<std::string, std::string>> paths = {
            {"query open", "SELECT * FROM oracle_query_transaction('tx', 'SELECT ID FROM ITEMS WHERE ID = 2 FOR UPDATE');"},
            {"scalar execute",
             "SELECT * FROM oracle_execute_transaction('tx', 'UPDATE ITEMS SET N = N + 1 WHERE ID = 2');"},
            {"batch", "SELECT * FROM oracle_execute_many_transaction('tx', "
                      "'UPDATE ITEMS SET N = N + 1 WHERE ID = :id', [{id: 2}]);"},
        };
        for (const auto &path : paths) {
            const auto warm = Who(db, "tx", "warm the pool");
            Run(holding, "BEGIN;", "holder begin");
            Run(holding, "SELECT * FROM oracle_execute_transaction('holder', 'UPDATE ITEMS SET N = N WHERE ID = 2');",
                "holder lock");
            Connection con(db);
            std::atomic<bool> interrupted_failed {false};
            std::atomic<bool> returned {false};
            std::chrono::steady_clock::time_point returned_at;
            {
                JoinedThread runner([&] {
                    auto result = con.Query(path.second);
                    returned_at = std::chrono::steady_clock::now();
                    interrupted_failed = result->HasError();
                    returned = true;
                });
                std::string waiting;
                for (int attempt = 0; attempt < 100 && waiting.empty(); attempt++) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    auto rows = Run(admin,
                                    "SELECT * FROM oracle_query('admin', 'SELECT AUDSID FROM V$SESSION WHERE USERNAME = ''" +
                                        user_a + "'' AND BLOCKING_SESSION IS NOT NULL');",
                                    "find waiting");
                    if (rows->RowCount() == 1) {
                        waiting = rows->GetValue(0, 0).ToString();
                    }
                }
                Check(waiting == warm.session_id, path.first + ": waits on the reused session");
                const auto interrupted_at = std::chrono::steady_clock::now();
                con.Interrupt();
                runner.Join();
                Check(returned && interrupted_failed, path.first + ": the interrupted statement fails");
                Check(returned_at - interrupted_at < std::chrono::seconds(2), path.first + ": the interrupt ended the wait");
                std::cout << "PASS interrupt reaches a reused session (" << path.first << "), "
                          << std::chrono::duration_cast<std::chrono::milliseconds>(returned_at - interrupted_at).count()
                          << " ms\n";
            }
            Run(holding, "ROLLBACK;", "holder rollback");
            Check(Items(db, "tx", "items") == "4:0", path.first + ": nothing replayed");
            Run(con, "BEGIN;", path.first + ": begin again");
            Run(con, "SELECT * FROM oracle_query_transaction('tx', 'SELECT N FROM ITEMS WHERE ID = 2');",
                path.first + ": read again");
            Run(con, "COMMIT;", path.first + ": commit again");
        }
        Run(admin, "DETACH holder;", "detach holder");

        // 5. Two users, two catalogs, two pools.
        Run(admin, "ATTACH 'rt_b' AS other (TYPE oracle_scanner);", "attach other");
        for (int round = 0; round < 2; round++) {
            Check(Who(db, "tx", "identity a").user == user_a, "catalog tx stays user A");
            Check(Who(db, "other", "identity b").user == user_b, "catalog other stays user B");
        }
        Check(Who(db, "tx", "identity a").session_id != Who(db, "other", "identity b").session_id,
              "the two catalogs never share a session");
        std::cout << "PASS users and secrets kept apart\n";

        // 6. Bounded: three concurrent transactions leave at most two idle.
        {
            Connection c1(db), c2(db), c3(db);
            for (auto *con : {&c1, &c2, &c3}) {
                Run(*con, "BEGIN;", "begin concurrent");
                (void)Run(*con, "SELECT * FROM oracle_query_transaction('tx', 'SELECT 1 AS X FROM DUAL');",
                          "concurrent read");
            }
            // Eventually, because the session stage 3 killed can linger in
            // V$SESSION as KILLED for a moment on a busy server: Free 23ai
            // showed four rows, one of them KILLED, and three a moment later.
            Check(SessionsEventually(admin, user_a, 3) == 3, "three transactions hold three sessions");
            for (auto *con : {&c1, &c2, &c3}) {
                Run(*con, "COMMIT;", "commit concurrent");
            }
        }
        Check(SessionsEventually(admin, user_a, 2) == 2, "at most two stay idle");
        Run(admin, "DETACH tx;", "detach");
        Run(admin, "DETACH other;", "detach other");
        Check(SessionsEventually(admin, user_a, 0) == 0 && SessionsEventually(admin, user_b, 0) == 0,
              "DETACH leaves no server session");
        std::cout << "PASS bounded idle sessions, none left after DETACH\n";
    } catch (const std::exception &error) {
        std::cerr << "live test stopped: " << (std::string(error.what()) == "live check failed" ? "" : "error") << "\n";
        status = 1;
    }
    if (created) {
        try {
            for (const auto &user : {user_a, user_b}) {
                auto left = Run(admin, "SELECT * FROM oracle_query('admin', 'SELECT SID || '','' || SERIAL# AS S FROM "
                                       "V$SESSION WHERE USERNAME = ''" + user + "''');",
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
            }
            const auto remaining = Scalar(admin,
                                          "SELECT * FROM oracle_query('admin', 'SELECT COUNT(*) AS N FROM DBA_USERS "
                                          "WHERE USERNAME IN (''" + user_a + "'', ''" + user_b + "'')');",
                                          "cleanup check");
            Check(remaining == "0", "test users dropped");
            std::cout << "PASS cleanup: test users and their sessions gone\n";
        } catch (const std::exception &) {
            std::cerr << "FAIL cleanup\n";
            status = 1;
        }
    }
    return status;
}
