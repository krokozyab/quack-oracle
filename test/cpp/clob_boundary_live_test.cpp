// Opt-in live checks of CLOB reads across packet and prefetch boundaries.
//
// ORA19C_HOST, ORA19C_PORT, ORA19C_SERVICE, ORA19C_USER and ORA19C_PASSWORD
// name an administrative account. The test creates a throwaway user with a
// random password, writes CLOBs of many lengths with ordinary SQL, reads them
// back through the extension, and drops the user. Only stage names and Oracle
// error codes are printed.
#include "duckdb.hpp"
#include "oracle_scanner_extension.hpp"
#include "core_functions_extension.hpp"
#include "live_query_result.hpp"

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

[[noreturn]] void Fail(const std::string &stage, const std::string &error = std::string()) {
    std::smatch code;
    const std::regex ora("ORA-[0-9]{5}");
    std::cerr << "FAIL " << stage;
    if (std::regex_search(error, code, ora)) {
        std::cerr << " " << code.str();
    } else if (!error.empty()) {
        // Driver-side errors carry no SQL, binds or endpoints; keep their kind.
        const std::regex driver("TTC[^\\n]{0,120}");
        if (std::regex_search(error, code, driver)) {
            std::cerr << " " << code.str();
        }
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

std::string Secret(const std::string &user, const std::string &password) {
    return "TYPE oracle, HOST " + SqlLiteral(Env("ORA19C_HOST")) + ", PORT " + Env("ORA19C_PORT") + ", SERVICE_NAME " +
           SqlLiteral(Env("ORA19C_SERVICE")) + ", USER " + SqlLiteral(user) + ", PASSWORD " + SqlLiteral(password) +
           ", CONNECT_TIMEOUT 5, READ_TIMEOUT 60";
}

struct Kind {
    std::string name;
    std::string first;     // UTF-8, the value's first character
    std::string character; // UTF-8, what RPAD pads with
    std::vector<int> lengths;
};

std::vector<int> Range(int from, int to) {
    std::vector<int> result;
    for (int value = from; value <= to; value++) {
        result.push_back(value);
    }
    return result;
}

std::vector<int> Every(int from, int to, int step) {
    std::vector<int> result;
    for (int value = from; value <= to; value += step) {
        result.push_back(value);
    }
    return result;
}

std::vector<int> Join(std::initializer_list<std::vector<int>> parts) {
    std::vector<int> result;
    for (const auto &part : parts) {
        result.insert(result.end(), part.begin(), part.end());
    }
    return result;
}

} // namespace

int main() {
    DuckDB db(nullptr);
    db.LoadStaticExtension<CoreFunctionsExtension>();
    db.LoadStaticExtension<OracleScannerExtension>();
    Connection admin(db);
    const auto user = "QO_CLOB_" + Random(8);
    const auto password = "P" + Random(20);
    bool created = false;
    int status = 0;
    // ASCII around the prefetch prefix (4096), the reported failure (8069)
    // and its neighbours (7941, 8965), packet-sized remainders, the 32767
    // read size and 65536; a two-byte character near the same boundaries.
    // Lengths are Oracle's, in UTF-16 units: a four-byte character is a
    // surrogate pair, two units. RPAD to an odd length would cut the last pair
    // in half and store that, so "emoji" uses even lengths only, and
    // "x+emoji" starts with one ASCII unit, so its pairs begin at odd offsets
    // and straddle the 4096 prefix and the 32767 read size.
    const std::vector<Kind> kinds = {
        {"ascii", "x", "x",
         Join({Range(1, 40), Range(4086, 4106), Range(7930, 8210), Range(8950, 8980), Range(12276, 12300),
               Range(16370, 16400), Range(32760, 32775), Range(65530, 65540)})},
        {"cyr", "\xd0\xb6", "\xd0\xb6", Join({Range(4090, 4100), Range(7936, 7946), Range(8060, 8080), Range(8960, 8970)})},
        {"emoji", "\xf0\x9f\x98\x80", "\xf0\x9f\x98\x80",
         Join({Every(4084, 4108, 2), Every(8060, 8080, 2), Every(16378, 16392, 2), Every(65530, 65540, 2)})},
        {"xemoji", "x", "\xf0\x9f\x98\x80", Join({Every(4089, 4105, 2), Every(8061, 8081, 2), Every(32761, 32775, 2)})},
    };
    try {
        Run(admin, "CREATE SECRET admin (" + Secret(Env("ORA19C_USER"), Env("ORA19C_PASSWORD")) + ");", "admin secret");
        Run(admin,
            "SELECT * FROM oracle_execute_admin('admin', 'CREATE USER " + user + " IDENTIFIED BY \"" + password +
                "\" QUOTA 64M ON USERS');",
            "create user");
        created = true;
        Run(admin, "SELECT * FROM oracle_execute_admin('admin', 'GRANT CREATE SESSION, CREATE TABLE TO " + user + "');",
            "grant");
        Run(admin,
            "SELECT * FROM oracle_execute_admin('admin', 'CREATE TABLE " + user +
                ".T (ID NUMBER(10) PRIMARY KEY, KIND VARCHAR2(8) NOT NULL, N NUMBER(10) NOT NULL, PAYLOAD CLOB)');",
            "create table");
        Run(admin, "CREATE SECRET rt (" + Secret(user, password) + ");", "runtime secret");
        Run(admin, "ATTACH 'rt' AS raw (TYPE oracle_scanner);", "attach");

        // Written by Oracle from ordinary SQL: RPAD over a CLOB.
        int id = 0;
        size_t total = 0;
        for (const auto &kind : kinds) {
            std::string rows;
            for (const auto length : kind.lengths) {
                rows += (rows.empty() ? "" : ", ") + std::string("{id: ") + std::to_string(++id) + ", kind: " +
                        SqlLiteral(kind.name) + ", n: " + std::to_string(length) + ", f: " + SqlLiteral(kind.first) + ", c: " + SqlLiteral(kind.character) + "}";
                total++;
            }
            Run(admin,
                "SELECT * FROM oracle_execute_many_transaction('raw', "
                "'INSERT INTO T (ID, KIND, N, PAYLOAD) VALUES (:id, :kind, :n, RPAD(TO_CLOB(:f), :n, :c))', [" +
                    rows + "]);",
                "insert " + kind.name);
        }
        Check(Scalar(admin, "SELECT * FROM oracle_query_transaction('raw', 'SELECT COUNT(*) AS N FROM T');", "count") ==
                  std::to_string(total),
              "every row written");

        // Every value, in one scan, exactly: content, Oracle's own length.
        const std::string compare =
        "SELECT count(*) AS rows, count(*) FILTER (WHERE payload IS DISTINCT FROM CASE kind "
        "WHEN 'ascii' THEN repeat('x', CAST(n AS BIGINT)) WHEN 'cyr' THEN repeat('\xd0\xb6', CAST(n AS BIGINT)) "
        "WHEN 'emoji' THEN repeat('\xf0\x9f\x98\x80', CAST(n AS BIGINT) // 2) "
        "ELSE 'x' || repeat('\xf0\x9f\x98\x80', (CAST(n AS BIGINT) - 1) // 2) END) AS wrong, "
        "count(*) FILTER (WHERE kind IN ('ascii', 'cyr') AND (length(payload) <> n OR oracle_length <> n)) "
        "AS wrong_length FROM ";
        for (const auto &source :
             {std::string("oracle_query_transaction('raw', 'SELECT ID, KIND, N, LENGTH(PAYLOAD) AS ORACLE_LENGTH, "
                          "PAYLOAD FROM T ORDER BY ID')"),
              std::string("oracle_query('rt', 'SELECT ID, KIND, N, LENGTH(PAYLOAD) AS ORACLE_LENGTH, PAYLOAD FROM T "
                          "ORDER BY ID')")}) {
            auto result = Run(admin, compare + source + ";", "read all");
            Check(result->GetValue(0, 0).ToString() == std::to_string(total), "every row read");
            Check(result->GetValue(1, 0).ToString() == "0", "every value exact");
            Check(result->GetValue(2, 0).ToString() == "0", "every length exact");
        }
        std::cout << "PASS " << total << " CLOBs exact (ASCII, two-byte, surrogate pairs), both read paths\n";

        // The reported shape, one ordinary SELECT per value, as the backend
        // runs it: 7941, 8069 and 8965 ASCII characters.
        for (const auto length : {7941, 8069, 8965}) {
            for (const auto &source :
                 {"oracle_query_transaction('raw', 'SELECT ID, PAYLOAD, ROWIDTOCHAR(ROWID) ODL_ROW_ID FROM T WHERE "
                  "KIND = ''ascii'' AND N = " + std::to_string(length) + "')",
                  "oracle_query('rt', 'SELECT ID, PAYLOAD FROM T WHERE KIND = ''ascii'' AND N = " +
                      std::to_string(length) + "')"}) {
                Connection con(db);
                Check(Scalar(con, "SELECT payload = repeat('x', " + std::to_string(length) + ") FROM " + source + ";",
                             "direct " + std::to_string(length)) == "true",
                      "direct " + std::to_string(length) + " exact");
            }
        }
        std::cout << "PASS direct SELECT of 7941, 8069 and 8965 characters\n";

        // A LOB read leaves its session clean: the next transaction reuses it,
        // and a rollback after reading still lets the connection go on.
        const auto who = "SELECT * FROM oracle_query_transaction('raw', 'SELECT SYS_CONTEXT(''USERENV'',''SESSIONID'') "
                         "AS S FROM DUAL');";
        {
            Connection con(db);
            const auto before = Scalar(con, who, "identity");
            Run(con, "BEGIN;", "begin");
            Check(Scalar(con,
                         "SELECT payload = repeat('x', 8069) FROM oracle_query_transaction('raw', "
                         "'SELECT PAYLOAD FROM T WHERE KIND = ''ascii'' AND N = 8069');",
                         "read in transaction") == "true",
                  "8069 inside a transaction");
            Run(con,
                "SELECT * FROM oracle_execute_transaction('raw', 'INSERT INTO T (ID, KIND, N, PAYLOAD) VALUES (999999, "
                "''ascii'', 1, TO_CLOB(''x''))');",
                "insert in transaction");
            Run(con, "ROLLBACK;", "rollback");
            Check(Scalar(con, "SELECT * FROM oracle_query_transaction('raw', 'SELECT COUNT(*) AS N FROM T');",
                         "count after rollback") == std::to_string(total),
                  "rollback undid the insert");
            Run(con, "BEGIN;", "begin again");
            Check(Scalar(con,
                         "SELECT payload = repeat('\xd0\xb6', 8069) FROM oracle_query_transaction('raw', "
                         "'SELECT PAYLOAD FROM T WHERE KIND = ''cyr'' AND N = 8069');",
                         "read again") == "true",
                  "next transaction reads");
            Run(con, "COMMIT;", "commit");
            Check(Scalar(con, who, "identity") == before, "the session that read LOBs went back to the pool");
        }
        std::cout << "PASS rollback and next transaction on the same connection; LOB reads leave the session reusable\n";
        Run(admin, "DETACH raw;", "detach");
    } catch (const std::exception &error) {
        std::cerr << "live test stopped" << (std::string(error.what()) == "live check failed" ? "" : ": error") << "\n";
        status = 1;
    }
    if (created) {
        try {
            (void)admin.Query("DETACH IF EXISTS raw;");
            auto left = Run(admin,
                            "SELECT * FROM oracle_query('admin', 'SELECT SID || '','' || SERIAL# AS S FROM V$SESSION "
                            "WHERE USERNAME = ''" + user + "''');",
                            "cleanup sessions");
            for (idx_t row = 0; row < left->RowCount(); row++) {
                (void)admin.Query("SELECT * FROM oracle_execute_admin('admin', 'ALTER SYSTEM KILL SESSION ''" +
                                  left->GetValue(0, row).ToString() + "'' IMMEDIATE');");
            }
            auto dropped = admin.Query("SELECT * FROM oracle_execute_admin('admin', 'DROP USER " + user + " CASCADE');");
            if (dropped->HasError()) {
                std::this_thread::sleep_for(std::chrono::seconds(2));
                Run(admin, "SELECT * FROM oracle_execute_admin('admin', 'DROP USER " + user + " CASCADE');", "drop user");
            }
            Check(Scalar(admin,
                         "SELECT * FROM oracle_query('admin', 'SELECT (SELECT COUNT(*) FROM DBA_USERS WHERE USERNAME = ''" +
                             user + "'') || ''/'' || (SELECT COUNT(*) FROM V$SESSION WHERE USERNAME = ''" + user +
                             "'') AS S FROM DUAL');",
                         "cleanup check") == "0/0",
                  "test user and sessions gone");
            std::cout << "PASS cleanup 0/0\n";
        } catch (const std::exception &) {
            std::cerr << "FAIL cleanup\n";
            status = 1;
        }
    }
    return status;
}
