// Opt-in live checks of the column types added in 0.6.0: NCHAR and NVARCHAR2,
// INTERVAL YEAR TO MONTH and DAY TO SECOND, ROWID and UROWID, LONG and LONG RAW,
// TIMESTAMP WITH LOCAL TIME ZONE, BOOLEAN (23ai only; skipped where the server
// has none), and writing the national and interval columns, BOOLEAN and LOBs.
//
// ORA19C_HOST, ORA19C_PORT, ORA19C_SERVICE, ORA19C_USER and ORA19C_PASSWORD
// name an administrative account. The test creates a throwaway user with a
// random password, writes the values with ordinary SQL, reads them back
// through oracle_query and through an attached catalog, and drops the user.
// Where Oracle can say what a value is — ROWIDTOCHAR, CAST(... AS VARCHAR2) —
// the comparison is against Oracle's own text rather than against a constant.
// Only stage names and Oracle error codes are printed.
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

std::string Admin(const std::string &statement) {
    std::string quoted;
    for (const auto c : statement) {
        quoted += c == '\'' ? "''" : std::string(1, c);
    }
    return "SELECT * FROM oracle_execute_admin('admin', '" + quoted + "');";
}

} // namespace

int main() {
    DuckDB db(nullptr);
    db.LoadStaticExtension<CoreFunctionsExtension>();
    db.LoadStaticExtension<OracleScannerExtension>();
    Connection admin(db);
    const auto user = "QO_TYPES_" + Random(8);
    const auto password = "P" + Random(20);
    bool created = false;
    int status = 0;
    const std::string emoji = "\xf0\x9f\x98\x80";
    try {
        Run(admin, "CREATE SECRET admin (" + Secret(Env("ORA19C_USER"), Env("ORA19C_PASSWORD")) + ");", "admin secret");
        Run(admin, Admin("CREATE USER " + user + " IDENTIFIED BY \"" + password + "\" QUOTA 512M ON USERS"), "create user");
        created = true;
        Run(admin, Admin("GRANT CREATE SESSION, CREATE TABLE TO " + user), "grant");
        const auto table = [&](const std::string &definition, const std::string &stage) {
            Run(admin, Admin("CREATE TABLE " + user + "." + definition), stage);
        };
        table("T_NATIONAL (ID NUMBER(5) PRIMARY KEY, NV NVARCHAR2(40), NC NCHAR(8))", "create national");
        table("T_INTERVAL (ID NUMBER(5) PRIMARY KEY, YM INTERVAL YEAR(4) TO MONTH, DS INTERVAL DAY(4) TO SECOND(6))",
              "create interval");
        table("T_ROWID (ID NUMBER(5) PRIMARY KEY, R ROWID, U UROWID(200))", "create rowid");
        table("T_LONG (ID NUMBER(5), L LONG)", "create long");
        table("T_LONG_RAW (ID NUMBER(5), L LONG RAW)", "create long raw");
        table("T_LONG_MID (A NUMBER(5), L LONG, B VARCHAR2(10))", "create long mid");
        table("T_IOT (K VARCHAR2(30) PRIMARY KEY, V NUMBER(5)) ORGANIZATION INDEX", "create iot");
        table("T_LOGICAL (ID NUMBER(5), U UROWID(4000))", "create logical");
        table("T_MIX (ID NUMBER(5), DOC CLOB, R ROWID)", "create mix");
        // Every table is created before the catalog is attached: it reads the
        // column dictionary once, and a table created after that is not in it.
        table("T_FINE (D INTERVAL DAY(2) TO SECOND(9))", "create fine");
        table("T_LTZ (ID NUMBER(5) PRIMARY KEY, L TIMESTAMP(6) WITH LOCAL TIME ZONE, L9 TIMESTAMP(9) WITH LOCAL TIME ZONE)",
              "create ltz");
        table("T_WRITE (ID NUMBER(5) PRIMARY KEY, NV NVARCHAR2(40), NC NCHAR(8), YM INTERVAL YEAR(4) TO MONTH, "
              "DS INTERVAL DAY(4) TO SECOND(6), L TIMESTAMP(6) WITH LOCAL TIME ZONE)",
              "create write");
        table("T_CHAR (ID NUMBER(3), C CHAR(4))", "create char");
        table("T_LOBW (ID NUMBER(5) PRIMARY KEY, C CLOB, B BLOB, N NCLOB)", "create lobw");
        table("T_XML (ID NUMBER(5) PRIMARY KEY, X XMLTYPE)", "create xml");
        table("T_PAR (ID NUMBER(10) PRIMARY KEY, G NUMBER(3), PAD VARCHAR2(60))", "create par");
        // BOOLEAN exists from 23ai. A server without it refuses the type, and the
        // stage is skipped rather than failed.
        bool has_boolean = true;
        {
            auto created_boolean = admin.Query(Admin("CREATE TABLE " + user + ".T_BOOL (ID NUMBER(5) PRIMARY KEY, B BOOLEAN)"));
            has_boolean = !created_boolean->HasError();
        }
        // JSON and VECTOR need 23ai. A server without them refuses the types and
        // the stage is skipped.
        bool has_json = true;
        {
            auto created_json = admin.Query(Admin("CREATE TABLE " + user + ".T_JV (ID NUMBER(5) PRIMARY KEY, J JSON, V3 VECTOR(3,FLOAT32), "
                                                  "VD VECTOR(2,FLOAT64), VI VECTOR(4,INT8), VB VECTOR(16,BINARY), VX VECTOR(*,*), "
                                                  "VS VECTOR(6,FLOAT32,SPARSE))"));
            has_json = !created_json->HasError();
            if (has_json) {
                table("T_JV_MIX (ID NUMBER(5) PRIMARY KEY, V VARCHAR2(20), D DATE, T TIMESTAMP(6), N NUMBER(6,2), C CLOB, J JSON, "
                      "E VECTOR(3,FLOAT32))",
                      "create json mix");
            }
        }
        Run(admin, "CREATE SECRET rt (" + Secret(user, password) + ");", "runtime secret");
        Run(admin, "ATTACH 'rt' AS raw (TYPE oracle_scanner);", "attach");
        const auto dml = [&](const std::string &sql, const std::string &stage) {
            Run(admin, "SELECT * FROM oracle_execute_transaction('raw', " + SqlLiteral(sql) + ");", stage);
        };

        // NCHAR and NVARCHAR2: ASCII, Latin-1, Cyrillic, CJK, and a character
        // outside the BMP, which UTF-16 spends a surrogate pair on.
        dml("INSERT INTO T_NATIONAL VALUES (1, N'plain', N'ab')", "national 1");
        dml("INSERT INTO T_NATIONAL VALUES (2, N'h\xc3\xa9llo \xd0\x9f\xd1\x80\xd0\xb8\xd0\xb2\xd0\xb5\xd1\x82 " + emoji + "', N'\xe6\x97\xa5\xe6\x9c\xac')", "national 2");
        dml("INSERT INTO T_NATIONAL VALUES (3, NULL, NULL)", "national 3");
        dml("INSERT INTO T_NATIONAL VALUES (4, RPAD(N'\xd0\xb6', 40, N'\xd0\xb6'), N'12345678')", "national 4");
        for (const auto &source : {std::string("oracle_query('rt', 'SELECT ID, NV, NC FROM T_NATIONAL ORDER BY ID')"),
                                   std::string("raw.T_NATIONAL")}) {
            auto result = Run(admin, "SELECT id, nv, nc FROM " + source + " ORDER BY id;", "national read");
            Check(result->RowCount() == 4, "national rows");
            Check(result->GetValue(1, 0).ToString() == "plain" && result->GetValue(2, 0).ToString() == "ab      ",
                  "national ascii and blank padding");
            Check(result->GetValue(1, 1).ToString() == "h\xc3\xa9llo \xd0\x9f\xd1\x80\xd0\xb8\xd0\xb2\xd0\xb5\xd1\x82 " + emoji &&
                      result->GetValue(2, 1).ToString() == "\xe6\x97\xa5\xe6\x9c\xac      ",
                  "national multibyte and surrogate pair");
            Check(result->GetValue(1, 2).IsNull() && result->GetValue(2, 2).IsNull(), "national NULL");
            std::string forty;
            for (int i = 0; i < 40; i++) {
                forty += "\xd0\xb6";
            }
            Check(result->GetValue(1, 3).ToString() == forty && result->GetValue(2, 3).ToString() == "12345678",
                  "national at full width");
        }
        std::cout << "PASS NCHAR and NVARCHAR2 read as UTF-8, both read paths\n";

        // INTERVALs, including negative spans and the largest fraction.
        dml("INSERT INTO T_INTERVAL VALUES (1, INTERVAL '2-3' YEAR TO MONTH, INTERVAL '3 04:05:06.789012' DAY TO SECOND)",
            "interval 1");
        dml("INSERT INTO T_INTERVAL VALUES (2, INTERVAL '-5-11' YEAR TO MONTH, INTERVAL '-12 23:59:59.5' DAY TO SECOND)",
            "interval 2");
        dml("INSERT INTO T_INTERVAL VALUES (3, INTERVAL '0-0' YEAR TO MONTH, INTERVAL '0 0:0:0' DAY TO SECOND)",
            "interval 3");
        dml("INSERT INTO T_INTERVAL VALUES (4, INTERVAL '9999-11' YEAR(4) TO MONTH, INTERVAL '9999 23:59:59.999999' DAY(4) TO SECOND(6))",
            "interval 4");
        dml("INSERT INTO T_INTERVAL VALUES (5, NULL, NULL)", "interval 5");
        for (const auto &source : {std::string("oracle_query('rt', 'SELECT ID, YM, DS FROM T_INTERVAL ORDER BY ID')"),
                                   std::string("raw.T_INTERVAL")}) {
            auto result = Run(admin,
                              "SELECT id, ym = INTERVAL 27 MONTH AS a, ds = INTERVAL '3 days 04:05:06.789012' AS b, "
                              "ym = INTERVAL (-71) MONTH AS c, ds = INTERVAL '-12 days -23:59:59.5' AS d, "
                              "ym = INTERVAL 0 MONTH AS e, ds = INTERVAL 0 SECOND AS f, "
                              "ym = INTERVAL (9999 * 12 + 11) MONTH AS g, ds = INTERVAL '9999 days 23:59:59.999999' AS h, "
                              "ym IS NULL AS i, ds IS NULL AS j FROM " + source + " ORDER BY id;",
                              "interval read");
            Check(result->RowCount() == 5, "interval rows");
            Check(result->GetValue(1, 0).ToString() == "true" && result->GetValue(2, 0).ToString() == "true", "interval positive");
            Check(result->GetValue(3, 1).ToString() == "true" && result->GetValue(4, 1).ToString() == "true", "interval negative");
            Check(result->GetValue(5, 2).ToString() == "true" && result->GetValue(6, 2).ToString() == "true", "interval zero");
            Check(result->GetValue(7, 3).ToString() == "true" && result->GetValue(8, 3).ToString() == "true", "interval at the limits");
            Check(result->GetValue(9, 4).ToString() == "true" && result->GetValue(10, 4).ToString() == "true", "interval NULL");
        }
        // A fraction finer than DuckDB's microsecond is refused, not rounded.
        dml("INSERT INTO T_FINE VALUES (INTERVAL '1 00:00:00.123456789' DAY TO SECOND(9))", "fine insert");
        auto fine = admin.Query("SELECT * FROM oracle_query('rt', 'SELECT D FROM T_FINE');");
        Check(fine->HasError() && fine->GetError().find("sub-microsecond") != std::string::npos, "fine fraction refused");
        std::cout << "PASS INTERVAL YEAR TO MONTH and DAY TO SECOND\n";

        // ROWID and UROWID against Oracle's own text for the same row.
        dml("INSERT INTO T_ROWID (ID) VALUES (1)", "rowid 1");
        dml("INSERT INTO T_ROWID (ID) VALUES (2)", "rowid 2");
        dml("INSERT INTO T_ROWID (ID) VALUES (3)", "rowid 3");
        dml("UPDATE T_ROWID SET R = ROWID, U = ROWID WHERE ID IN (1, 2)", "rowid fill");
        for (const auto &source :
             {std::string("oracle_query('rt', 'SELECT ID, R, U, ROWIDTOCHAR(R) AS RC, CAST(U AS VARCHAR2(200)) AS UC, "
                          "ROWIDTOCHAR(ROWID) AS OWN FROM T_ROWID ORDER BY ID')")}) {
            auto result = Run(admin, "SELECT id, r, u, rc, uc, own FROM " + source + " ORDER BY id;", "rowid read");
            Check(result->RowCount() == 3, "rowid rows");
            for (idx_t row = 0; row < 2; row++) {
                Check(result->GetValue(1, row).ToString() == result->GetValue(3, row).ToString() &&
                          result->GetValue(1, row).ToString().size() == 18,
                      "ROWID text equals ROWIDTOCHAR");
                Check(result->GetValue(2, row).ToString() == result->GetValue(4, row).ToString(),
                      "UROWID text equals CAST AS VARCHAR2");
                Check(result->GetValue(1, row).ToString() == result->GetValue(5, row).ToString(),
                      "the stored ROWID is the row's own");
            }
            Check(result->GetValue(1, 2).IsNull() && result->GetValue(2, 2).IsNull(), "ROWID NULL");
        }
        // The attached catalog reads them the same way.
        {
            auto result = Run(admin, "SELECT count(*) FROM raw.T_ROWID WHERE r IS NOT NULL AND u IS NOT NULL;", "rowid attached");
            Check(result->GetValue(0, 0).ToString() == "2", "attached ROWID and UROWID");
        }
        // A logical UROWID frames cleanly and is refused with a reason.
        dml("INSERT INTO T_IOT VALUES ('alpha', 1)", "iot 1");
        dml("INSERT INTO T_LOGICAL SELECT 1, ROWID FROM T_IOT", "logical fill");
        auto logical = admin.Query("SELECT * FROM oracle_query('rt', 'SELECT ID, U FROM T_LOGICAL');");
        Check(logical->HasError() && logical->GetError().find("logical UROWID") != std::string::npos,
              "logical UROWID refused with its name");
        auto logical_id = Run(admin, "SELECT id FROM oracle_query('rt', 'SELECT ID FROM T_LOGICAL');", "logical id");
        Check(logical_id->GetValue(0, 0).ToString() == "1", "a table with a logical UROWID is still readable without it");
        std::cout << "PASS ROWID and UROWID equal Oracle's own text; logical UROWID refused\n";

        // LONG and LONG RAW: a short value, NULL, one that needs chunks, and
        // a LONG between two other columns.
        dml("INSERT INTO T_LONG VALUES (1, 'short')", "long 1");
        dml("INSERT INTO T_LONG VALUES (2, NULL)", "long 2");
        dml("INSERT INTO T_LONG VALUES (3, RPAD('ab', 4000, 'cd'))", "long 3");
        dml("INSERT INTO T_LONG VALUES (4, 'h\xc3\xa9llo \xd0\x9f\xd1\x80\xd0\xb8\xd0\xb2\xd0\xb5\xd1\x82')", "long 4");
        dml("INSERT INTO T_LONG_RAW VALUES (1, HEXTORAW('DEADBEEF'))", "long raw 1");
        dml("INSERT INTO T_LONG_RAW VALUES (2, NULL)", "long raw 2");
        dml("INSERT INTO T_LONG_MID VALUES (1, 'xy', 'p')", "mid 1");
        dml("INSERT INTO T_LONG_MID VALUES (2, NULL, 'q')", "mid 2");
        dml("INSERT INTO T_LONG_MID VALUES (3, 'z', NULL)", "mid 3");
        // The LONG tables have no key, so rows are ordered by their own id.
        for (const auto &source : {std::string("oracle_query('rt', 'SELECT ID, L FROM T_LONG')"), std::string("raw.T_LONG")}) {
            auto result = Run(admin, "SELECT id, l FROM " + source + " ORDER BY id;", "long read");
            Check(result->RowCount() == 4, "long rows");
            Check(result->GetValue(1, 0).ToString() == "short" && result->GetValue(1, 1).IsNull(), "long short and NULL");
            std::string expected = "ab";
            while (expected.size() < 4000) {
                expected += "cd";
            }
            expected.resize(4000);
            Check(result->GetValue(1, 2).ToString() == expected, "long of 4000 characters");
            Check(result->GetValue(1, 3).ToString() == "h\xc3\xa9llo \xd0\x9f\xd1\x80\xd0\xb8\xd0\xb2\xd0\xb5\xd1\x82", "long multibyte");
        }
        for (const auto &source : {std::string("oracle_query('rt', 'SELECT ID, L FROM T_LONG_RAW')"), std::string("raw.T_LONG_RAW")}) {
            auto result = Run(admin, "SELECT id, l FROM " + source + " ORDER BY id;", "long raw read");
            Check(result->RowCount() == 2 && result->GetValue(1, 0).ToString() == "\\xDE\\xAD\\xBE\\xEF" && result->GetValue(1, 1).IsNull(),
                  "long raw value and NULL");
        }
        for (const auto &source : {std::string("oracle_query('rt', 'SELECT A, L, B FROM T_LONG_MID')"), std::string("raw.T_LONG_MID")}) {
            auto result = Run(admin, "SELECT a, l, b FROM " + source + " ORDER BY a;", "long mid read");
            Check(result->RowCount() == 3, "mid rows");
            Check(result->GetValue(1, 0).ToString() == "xy" && result->GetValue(2, 0).ToString() == "p", "mid first");
            Check(result->GetValue(1, 1).IsNull() && result->GetValue(2, 1).ToString() == "q", "mid NULL LONG");
            Check(result->GetValue(1, 2).ToString() == "z" && result->GetValue(2, 2).IsNull(), "mid NULL neighbour");
        }
        std::cout << "PASS LONG and LONG RAW, alone and between other columns\n";

        // A CLOB beside a ROWID: the LOB-prefetch path declines columns it
        // does not know, and the ordinary LOB path has to frame both.
        dml("INSERT INTO T_MIX VALUES (1, TO_CLOB('first'), NULL)", "mix 1");
        dml("INSERT INTO T_MIX VALUES (2, RPAD(TO_CLOB('x'), 9000, 'y'), NULL)", "mix 2");
        dml("UPDATE T_MIX SET R = ROWID", "mix fill");
        auto mix = Run(admin,
                       "SELECT id, length(doc) AS n, r = rc AS same FROM oracle_query('rt', 'SELECT ID, DOC, R, "
                       "ROWIDTOCHAR(R) AS RC FROM T_MIX') ORDER BY id;",
                       "mix read");
        Check(mix->RowCount() == 2 && mix->GetValue(1, 0).ToString() == "5" && mix->GetValue(1, 1).ToString() == "9000" &&
                  mix->GetValue(2, 0).ToString() == "true" && mix->GetValue(2, 1).ToString() == "true",
              "CLOB and ROWID in one row");
        std::cout << "PASS CLOB and ROWID in one row\n";

        // TIMESTAMP WITH LOCAL TIME ZONE is an instant: the session is UTC, so
        // the wall time on the wire is UTC. Compared with SYS_EXTRACT_UTC, which
        // is Oracle's own statement of the same instant.
        dml("INSERT INTO T_LTZ VALUES (1, TO_TIMESTAMP_TZ('2026-03-04 05:06:07.123456 +03:00', 'YYYY-MM-DD HH24:MI:SS.FF6 TZH:TZM'), NULL)", "ltz 1");
        dml("INSERT INTO T_LTZ VALUES (2, TO_TIMESTAMP_TZ('1969-12-31 23:59:59 -05:00', 'YYYY-MM-DD HH24:MI:SS TZH:TZM'), NULL)", "ltz 2");
        dml("INSERT INTO T_LTZ VALUES (3, NULL, NULL)", "ltz 3");
        dml("INSERT INTO T_LTZ VALUES (4, TIMESTAMP '2026-06-15 12:00:00.5 +00:00', TIMESTAMP '2026-06-15 12:00:00.000000100 +00:00')", "ltz 4");
        Check(Scalar(admin, "SELECT * FROM oracle_query('rt', 'SELECT SESSIONTIMEZONE FROM DUAL');", "session zone") == "+00:00",
              "the session time zone is UTC");
        for (const auto &source :
             {std::string("oracle_query('rt', 'SELECT ID, L, TO_CHAR(SYS_EXTRACT_UTC(L), ''YYYY-MM-DD HH24:MI:SS.FF6'') AS U FROM T_LTZ WHERE ID <> 4 ORDER BY ID')")}) {
            auto result = Run(admin, "SELECT id, l, typeof(l), u FROM " + source + " ORDER BY id;", "ltz read");
            Check(result->RowCount() == 3, "ltz rows");
            Check(result->GetValue(2, 0).ToString() == "TIMESTAMP WITH TIME ZONE", "ltz is TIMESTAMPTZ");
            Check(result->GetValue(1, 0).ToString().substr(0, 26) == "2026-03-04 02:06:07.123456" &&
                      result->GetValue(3, 0).ToString() == "2026-03-04 02:06:07.123456",
                  "ltz instant equals Oracle's UTC");
            Check(result->GetValue(1, 1).ToString().substr(0, 19) == "1970-01-01 04:59:59" &&
                      result->GetValue(3, 1).ToString() == "1970-01-01 04:59:59.000000",
                  "ltz before 1970 and across a day boundary");
            Check(result->GetValue(1, 2).IsNull(), "ltz NULL");
        }
        {
            auto attached = Run(admin, "SELECT count(*) FROM raw.T_LTZ WHERE l IS NOT NULL AND id <> 4;", "ltz attached");
            Check(attached->GetValue(0, 0).ToString() == "2", "attached ltz");
        }
        // TIMESTAMP(9) with a fraction a microsecond cannot hold is reported.
        auto too_fine = admin.Query("SELECT * FROM oracle_query('rt', 'SELECT L9 FROM T_LTZ WHERE ID = 4');");
        Check(too_fine->HasError() && too_fine->GetError().find("sub-microsecond") != std::string::npos,
              "ltz finer than a microsecond is refused");
        std::cout << "PASS TIMESTAMP WITH LOCAL TIME ZONE reads as an instant\n";

        // Writing national text, intervals and local-zone times through the catalog.
        Run(admin,
            "INSERT INTO raw.T_WRITE VALUES (1, 'h\xc3\xa9llo \xd0\x9f\xd1\x80\xd0\xb8\xd0\xb2\xd0\xb5\xd1\x82 " + emoji +
                "', '\xe6\x97\xa5\xe6\x9c\xac', INTERVAL 27 MONTH, INTERVAL '3 days 04:05:06.789012', "
                "TIMESTAMPTZ '2026-03-04 05:06:07.123456+00'), "
                "(2, 'plain', 'ab', INTERVAL (-71) MONTH, INTERVAL '-12 days -23:59:59.5', TIMESTAMPTZ '2026-03-04 08:06:07+03'), "
                "(3, NULL, NULL, NULL, NULL, NULL), "
                "(4, 'x', 'y', INTERVAL 0 MONTH, INTERVAL '25 hours', TIMESTAMPTZ '1969-12-31 23:59:59+00');",
            "write insert");
        {
            auto result = Run(admin,
                              "SELECT id, nv, nc, ym, ds, l, ymt, dst, lu FROM oracle_query('rt', 'SELECT ID, NV, NC, YM, DS, L, "
                              "TO_CHAR(YM) AS YMT, TO_CHAR(DS) AS DST, TO_CHAR(SYS_EXTRACT_UTC(L), ''YYYY-MM-DD HH24:MI:SS.FF6'') AS LU "
                              "FROM T_WRITE ORDER BY ID') ORDER BY id;",
                              "write read back");
            Check(result->RowCount() == 4, "write rows");
            Check(result->GetValue(1, 0).ToString() == "h\xc3\xa9llo \xd0\x9f\xd1\x80\xd0\xb8\xd0\xb2\xd0\xb5\xd1\x82 " + emoji &&
                      result->GetValue(2, 0).ToString() == "\xe6\x97\xa5\xe6\x9c\xac      ",
                  "national text written and read back");
            Check(result->GetValue(1, 1).ToString() == "plain" && result->GetValue(2, 1).ToString() == "ab      ", "national ascii written");
            Check(result->GetValue(1, 2).IsNull() && result->GetValue(2, 2).IsNull(), "national NULL written");
            Check(result->GetValue(6, 0).ToString() == "+0002-03" && result->GetValue(6, 1).ToString() == "-0005-11",
                  "INTERVAL YEAR TO MONTH as Oracle prints it");
            Check(result->GetValue(7, 0).ToString() == "+0003 04:05:06.789012" && result->GetValue(7, 1).ToString() == "-0012 23:59:59.500000",
                  "INTERVAL DAY TO SECOND as Oracle prints it");
            Check(result->GetValue(7, 3).ToString() == "+0001 01:00:00.000000", "25 hours is 1 day 1 hour");
            Check(result->GetValue(8, 0).ToString() == "2026-03-04 05:06:07.123456" && result->GetValue(8, 1).ToString() == "2026-03-04 05:06:07.000000" &&
                      result->GetValue(8, 3).ToString() == "1969-12-31 23:59:59.000000",
                  "TIMESTAMPTZ written as the instant it names");
            Check(result->GetValue(3, 2).IsNull() && result->GetValue(4, 2).IsNull() && result->GetValue(5, 2).IsNull(),
                  "interval and local-zone NULLs written");
        }
        // RETURNING hands back what Oracle stored, for the new types as well. A
        // CHAR is as wide as its column, not as wide as the bind buffer.
        {
            auto returned = Run(admin,
                                "INSERT INTO raw.T_WRITE VALUES (5, 'ret', 'r', INTERVAL 14 MONTH, INTERVAL '1 day 02:03:04', "
                                "TIMESTAMPTZ '2026-03-04 05:06:07+00') RETURNING nv, nc, length(nc), ym, ds, l;",
                                "returning");
            Check(returned->RowCount() == 1 && returned->GetValue(0, 0).ToString() == "ret" &&
                      returned->GetValue(1, 0).ToString() == "r       " && returned->GetValue(2, 0).ToString() == "8" &&
                      returned->GetValue(3, 0).ToString() == "1 year 2 months" &&
                      returned->GetValue(4, 0).ToString() == "1 day 02:03:04" &&
                      returned->GetValue(5, 0).ToString().substr(0, 19) == "2026-03-04 05:06:07",
                  "RETURNING national, interval and local-zone columns");
            auto plain = Run(admin, "INSERT INTO raw.T_CHAR VALUES (1, 'r') RETURNING length(c);", "returning char");
            Check(plain->GetValue(0, 0).ToString() == "4", "a CHAR comes back as wide as its column");
            Run(admin, "DELETE FROM raw.T_WRITE WHERE id = 5;", "returning cleanup");
        }
        // UPDATE goes through the same binds.
        Run(admin, "UPDATE raw.T_WRITE SET nv = 'new' || chr(233), ds = INTERVAL '1 day', l = TIMESTAMPTZ '2030-01-01 00:00:00+00' WHERE id = 2;",
            "write update");
        {
            auto result = Run(admin,
                              "SELECT nv, dst, lu FROM oracle_query('rt', 'SELECT NV, TO_CHAR(DS) AS DST, "
                              "TO_CHAR(SYS_EXTRACT_UTC(L), ''YYYY-MM-DD HH24:MI:SS'') AS LU FROM T_WRITE WHERE ID = 2');",
                              "write update read");
            Check(result->GetValue(0, 0).ToString() == "new\xc3\xa9" && result->GetValue(1, 0).ToString() == "+0001 00:00:00.000000" &&
                      result->GetValue(2, 0).ToString() == "2030-01-01 00:00:00",
                  "national, interval and local-zone UPDATE");
        }
        // What cannot be a value of the column is refused with the column named.
        auto mixed = admin.Query("INSERT INTO raw.T_WRITE (id, ds) VALUES (9, INTERVAL '1 day -1 hour');");
        Check(mixed->HasError() && mixed->GetError().find("opposite signs") != std::string::npos, "mixed-sign interval refused");
        auto months = admin.Query("INSERT INTO raw.T_WRITE (id, ds) VALUES (9, INTERVAL 1 MONTH);");
        Check(months->HasError() && months->GetError().find("cannot hold months") != std::string::npos, "months refused for DAY TO SECOND");
        auto too_long = admin.Query("INSERT INTO raw.T_WRITE (id, nv) VALUES (9, repeat('x', 41));");
        Check(too_long->HasError() && std::string(too_long->GetError()).find("ORA-12899") != std::string::npos,
              "Oracle's own length check applies to a national column");
        // A filter on a national column is not translated; with pushdown on it
        // is applied to the rows that come back, and gives the same answer.
        Run(admin, "SET oracle_filter_pushdown = true;", "pushdown on");
        auto filtered = Run(admin, "SELECT count(*) FROM raw.T_WRITE WHERE nv = 'new\xc3\xa9';", "local filter when pushed");
        Check(filtered->GetValue(0, 0).ToString() == "1", "a national-column filter runs locally when pushdown is on");
        Run(admin, "SET oracle_filter_pushdown = false;", "pushdown off");
        auto unfiltered = Run(admin, "SELECT count(*) FROM raw.T_WRITE WHERE nv = 'new\xc3\xa9';", "local filter");
        Check(unfiltered->GetValue(0, 0).ToString() == "1", "the same filter runs in DuckDB when it is not pushed down");
        std::cout << "PASS national text, intervals and local-zone times can be written\n";

        // Writing LOBs: sizes either side of the 32767 and 32768 boundaries and
        // well past the 4000 a VARCHAR2 holds, in the same row as short columns
        // (a long bind's value travels after the short ones). Lengths and the
        // last characters are Oracle's own statement of what it stored.
        Run(admin,
            "INSERT INTO raw.T_LOBW VALUES (1, 'small', '\\x01\\x02'::BLOB, 'h' || chr(233)), "
            "(2, repeat('x', 100000), NULL, repeat(chr(20013), 40000)), "
            "(3, NULL, repeat('\\xAB'::BLOB, 100000), NULL), (4, '', ''::BLOB, ''), "
            "(5, repeat('y', 32767), repeat('\\x01'::BLOB, 32768), repeat('z', 300));",
            "lob insert");
        Run(admin, "INSERT INTO raw.T_LOBW VALUES (6, repeat('w', 5000000), repeat('\\x07'::BLOB, 5000000), NULL);", "lob insert big");
        Run(admin, "INSERT INTO raw.T_LOBW (id, c) VALUES (7, repeat('v', 4001));", "lob insert 4001");
        Run(admin, "INSERT INTO raw.T_LOBW (id, n, c) VALUES (8, NULL, repeat('u', 40000));", "lob insert reordered");
        {
            auto result = Run(admin,
                              "SELECT id, lc, lb, ln, tail, bhex FROM oracle_query('rt', 'SELECT ID, DBMS_LOB.GETLENGTH(C) AS LC, "
                              "DBMS_LOB.GETLENGTH(B) AS LB, DBMS_LOB.GETLENGTH(N) AS LN, DBMS_LOB.SUBSTR(C, 3, DBMS_LOB.GETLENGTH(C) - 2) AS TAIL, "
                              "RAWTOHEX(DBMS_LOB.SUBSTR(B, 2, 1)) AS BHEX FROM T_LOBW ORDER BY ID') ORDER BY id;",
                              "lob lengths");
            Check(result->RowCount() == 8, "lob rows");
            const std::vector<std::string> lc = {"5", "100000", "NULL", "NULL", "32767", "5000000", "4001", "40000"};
            const std::vector<std::string> lb = {"2", "NULL", "100000", "NULL", "32768", "5000000", "NULL", "NULL"};
            const std::vector<std::string> ln = {"2", "40000", "NULL", "NULL", "300", "NULL", "NULL", "NULL"};
            for (idx_t row = 0; row < 8; row++) {
                Check(result->GetValue(1, row).ToString() == lc[row] && result->GetValue(2, row).ToString() == lb[row] &&
                          result->GetValue(3, row).ToString() == ln[row],
                      "lob lengths as Oracle counts them");
            }
            Check(result->GetValue(4, 1).ToString() == "xxx" && result->GetValue(4, 5).ToString() == "www" &&
                      result->GetValue(5, 2).ToString() == "ABAB" && result->GetValue(5, 5).ToString() == "0707",
                  "lob ends and bytes");
        }
        {
            // And back through this client's own LOB read, content and all.
            auto result = Run(admin,
                              "SELECT id, length(c), md5(c) = md5(repeat(substr(c, 1, 1), length(c))) AS same, "
                              "octet_length(b), length(n) FROM raw.T_LOBW WHERE id IN (2, 5, 6) ORDER BY id;",
                              "lob read back");
            Check(result->RowCount() == 3 && result->GetValue(1, 0).ToString() == "100000" &&
                      result->GetValue(2, 0).ToString() == "true" && result->GetValue(1, 2).ToString() == "5000000" &&
                      result->GetValue(3, 2).ToString() == "5000000" && result->GetValue(4, 0).ToString() == "40000",
                  "lob content round trip");
        }
        Run(admin, "UPDATE raw.T_LOBW SET c = repeat('u', 70000), b = '\\xDE\\xAD'::BLOB, n = repeat('q', 50000) WHERE id = 1;", "lob update");
        Check(Scalar(admin,
                     "SELECT * FROM oracle_query('rt', 'SELECT DBMS_LOB.GETLENGTH(C) || ''/'' || DBMS_LOB.GETLENGTH(B) || ''/'' || "
                     "DBMS_LOB.GETLENGTH(N) AS S FROM T_LOBW WHERE ID = 1');",
                     "lob update check") == "70000/2/50000",
              "UPDATE replaces LOB content");
        // Past what an ordinary bind carries a LOB goes through a temporary LOB,
        // inside a transaction so the session that wrote it can be asked what it
        // still holds: nothing, once the statement is done.
        const auto temporary_lobs = "SELECT * FROM oracle_query('admin', 'SELECT NVL(SUM(T.CACHE_LOBS + T.NOCACHE_LOBS + "
                                    "T.ABSTRACT_LOBS), 0) AS S FROM V$TEMPORARY_LOBS T JOIN V$SESSION S ON S.SID = T.SID "
                                    "WHERE S.USERNAME = ''" + user + "''');";
        Run(admin, "BEGIN;", "temporary lob begin");
        Run(admin,
            "INSERT INTO raw.T_LOBW (id, c, b) VALUES (9, repeat('x', 17000000), repeat('\\x05'::BLOB, 9000000));",
            "temporary lob insert");
        Check(Scalar(admin, temporary_lobs, "temporary lobs held") == "0", "the temporary LOBs are released after the statement");
        Run(admin, "COMMIT;", "temporary lob commit");
        // One batch, one column: a row that needs the temporary LOB, a short one, a NULL and an empty one.
        Run(admin,
            "INSERT INTO raw.T_LOBW (id, c, n) VALUES (11, repeat(chr(128512) || 'e', 5000000), repeat('n', 9000000)), "
            "(12, 'short', 'short'), (13, NULL, NULL), (14, '', '');",
            "temporary lob batch");
        {
            auto result = Run(admin,
                              "SELECT id, lc, lb, ln FROM oracle_query('rt', 'SELECT ID, DBMS_LOB.GETLENGTH(C) AS LC, "
                              "DBMS_LOB.GETLENGTH(B) AS LB, DBMS_LOB.GETLENGTH(N) AS LN FROM T_LOBW WHERE ID IN (9, 11, 12, 13, 14) "
                              "ORDER BY ID') ORDER BY id;",
                              "temporary lob lengths");
            Check(result->RowCount() == 5, "temporary lob rows");
            // 11: 5,000,000 pairs of (U+1F600, 'e') is 3 UTF-16 units each.
            const std::vector<std::string> lc = {"17000000", "15000000", "5", "NULL", "NULL"};
            const std::vector<std::string> lb = {"9000000", "NULL", "NULL", "NULL", "NULL"};
            const std::vector<std::string> ln = {"NULL", "9000000", "5", "NULL", "NULL"};
            for (idx_t row = 0; row < 5; row++) {
                Check(result->GetValue(1, row).ToString() == lc[row] && result->GetValue(2, row).ToString() == lb[row] &&
                          result->GetValue(3, row).ToString() == ln[row],
                      "temporary lob lengths as Oracle counts them");
            }
        }
        {
            auto result = Run(admin,
                              "SELECT md5(c) = md5(repeat(chr(128512) || 'e', 5000000)), md5(n) = md5(repeat('n', 9000000)) "
                              "FROM raw.T_LOBW WHERE id = 11;",
                              "temporary lob read back");
            Check(result->GetValue(0, 0).ToString() == "true" && result->GetValue(1, 0).ToString() == "true",
                  "a CLOB written through a temporary LOB reads back identical, surrogate pairs and all");
        }
        Run(admin, "UPDATE raw.T_LOBW SET c = repeat('u', 12000000) WHERE id = 12;", "temporary lob update");
        Check(Scalar(admin, "SELECT * FROM oracle_query('rt', 'SELECT DBMS_LOB.GETLENGTH(C) AS S FROM T_LOBW WHERE ID = 12');",
                     "temporary lob update check") == "12000000",
              "UPDATE writes a large LOB through a temporary LOB");
        // XMLTYPE as text, small and past the inline limit.
        Run(admin, "INSERT INTO raw.T_XML VALUES (1, '<a><b>one</b></a>'), (2, NULL), (3, '<r>' || repeat('t', 10000000) || '</r>');",
            "xml insert");
        {
            auto result = Run(admin, "SELECT id, length(x), x LIKE '<a>%' FROM raw.T_XML ORDER BY id;", "xml read");
            Check(result->RowCount() == 3 && result->GetValue(1, 0).ToString() == "17" && result->GetValue(1, 1).IsNull() &&
                      result->GetValue(1, 2).ToString() == "10000007" && result->GetValue(2, 0).ToString() == "true",
                  "XMLTYPE reads back as the serialized document");
        }
        Run(admin, "UPDATE raw.T_XML SET x = '<changed/>' WHERE id = 1;", "xml update");
        Check(Scalar(admin, "SELECT x FROM raw.T_XML WHERE id = 1;", "xml update check") == "<changed/>", "XMLTYPE can be updated");
        auto bad_xml = admin.Query("INSERT INTO raw.T_XML VALUES (4, '<unclosed');");
        Check(bad_xml->HasError() && bad_xml->GetError().find("ORA-31011") != std::string::npos, "malformed XML is Oracle's to refuse");
        auto lob_returning = admin.Query("INSERT INTO raw.T_LOBW (id) VALUES (10) RETURNING id;");
        Check(lob_returning->HasError() && lob_returning->GetError().find("cannot return the LOB, JSON or VECTOR column") != std::string::npos,
              "RETURNING over a LOB table says why it cannot");
        std::cout << "PASS CLOB, NCLOB and BLOB are written, whole and updated; large ones and XMLTYPE too\n";

        if (has_boolean) {
            Run(admin, "SELECT * FROM oracle_execute_transaction('raw', 'INSERT INTO T_BOOL VALUES (1, TRUE)');", "bool 1");
            dml("INSERT INTO T_BOOL VALUES (2, FALSE)", "bool 2");
            dml("INSERT INTO T_BOOL VALUES (3, NULL)", "bool 3");
            for (const auto &source : {std::string("oracle_query('rt', 'SELECT ID, B FROM T_BOOL')"), std::string("raw.T_BOOL")}) {
                auto result = Run(admin, "SELECT id, b, typeof(b) FROM " + source + " ORDER BY id;", "bool read");
                Check(result->RowCount() == 3 && result->GetValue(1, 0).ToString() == "true" &&
                          result->GetValue(1, 1).ToString() == "false" && result->GetValue(1, 2).IsNull() &&
                          result->GetValue(2, 0).ToString() == "BOOLEAN",
                      "BOOLEAN read as true, false and NULL");
            }
            Run(admin, "INSERT INTO raw.T_BOOL VALUES (4, true), (5, false), (6, NULL);", "bool write");
            Run(admin, "UPDATE raw.T_BOOL SET b = NOT b WHERE id IN (4, 5);", "bool update");
            auto returned_bool = Run(admin, "INSERT INTO raw.T_BOOL VALUES (7, true) RETURNING b;", "bool returning");
            Check(returned_bool->GetValue(0, 0).ToString() == "true", "BOOLEAN RETURNING");
            auto written = Run(admin,
                               "SELECT id, b, bt FROM oracle_query('rt', 'SELECT ID, B, CASE WHEN B THEN ''T'' WHEN NOT B THEN ''F'' END AS BT "
                               "FROM T_BOOL WHERE ID BETWEEN 4 AND 6 ORDER BY ID') ORDER BY id;",
                               "bool written read");
            Check(written->RowCount() == 3 && written->GetValue(1, 0).ToString() == "false" && written->GetValue(2, 0).ToString() == "F" &&
                      written->GetValue(1, 1).ToString() == "true" && written->GetValue(2, 1).ToString() == "T" &&
                      written->GetValue(1, 2).IsNull(),
                  "BOOLEAN written and updated, checked by Oracle itself");
            std::cout << "PASS BOOLEAN reads and writes\n";
        } else {
            std::cout << "SKIP BOOLEAN: this server has no such type\n";
        }
        if (has_json) {
            // Written through this client as text and read back through the
            // inline define, then checked by Oracle itself where it matters.
            Run(admin,
                "INSERT INTO raw.T_JV VALUES (1, '{\"a\":[1,2,{\"b\":null}],\"s\":\"h\xc3\xa9llo " + emoji + "\"}', [1.5, 2.0, 3.0], "
                "[0.1, -2.5e300], [1, -2, 3, 127], [1, 255], [1.0, 2.0, 3.0, 4.0], "
                "{'dimensions': 6, 'indices': [1, 4], 'values': [1.5, -2.5]}), (2, NULL, NULL, NULL, NULL, NULL, NULL, NULL), "
                "(3, '[1,2,3]', [0.5, 0.25, -1.0], [1e-300, 3.0], [-128, 0, 0, 1], [0, 0], [7.0], "
                "{'dimensions': 6, 'indices': [], 'values': []});",
                "json vector write");
            for (const auto &source : {std::string("raw.T_JV"), std::string("oracle_query('rt', 'SELECT * FROM T_JV')")}) {
                auto result = Run(admin, "SELECT id, j, v3, vd, vi, vb, vx, vs FROM " + source + " ORDER BY id;", "json vector read");
                Check(result->RowCount() == 3, "json vector rows");
                Check(result->GetValue(1, 0).ToString().find("\"b\":null") != std::string::npos &&
                          result->GetValue(1, 0).ToString().find("h\xc3\xa9llo " + emoji) != std::string::npos &&
                          result->GetValue(1, 2).ToString() == "[1,2,3]",
                      "JSON text");
                Check(result->GetValue(2, 0).ToString() == "[1.5, 2.0, 3.0]" && result->GetValue(2, 2).ToString() == "[0.5, 0.25, -1.0]",
                      "FLOAT32 vectors");
                Check(result->GetValue(3, 0).ToString() == "[0.1, -2.5e+300]" && result->GetValue(3, 2).ToString() == "[1e-300, 3.0]",
                      "FLOAT64 vectors");
                Check(result->GetValue(4, 0).ToString() == "[1, -2, 3, 127]" && result->GetValue(4, 2).ToString() == "[-128, 0, 0, 1]",
                      "INT8 vectors");
                Check(result->GetValue(5, 0).ToString() == "[1, 255]", "BINARY vectors");
                Check(result->GetValue(6, 0).ToString() == "[1.0, 2.0, 3.0, 4.0]", "vectors of any format");
                Check(result->GetValue(7, 0).ToString() == "{'dimensions': 6, 'indices': [1, 4], 'values': [1.5, -2.5]}", "sparse vectors");
                for (idx_t column = 1; column < 8; column++) {
                    Check(result->GetValue(column, 1).IsNull(), "NULL JSON and vectors");
                }
            }
            Check(Scalar(admin,
                         "SELECT * FROM oracle_query('rt', 'SELECT JSON_VALUE(J, ''$.a[0]'') || ''/'' || VECTOR_DIMS(V3) || ''/'' || "
                         "VECTOR_DIMENSION_COUNT(VS) AS S FROM T_JV WHERE ID = 1');",
                         "json vector check") == "1/3/6",
                  "Oracle reads what was written");
            Run(admin, "UPDATE raw.T_JV SET j = '{\"updated\":true}', v3 = [9, 8, 7] WHERE id = 3;", "json vector update");
            Check(Scalar(admin, "SELECT * FROM oracle_query('rt', 'SELECT JSON_VALUE(J, ''$.updated'') || ''/'' || VECTOR_SERIALIZE(V3) AS S FROM T_JV WHERE ID = 3');",
                         "json vector update check").find("true/") == 0,
                  "UPDATE replaces JSON and VECTOR");

            // Many rows: the first fetch defines the columns, the later ones
            // keep fetching with that define, and the rows come back in order.
            Run(admin,
                "INSERT INTO raw.T_JV (id, j, v3) SELECT 100 + i, ('{\"n\":' || i || ',\"s\":\"' || repeat('x', i % 50) || '\"}')::JSON, "
                "[i, i + 0.5, -i]::FLOAT[3] FROM range(1000) t(i);",
                "json vector bulk write");
            auto bulk = Run(admin,
                            "SELECT count(*), sum((json_extract(j, '$.n'))::BIGINT), sum(v3[1]), min(length(json_extract_string(j, '$.s'))) "
                            "FROM raw.T_JV WHERE id >= 100;",
                            "json vector bulk read");
            Check(bulk->GetValue(0, 0).ToString() == "1000" && bulk->GetValue(1, 0).ToString() == "499500" &&
                      bulk->GetValue(2, 0).ToString() == "499500.0" && bulk->GetValue(3, 0).ToString() == "0",
                  "a thousand JSON and VECTOR rows");
            // Past the 64 KiB asked for ahead of the locator: a 300 KiB document, a
            // vector of 30000 FLOAT32 (120 KB) and a field name over 255 bytes.
            Run(admin,
                "INSERT INTO raw.T_JV (id, j, vx) SELECT 5000, ('{\"big\":\"' || repeat('y', 300000) || '\"}')::JSON, "
                "list_transform(range(30000), lambda x: x / 8.0);",
                "json vector large write");
            Run(admin,
                "INSERT INTO raw.T_JV (id, j) VALUES (5001, ('{\"' || repeat('k', 300) || '\":1,\"a\":2}')::JSON);",
                "json long name write");
            auto large = Run(admin,
                             "SELECT length(json_extract_string(j, '$.big')), array_length(vx), vx[30000], length(j) FROM raw.T_JV WHERE id = 5000;",
                             "json vector large read");
            Check(large->GetValue(0, 0).ToString() == "300000" && large->GetValue(1, 0).ToString() == "30000" &&
                      large->GetValue(2, 0).ToString() == "3749.875",
                  "values longer than the prefix are completed from the locator");
            Check(Scalar(admin,
                         "SELECT max(length(k)) || '/' || count(*) FROM (SELECT unnest(json_keys(j)) AS k FROM raw.T_JV WHERE id = 5001);",
                         "json long name read") == "300/2",
                  "a field name over 255 bytes");
            auto refused_returning = admin.Query("INSERT INTO raw.T_JV (id) VALUES (6000) RETURNING id;");
            Check(refused_returning->HasError() &&
                      refused_returning->GetError().find("cannot return the LOB, JSON or VECTOR column") != std::string::npos,
                  "RETURNING over JSON and VECTOR says why it cannot");

            // Beside other columns: the define is written for all of them.
            Run(admin,
                "INSERT INTO raw.T_JV_MIX VALUES (1, 'abc', DATE '2020-01-02', TIMESTAMP '2020-01-02 03:04:05.123456', 2.5, 'clob text', "
                "'{\"m\":1}', [1.0, 2.0, 3.0]), (2, NULL, NULL, NULL, NULL, NULL, NULL, NULL), "
                "(3, 'xyz', DATE '2021-12-31', TIMESTAMP '2021-12-31 23:59:59', -0.5, repeat('c', 20000), '{\"m\":3}', [3.0, 2.0, 1.0]);",
                "json mix write");
            for (const auto &source : {std::string("raw.T_JV_MIX"), std::string("oracle_query('rt', 'SELECT * FROM T_JV_MIX')")}) {
                auto mix = Run(admin, "SELECT id, v, d, t, n, length(c), j, e FROM " + source + " ORDER BY id;", "json mix read");
                Check(mix->RowCount() == 3 && mix->GetValue(1, 0).ToString() == "abc" && mix->GetValue(5, 0).ToString() == "9" &&
                          mix->GetValue(5, 2).ToString() == "20000" && mix->GetValue(6, 0).ToString() == "{\"m\":1}" &&
                          mix->GetValue(6, 2).ToString() == "{\"m\":3}" && mix->GetValue(7, 2).ToString() == "[3.0, 2.0, 1.0]" &&
                          mix->GetValue(3, 0).ToString() == "2020-01-02 03:04:05.123456" && mix->GetValue(1, 1).IsNull(),
                      "JSON and VECTOR beside CLOB and scalar columns");
            }
            {
                // The nearest rows by Oracle's own VECTOR_DISTANCE; DOUBLE numbers against a FLOAT32 column.
                auto nearest = Run(admin,
                                   "SELECT id, distance FROM oracle_vector_search('rt', 'T_JV_MIX', 'E', "
                                   "[3.0, 2.0, 1.0]::DOUBLE[3], k := 2, metric := 'EUCLIDEAN', approximate := false) "
                                   "ORDER BY distance;",
                                   "vector search");
                Check(nearest->RowCount() == 2 && nearest->GetValue(0, 0).ToString() == "3" &&
                          nearest->GetValue(1, 0).GetValue<double>() == 0.0 && nearest->GetValue(0, 1).ToString() == "1",
                      "oracle_vector_search ranks by Oracle's distance");
                auto cosine = Run(admin,
                                  "SELECT id FROM oracle_vector_search('rt', 'T_JV_MIX', 'E', [1.0, 2.0, 3.0]::FLOAT[3], k := 1);",
                                  "vector search cosine");
                Check(cosine->RowCount() == 1 && cosine->GetValue(0, 0).ToString() == "1", "the default metric finds the same row");
            }
            std::cout << "PASS JSON and VECTOR read and write, inline and past the prefix\n";
        } else {
            std::cout << "SKIP JSON and VECTOR: this server has no such types\n";
        }
        {
            // A table read in ROWID ranges at one SCN is the same table. The test
            // user cannot read DBA_EXTENTS, so the administrator's own attachment
            // of the user's schema does the reading.
            Run(admin,
                "SELECT * FROM oracle_plsql('admin', 'BEGIN INSERT INTO " + user + ".T_PAR SELECT level, MOD(level, 50), "
                "RPAD(''p'', 60, ''p'') FROM dual CONNECT BY level <= 300000; COMMIT; "
                "DBMS_STATS.GATHER_TABLE_STATS(''" + user + "'', ''T_PAR''); END;');",
                "parallel fill");
            Run(admin, "ATTACH 'admin' AS adm (TYPE oracle_scanner, SCHEMA '" + user + "');", "attach schema");
            Run(admin, "SET oracle_parallel_scan = 0;", "serial setting");
            Run(admin, "CREATE TEMP TABLE par_serial AS SELECT * FROM adm.main.T_PAR;", "serial read");
            Run(admin, "SET oracle_parallel_scan = 8;", "parallel setting");
            Run(admin, "CREATE TEMP TABLE par_ranges AS SELECT * FROM adm.main.T_PAR;", "parallel read");
            Check(Scalar(admin,
                         "SELECT (SELECT count(*) FROM (SELECT * FROM par_serial EXCEPT SELECT * FROM par_ranges)) + "
                         "(SELECT count(*) FROM (SELECT * FROM par_ranges EXCEPT SELECT * FROM par_serial)) + "
                         "abs((SELECT count(*) FROM par_serial) - (SELECT count(*) FROM par_ranges)) + "
                         "abs((SELECT count(*) FROM par_ranges) - 300000);",
                         "parallel diff") == "0",
                  "a table read in ROWID ranges equals the same table read in one stream");
            // And Oracle really was asked for ranges, each at the one SCN.
            Check(std::stoll(Scalar(admin,
                                    "SELECT * FROM oracle_query('admin', 'SELECT COUNT(*) FROM V$SQL WHERE SQL_TEXT LIKE "
                                    "''SELECT % FROM \"" + user + "\".\"T_PAR\" AS OF SCN % WHERE ROWID%''');",
                                    "parallel statements")) >= 2,
                  "the parallel scan sent ROWID-range statements");
            Run(admin, "SET oracle_parallel_scan = 0;", "serial again");
            Run(admin, "DETACH adm;", "detach schema");
            std::cout << "PASS an attached table reads in ROWID ranges at one SCN\n";
        }
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
