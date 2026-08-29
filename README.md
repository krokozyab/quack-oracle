# oracle_scanner

A DuckDB extension that reads and writes **Oracle Database** directly.

No Oracle Instant Client, no OCI, no ODPI-C, no ODBC, no JDBC, no Python, no
helper process. It speaks Oracle's own network protocol (TNS/TTC) itself, so
installing it is copying one file — there is nothing else to set up.

```sql
CREATE SECRET ora (TYPE oracle, HOST 'db.example.com', PORT 1521,
                   SERVICE_NAME 'ORCLPDB1', USER 'scott', PASSWORD '...');

SELECT * FROM oracle_query('ora', 'SELECT id, label FROM app.items');
```

> **Status:** version 0.2.0, published to DuckDB Community Extensions — one
> `INSTALL` and you are done, see [Install](#1-install). Reads, writes,
> procedure calls and TLS are verified against live Oracle 19c, Oracle Free
> 23ai, and OCI Autonomous Database.

---

## If you know Oracle but not DuckDB

Most people who need this extension arrive from the Oracle side, so here is the
part that is usually assumed.

**DuckDB is not a server.** There is no listener, no instance to start, no
tnsnames on its side, nothing to administer. It is a library that runs inside
whatever process opened it — think SQLite, but columnar and built for analytical
SQL. You open it, you query, you close it. A database can even live entirely in
memory and leave nothing behind.

**An extension is a plugin for it.** `oracle_scanner` is a single file that
DuckDB loads at runtime, after which DuckDB itself speaks Oracle's TNS/TTC
protocol. Nothing else is installed on the machine, and nothing is installed on
your Oracle server — from the database's point of view, another client
connected.

**Why put it between you and Oracle at all?** Because once Oracle is one source
among many, joining `APP.ORDERS` to a Parquet file, a CSV export, or a
PostgreSQL table is one `SELECT`, and moving rows between them is one `INSERT`.
That is what a small analytical engine buys you here — not faster access to
Oracle alone.

Terms you will meet below, in Oracle terms:

| In DuckDB | The closest thing you already know |
| --- | --- |
| `duckdb` shell | `sqlplus` / SQLcl — the client you type SQL into |
| secret | stored credentials for a connection; the Oracle equivalent of what you keep in a wallet or a connect string |
| `TNS_ALIAS` in a secret | an alias from `tnsnames.ora` — the extension reads it out of the wallet ZIP itself |
| table function (`oracle_query(...)`) | a pipelined table function: something you `SELECT` *from* |
| `ATTACH` | closest to a database link, but pointing the other way: DuckDB mounts your Oracle schema, not the reverse |
| catalog | one attached database; its schema and tables keep their Oracle names |
| filter pushdown | predicate sent to Oracle instead of being evaluated after the fetch |
| vector / chunk | a batch of rows, like `arraysize` in SQL\*Plus, but columnar |

**What this does not replace.** Data Pump and GoldenGate — this is not export,
import, or replication. `ora2pg` — that converts schemas and PL/SQL, this moves
data. A database link inside Oracle — that lets Oracle reach out, this lets you
reach in without installing anything on the server. RMAN — no backup here of any
kind.

---

## Contents

0. [If you know Oracle but not DuckDB](#if-you-know-oracle-but-not-duckdb)
1. [Install](#1-install)
2. [Connect to a database](#2-connect-to-a-database)
3. [Read data](#3-read-data)
4. [Use a whole Oracle schema (`ATTACH`)](#4-use-a-whole-oracle-schema-attach)
5. [Write data](#5-write-data)
6. [Call procedures and functions](#6-call-procedures-and-functions)
7. [Read a big table faster](#7-read-a-big-table-faster)
8. [Settings](#8-settings)
9. [Which Oracle types work](#9-which-oracle-types-work)
10. [Troubleshooting](#10-troubleshooting)
11. [Build and test from source](#11-build-and-test-from-source)
12. [Security, limits, further reading](#12-security-limits-further-reading)
13. [Try it yourself](#13-try-it-yourself)

---

## 1. Install

The extension is in DuckDB Community Extensions, so installing it is two
statements:

```sql
INSTALL oracle_scanner FROM community;
LOAD oracle_scanner;
```

A signed binary for your platform is downloaded once and stays installed; no
`-unsigned` flag, no build, and nothing from an Oracle client comes with it.
Version 0.2.0 targets **DuckDB v1.5.5**, which is the DuckDB version that will
load it.

Prefer to build from source — to hack on it, or to run against a DuckDB you
built yourself? That path still works:

```sh
git clone --recurse-submodules https://github.com/krokozyab/quack-oracle.git
cd quack-oracle
make release
./build/release/duckdb -unsigned
```

You need a C++17 compiler, CMake, and OpenSSL. The first build compiles DuckDB
itself and takes twenty to forty minutes; later builds are much faster. A
locally built extension is unsigned, so loading it into another DuckDB needs
`duckdb -unsigned` (or the `allow_unsigned_extensions` setting in a client
library) and the file at
`build/release/extension/oracle_scanner/oracle_scanner.duckdb_extension`.

Check that it worked:

```sql
SELECT extension_name, loaded FROM duckdb_extensions()
WHERE extension_name = 'oracle_scanner';
```

No Oracle to point at yet? [§13](#13-try-it-yourself) starts a free one in a
container, creates a small demo schema, and walks every feature against it.

---

## 2. Connect to a database

A connection is stored as a DuckDB **secret**. You create it once per session
and then refer to it by name. There is no connection string and no
`tnsnames.ora` on disk to configure.

### The usual case

```sql
CREATE SECRET ora (
    TYPE oracle,
    HOST 'db.example.com',
    PORT 1521,
    SERVICE_NAME 'ORCLPDB1',
    USER 'scott',
    PASSWORD 'tiger'
);
```

`ora` is just a name you pick; every function below takes it as its first
argument. Make several secrets if you use several databases.

### Oracle Autonomous Database, or anything with a wallet

Cloud Oracle hands you a wallet ZIP. Point at the ZIP and name the alias from
the `tnsnames.ora` inside it — the ZIP is read in memory and never unpacked to
disk:

```sql
CREATE SECRET ora_cloud (
    TYPE oracle,
    TNS_ALIAS 'mydb_low',
    USER 'ADMIN',
    PASSWORD '...',
    PROTOCOL 'tcps',
    TLS_SERVER_NAME 'adb.<your-region>.oraclecloud.com',
    WALLET_FILE '/secure/Wallet_mydb.zip'
);
```

The wallet ZIP needs no password: its `cwallet.sso` is an auto-login store, the
same one SQL\*Plus and JDBC open. Add `WALLET_PASSWORD` only for a bare
`ewallet.pem` whose key is encrypted.

### Encrypted connection without a wallet

```sql
CREATE SECRET ora_tls (
    TYPE oracle, HOST 'db.example.com', PORT 2484, SERVICE_NAME 'service',
    USER 'app_user', PASSWORD '...', PROTOCOL 'tcps',
    TLS_SERVER_NAME 'db.example.com', TLS_CA_FILE '/secure/ca.pem'
);
```

### All the fields

| Field | What it is |
| --- | --- |
| `HOST`, `PORT`, `SERVICE_NAME` | The database endpoint |
| `USER`, `PASSWORD` | Your Oracle credentials |
| `PROTOCOL` | `tcp` (the default) or `tcps` for TLS |
| `TNS_ALIAS` | An alias from the `tnsnames.ora` inside the wallet ZIP — use *instead of* HOST/PORT/SERVICE_NAME |
| `WALLET_FILE` | A cloud wallet ZIP, an `ewallet.pem` bundle, or an auto-login `cwallet.sso` |
| `WALLET_PASSWORD` | The password the wallet's encrypted `ewallet.pem` is locked with. Not needed when the wallet carries `cwallet.sso` — every wallet OCI hands out does |
| `TLS_SERVER_NAME` | The name checked against the server certificate |
| `TLS_SNI_NAME` | Only when the endpoint is an IP or a different virtual host |
| `TLS_CA_FILE` | An explicit PEM trust list; system roots are then not used |
| `TLS_SERVER_CERT_DN` | Require this exact certificate subject, in addition to the hostname |
| `CONNECT_TIMEOUT`, `READ_TIMEOUT` | Socket timeouts in seconds |

**A service name, not a SID.** The connect descriptor this client builds always
uses `(CONNECT_DATA=(SERVICE_NAME=...))`; there is no `SID` field. On an older
non-CDB instance where you are used to connecting by SID, ask the database for a
service name it also answers to:

```sql
SELECT value FROM v$parameter WHERE name = 'service_names';
```

or read them off the listener with `lsnrctl services`. Every supported Oracle
version registers at least one service name, so this is a lookup, not a
migration.

**Certificate and hostname verification are always on and cannot be turned
off.** That is deliberate: there is no insecure mode to fall back to. TLS
fields combined with plain `tcp` are rejected rather than quietly ignored, so a
typo cannot downgrade your connection.

---

## 3. Read data

`oracle_query` runs a `SELECT` on Oracle and streams the rows into DuckDB:

```sql
SELECT * FROM oracle_query('ora', 'SELECT id, label FROM app.items');
```

Rows stream as they arrive, so `LIMIT` is fast and a table far bigger than
memory is fine.

Join Oracle data with anything else DuckDB can read:

```sql
SELECT i.label, s.total
FROM oracle_query('ora', 'SELECT id, label FROM app.items') AS i
JOIN read_csv('sales.csv') AS s ON s.item_id = i.id;
```

### Passing values safely (bind parameters)

Never paste values into the SQL text. Pass them as a third argument instead —
Oracle then treats them as data, not as SQL.

**Named placeholders** use a `STRUCT`:

```sql
SELECT * FROM oracle_query(
    'ora', 'SELECT * FROM app.items WHERE label = :label AND id > :low',
    {'label': 'widget', 'low': 100});
```

**Numbered placeholders** use a `LIST`:

```sql
SELECT * FROM oracle_query(
    'ora', 'SELECT * FROM app.items WHERE id BETWEEN :1 AND :2',
    [10, 20]);
```

⚠️ **One catch worth knowing.** A DuckDB `LIST` can only hold one type, so
`[1, 'one', DATE '2026-01-02']` will not even build. When your values have
different types, use a `STRUCT` whose keys are `'1'`, `'2'`, … — it fills
numbered placeholders and accepts any mix:

```sql
SELECT * FROM oracle_execute(
    'ora', 'INSERT INTO app.items VALUES (:1, :2, :3)',
    {'1': 1, '2': 'one', '3': DATE '2026-01-02'});
```

---

## 4. Use a whole Oracle schema (`ATTACH`)

Instead of writing Oracle SQL by hand, mount the schema and use plain DuckDB
SQL against it:

```sql
ATTACH 'ora' AS o (TYPE oracle_scanner);

SHOW TABLES;
SELECT * FROM o.ITEMS WHERE id > 100;
SELECT count(*) FROM o.ORDERS;
```

The thing in quotes is the **secret name**, not a connection string.

You get the tables and views of the user you connected as — the same set
`USER_TABLES` and `USER_VIEWS` would give you, resolved lazily as you name them
rather than all at once. Names come back as Oracle stores them, which is upper
case unless they were created quoted — so `o.ITEMS`, not `o.items`. `DESCRIBE`
works, and `NOT NULL` columns and primary keys show up in
`duckdb_constraints()`.

The dictionary queries you would reach for have local equivalents here, so you
can stay in one SQL dialect:

| Instead of | Use |
| --- | --- |
| `SELECT table_name FROM user_tables` | `SHOW ALL TABLES` |
| `DESC APP.ITEMS` | `DESCRIBE o.ITEMS` |
| `SELECT * FROM user_tab_columns` | `SELECT * FROM duckdb_columns()` |
| `SELECT * FROM user_constraints` | `SELECT * FROM duckdb_constraints()` |
| `SELECT * FROM all_arguments` | `SELECT * FROM oracle_arguments('ora', 'APP.PROC')` |

You can also `INSERT`, `UPDATE` and `DELETE` here — see the next section.

**What `ATTACH` will not do:** create or drop tables, create schemas, or reach
another user's schema. This extension issues no DDL at all. For those, use
`oracle_query` with a fully qualified name, or see
[the DDL note](#i-need-to-run-create-table-or-another-ddl-statement).

### Pushing filters down to Oracle

By default DuckDB fetches the rows and filters them itself. To have Oracle do
the filtering:

```sql
SET oracle_filter_pushdown = true;
```

It is off by default on purpose. Once DuckDB hands a filter to the scan it
removes it from its own plan, so the scan has to apply it *exactly* — and this
extension refuses any filter whose Oracle meaning it cannot prove identical.
With pushdown on, such a filter raises an error instead of just being slower.

Pushed down: `=`, `<>`, `<`, `<=`, `>`, `>=`, `IS NULL`, `IS NOT NULL`, `IN`
(up to 1,000 values), and `AND`/`OR` of those, on number, date and timestamp
columns. Text comparisons are mostly refused because Oracle's collation and its
blank-padded `CHAR` comparison depend on session settings this client does not
negotiate.

---

## 5. Write data

### Through an attached schema — with real transactions

```sql
ATTACH 'ora' AS o (TYPE oracle_scanner);

BEGIN TRANSACTION;
INSERT INTO o.ITEMS VALUES (7, 'seven');
UPDATE o.ITEMS SET label = 'VII' WHERE id = 7;
SELECT count(*) FROM o.ITEMS;   -- sees the rows you just wrote
COMMIT;                         -- or ROLLBACK, and Oracle rolls back too
```

DuckDB's `COMMIT` and `ROLLBACK` mean exactly what they say in Oracle: one
Oracle session is pinned to the transaction. A query inside the transaction
reads through that same session, so it sees your own uncommitted rows — which
no other session can see.

`INSERT ... RETURNING` works and asks Oracle for the row it actually stored, so
identity values, `DEFAULT`s and trigger results come back:

```sql
INSERT INTO o.ITEMS (label) VALUES ('eight') RETURNING id, label;
```

Columns you do not name are left out of the statement, so Oracle's own
`DEFAULT` still applies. `UPDATE` and `DELETE` find rows by Oracle's ROWID, so
the table does not need a primary key. (`RETURNING` on `UPDATE`/`DELETE` is not
supported yet.)

### One statement at a time

```sql
SELECT * FROM oracle_execute('ora',
    'UPDATE app.items SET label = :1 WHERE id = :2', ['x', 7]);
```

Returns `affected_rows`. Accepts `INSERT`, `UPDATE` and `DELETE` only.

### Many rows at once

```sql
SELECT * FROM oracle_execute_many('ora',
    'INSERT INTO app.items (id, label) VALUES (:id, :label)',
    [{'id': 1, 'label': 'one'}, {'id': 2, 'label': 'two'}]);
```

This is much faster than a loop: the rows go as Oracle array DML — one parse,
one round trip for up to 1,024 rows. If a row fails, the error tells you which
row it was, counted from the start of your batch.

> `oracle_execute` and `oracle_execute_many` commit in Oracle by themselves, so
> they **refuse to run inside `BEGIN TRANSACTION`**. If you need transactional
> writes, use the attached-schema form above.

---

## 6. Call procedures and functions

### Start by asking what the arguments are

```sql
SELECT * FROM oracle_arguments('ora', 'APP.CALCULATE_TOTAL');
```

One row per argument: its name, position, direction (`IN`/`OUT`/`IN OUT`),
Oracle type — and, if this version cannot pass that type, the reason. Position 0
is a function's return value. Names reached through a synonym are resolved.

### The easy way

`oracle_call_auto` reads that signature for you, so you only supply values — a
list of text, one per argument in declaration order, with `NULL` in each `OUT`
slot:

```sql
SELECT * FROM oracle_call_auto('ora', 'APP.CALCULATE_TOTAL', ['42', NULL]);
```

You get back `(name, value, cursor_handle)` rows, with a function's return
value first, named `return_value`.

### The explicit way

When you want to state the shape yourself, use `oracle_call_named` (or
`oracle_call_named_function`) with one struct per argument:

```sql
SELECT * FROM oracle_call_named('ora', 'APP.CALCULATE_TOTAL',
    [{'name': 'p_id',    'direction': 'in',  'type': 'number',  'value': '42'},
     {'name': 'p_total', 'direction': 'out', 'type': 'number',  'value': NULL}]);
```

Types are `number`, `varchar`, `date`, `timestamp`, `raw` (uppercase hex),
`float`, `double`, and `cursor`.

### Getting a result set back

A procedure or function that returns a `SYS_REFCURSOR` gives you a handle
instead of a value. Read it once with `oracle_cursor`:

```sql
SELECT * FROM oracle_call_auto('ora', 'APP.LIST_ITEMS', [NULL]);
-- cursor_handle → 'oracle:...'
SELECT * FROM oracle_cursor('oracle:...');
```

Handles belong to your DuckDB connection and are consumed once. Release one you
decide not to read with `oracle_close_call`.

---

## 7. Read a big table faster

A normal scan is one Oracle session on one thread. For a large table, split it
across several sessions by a numeric key:

```sql
SELECT * FROM oracle_scan_parallel('ora', 'BIG_TABLE', 'ID', shards := 8);
```

Every shard reads the table `AS OF SCN` at one change number taken before any
of them start, so you get **one consistent snapshot**, not several moments
stitched together. If the database will not give out a change number, the scan
is refused rather than run unpinned.

Requirements: the key column must be `NUMBER` with whole-number values (a
boundary computed by rounding could fall between two keys). Rows with a NULL key
get a shard of their own, so nothing is skipped. `shards` defaults to your
DuckDB thread count.

You also need `EXECUTE` on `SYS.DBMS_FLASHBACK` and `FLASHBACK` on the table.

---

## 8. Settings

| Setting | Default | What it does |
| --- | --- | --- |
| `oracle_session_pool_size` | `4` | How many authenticated Oracle sessions to keep and reuse for reads, per DuckDB connection per secret. `0` opens a fresh one every time. |
| `oracle_filter_pushdown` | `false` | Send `WHERE` clauses on attached tables to Oracle. See [section 4](#pushing-filters-down-to-oracle). |

Pooling matters more than it looks. Opening a session costs a TCP connect, a TLS
handshake and an authentication round trip: against a cloud endpoint that was
**1.57 s per statement**, against **0.18 s** when reusing one.

---

## 9. Which Oracle types work

| Oracle | Comes back as | Note |
| --- | --- | --- |
| `NUMBER(p,0)`, p ≤ 18 | `BIGINT` | |
| `NUMBER(p,s)` | `DECIMAL(p,s)` | up to p = 38 |
| `NUMBER` (unconstrained) | `VARCHAR` | exact only as text |
| `VARCHAR2`, `CHAR` | `VARCHAR` | |
| `DATE` | `TIMESTAMP` | an Oracle `DATE` carries a time, so it is not a DuckDB `DATE` |
| `TIMESTAMP(0–6)` | `TIMESTAMP` | |
| `TIMESTAMP(7–9)` | `TIMESTAMP_NS` | |
| `TIMESTAMP WITH TIME ZONE` | `VARCHAR` | keeps its offset, which `TIMESTAMPTZ` would drop |
| `RAW` | `BLOB` | |
| `BINARY_FLOAT`, `BINARY_DOUBLE` | `FLOAT`, `DOUBLE` | |
| `CLOB`, `NCLOB` | `VARCHAR` | see the warning below |
| `BLOB` | `BLOB` | see the warning below |

Anything else — `NCHAR`, `NVARCHAR2`, `INTERVAL`, `TIMESTAMP WITH LOCAL TIME
ZONE`, `BFILE`, object and collection types — is **refused when the query is
bound**, with a message naming the column and the reason. It is never decoded
into something that looks right and is not.

### Why your table came back as all text

A column declared plain `NUMBER`, with no precision or scale, is the third row
of that table: it arrives as `VARCHAR`. On a schema where most columns are
declared that way — which is usual for anything generated by an ETL tool or an
integration platform — the result is a table with no numeric column at all, and
`SUM` or a join on a numeric key will not work until you say what the type is.

That is deliberate, and the reason is that Oracle's `NUMBER` is a base-100
decimal with up to 38 significant digits. Nothing in DuckDB holds every such
value: `DOUBLE` loses digits (summing 200,000 invoice amounts drifts by about
two cents), and any fixed `DECIMAL(38,s)` has to pick an `s` and silently round
whatever has more. Text is the only form that is always exact, so an
unconstrained `NUMBER` is handed over intact and you choose the type you want:

```sql
SELECT
    CAST(TRX_ID       AS BIGINT)         AS trx_id,
    CAST(UNIT_WEIGHT  AS DECIMAL(38,6))  AS unit_weight,   -- exact to 6 places
    CAST(UNIT_VOLUME  AS DOUBLE)         AS unit_volume    -- fine for ratios
FROM atp.main.ITEMS;
```

Two practical notes. `CAST(... AS DECIMAL(p,s))` is what you want for money and
for anything you will reconcile — it is exact within the scale you name, and it
errors rather than rounds if a value does not fit. And if the table is yours,
declaring the column as `NUMBER(p)` or `NUMBER(p,s)` in Oracle is better than
casting on every read: the extension then maps it to `BIGINT` or `DECIMAL`
directly, and every client that touches the table gets a real numeric type.

⚠️ **LOB columns are expensive.** A `CLOB`/`BLOB` value is not in the row; the
row carries only a pointer, and fetching the content costs extra round trips per
value. Measured: 2,000 rows with a 2,000-character CLOB took **1.22 s**, against
**0.004 s** for the same rows without that column. Select a LOB column only when
you need it. Writing a LOB is not supported.

---

## 10. Troubleshooting

### `The file was built specifically for DuckDB version 'v1.5.5'`

Your DuckDB is a different version. Install DuckDB v1.5.5 and run
`INSTALL oracle_scanner FROM community` again, or, if you built from source,
use the shell this project produced (`./build/release/duckdb`).

### DuckDB refuses the extension as unsigned

A locally built extension carries no DuckDB signature. Start the shell with
`-unsigned`, or set `allow_unsigned_extensions` in your client library.

### `Oracle SQL statement terminators are not accepted`

Remove the `;` from the end of the SQL string you passed. The string is one
statement, not a script.

### `oracle_query accepts only SELECT or WITH queries`

`oracle_query` reads. Use `oracle_execute` for `INSERT`/`UPDATE`/`DELETE`.

### `oracle_execute accepts only INSERT, UPDATE, or DELETE`

<a id="i-need-to-run-create-table-or-another-ddl-statement"></a>
You are trying to run DDL. This extension issues no DDL, but you can ask Oracle
to do it through a standard Oracle procedure:

```sql
SELECT * FROM oracle_call_auto('ora', 'DBMS_UTILITY.EXEC_DDL_STATEMENT',
    ['CREATE TABLE t (id NUMBER(10), label VARCHAR2(50))']);
```

The same route runs anything that is a single procedure call. Anonymous PL/SQL
blocks (`BEGIN ... END;`) cannot be run at all.

### `oracle_execute cannot run inside an explicit DuckDB transaction`

`oracle_execute` commits in Oracle on its own, which a DuckDB `ROLLBACK` could
not undo. Either drop the `BEGIN TRANSACTION`, or write through an attached
schema instead ([section 5](#5-write-data)).

### `oracle_query params must be a LIST or STRUCT`

Bind values go in **one** third argument, not as extra arguments:
`oracle_query('ora', 'SELECT :1 FROM dual', ['x'])`.

### `Could not convert string 'one' to INT32`

Your `LIST` mixes types, and a DuckDB list only holds one. Use a `STRUCT` keyed
`'1'`, `'2'`, … instead — see [section 3](#passing-values-safely-bind-parameters).

### `Oracle column "X" cannot be read: ...`

That column's type is not supported. List the columns you need instead of
`SELECT *`; the rest of the table still works.

### `ORA-01466: unable to read data`

`oracle_scan_parallel` takes a consistent snapshot, and the table was created or
altered too recently to read as of an earlier moment. Wait a few minutes, or use
a plain `oracle_query`.

### `ORA-28000: the account is locked`

Too many failed logins locked the Oracle account. Ask a DBA to unlock it — and
check for a stale password in an old secret.

### `OpenSSL could not decrypt the client private key in wallet PEM`

You set `WALLET_PASSWORD` and it is not the password that `ewallet.pem` was
encrypted with — it is the one you chose when downloading the wallet, not the
database (ADMIN) password.

If you no longer have it, drop `WALLET_PASSWORD` entirely: the extension then
opens the wallet's `cwallet.sso` instead, which is the auto-login store SQL\*Plus,
SQLcl and JDBC use, and it needs no password at all. That works for every wallet
OCI hands out. The one wallet it cannot open is an *auto-login local* store,
which is tied to the machine and account that created it; that case is refused
by name.

---

## 11. Build and test from source

```sh
make debug                    # builds DuckDB + the extension with sanitizers
make test_debug               # the SQL test suite
ctest --test-dir build/debug/extension/oracle_scanner --output-on-failure
```

`ctest` runs both C++ suites: `oracle_scanner_protocol_test` for the protocol
and codec layers, and `oracle_scanner_adapter_test`, which drives the DuckDB
adapter against a fake Oracle session and so needs no database, network, or
credentials.

For a fast protocol-only check that does not build DuckDB at all — seconds
rather than tens of minutes:

```sh
scripts/build_protocol_test.sh
```

It derives its source list from the `oracle_scanner_protocol_test` target in
`CMakeLists.txt`, builds this project's sources with `-Wall -Wextra -Werror`,
and runs the result. OpenSSL comes from vcpkg in Community builds and may come
from the system locally.

`scripts/run_live_stages.sh` runs every live wire stage against one endpoint;
`scripts/check_no_oracle_client.sh` proves a built extension links and imports
nothing from an Oracle client, and fails rather than reporting success if it
cannot inspect the binary.

---

## 12. Security, limits, further reading

- **[docs/CAPABILITIES.md](docs/CAPABILITIES.md)** — the precise support
  boundary: every type, every refusal and its reason, what `ATTACH` can and
  cannot do, and the full list of what is not supported. Read this before
  planning a migration around the extension.
- **[docs/RELEASING.md](docs/RELEASING.md)** — where the version lives and what
  a Community Extensions submission needs.
- **[PROVENANCE.md](PROVENANCE.md)** — what this project reuses and from where,
  plus every byte of recorded wire traffic in the tree with its SHA-256.
- **[Moving Oracle to PostgreSQL with a Single `INSERT`](https://medium.com/@rudenko.s/moving-oracle-to-postgresql-with-a-single-insert-no-oracle-client-no-python-3efc99baaa40)**
  — a worked write-up of the whole pattern: the load as one statement, sharding
  the read across sessions under one snapshot, and reconciling both databases
  without dragging the tables across the network.

Guarantees that hold by construction: no Oracle client is linked or loaded (CI
checks the shipped binary on every build); no password, wallet password, key or
bind value is ever logged or persisted; wallet ZIPs are read in memory and never
written to disk; and TLS verification has no off switch.

Never commit database credentials, wallets, production descriptors, or raw
captures to this repository.

This is an independent community project and is not affiliated with Oracle or
DuckDB Labs.

---

## 13. Try it yourself

Everything below runs against a demo schema this repository ships, so you can
follow it end to end without touching a real database. It takes about five
minutes: get an Oracle, create six demo objects, then walk every feature.

Each example shows what it actually prints — the output here was captured from
a real run, not written by hand.

### 13.1 Get an Oracle to point at

**A container, free and local.** `gvenzl/oracle-free` needs no Oracle account:

```sh
docker run -d --name oracle-demo -p 1521:1521 -e ORACLE_PASSWORD=demo_password \
    gvenzl/oracle-free:slim
docker logs -f oracle-demo   # wait for "DATABASE IS READY TO USE!"
```

That gives you service `FREEPDB1` on port 1521, user `system`. Oracle's own
`container-registry.oracle.com/database/free` works the same way, and a 19c
image built from [Oracle's docker-images](https://github.com/oracle/docker-images)
serves `ORCLPDB1` instead.

**Oracle Autonomous Database, free forever.** Create an Always Free ADB in the
OCI console, then **Database connection → Download wallet**. You get a
`Wallet_<name>.zip`; keep it somewhere private. Its `tnsnames.ora` holds aliases
like `<name>_low`, `<name>_medium`, `<name>_high` — you connect by alias, and the
extension reads the wallet out of the ZIP in memory. Nothing is unpacked to disk.

### 13.2 Create the demo schema

[`examples/demo_setup.sql`](examples/demo_setup.sql) creates six objects and is
safe to re-run — it drops its own tables first. It works unchanged on 19c, 23ai
Free and Autonomous, in whatever schema you connect as.

| Object | What it is there for |
| --- | --- |
| `QUACK_DEMO_DEPARTMENTS` | 4 rows to scan, filter and read in parallel. `LOCATION` and `HEADCOUNT` are NULL in one row on purpose. |
| `QUACK_DEMO_LOG` | An IDENTITY key and a `DEFAULT SYSDATE`, to write to. |
| `QUACK_DEMO_TYPES` | One row holding one column of every type in [§9](#9-which-oracle-types-work). |
| `QUACK_DEMO_ADD` | A function, for a return value. |
| `QUACK_DEMO_GREET` | A procedure with an `OUT` argument. |
| `QUACK_DEMO_LIST` | A procedure returning a `SYS_REFCURSOR`. |

In a container:

```sh
docker cp examples/demo_setup.sql oracle-demo:/tmp/
docker exec -i oracle-demo bash -c \
    'sqlplus -s system/$ORACLE_PASSWORD@localhost:1521/FREEPDB1 @/tmp/demo_setup.sql'
```

On Autonomous, the easiest route is **Database Actions → SQL** in the OCI
console: paste the file and run it. With a local SQL\*Plus and the wallet
unpacked into `$TNS_ADMIN`, `sqlplus admin/<password>@<name>_low @examples/demo_setup.sql`
does the same.

Either way it ends by listing what it made:

```
QUACK_DEMO_ADD          FUNCTION    VALID
QUACK_DEMO_DEPARTMENTS  TABLE       VALID
QUACK_DEMO_GREET        PROCEDURE   VALID
QUACK_DEMO_LIST         PROCEDURE   VALID
QUACK_DEMO_LOG          TABLE       VALID
QUACK_DEMO_TYPES        TABLE       VALID
```

### 13.3 Connect

Start DuckDB with the extension loaded ([§1](#1-install)), then create a secret.
Against the container:

```sql
CREATE SECRET demo (
    TYPE oracle, HOST '127.0.0.1', PORT 1521,
    SERVICE_NAME 'FREEPDB1', USER 'system', PASSWORD 'demo_password'
);
```

Against Autonomous — alias instead of host, and the wallet ZIP exactly as you
downloaded it:

```sql
CREATE SECRET demo (
    TYPE oracle,
    TNS_ALIAS 'mydb_low',
    USER 'ADMIN', PASSWORD '<your ADMIN password>',
    WALLET_FILE '/secure/Wallet_mydb.zip'
);
```

The alias carries the host, port, service and TLS settings, so those fields must
not be repeated — the extension rejects the combination rather than guessing
which wins.

No wallet password appears there, and none is needed: the extension opens the
wallet's `cwallet.sso`, the auto-login store SQL\*Plus, SQLcl and JDBC use, whose
key is unlocked by the file itself. Nothing is unpacked to disk — the ZIP is read
in memory and the identity goes straight into the TLS context.

`WALLET_PASSWORD` remains for the other case: a wallet you hold as a bare
`ewallet.pem`, whose private key is encrypted. It is the password you chose when
downloading the wallet, never the ADMIN password. Supply it and `ewallet.pem` is
used instead of the auto-login store:

```sql
CREATE SECRET demo_pem (
    TYPE oracle,
    TNS_ALIAS 'mydb_low',
    USER 'ADMIN', PASSWORD '<your ADMIN password>',
    WALLET_FILE '/secure/Wallet_mydb.zip',
    WALLET_PASSWORD '<the wallet password, not the ADMIN password>'
);
```

If that password is wrong, the error is:

> OpenSSL could not decrypt the client private key in wallet PEM

Check the connection, and that the password is not readable back:

```sql
SELECT * FROM oracle_query('demo', 'SELECT user FROM DUAL');
SELECT name, type, secret_string FROM duckdb_secrets();
```
```
┌─────────┐    name=demo;type=oracle;provider=config;serializable=true;scope;
│  USER   │    host=127.0.0.1;password=redacted;port=1521;
│ SYSTEM  │    service_name=FREEPDB1;user=system
└─────────┘
```

### 13.4 Read

```sql
SELECT * FROM oracle_query('demo',
    'SELECT department_id, department_name FROM quack_demo_departments ORDER BY 1');
```
```
┌───────────────┬─────────────────┐
│ DEPARTMENT_ID │ DEPARTMENT_NAME │
├───────────────┼─────────────────┤
│            10 │ ACCOUNTING      │
│            20 │ RESEARCH        │
│            30 │ SALES           │
│            40 │ OPERATIONS      │
└───────────────┴─────────────────┘
```

Never paste values into the SQL — bind them, by name or by position:

```sql
SELECT * FROM oracle_query('demo',
    'SELECT * FROM quack_demo_departments WHERE headcount > :min', {'min': 20});

SELECT * FROM oracle_query('demo',
    'SELECT * FROM quack_demo_departments WHERE department_id BETWEEN :1 AND :2', [10, 30]);
```

### 13.5 Mount the whole schema

```sql
ATTACH 'demo' AS ora (TYPE oracle_scanner);
SHOW ALL TABLES;
SELECT * FROM ora.QUACK_DEMO_DEPARTMENTS WHERE HEADCOUNT > 20;
```

Nothing is read from Oracle's dictionary until you ask for it: `ATTACH` costs a
single round trip, a table's columns are fetched when the table is first named,
and the whole schema's column metadata arrives in one query rather than one per
table.

The types come back as [§9](#9-which-oracle-types-work) promises — this is what
`QUACK_DEMO_TYPES` is for:

```sql
DESCRIBE ora.QUACK_DEMO_TYPES;
```
```
N_INT      bigint        -- NUMBER(5,0)
N_DECIMAL  decimal(10,5) -- NUMBER(10,5)
N_ANY      varchar       -- unconstrained NUMBER: exact only as text
V, C       varchar       -- VARCHAR2, CHAR
D          timestamp     -- an Oracle DATE carries a time
TS         timestamp     -- TIMESTAMP(6)
TS_NS      timestamp_ns  -- TIMESTAMP(9)
TS_TZ      varchar       -- keeps the offset TIMESTAMPTZ would drop
R          blob          -- RAW
BF, BD     float, double -- BINARY_FLOAT, BINARY_DOUBLE
```

### 13.6 Push the filtering into Oracle

```sql
SET oracle_filter_pushdown = true;

SELECT DEPARTMENT_NAME, HEADCOUNT FROM ora.QUACK_DEMO_DEPARTMENTS WHERE HEADCOUNT > 20;
SELECT DEPARTMENT_NAME FROM ora.QUACK_DEMO_DEPARTMENTS WHERE LOCATION IS NULL;
SELECT DEPARTMENT_NAME FROM ora.QUACK_DEMO_DEPARTMENTS WHERE DEPARTMENT_ID IN (10, 30);
SELECT DEPARTMENT_NAME FROM ora.QUACK_DEMO_DEPARTMENTS WHERE DEPARTMENT_NAME = 'SALES';
SELECT D FROM ora.QUACK_DEMO_TYPES WHERE D = TIMESTAMP '2024-03-01 00:00:00';
```

All five are sent to Oracle. These three are refused, by name, instead of being
approximated — and the message tells you how to turn pushdown off:

```sql
SELECT * FROM ora.QUACK_DEMO_DEPARTMENTS WHERE DEPARTMENT_NAME > 'A';
-- ordered comparison on a column that is not NUMBER, DATE or TIMESTAMP
--   (text ordering follows NLS_SORT/NLS_COMP, which this client never negotiates)

SELECT * FROM ora.QUACK_DEMO_DEPARTMENTS WHERE DEPARTMENT_NAME = '';
-- a comparison against an empty string, which Oracle treats as NULL

SELECT D FROM ora.QUACK_DEMO_TYPES WHERE D = TIMESTAMP '2024-03-01 00:00:00.5';
-- a sub-second constant compared against a DATE column, which stores whole seconds
```

Note that `= 'SALES'` **is** pushed while `> 'A'` is not: equality does not
depend on collation, ordering does.

### 13.7 Write, with real transactions

```sql
BEGIN TRANSACTION;
INSERT INTO ora.QUACK_DEMO_LOG (LABEL, AMOUNT) VALUES ('first', 10.50);
SELECT LOG_ID, LABEL, AMOUNT FROM ora.QUACK_DEMO_LOG;   -- sees its own uncommitted row
ROLLBACK;
SELECT count(*) FROM ora.QUACK_DEMO_LOG;                -- 0: Oracle rolled back too
```

Columns you do not name are left out of the statement, so Oracle's `IDENTITY`
and `DEFAULT` still apply, and `RETURNING` asks Oracle what it actually stored:

```sql
INSERT INTO ora.QUACK_DEMO_LOG (LABEL) VALUES ('with-defaults')
RETURNING LOG_ID, LABEL, LOGGED_AT;
```
```
┌────────┬───────────────┬─────────────────────┐
│ LOG_ID │     LABEL     │      LOGGED_AT      │
│ 2      │ with-defaults │ 2026-08-22 09:40:53 │
└────────┴───────────────┴─────────────────────┘
```

`UPDATE` and `DELETE` find rows by Oracle's ROWID, so the table needs no primary
key:

```sql
UPDATE ora.QUACK_DEMO_LOG SET AMOUNT = 99.99 WHERE LABEL = 'with-defaults';
DELETE FROM ora.QUACK_DEMO_LOG WHERE LABEL = 'with-defaults';
```

Outside a transaction you can also send one statement, or a whole batch as
Oracle array DML — one parse, one round trip:

```sql
SELECT * FROM oracle_execute_many('demo',
    'INSERT INTO QUACK_DEMO_LOG (LABEL, AMOUNT) VALUES (:label, :amount)',
    [{'label': 'a', 'amount': 1.5}, {'label': 'b', 'amount': 2.5}]);
-- affected_rows = 2

SELECT * FROM oracle_execute('demo',
    'DELETE FROM QUACK_DEMO_LOG WHERE LABEL IN (:1, :2)', ['a', 'b']);
-- affected_rows = 2
```

### 13.8 Call the procedures

Ask what the arguments are first — the answer comes from `ALL_ARGUMENTS`,
resolving synonyms:

```sql
SELECT position, argument_name, direction, oracle_type
FROM oracle_arguments('demo', 'QUACK_DEMO_GREET');
```
```
┌──────────┬───────────────┬───────────┬─────────────┐
│        1 │ P_NAME        │ in        │ VARCHAR2    │
│        2 │ P_GREETING    │ out       │ VARCHAR2    │
└──────────┴───────────────┴───────────┴─────────────┘
```

Then supply one text value per argument, in declaration order, `NULL` for each
`OUT` slot:

```sql
SELECT * FROM oracle_call_auto('demo', 'QUACK_DEMO_ADD',   ['2', '3']);
-- return_value = 5
SELECT * FROM oracle_call_auto('demo', 'QUACK_DEMO_GREET', ['world', NULL]);
-- P_GREETING = hello, world
```

A `SYS_REFCURSOR` comes back as a handle you read once:

```sql
SELECT * FROM oracle_call_auto('demo', 'QUACK_DEMO_LIST', [NULL]);
-- P_ROWS  NULL  oracle:1:1
SELECT * FROM oracle_cursor('oracle:1:1');
```
```
┌───────────────┬─────────────────┐
│ DEPARTMENT_ID │ DEPARTMENT_NAME │
├───────────────┼─────────────────┤
│            10 │ ACCOUNTING      │
│            20 │ RESEARCH        │
│            30 │ SALES           │
│            40 │ OPERATIONS      │
└───────────────┴─────────────────┘
```

### 13.9 Read one table through several sessions

```sql
SELECT count(*) FROM oracle_scan_parallel('demo',
    'QUACK_DEMO_DEPARTMENTS', 'DEPARTMENT_ID', shards := 4);
```

Four rows through four sessions is pointless in itself — the point is that every
shard reads `AS OF SCN` at one change number taken before any of them start, so
the result is one snapshot. Against a real table, compare it with
`SELECT count(*) FROM ora.QUACK_DEMO_DEPARTMENTS`: the numbers must agree.

This needs `EXECUTE` on `SYS.DBMS_FLASHBACK` and `FLASHBACK` on the table. If
the database will not give out a change number, the scan is refused rather than
run unpinned.

### 13.10 Clean up

```sh
docker exec -i oracle-demo bash -c \
    'sqlplus -s system/$ORACLE_PASSWORD@localhost:1521/FREEPDB1' < examples/demo_teardown.sql
```

Or, in DuckDB, just `DETACH ora; DROP SECRET demo;` and stop the container.
