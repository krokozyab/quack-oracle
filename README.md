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

> **Status:** version 0.1.0-dev, and honest about it. Reads, writes, procedure
> calls and TLS are verified against live Oracle 19c, Oracle Free 23ai, and OCI
> Autonomous Database. It is not yet published to DuckDB Community Extensions,
> so today you build it yourself — see [Install](#1-install).

---

## Contents

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

---

## 1. Install

The extension is not on DuckDB Community Extensions yet, so there is no
`INSTALL oracle_scanner` yet. Build it once:

```sh
git clone --recurse-submodules https://github.com/krokozyab/quack-oracle.git
cd quack-oracle
make release
```

You need a C++17 compiler, CMake, and OpenSSL. The first build compiles DuckDB
itself and takes a while — twenty to forty minutes is normal. Later builds are
much faster.

That produces two things you can use:

**The simplest way — use the DuckDB shell it just built.** The extension is
already inside it:

```sh
./build/release/duckdb -unsigned
```

**Or load it into your own DuckDB.** The extension file is at
`build/release/extension/oracle_scanner/oracle_scanner.duckdb_extension`:

```sh
duckdb -unsigned
```
```sql
LOAD '/path/to/quack-oracle/build/release/extension/oracle_scanner/oracle_scanner.duckdb_extension';
```

Two things to know here:

- **`-unsigned` is required.** DuckDB only loads extensions it did not sign if
  you ask it to. In a client library, pass the `allow_unsigned_extensions`
  setting instead.
- **The DuckDB versions must match exactly.** This builds against DuckDB
  v1.5.4, and v1.5.4 is the only version that will load it.

Check that it worked:

```sql
SELECT extension_name, loaded FROM duckdb_extensions()
WHERE extension_name = 'oracle_scanner';
```

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
    TLS_SERVER_NAME 'adb.eu-frankfurt-1.oraclecloud.com',
    WALLET_FILE '/secure/Wallet_mydb.zip',
    WALLET_PASSWORD '...'
);
```

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
| `WALLET_FILE`, `WALLET_PASSWORD` | A cloud wallet ZIP, or an `ewallet.pem` bundle |
| `TLS_SERVER_NAME` | The name checked against the server certificate |
| `TLS_SNI_NAME` | Only when the endpoint is an IP or a different virtual host |
| `TLS_CA_FILE` | An explicit PEM trust list; system roots are then not used |
| `TLS_SERVER_CERT_DN` | Require this exact certificate subject, in addition to the hostname |
| `CONNECT_TIMEOUT`, `READ_TIMEOUT` | Socket timeouts in seconds |

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

You get the tables and views of the user you connected as. Names come back as
Oracle stores them, which is upper case unless they were created quoted — so
`o.ITEMS`, not `o.items`. `DESCRIBE` works, and `NOT NULL` columns and primary
keys show up in `duckdb_constraints()`.

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

⚠️ **LOB columns are expensive.** A `CLOB`/`BLOB` value is not in the row; the
row carries only a pointer, and fetching the content costs extra round trips per
value. Measured: 2,000 rows with a 2,000-character CLOB took **1.22 s**, against
**0.004 s** for the same rows without that column. Select a LOB column only when
you need it. Writing a LOB is not supported.

---

## 10. Troubleshooting

### `The file was built specifically for DuckDB version 'v1.5.4'`

Your DuckDB is a different version. Use the shell this project built
(`./build/release/duckdb`), or install DuckDB v1.5.4.

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

Guarantees that hold by construction: no Oracle client is linked or loaded (CI
checks the shipped binary on every build); no password, wallet password, key or
bind value is ever logged or persisted; wallet ZIPs are read in memory and never
written to disk; and TLS verification has no off switch.

Never commit database credentials, wallets, production descriptors, or raw
captures to this repository.

This is an independent community project and is not affiliated with Oracle or
DuckDB Labs.
