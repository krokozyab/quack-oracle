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

> **Status:** version 0.6.1, for DuckDB v2.0.0, published to DuckDB Community
> Extensions — one `INSTALL` and you are done, see [Install](#1-install).
> Reads, writes, procedure calls and TLS are verified against live Oracle 19c,
> Oracle Free 23ai, and OCI Autonomous Database; the 0.6 additions were verified
> on 19c and Free 23ai. What changed: [0.6.1](docs/RELEASE_NOTES_0.6.1.md),
> [0.6.0](docs/RELEASE_NOTES_0.6.0.md).

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
| `DSN` / `TNS_ALIAS` in a secret | Easy Connect strings, and aliases from `tnsnames.ora` — read from `CONFIG_DIR`, or out of the wallet ZIP or folder, by the extension itself |
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
   - 7a. [Nearest-neighbour search on Oracle 23ai vectors](#7a-nearest-neighbour-search-on-oracle-23ai-vectors)
8. [Settings](#8-settings)
9. [Which Oracle types work](#9-which-oracle-types-work)
10. [Troubleshooting](#10-troubleshooting)
11. [Build and test from source](#11-build-and-test-from-source)
12. [Security, limits, further reading](#12-security-limits-further-reading)

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
Version 0.6.1 targets **DuckDB v2.0.0**, and new releases are built for DuckDB 2.0
only. An extension loads only into the DuckDB version it was built for, so a
DuckDB 2.0 pre-release cannot load it; upgrade to v2.0.0. On **DuckDB v1.5.6**
the same command installs 0.4.0, the last release built for it; on v1.5.5,
0.2.2.

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

---

## 2. Connect to a database

A connection is stored as a DuckDB **secret**. You create it once per session
and then refer to it by name. Give it the host, port and service name, or one
connection string (`DSN`), or an alias from a `tnsnames.ora`; none of them needs
anything configured on disk.

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

### The shortest form: one connection string

If you already have a connection string — the kind SQL\*Plus, SQLcl or
python-oracledb take — put it in `DSN` and skip `HOST`, `PORT` and
`SERVICE_NAME`:

```sql
CREATE SECRET ora (
    TYPE oracle,
    DSN 'db.example.com:1521/ORCLPDB1',
    USER 'scott',
    PASSWORD 'tiger'
);
```

`DSN` takes three shapes, told apart by how they look:

| You write | It is read as |
| --- | --- |
| `host:port/service` (also `//host/service`, `tcps://host:2484/service`, several hosts separated by commas, and `?retry_count=3`-style parameters) | An Easy Connect string |
| `(DESCRIPTION=...)` | A full descriptor, the same as `CONNECT_DESCRIPTOR` |
| `mydb_low` (a bare name) | An alias from `tnsnames.ora`. It is looked up in `CONFIG_DIR` if you give one, then in the wallet, then in the folder the `TNS_ADMIN` environment variable names |

For an encrypted connection, write `tcps://` and name the certificate to
check:

```sql
CREATE SECRET ora_tls (
    TYPE oracle,
    DSN 'tcps://db.example.com:2484/sales.example.com',
    USER 'app_user', PASSWORD '...',
    TLS_SERVER_NAME 'db.example.com'
);
```

An alias with a `tnsnames.ora` you keep in a folder of your own:

```sql
CREATE SECRET ora_alias (
    TYPE oracle, DSN 'sales', USER 'scott', PASSWORD 'tiger',
    CONFIG_DIR '/etc/oracle/network/admin'
);
```

`DSN` is used *instead of* `HOST`/`PORT`/`SERVICE_NAME`, `TNS_ALIAS` and
`CONNECT_DESCRIPTOR`; combining them is refused. The Easy Connect parameters
that are read are listed in
[CAPABILITIES](docs/CAPABILITIES.md); any other parameter is refused by name.

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

The wallet's own descriptor usually carries `(retry_count=20)(retry_delay=3)`.
Those are honoured: a database that is asleep or briefly unreachable is
retried, within the 60-second connect budget described under
[Several addresses and listener redirects](#several-addresses-and-listener-redirects).

### Encrypted connection without a wallet

```sql
CREATE SECRET ora_tls (
    TYPE oracle, HOST 'db.example.com', PORT 2484, SERVICE_NAME 'service',
    USER 'app_user', PASSWORD '...', PROTOCOL 'tcps',
    TLS_SERVER_NAME 'db.example.com', TLS_CA_FILE '/secure/ca.pem'
);
```

### Several addresses and listener redirects

Everything in this section is covered by offline tests — a scripted listener and
transport, plus loopback sockets.

Give the whole descriptor inline with `CONNECT_DESCRIPTOR`. No wallet is
needed for it (a `TNS_ALIAS` from a wallet can now name several addresses too):

```sql
-- A SCAN name: every IP it resolves to is tried in turn, and the SCAN
-- listener's redirect to a node listener is followed.
CREATE SECRET ora_scan (
    TYPE oracle, USER 'scott', PASSWORD 'tiger',
    CONNECT_DESCRIPTOR '(DESCRIPTION=
        (CONNECT_TIMEOUT=90)(RETRY_COUNT=3)(RETRY_DELAY=3)(TRANSPORT_CONNECT_TIMEOUT=3)
        (ADDRESS=(PROTOCOL=TCP)(HOST=sales-scan.example.com)(PORT=1521))
        (CONNECT_DATA=(SERVICE_NAME=sales.example.com)))'
);

-- Several listeners, spread across new connections, with a standby list
-- tried only when the first list has nothing left.
CREATE SECRET ora_multi (
    TYPE oracle, USER 'scott', PASSWORD 'tiger',
    CONNECT_DESCRIPTOR '(DESCRIPTION=
        (ADDRESS_LIST=(LOAD_BALANCE=on)
            (ADDRESS=(PROTOCOL=TCP)(HOST=node1.example.com)(PORT=1521))
            (ADDRESS=(PROTOCOL=TCP)(HOST=node2.example.com)(PORT=1521)))
        (ADDRESS_LIST=
            (ADDRESS=(PROTOCOL=TCP)(HOST=standby.example.com)(PORT=1521)))
        (CONNECT_DATA=(SERVICE_NAME=sales.example.com)))'
);
```

What each setting does here, with its default:

| Descriptor setting | Meaning in this client | Default |
| --- | --- | --- |
| `ADDRESS`, `ADDRESS_LIST` | Where to connect. A DESCRIPTION's own `ADDRESS` entries form one list; up to 16 addresses in all. `PROTOCOL` defaults to TCP, `PORT` to 1521 | — |
| `FAILOVER` | On: every address is tried in turn. Off: only one address is tried | on |
| `LOAD_BALANCE` | On: the order is shuffled for every new physical connection (with `FAILOVER=off`: one address picked at random). Off: the written order | off |
| `RETRY_COUNT` | Extra passes over the whole address order after a pass fails (at most 100) | 0 |
| `RETRY_DELAY` | Seconds to wait before each extra pass | 1 |
| `TRANSPORT_CONNECT_TIMEOUT` | Per attempt: TCP connect plus TLS handshake to one resolved address. The same as the secret's `CONNECT_TIMEOUT`, which it must agree with if both are set | 10 |
| `CONNECT_TIMEOUT` | **The overall budget** for one physical connection: every attempt, redirect and retry delay together. Oracle reads it per attempt; here it bounds the whole connect, so a long `RETRY_COUNT` cannot run on for minutes | 60, or `TRANSPORT_CONNECT_TIMEOUT` if larger |
| `INSTANCE_NAME`, `SERVER` in `CONNECT_DATA` | Passed on to the listener. `SERVER` is `DEDICATED` or `SHARED` | — |
| `SECURITY` | `SSL_SERVER_CERT_DN` is honoured as before | — |

The budget is an absolute deadline for everything up to a usable connection:
name resolution, each TCP connect and TLS handshake, every read and write of the
listener exchange (however slowly the bytes arrive), the redirects, the retry
delays, and then protocol negotiation and authentication with the server that
accepted. A connect that is not authenticated by the time it runs out is
closed, not returned; once authenticated, the session is bounded by
`READ_TIMEOUT` only.
The one wait that can overrun it is a TCP connect or TLS handshake already in
progress, by less than a second, because that timeout is set in whole seconds.
Name lookups run on a small fixed pool (4 workers, 16 queued), so a DNS server
that hangs costs at most those threads however many connects give up on it.

How a connect proceeds: the addresses are ordered by `FAILOVER` and
`LOAD_BALANCE`; each host name is resolved and **every IP it resolves to is a
separate attempt** with its own timeout, so one dead SCAN IP costs one attempt,
not the whole connect. An attempt that fails for a reason another listener
might not share — refused TCP connect, timeout, a dropped connection, a
listener `REFUSE` (its `ORA-` code is kept), a TLS handshake that broke off — moves on to
the next IP, then the next address, then the next pass. A listener `REDIRECT`
(the SCAN listener handing the connection to a node listener) is followed, up
to 3 hops, with loops refused; if the node it names is unreachable, the other
nodes that listener named, then the remaining SCAN IPs and addresses, are still
tried. When everything fails, the
error names every attempt and what happened to it — addresses and outcomes only,
never credentials or connect data.

These stop the connect at once instead of trying elsewhere: a certificate that
does not verify, a listener answer that does not parse, a redirect that would
change the protocol (a TCPS connection is never sent to TCP), and cancellation
(Ctrl+C / interrupt, checked before every attempt, during name resolution and
retry delays, and on every read and write until authentication completes; a
TCP connect or TLS handshake in progress finishes or times out first).

With TCPS, every hop — redirect targets included — is verified against
`TLS_SERVER_NAME` if you set it, otherwise against the host name you
configured for that address (the SCAN name, not an IP it resolved to, and not
a host a listener named). `TLS_SERVER_CERT_DN` applies to every hop.

**What this is not: failover of a running session.** There is no Transparent
Application Failover, Application Continuity, FAN/ONS, and no automatic retry of
SQL or transaction recovery. If an established session is lost, the statement
running on it fails with an error and nothing is re-sent; the next statement
opens a new connection, which may land on another address. Descriptor settings
that would promise otherwise are refused by name rather than ignored:
`FAILOVER_MODE` (TAF), a `DESCRIPTION_LIST` whose descriptions name different
databases, `SOURCE_ROUTE=ON`, `SERVER=POOLED`, `HTTPS_PROXY`, and any other key this client does not know.
`ENABLE`, `EXPIRE_TIME`, `SDU`, `TDU`, `SEND_BUF_SIZE`, `RECV_BUF_SIZE`,
`TYPE_OF_SERVICE` and `USE_SNI` are accepted and ignored.

### All the fields

| Field | What it is |
| --- | --- |
| `HOST`, `PORT`, `SERVICE_NAME` | The database endpoint |
| `USER`, `PASSWORD` | Your Oracle credentials |
| `PROTOCOL` | `tcp` (the default) or `tcps` for TLS |
| `DSN` | One string in python-oracledb's forms: an Easy Connect string (`tcps://host:2484/service?retry_count=3`), a full `(DESCRIPTION=...)`, or an alias name. Use *instead of* HOST/PORT/SERVICE_NAME. See [CAPABILITIES](docs/CAPABILITIES.md) for the Easy Connect parameters |
| `TNS_ALIAS` | An alias from the `tnsnames.ora` in `CONFIG_DIR`, or else inside the wallet — use *instead of* HOST/PORT/SERVICE_NAME |
| `MODULE`, `ACTION`, `CLIENT_IDENTIFIER`, `CLIENT_INFO` | Session attributes Oracle shows in `V$SESSION` and `SYS_CONTEXT('USERENV', ...)`, set when each session opens (limits 48, 32, 64 and 64 bytes). Setting a module clears the action unless one is given |
| `SID` | The database by SID instead of `SERVICE_NAME`; one of the two |
| `CONFIG_DIR` | A folder holding `tnsnames.ora` (or that file) for `TNS_ALIAS`, or for an alias given as `DSN`. Without it, the wallet, then the `TNS_ADMIN` environment variable |
| `CONNECT_DESCRIPTOR` | A full `(DESCRIPTION=...)` given inline — use *instead of* HOST/PORT/SERVICE_NAME and TNS_ALIAS. See [Several addresses and listener redirects](#several-addresses-and-listener-redirects) |
| `WALLET_FILE` | A cloud wallet ZIP, an unpacked wallet folder, an `ewallet.pem` bundle, or an auto-login `cwallet.sso` |
| `WALLET_PASSWORD` | The password the wallet's encrypted `ewallet.pem` is locked with. Not needed when the wallet carries `cwallet.sso` — every wallet OCI hands out does |
| `TLS_SERVER_NAME` | The name checked against the server certificate |
| `TLS_SNI_NAME` | Only when the endpoint is an IP or a different virtual host |
| `TLS_CA_FILE` | An explicit PEM trust list; system roots are then not used |
| `TLS_SERVER_CERT_DN` | Require this exact certificate subject, in addition to the hostname |
| `CONNECT_TIMEOUT`, `READ_TIMEOUT` | Socket timeouts in seconds. `CONNECT_TIMEOUT` is per attempt (TCP connect plus TLS handshake, default 10); the whole connect is bounded separately (see [Several addresses and listener redirects](#several-addresses-and-listener-redirects)) |

**The database's character set does not matter.** There is nothing to configure
and nothing to convert on your side: the client asks Oracle for AL32UTF8 and the
server converts, so text arrives as UTF-8 and is taken back as UTF-8 whatever
the database is stored in. Verified live against `TR8MSWIN1254`,
`WE8MSWIN1252`, `ZHS16GBK` and `AL32UTF8`, reading and writing text that only
exists in each of those character sets.

**A service name, or a SID.** Prefer `SERVICE_NAME`; a database that only answers
to a SID (an older non-CDB instance, or the root of a container database) can be
reached with `SID 'ORCL'` in the secret instead, or `(CONNECT_DATA=(SID=...))` in a
descriptor. A secret or descriptor names one of the two, never both. To find a
service name the database also answers to, ask it:

```sql
SELECT value FROM v$parameter WHERE name = 'service_names';
```

A `DESCRIPTION_LIST` whose descriptions all name the same database (the same
service name or SID, instance and certificate DN) is read as their addresses in
order, so a primary and a standby listed as two descriptions fail over as two
address lists would. Descriptions that name different databases are refused.

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
case unless they were created quoted. A name typed in another case finds the one
object that matches ignoring case (`o.items` reads `ITEMS`); if a schema holds both
`"items"` and `ITEMS`, write the exact spelling. `DESCRIBE`
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

**Another user's schema.** Most people connect as a reader, not as the owner of the
data. `ATTACH 'ora' AS hr (TYPE oracle_scanner, SCHEMA 'HR')` mounts that schema's
tables and views instead — what `ALL_TABLES` and `ALL_VIEWS` show for that owner —
and every statement names the table as `"HR"."EMPLOYEES"`. The name is resolved
against `ALL_USERS`: as written, else the one user it matches ignoring case. Writes
need the grants Oracle itself would ask for. One attachment is one schema; attach
again, under another alias, for a second.

**What `ATTACH` will not do:** create or drop tables, or create schemas. This extension issues no DDL at all. For those, use
`oracle_query` with a fully qualified name, or see
[the DDL note](#i-need-to-run-create-table-or-another-ddl-statement).

### Pushing filters down to Oracle

Filters on an attached table are sent to Oracle where that is provably the same
answer, and applied by the extension to the returned rows where it is not, so a
query never fails for lack of a translation — it is only slower. To switch it off
and have DuckDB filter everything itself:

```sql
SET oracle_filter_pushdown = false;
```

It is on by default. Once DuckDB hands a filter to the scan it removes it from
its own plan, so the scan applies every one: those whose Oracle meaning it can
prove identical go into the `WHERE` clause, and the rest are evaluated by DuckDB's
own expression over each fetched batch. (Before 0.6.0 the second kind raised
an error and pushdown was off by default.)

Pushed down: `=`, `<>`, `<`, `<=`, `>`, `>=`, `IS NULL`, `IS NOT NULL`, `IN`
(up to 16,384 values, as lists of 1,000), and `AND`/`OR` of those, on number, date and timestamp
columns, and `=`, `<>` and `IN` on `VARCHAR2` columns against a non-empty constant
(equality does not depend on collation). Ordered comparisons of text, `LIKE`, and any
comparison on a `CHAR` or `NVARCHAR2` column are applied by DuckDB to the rows that come
back, because Oracle's collation and its blank-padded `CHAR` comparison depend on session
settings this client does not negotiate.

### What else goes to Oracle

Besides the filters above, these are done by Oracle, where its answer is provably the one
DuckDB would give. Each has a setting to turn it off, and what it does not cover is stated
in its own paragraph.

| What | Example | Setting |
| --- | --- | --- |
| [Keys of a join](#joining-to-something-duckdb-reads) | `JOIN read_parquet('vip.parquet') ON …` reads only the matching rows | `oracle_filter_pushdown` |
| [Joining two attached tables](#joining-two-attached-tables) | `FROM o.ORDERS x JOIN o.CUSTOMERS y ON …` is one statement | `oracle_join_pushdown` |
| [Aggregates](#aggregates) | `SELECT region, count(*), sum(amount) … GROUP BY region` | `oracle_aggregate_pushdown` |
| [Top-N](#top-n) | `ORDER BY amount DESC LIMIT 100` | `oracle_top_n_pushdown` |
| [JSON paths](#json-paths) | `WHERE doc->>'$.customer.id' = 'c42'` | `oracle_filter_pushdown` |
| [Samples](#samples-and-limit) | `TABLESAMPLE SYSTEM (1%)` | — |
| [Heavy columns after the filter](#heavy-columns-after-the-filter) | LOBs are read only for the rows that pass | `oracle_deferred_columns` |
| [One moment for a whole statement](#one-moment-for-a-whole-statement) | every table of a statement `AS OF` one SCN | `oracle_consistent_read` (off by default) |
| [Local snapshots](#local-snapshots) | a DuckDB table built from Oracle at one SCN | `oracle_snapshot(…)` |
| [A scan's own report](#what-a-scan-sent-and-moved-explain-analyze) | `EXPLAIN ANALYZE` shows the SQL sent and what came back | — |

#### Joining to something DuckDB reads

When an attached table is joined to something DuckDB reads itself — a
Parquet file, a CSV, another database, a literal list — the keys the other side
holds are sent to Oracle too, so
`SELECT … FROM o.SALES s JOIN read_parquet('vip.parquet') v ON s.client_id = v.client_id`
reads the 50 clients' rows (`WHERE "CLIENT_ID" IN (101, 205, …)`) and not the whole
table. Few keys go as an `IN` list; more as the ranges of the key they fall in
(`BETWEEN … OR …`, or the smallest and largest key), and a key range DuckDB
describes only as a bloom filter is applied locally. It needs a numeric key and is
only ever a narrowing: DuckDB still checks every row against the join.

#### Keys of a join, text keys, long lists

When one side of a join is an attached table, DuckDB sends the other side's keys to
the scan once they are known; they reach Oracle as `IN` lists (numbers also as `BETWEEN` ranges),
so a small build side reads a few rows instead of the table. Text keys of `VARCHAR2` columns work
the same way, because equality does not depend on collation. DuckDB builds an `IN` list only up to
its own `dynamic_or_filter_threshold` (50 by default); `SET dynamic_or_filter_threshold = 5000`
lets a larger build side through, and a list over Oracle's 1000-entry limit is sent as several
lists joined by `OR`, up to 16384 values (more than that is read unfiltered, as before). A
composite key is filtered column by column, never as a tuple, since DuckDB hands the scan one
filter per column.

DuckDB can only choose that plan if it knows the Oracle table is the big side.
It reads the table's row count from Oracle's optimizer statistics
(`USER_TABLES.NUM_ROWS`), so a table that has never had statistics gathered looks
tiny to it and may be built into the hash table instead of probed. Gather them
(`BEGIN DBMS_STATS.GATHER_TABLE_STATS(USER, 'SALES'); END;` through
`oracle_plsql`) for the tables you join. The same statistics give each column's
distinct-value count (`NUM_DISTINCT`), which sizes `GROUP BY`s and joins on it.
Only counts are passed on: a statistic can be stale, and a stale minimum, maximum
or null count could make DuckDB skip rows, where a stale count only misjudges a plan.

#### Joining two attached tables

An inner join of two tables attached from the same Oracle database
(`SELECT … FROM o.ORDERS x JOIN o.CUSTOMERS y ON x.cust = y.id WHERE …`) is one statement,
`FROM (SELECT … WHERE <x's filters>) a JOIN (SELECT … WHERE <y's filters>) b ON …`, so the join's
result travels and not both tables. Conditions are comparisons (`=`, `<>`, `<`, `<=`, `>`, `>=`)
between columns of the same number, date or timestamp type; all filters on both sides must have
gone to Oracle, neither side may be a sample, and the columns read must not be LOB, JSON, VECTOR,
XML or ROWID. Outer, semi and anti joins, text keys and joins of more than two tables (a join of
three comes out as a pushed pair joined by DuckDB to the third) are left to DuckDB.
`SET oracle_join_pushdown = false` turns it off. 40 random joins (equality, inequality, composite
conditions, self-joins, NULLs, pushed filters on both sides) returned the same rows with and
without it on 19c and 23ai.

#### Aggregates

`SELECT region, count(*), sum(amount), max(day) FROM o.SALES WHERE … GROUP BY region`
is computed by Oracle (`SELECT "REGION", CAST(COUNT(*) …), …, MAX("DAY") FROM "SALES" WHERE … GROUP BY "REGION"`),
so the groups travel, not the rows. Covered: `count(*)`, `count(col)`, `sum`, `min`, `max`, with
or without `GROUP BY`, without `DISTINCT`, `FILTER`, `ORDER BY` or `GROUPING SETS`. `sum` is
pushed for exact numbers only (integers arrive as text and are read as `HUGEINT`, fixed-scale
decimals as `DECIMAL(38,s)`, the types DuckDB itself returns); `min`, `max` and group keys for
numbers, dates and timestamps. Text keys and floating point are left to DuckDB (Oracle may
group and order text by a collation or blank-padding where DuckDB compares bytes, and the order of
addition changes a floating-point sum). Every filter must have gone to Oracle too, and the scan
must have no sample and no join filter coming later; otherwise the plan is unchanged.
`SET oracle_aggregate_pushdown = false` turns it off. 60 random aggregate queries (up to two
group keys, NULLs, ties, decimals, dates, timestamps, pushed filters) returned the same rows with
and without it on 19c and 23ai.

#### Top-N

`SELECT … FROM o.SALES WHERE … ORDER BY amount DESC LIMIT 100` is ranked by
Oracle (`ORDER BY "AMOUNT" DESC NULLS LAST FETCH FIRST 100 ROWS ONLY`), so 100 rows
travel, not the table; the `TOP_N` stays in DuckDB's plan and sorts what came back, so
Oracle only has to return rows that include the true first 100 (an `OFFSET` counts: it
asks for limit plus offset). Every sort key has to be a number, a date or a timestamp
column, because those compare the same in both engines, and `NULLS FIRST`/`LAST` is always
written out; a text key, a computed key, a join, or any filter Oracle was not sent (the
rows would be cut before the filter) leaves the scan reading everything, as before.
`SET oracle_top_n_pushdown = false` turns it off. 40 random `ORDER BY … LIMIT … OFFSET`
queries over a table with NULLs and ties, with and without pushed filters, returned the same
rows with and without it on 19c and 23ai.

#### Samples and `LIMIT`

`SELECT … FROM o.BIG TABLESAMPLE SYSTEM (1%)` and
`USING SAMPLE 1000 ROWS (system)` are taken by Oracle (`SAMPLE (p)`, or `SAMPLE BLOCK (p)`
for tables of tens of millions of rows, with `SEED` for `REPEATABLE`), so 1% of a
2,000,000-row table sends 20,000 rows, not 2,000,000. Block sampling on a table of a few
hundred thousand rows came back as 0 rows in some runs, so smaller tables are sampled by
row. A sample of a view, a `BERNOULLI` sample and a sample taken after a filter inside
the sampled query stay in DuckDB. `LIMIT` needs nothing of the kind: the scan reads one
batch of 2,048 rows and stops (`SELECT * FROM o.BIG LIMIT 10` moved 2,048 rows of 2,000,000).

#### JSON paths

A test of a path in a native `JSON` column
(`WHERE doc->>'$.customer.id' = 'c42'`, also `json_extract_string`, an `IN` list as `OR`, `IS NOT NULL`) is
narrowed in Oracle with `JSON_VALUE(doc, '$.customer.id' RETURNING VARCHAR2(4000) NULL ON ERROR) = 'c42'`
or `JSON_EXISTS`, so only candidate documents are read and decoded, and DuckDB still applies its own test
to them. The Oracle predicate is a superset on purpose: DuckDB renders a number as the document wrote it and an
object as JSON text, Oracle does neither, so a constant that could be a JSON number, `true`, `false`,
`null`, an object or an array is not narrowed, and neither is a path with a quoted key, a wildcard or a
filter (`$.a`, `$.a.b` and `$.a[0]` are). The answer is always DuckDB's: on 20,000 documents, with numbers,
booleans, nulls, objects, quotes and non-ASCII text as values, the same rows came back with the pushdown
on and off. A comparison with an `OR` of paths narrows only if every branch can be. Needs Oracle 21c or later
for the `JSON` type; `VARCHAR2`/`CLOB` columns with `IS JSON` are not narrowed.

#### Heavy columns after the filter

When a filter has to be applied by DuckDB (one Oracle was not
sent, such as an ordered comparison of text) and the query also reads CLOB, BLOB, JSON, VECTOR or
XMLTYPE columns the filter never looks at, the scan reads the other columns plus each row's
ROWID first, applies the filter, and then fetches the heavy columns only for the rows that passed,
`WHERE ROWID IN (…)` in groups of 500. Both steps read `AS OF SCN` at one change number, so the second
sees the rows the first did; a table that cannot be pinned that way (a view, an index-organized,
clustered or temporary table, no flashback privilege, or a transaction that has written) is read
the ordinary way. On a 5,000-row table with 8 KB of LOB per row, a filter keeping 900 rows moved
12.5 MiB instead of 68.9 MiB, with identical results on 19c and 23ai. `EXPLAIN ANALYZE` shows
*Columns read after the filter*. `SET oracle_deferred_columns = false` turns it off.

#### One moment for a whole statement

A statement that reads several attached tables (a join DuckDB
does itself, a union, a subquery) normally reads each at the moment its scan starts. `SET
oracle_consistent_read = true` takes one change number when the statement's first scan starts and reads
every attached table of it `AS OF SCN` that number, including the pushed-down joins and aggregates
and each ROWID range of a parallel scan. It needs flashback on the tables and undo that reaches back
that far; a database that gives out no change number fails the statement rather than reading several
moments, and a transaction that has written reads through its own session as before. Off by default.

#### Local snapshots

To keep a copy of Oracle data in DuckDB that you control, build it explicitly:

```sql
SELECT * FROM oracle_snapshot('o', 'sales_eu', 'SELECT * FROM o.main.SALES WHERE region = ''EU''');
-- table_name | row_count | scn        | taken_at
SELECT * FROM oracle_snapshots();                 -- every snapshot: where it is, catalog, SCN, when, rows, the query
SELECT * FROM oracle_snapshot_refresh('sales_eu'); -- run the query again, at a new SCN
```

`oracle_snapshot(catalog, table, query)` takes one change number from the Oracle behind the attached catalog
`catalog`, runs `query` (any DuckDB query: joins, aggregates and filters over its attached tables, which are
pushed down as usual) with every table of that catalog read `AS OF` that number, and writes the result with
`CREATE OR REPLACE TABLE`. What it came from (catalog, SCN, time, query) is kept in the table's own comment, so
there is no hidden state: the result is an ordinary DuckDB table you can query, index, export or `DROP`, it lives
in the database file if you use one, and `oracle_snapshots()` finds it again by that comment, in every attached
database. The table is made where an unqualified `CREATE TABLE` would go (the database and schema `USE` points
at), and a refresh rebuilds it there; `oracle_snapshot_refresh` takes `table`, `schema.table` or
`database.schema.table`, and refuses a name that two snapshots share rather than pick one. Tables of other
attached catalogs in the same query are read as they are now. It runs on a connection of its own, so it cannot
be part of the transaction that asked for it; the Oracle user needs flashback on the tables. Fewer moving parts
than a materialized view, and unlike one it never changes by itself.

### What a scan sent and moved: `EXPLAIN ANALYZE`

`EXPLAIN ANALYZE` on a query over an attached table shows, on the scan:

```
Oracle SQL: SELECT "GRP", "PAD", "ID" FROM "MT" WHERE "GRP" < 10
Oracle sessions: 1
Oracle rows returned: 100000
Oracle network: 1.2 MiB received, 1.0 KiB sent, 50 round trips
Oracle fetch time: 0.056 s
Value conversion time: 0.004 s
Filters applied after fetching: ((#1 >= 'x') AND (#1 < 'y'))
```

The statement is the one Oracle ran (the first of the ROWID ranges, with a count of the
rest, for a parallel scan); the rows are what Oracle returned before DuckDB filtered them;
the network line is the bytes and request/response round trips on the connections the
scan used; fetch time is the wait for Oracle plus decoding its answer, conversion time is
turning that into DuckDB values; and the last line is every filter Oracle was *not* sent.

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
the table does not need a primary key.

`UPDATE ... RETURNING` gives the rows as Oracle stored them after the change, and
`DELETE ... RETURNING` the rows as they were when it deleted them:

```sql
UPDATE o.ITEMS SET label = upper(label) WHERE id < 3 RETURNING id, label;
DELETE FROM o.ITEMS WHERE id > 100 RETURNING *;
```

Like `INSERT`, each row is its own statement, so a large `RETURNING` costs a round
trip a row. A row removed by someone else between the scan and the statement is
left out of the result. A table with a LOB, JSON or VECTOR column cannot be
returned from.

`ATTACH 'ora' AS o (TYPE oracle_scanner, READ_ONLY)` prevents writes through
both normal SQL and `oracle_execute_transaction`. Prepared raw DML rechecks the
current catalog mode at execution. `HIDDEN` is accepted for internal catalogs;
DuckDB enforces visibility. The scanner's in-memory storage wrapper stays
writable internally because DuckDB cannot open an in-memory database read-only;
the attached Oracle catalog retains its read-only access flag.

### Raw SQL in the attached transaction

The explicit catalog functions pin a session even when a SELECT comes before
the first write. Their first argument is the ATTACH alias, not a secret name:

```sql
BEGIN;
SELECT * FROM oracle_query_transaction('o', 'SELECT id FROM ITEMS WHERE id = :1', [7]);
SELECT * FROM oracle_execute_transaction('o', 'UPDATE ITEMS SET label = :1 WHERE id = :2', ['VII', 7]);
ROLLBACK;
```

`oracle_execute_transaction` accepts INSERT, UPDATE and DELETE and returns the
affected row count. Physical DDL is rejected. A statement or fetch failure
invalidates the remote transaction: issue ROLLBACK before starting another.
COMMIT failures report an unknown outcome; reconcile the database before replay
or file cleanup. Atomic commit across multiple catalogs is not guaranteed.

Statement/fetch errors expose numeric `oracle_error_code` and
`oracle_connection_state` in DuckDB's `ErrorData::ExtraInfo()`. DuckDB discards
extra fields while wrapping COMMIT errors (1.5.6 did), so immediately inspect
`SELECT * FROM oracle_transaction_status('o')` after a failed COMMIT. It opens
no Oracle session and returns `commit_outcome`, `connection_state`, nullable
`oracle_error_code` and `protocol_error_kind`. A new remote transaction resets
this status; inspect it before replay. `unknown` requires reconciliation.

Physical DDL has a separate explicit API:

```sql
SELECT * FROM oracle_execute_admin('ora', 'CREATE TABLE ADMIN_PROBE (ID NUMBER)');
```

It accepts one CREATE/ALTER/DROP/GRANT/REVOKE/COMMENT/TRUNCATE command on a
dedicated session and returns `completed`. It rejects explicit DuckDB
transactions at bind and execution, including a previously prepared command.
Oracle DDL commits implicitly; this is an administrative bootstrap/migration
path, never part of a metadata DML transaction. No automatic DDL replay occurs.
After schema changes, refresh dictionary entries outside transactions using
`DETACH o` followed by the original `ATTACH 'ora' AS o (TYPE oracle_scanner)`;
prepare dependent statements again. In-place cache refresh is not supported.

Prepared transactional SELECTs acquire the current transaction at each execution.
`oracle_query_transaction` learns its result columns from Oracle, so it runs the
SELECT once while binding and again when it executes; account for that extra
round trip and for the locks a blocking SELECT takes. When you know the
columns, declare them with
[`oracle_query_transaction_typed`](#reading-with-declared-columns) and the SELECT
runs once. Use the ordinary functions below for their existing autocommit
behavior.

### Reading with declared columns

```sql
PREPARE by_location AS
SELECT * FROM oracle_query_transaction_typed('o',
    'SELECT DEPARTMENT_ID, DEPARTMENT_NAME FROM QUACK_DEMO_DEPARTMENTS WHERE LOCATION = :loc',
    ['DEPARTMENT_ID', 'DEPARTMENT_NAME'], ['BIGINT', 'VARCHAR'], {loc: 'DALLAS'});

BEGIN;
EXECUTE by_location;
COMMIT;
```

The third and fourth arguments name the result columns and give their DuckDB
types; an optional fifth takes binds, as a LIST (positional) or a STRUCT
(named). Binding checks the SQL, the binds and the declaration locally and sends
nothing to Oracle, so `PREPARE` neither connects nor waits on a lock. Each
execution runs the statement exactly once, on the transaction current at that
moment — after a `COMMIT` or `ROLLBACK`, the next one — and compares Oracle's
describe with the declaration: the same number of columns, the same names
(case-insensitively), and each column mapping to the declared type under the
[type table](#9-which-oracle-types-work). A difference is an error naming the
column, never a quietly different result, and like any failure from Oracle it
invalidates the transaction.

The declarable types are the ones that table maps Oracle columns to: `VARCHAR`,
`BIGINT`, `DECIMAL(p,s)`, `DOUBLE`, `FLOAT`, `BLOB`, `TIMESTAMP` and
`TIMESTAMP_NS`. Declare what the mapping gives, not the type you want: a
`NUMBER(19)` or an unconstrained `NUMBER` is `VARCHAR`, a `DATE` is `TIMESTAMP`.
Cast around the function in DuckDB for anything else.

### Batches and procedure calls in the attached transaction

Two more functions run on the same pinned session, so their work commits or
rolls back with everything else in the DuckDB transaction. Neither commits on
its own.

```sql
BEGIN;
SELECT * FROM oracle_execute_many_transaction('o',
    'UPDATE ITEMS SET label = :label WHERE id = :id',
    [{'id': 7, 'label': 'VII'}, {'id': 8, 'label': 'VIII'}]);
SELECT * FROM oracle_call_named_transaction('o', 'APP.TOUCH_ITEM',
    [{name: 'P_ID', direction: 'in', type: 'number', value: '7'},
     {name: 'P_STATUS', direction: 'out', type: 'varchar', value: NULL::VARCHAR}]);
COMMIT;
```

`oracle_execute_many_transaction` takes 1 to 2048 rows of binds, SQL of at most
65536 bytes, and at most 131072 bytes of encoded binds and names. By default it
executes the rows one at a time and returns one row per input row: `row_index`,
its `affected_rows`, and `exact_counts = true`. With `exact_counts := false` it
sends Oracle array DML instead, in groups of up to 1024 rows, and returns a
single row whose `affected_rows` is the total and whose `row_index` is NULL —
the count of the whole batch, not a per-row breakdown.

`oracle_call_named_transaction` calls a procedure with 1 to 64 `NUMBER` or
`VARCHAR` arguments, `IN`, `OUT` or `IN OUT`, NULL included, and returns one
row per `OUT`/`IN OUT` argument. REF CURSOR, LOB and object arguments are not
supported here. The procedure runs inside your transaction, so it must not
`COMMIT`, run DDL or use an autonomous transaction.

Both refuse on a `READ_ONLY` catalog. A bind that fails local validation is
refused at bind time and leaves the transaction as it was. A failure from
Oracle invalidates the remote transaction, as for `oracle_execute_transaction`:
`ROLLBACK` before going on. Nothing is retried or replayed automatically.

### Several statements in one round trip

```sql
BEGIN;
SELECT * FROM oracle_execute_composite_transaction('o',
    ['INSERT INTO ITEMS (ID, LABEL) VALUES (:id, :label)',
     'UPDATE ITEM_TOTALS SET N = N + 1 WHERE KIND = :kind',
     'DELETE FROM ITEM_DRAFTS WHERE ID = :id'],
    {id: 7, label: 'VII', kind: 'roman'},
    [1, 1, 0]);
COMMIT;
```

`oracle_execute_composite_transaction` takes up to 16 `INSERT`, `UPDATE` or
`DELETE` statements, each validated the way `oracle_execute_transaction`
validates one, and sends them as one anonymous block that the extension builds
itself. After each statement Oracle compares its row count with the count at the
same position in the fourth argument, and the first mismatch fails the call with
`ORA-20906: DML composite operation N affected row count mismatch`. On success
it returns one row, `affected_rows`, the sum of the expected counts — exactly
what ran, since anything else would have failed.

The binds are one STRUCT of named binds or one LIST of positional ones, for all
the statements together: a name that several statements use is bound once, with
one value. Every placeholder needs a bind and every bind must be used. The
limits are 16 statements, 256 binds, 64 KiB of SQL in total, 8 MiB of bind
values, and 0 to 1,000,000 expected rows per statement. DDL, PL/SQL, `COMMIT`,
`ROLLBACK`, `MERGE`, a `;`, and a missing or unused bind are refused at bind,
before any session is opened.

It never commits or rolls back. When it fails — a count check, a constraint, an
interrupt, `READ_TIMEOUT` — the statements of the block before the failing one
have run inside the Oracle transaction, so the transaction is invalidated:
`ROLLBACK`, which takes back everything the transaction did. Nothing is retried.
It saves round trips — one call instead of one per statement — which matters
most on a slow link; it does no less work in Oracle, and measurements of small
transactions on a local database were mixed.

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

Types are `number`, `varchar`, `nvarchar`, `boolean`, `date`, `timestamp`,
`timestamp_ltz` (an offset in the text, bound as UTC), `interval_ym`,
`interval_ds` (DuckDB interval text, such as `2 years 3 months` or
`1 day 02:03:04`), `raw` (uppercase hex), `float`, `double`, and `cursor`.

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

### Function reference

Every function documents itself in DuckDB: argument names, a one-sentence
description, one example and categories.

```sql
SELECT function_name, parameters, description, examples
FROM duckdb_functions()
WHERE starts_with(function_name, 'oracle_')
ORDER BY function_name;
```

The examples there are meant to be run, but not against an empty DuckDB. They
assume:

- the extension is loaded;
- an Oracle secret named `demo` exists (see [Connect to a database](#2-connect-to-a-database));
- [`examples/demo_setup.sql`](examples/demo_setup.sql) has been run in the schema
  you connect as. It creates twelve objects, is safe to run again (it drops its own
  tables first and replaces its PL/SQL objects), and works unchanged on 19c, 23ai Free
  and Autonomous: the tables `QUACK_DEMO_DEPARTMENTS` (four rows), `QUACK_DEMO_LOG`
  (to write to) and `QUACK_DEMO_TYPES` (one column of every type in
  [section 9](#9-which-oracle-types-work)), and one small PL/SQL object for each
  `oracle_call_*` shape: `QUACK_DEMO_ADD`, `QUACK_DEMO_GREET`, `QUACK_DEMO_LIST`,
  `QUACK_DEMO_ANSWER`, `QUACK_DEMO_COUNT_DEPARTMENTS`, `QUACK_DEMO_MOTTO`,
  `QUACK_DEMO_DOUBLE`, `QUACK_DEMO_SHOUT` and `QUACK_DEMO_IMPLICIT`.

Run it with SQL\*Plus or SQLcl as that user, for example in a container:

```sh
docker cp examples/demo_setup.sql oracle-demo:/tmp/
docker exec -i oracle-demo bash -c \
    'sqlplus -s system/$ORACLE_PASSWORD@localhost:1521/FREEPDB1 @/tmp/demo_setup.sql'
```

or `sqlplus admin/<password>@<name>_low @examples/demo_setup.sql` with a wallet in
`$TNS_ADMIN` (on Autonomous, *Database Actions → SQL* works too: paste the file and run it).
It ends by listing what it made, twelve rows, all `VALID`.

The `oracle_execute` and `oracle_execute_many` examples write to
`QUACK_DEMO_LOG` and commit in Oracle as they run.

The `*_transaction` functions, `oracle_transaction_status` and `oracle_snapshot` take an
attached catalog rather than a secret; their examples assume
`ATTACH 'demo' AS ora (TYPE oracle_scanner)`. `oracle_snapshot_refresh` and
`oracle_snapshots` have something to show only after `oracle_snapshot` has run
(its example makes `departments_snapshot`). The
`oracle_execute_composite_transaction` example inserts one `QUACK_DEMO_LOG` row
and deletes it again, so its counts `[1, 1]` hold as long as no row is already
labelled `composite example`. The `oracle_execute_admin`
example creates a table, `QUACK_DEMO_SCRATCH`, and Oracle commits DDL at once;
drop it afterwards.

`oracle_cursor` and `oracle_close_call` take a handle, so their examples read
it from a DuckDB variable. Fill each from its own fresh call, on the same
connection, first — a handle is consumed by its first use:

```sql
SET VARIABLE oracle_example_handle =
    (SELECT cursor_handle FROM oracle_call('demo', 'QUACK_DEMO_LIST', 'P_ROWS'));
SELECT * FROM oracle_cursor(getvariable('oracle_example_handle'));

SET VARIABLE oracle_close_handle =
    (SELECT cursor_handle FROM oracle_call('demo', 'QUACK_DEMO_LIST', 'P_ROWS'));
SELECT * FROM oracle_close_call(getvariable('oracle_close_handle'));
```

### Anonymous PL/SQL blocks

When the work is more than one procedure call, send the block itself:

```sql
SELECT * FROM oracle_plsql('ora', '
    DECLARE s NUMBER := 0;
    BEGIN
        FOR i IN 1 .. :n LOOP s := s + i; END LOOP;
        :total := s;
    END;',
    [{name: 'n',     direction: 'in',  type: 'number', value: '100'},
     {name: 'total', direction: 'out', type: 'number', value: NULL::VARCHAR}]);
-- total | 5050
```

The block begins with `BEGIN` or `DECLARE` and ends with the `;` after its last
`END`; a `/` alone on a last line is dropped. The binds are the same
`STRUCT(name, direction, type, value)` that `oracle_call_named` takes, matched to
the block's `:name` placeholders by name: a bind the block does not mention, or a
placeholder without a bind, is refused before anything is sent. The `OUT` and
`IN OUT` ones come back as rows, in the order the block first mentions them, and a
`REF CURSOR` as a handle for `oracle_cursor`. Binds are optional.

`oracle_plsql` runs on a session of its own and **commits when the block
succeeds**, like `oracle_execute`; a block that fails is rolled back with the
session, and Oracle's error comes back as it is (`ORA-20001: boom`).
`oracle_plsql_transaction('o', block, binds)` runs it on the attached catalog's
pinned session instead and commits nothing, so DuckDB's `COMMIT` and `ROLLBACK`
decide; there the block must not commit, run DDL or use an autonomous
transaction, takes up to 64 binds, and cannot return cursors. It leaves that
session closed afterwards, not reused, because a block can change a session's
state. Both refuse a `READ_ONLY` catalog where one is involved.

A block can run DDL with `EXECUTE IMMEDIATE`, which is how a procedure is
created: `BEGIN EXECUTE IMMEDIATE 'CREATE OR REPLACE PROCEDURE …'; END;`.
`DBMS_OUTPUT` is not collected; return what you want to see through an `OUT` bind.

Every example is run by the adapter test suite against a scripted session,
which checks the request each one sends, and has also been run against a live
Oracle 19c and Oracle Free 23ai with the demo schema above. The exceptions are
`oracle_vector_search`, which needs a table with a `VECTOR` column (23ai only), and
`oracle_cursor` and `oracle_close_call`, which need a cursor handle from an earlier call.

---

## 7. Read a big table faster

Without choosing a key column or calling anything, an attached table is read through
several sessions when Oracle's statistics say it has 500,000 rows or more (`oracle_parallel_scan`
is `-1`, automatic: as many sessions as DuckDB has threads, up to eight). To choose the number
yourself, or to turn it off with `0`:

```sql
SET oracle_parallel_scan = 8;
SELECT * FROM o.BIG_TABLE;          -- up to 8 sessions, each reading ROWID ranges
```

The table is cut into ROWID ranges at its extent boundaries (about four chunks to a
session, so a thread that finishes early takes another), and every chunk reads
`AS OF SCN` at one change number taken first, so together they are one snapshot, not several
moments. On a 2,000,000-row table four sessions took 0.9 s against 2.2 s for one, and eight
0.7 s; the result matched row for row. A partitioned table is cut the same way across its
partitions. No numeric key is needed.

It reads one stream instead, and says nothing, when: the setting is 0 or 1; the user cannot
read `DBA_EXTENTS` (the extents give the cut points, and without them a table cannot be
divided evenly — a sample of its blocks came back in a few clumps and cut a test table 99 to
1); the table is under 2,048 blocks, index-organized, clustered or temporary; the database
gives out no change number (`EXECUTE` on `DBMS_FLASHBACK`) or no flashback read of the
table; the query is a `TABLESAMPLE`; or the transaction has already written to the catalog,
whose own session is the only one that sees those rows. Filters Oracle can be sent go into
every chunk. If the table is dropped or truncated while the scan runs, Oracle's own error
(`ORA-01466`) is the answer.

`oracle_scan_parallel` (below) still exists for a numeric key you want split by value,
and for a table the user may read but whose extents they may not.


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

## 7a. Nearest-neighbour search on Oracle 23ai vectors

A `VECTOR` column is read and written as a DuckDB array (see the type table above). To find the rows
nearest to a query vector without pulling the table over, let Oracle rank them:

```sql
SELECT id, title, distance
FROM oracle_vector_search('ora', 'DOCS', 'EMBEDDING', (SELECT embedding FROM my_questions WHERE id = 1)::FLOAT[768],
                          k := 10, metric := 'COSINE');
```

It returns every column of the table plus `distance`, for the `k` nearest rows
(1 to 100,000; default 10). The statement is
`SELECT t.*, VECTOR_DISTANCE(t.col, :1, metric) AS DISTANCE FROM tbl t ORDER BY DISTANCE
FETCH APPROX FIRST k ROWS ONLY`, so Oracle uses a vector index (HNSW or IVF) when the
table has one — checked against an IVF index on 23ai, where the plan goes through the
index's centroid tables — and only `k` rows travel. `metric` is `COSINE` (default),
`EUCLIDEAN`, `EUCLIDEAN_SQUARED`, `DOT`, `MANHATTAN` or `HAMMING`; `approximate := false`
asks for the exact top `k`. The table is `'T'` or `'OWNER.T'`; a name without quotes is
read in upper case as Oracle reads it, and one in double quotes is kept as written.

The query vector is a list or array of numbers. Oracle will not compare vectors of two
storage formats, so it is sent in the column's own (`FLOAT32`, `FLOAT64`, `INT8` or
`BINARY`, read from the dictionary); for a column declared `VECTOR(*, *)` it goes as
`FLOAT32` when your numbers are `FLOAT` and `FLOAT64` otherwise. Filter after the
function, not before: `WHERE` on its result narrows the `k` rows, it does not pick
the `k` from a subset.

---

## 8. Settings

| Setting | Default | What it does |
| --- | --- | --- |
| `oracle_session_pool_size` | `4` | How many authenticated Oracle sessions to keep and reuse for reads, per DuckDB connection per secret. `0` opens a fresh one every time. |
| `oracle_transaction_pool_size` | `2` | How many idle sessions an attached catalog keeps between its transactions, so the next transaction need not connect and authenticate. Read at `ATTACH`; `0` opens a session per transaction. |
| `oracle_unconstrained_number` | `'varchar'` | What a `NUMBER` with no declared precision becomes: `'varchar'`, `'double'` or `'decimal(38,9)'`-style. Set it before the query or the table's first use. See [section 9](#9-which-oracle-types-work). |
| `oracle_filter_pushdown` | `true` | Send `WHERE` clauses on attached tables to Oracle, and narrow JSON path tests. See [Pushing filters down](#pushing-filters-down-to-oracle). |
| `oracle_top_n_pushdown` | `true` | Let Oracle rank and cut an `ORDER BY … LIMIT` over a number, date or timestamp key. See [Top-N](#top-n). |
| `oracle_aggregate_pushdown` | `true` | Let Oracle compute `count`, `sum`, `min`, `max` and `GROUP BY` over number, date and timestamp keys. See [Aggregates](#aggregates). |
| `oracle_join_pushdown` | `true` | Let Oracle join two attached tables of one database (an inner join on number, date or timestamp columns). See [Joining two attached tables](#joining-two-attached-tables). |
| `oracle_deferred_columns` | `true` | Read LOB, JSON, VECTOR and XML columns only for the rows that pass a filter DuckDB applies itself. See [Heavy columns after the filter](#heavy-columns-after-the-filter). |
| `oracle_parallel_scan` | `-1` | How many sessions one scan of an attached table may read through at once: `-1` chooses (DuckDB's thread count, up to 8, for a table of 500,000 rows or more), `0` or `1` is one session. See [section 7](#7-read-a-big-table-faster). |
| `oracle_consistent_read` | `false` | Read every attached table of a statement `AS OF` one SCN. See [One moment for a whole statement](#one-moment-for-a-whole-statement). |

Pooling matters more than it looks. Opening a session costs a TCP connect, a TLS
handshake and an authentication round trip: against a cloud endpoint that was
**1.57 s per statement**, against **0.18 s** when reusing one.

---

## 9. Which Oracle types work

| Oracle | Comes back as | Note |
| --- | --- | --- |
| `NUMBER(p,0)`, p ≤ 18 | `BIGINT` | |
| `NUMBER(p,s)` | `DECIMAL(p,s)` | up to p = 38; `NUMBER(p,-s)` is a `BIGINT`, `NUMBER(2,4)` a `DECIMAL(4,4)` |
| `NUMBER` (unconstrained) | `VARCHAR` | exact only as text; see `oracle_unconstrained_number` below |
| `VARCHAR2`, `CHAR` | `VARCHAR` | UTF-8, whatever the database character set is |
| `DATE` | `TIMESTAMP` | an Oracle `DATE` carries a time, so it is not a DuckDB `DATE` |
| `TIMESTAMP(0–6)` | `TIMESTAMP` | |
| `TIMESTAMP(7–9)` | `TIMESTAMP_NS` | |
| `TIMESTAMP WITH TIME ZONE` | `VARCHAR` | keeps its offset, which `TIMESTAMPTZ` would drop; the time is on that offset's clock, as Oracle prints it (`2026-03-28 15:30:00+03:00`) |
| `RAW` | `BLOB` | |
| `BINARY_FLOAT`, `BINARY_DOUBLE` | `FLOAT`, `DOUBLE` | |
| `CLOB`, `NCLOB` | `VARCHAR` | see the warning below |
| `BLOB` | `BLOB` | see the warning below |
| `NCHAR`, `NVARCHAR2` | `VARCHAR` | converted from UTF-16, and written back as UTF-16 |
| `INTERVAL YEAR TO MONTH` | `INTERVAL` | whole months |
| `INTERVAL DAY TO SECOND` | `INTERVAL` | days and microseconds; a finer fraction is refused |
| `TIMESTAMP WITH LOCAL TIME ZONE` | `TIMESTAMPTZ` | an instant; sessions opened here use UTC |
| `BOOLEAN` (23ai) | `BOOLEAN` | |
| `JSON` (23ai) | `JSON` | the stored OSON image, decoded to JSON text |
| `VECTOR` (23ai) | `FLOAT[n]`, `DOUBLE[n]`, `TINYINT[n]`, `UTINYINT[n]`; `STRUCT` for `SPARSE` | by the column's declared format and dimensions |
| `XMLTYPE` | `VARCHAR` | the document as text (`XMLSERIALIZE ... NO INDENT`); written back through `XMLPARSE(DOCUMENT ...)`. An attached table only |
| `ROWID`, `UROWID` | `VARCHAR` | the 18 characters `ROWIDTOCHAR` gives; a logical UROWID is refused |
| `LONG`, `LONG RAW` | `VARCHAR`, `BLOB` | up to 1 MiB a value |

Anything else — `BFILE`, object and collection types — is **refused when the query is
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

When the table is not yours, or the column is a `SUM(x)` or `count(*)`, say what
you want once instead of casting in every query:

```sql
SET oracle_unconstrained_number = 'decimal(38,9)';   -- or 'double'; the default is 'varchar'
```

It applies to every `NUMBER` that has no declared precision, in `oracle_query`,
`oracle_scan_parallel` and attached tables, read when the query is bound or the
table is first used. `'double'` and a `DECIMAL` round what does not fit — digits
past the scale, or past 15 or 17 significant digits — which is the trade;
a `DECIMAL` that cannot hold a value's integer digits raises instead. Since the
value DuckDB then holds is a rounding of the stored one, a filter, `GROUP BY` key,
join key or `ORDER BY ... LIMIT` key on such a column is evaluated in DuckDB and not
sent to Oracle, which would compare the stored values: under `'decimal(10,1)'`,
1.21 and 1.24 are one group and neither is `> 1.2`.

⚠️ **LOB columns are expensive.** A `CLOB`/`BLOB` value is not in the row; the
row carries only a pointer, and fetching the content costs extra round trips per
value. Measured: 2,000 rows with a 2,000-character CLOB took **1.22 s**, against
**0.004 s** for the same rows without that column. Select a LOB column only when
you need it; when a filter DuckDB applies itself narrows the rows first, the LOBs are
read for the survivors only (see [Heavy columns after the filter](#heavy-columns-after-the-filter)). Writing is cheap by comparison: a LOB value goes out as an ordinary bind up to 8 MiB, and past that through a temporary LOB, up to 1 GiB each.

---

## 10. Troubleshooting

### `The file was built specifically for DuckDB version '…'`

Your DuckDB is a different version from the one the file was built for. An
extension loads only into the exact DuckDB version it was built against, and
a 2.0 pre-release is not v2.0.0. Run `INSTALL oracle_scanner FROM community`
from the DuckDB you use — it fetches the build for that version if one exists —
or, if you built from source, use the shell this project produced (`./build/release/duckdb`).

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

The same route runs anything that is a single procedure call. Anything longer
is an anonymous block; see `oracle_plsql` in section 6.

### `ORA-20906: DML composite operation N affected row count mismatch`

Statement N of an `oracle_execute_composite_transaction` call changed a
different number of rows from the count you gave for it. The statements before
it did run, so `ROLLBACK` the transaction, find out why the count differed, and
start again.

### `Oracle column … where … was declared`

`oracle_query_transaction_typed` found a describe that differs from the
declared columns — a renamed or retyped column, one more or one fewer, often
after DDL on the table. The message names the column. Correct the declaration
(`DESCRIBE`-ing the query with `oracle_query` shows what Oracle returns), then
`PREPARE` again; `ROLLBACK` first if it happened inside a transaction.

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

### `Oracle offered the … password verifier (type 0x…) for this account`

The connection itself worked; the server asked to authenticate with an older
password format than the 12C one this extension signs in with. The type in the
message says which case you are in.

**`10G` (type `0x0939`).** The database most likely runs with
`SEC_CASE_SENSITIVE_LOGON = FALSE` (case-insensitive passwords). The server then
offers the 10G verifier even to accounts that also have a 12C password version,
so every account on that database is affected. Check it with your DBA:

```sql
SHOW PARAMETER sec_case_sensitive_logon
```

Switching to case-sensitive passwords is a database-wide decision for the DBA,
made through whatever procedure the applications on that database require.
python-oracledb in thin mode stops at the same point (DPY-3015); only clients
built on OCI or JDBC accept the 10G verifier.

**`11G` (type `0xB152` or `0x1B25`).** The account's password is stored only in
older formats. Ask your DBA which versions it has:

```sql
SELECT username, password_versions FROM dba_users WHERE username = 'SCOTT';
```

`12C` has to be among them. An account showing only `10G 11G` needs its
password version upgraded by the DBA, through whatever tool your application
requires for password changes.

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
- **[docs/RELEASE_NOTES_0.6.1.md](docs/RELEASE_NOTES_0.6.1.md)** — what changed since 0.6.0 (faster `INSERT`).
- **[docs/RELEASE_NOTES_0.6.0.md](docs/RELEASE_NOTES_0.6.0.md)** — what changed since 0.5.1.
- **[docs/RELEASING.md](docs/RELEASING.md)** — where the version lives and what
  a Community Extensions submission needs.
- **[PROVENANCE.md](PROVENANCE.md)** — what this project reuses and from where,
  plus every byte of recorded wire traffic in the tree with its SHA-256.

This is an independent community project and is not affiliated with Oracle or
DuckDB Labs.

---
