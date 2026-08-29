# What works, and what does not

The support surface of `oracle_scanner`, stated precisely enough to plan against.
[README.md](../README.md) is the introduction; this is the boundary.

Every "works" below was run against a live Oracle — 19.3 EE, OCI Autonomous, and
Free 23ai — and every "refused" is a refusal this extension raises by name, not
a guess about what Oracle would do. Where the three servers differ, it says so.

The governing rule behind most of the refusals: **anything this client cannot
prove it will do identically to Oracle, it refuses instead of approximating.**
A wrong number is worse than an error, so the boundary is drawn at proof.

---

## 1. Connecting

### Where it runs

Native builds: **Linux, macOS, Windows**. Those are what the live lanes and the
clean-machine gate exercise.

**A WebAssembly build cannot connect to Oracle.** Not "is untested" — it is
refused, by name, at connect:

> the default Oracle transport needs a TCP socket, which a WebAssembly build
> does not have

The reason is the transport and nothing above it. TNS runs over a raw TCP
stream, and no browser WebAssembly runtime has one: a page gets `fetch`,
WebSocket, and WebRTC, none of which is a socket. So the refusal is a property
of where the code runs, not a gap in the protocol implementation.

Everything above the byte transport is already transport-agnostic —
`TnsClientConnection` holds a `ByteStream`, and the connect path opens one
through `OpenOracleTransport`, so a different transport is installed rather than
threaded through. That seam exists and is tested. It is deliberately **not** a
WebAssembly port, and should not be read as most of one, because two things sit
outside it:

- **Every TTC exchange is a synchronous request and response.** `Receive()`
  blocks until a whole TNS packet arrives. Browser WebSocket APIs are
  callback-driven, and the main thread cannot block at all. Bridging that needs
  Asyncify (large binary cost, and it has to cover DuckDB's own call stack),
  JSPI, or a worker with `Atomics.wait` — the last requiring cross-origin
  isolation on the *hosting page*, which an extension cannot guarantee.
- **A WebSocket-to-TCP bridge is a helper process,** which this project excludes
  by definition. It also decides where Oracle TLS terminates: inside the tunnel
  (needs OpenSSL compiled to wasm) or at the bridge — and at the bridge, the
  bridge sees the password and every row in cleartext. That is a different trust
  model from the one stated in section 10, not an implementation detail.

Both are decisions to take deliberately. Neither is blocked on the code.

This has now been measured rather than assumed. Our own sources **do** compile
for `wasm32-emscripten`, and so does OpenSSL through vcpkg. What fails is the
link of the threaded target:

> `wasm-ld: error: --shared-memory is disallowed by libssl-lib-ssl_lib.o because
> it was not compiled with 'atomics' or 'bulk-memory' features`

That is a mismatch in how the dependency was built, not a limit of this code.
The wasm targets are excluded from the distribution matrix regardless, because a
build that links would still refuse at connect for the reason above, and an
artifact that always refuses is worse than no artifact.

### Secrets

A connection is a DuckDB secret. There is no connection string and no `TNS_ADMIN`
lookup on disk.

```sql
CREATE SECRET ora (
    TYPE oracle,
    HOST '...', PORT 1521, SERVICE_NAME '...',
    USER '...', PASSWORD '...'
);
```

| Field | Meaning |
| --- | --- |
| `HOST`, `PORT`, `SERVICE_NAME` | The endpoint, given directly |
| `TNS_ALIAS` | An alias resolved from `tnsnames.ora` **inside the wallet ZIP** |
| `USER`, `PASSWORD` | Credentials |
| `PROTOCOL` | `tcp` (default) or `tcps` |
| `WALLET_FILE`, `WALLET_PASSWORD` | A cloud wallet ZIP, read in memory only |
| `TLS_CA_FILE`, `TLS_SERVER_NAME`, `TLS_SNI_NAME`, `TLS_SERVER_CERT_DN` | TLS material and the identity to check |
| `CONNECT_TIMEOUT`, `READ_TIMEOUT` | Socket timeouts |

**Works**

- Plain TCP, and TCPS with a cloud wallet (`TNS_ALIAS` + `WALLET_FILE`) or with
  an explicit `TLS_CA_FILE`.
- Server DN matching (`TLS_SERVER_CERT_DN`), compared attribute by attribute so
  the RDN order OpenSSL prints and the order `tnsnames.ora` uses both match.
- The wallet ZIP is parsed in memory. Nothing is ever extracted to disk.

**Refused, by design**

- `TNS_ALIAS` together with `HOST`/`PORT`/`SERVICE_NAME` — one or the other.
- `TNS_ALIAS` without `WALLET_FILE`; an alias resolving to more than one
  `ADDRESS`; an alias whose protocol disagrees with `PROTOCOL`.
- Any `TLS_*` or `WALLET_*` field with `PROTOCOL 'tcp'`.
- Any `PROTOCOL` other than `tcp` or `tcps`.

**No bypass exists** for certificate or hostname verification. There is no
setting to turn it off, deliberately.

**Not supported:** the 11g SHA-1 verifier, Native Network Encryption (ANO),
`ewallet.p12`/`cwallet.sso` outside a cloud wallet ZIP, SEPS, IAM tokens, RAC
failover, Application Continuity, and proxy authentication.

---

## 2. The statement gate — read this before anything else

This is the limit people hit first, so it comes before the feature list.

Every SQL string handed to this extension goes through one gate:

| Function | Accepts | First keyword must be |
| --- | --- | --- |
| `oracle_query` | queries only | `SELECT`, `WITH` |
| `oracle_execute`, `oracle_execute_many` | DML only | `INSERT`, `UPDATE`, `DELETE` |

And, in **all** cases:

> **A statement terminator `;` anywhere outside a string, a comment, or a
> `q'[...]'` literal is refused.**

The consequences are concrete and worth stating plainly:

- **Anonymous PL/SQL blocks cannot be run at all.** `BEGIN … END;` fails twice
  over: `BEGIN` is not an accepted first keyword for either function, and the
  `;` that PL/SQL itself requires is refused. There is no third function that
  takes a block.
- **DDL cannot be issued.** `CREATE`, `DROP`, `ALTER`, `TRUNCATE`, and
  `CREATE OR REPLACE PROCEDURE` are all refused — the last one also because a
  procedure body is full of semicolons.
- **`COMMIT` and `ROLLBACK` cannot be sent as SQL.** Transaction control is
  DuckDB's; see §6.

**The workaround for DDL**, and the only one:

```sql
SELECT * FROM oracle_call_auto('ora', 'DBMS_UTILITY.EXEC_DDL_STATEMENT',
    ['CREATE TABLE t (id NUMBER(10), label VARCHAR2(50))']);
```

`DBMS_UTILITY.EXEC_DDL_STATEMENT` is an ordinary Oracle procedure taking one
`VARCHAR2`, so it goes through the callable path (§7) and never touches the SQL
gate. The DDL text it carries is not parsed here at all. The same trick runs
anything expressible as a single procedure call; it does **not** give you
anonymous blocks, because the argument is a statement, not a block.

This is a real limitation, not a policy statement dressed up as one. It exists
because the gate is a whitelist of shapes whose bind, describe, and fetch
behavior this client has capture-backed evidence for.

---

## 3. Reading

```sql
SELECT * FROM oracle_query('ora', 'SELECT id, label FROM app.items');
```

### Bind parameters

An optional third argument carries binds. It is a **`LIST`** for positional
placeholders or a **`STRUCT`** for named ones — never loose trailing arguments.

```sql
-- named placeholders, :name
SELECT * FROM oracle_query('ora', 'SELECT * FROM t WHERE name = :name', {'name': 'nick'});

-- positional placeholders, :1 :2 — all of one type
SELECT * FROM oracle_query('ora', 'SELECT :1 AS a, :2 AS b FROM dual', ['hi', 'there']);

-- positional placeholders of mixed types: use a STRUCT keyed '1', '2', …
SELECT * FROM oracle_execute('ora', 'INSERT INTO t VALUES (:1, :2, :3)',
    {'1': 1, '2': 'one', '3': DATE '2026-01-02'});
```

The mixed-type case is the one that surprises: a DuckDB `LIST` literal is
homogeneous, so `[1, 'one', DATE '2026-01-02']` cannot even be constructed. A
`STRUCT` whose keys are `'1'`, `'2'`, … binds positionally and takes any mix.

### Column types

| Oracle type | Reads as | Notes |
| --- | --- | --- |
| `NUMBER(p,0)`, p ≤ 18 | `BIGINT` | |
| `NUMBER(p,s)`, p ≤ 38, 1 ≤ s ≤ p | `DECIMAL(p,s)` | |
| `NUMBER` otherwise | `VARCHAR` | Unconstrained NUMBER is exact only as text |
| `VARCHAR2`, `CHAR` | `VARCHAR` | Database character set, UTF-8 here |
| `DATE` | `TIMESTAMP` | An Oracle `DATE` carries a time; it is not a DuckDB `DATE` |
| `TIMESTAMP(n)` | `TIMESTAMP`, or `TIMESTAMP_NS` when n > 6 | |
| `TIMESTAMP WITH TIME ZONE` | `VARCHAR` | The value carries its own offset, which `TIMESTAMPTZ` would drop |
| `RAW` | `BLOB` | |
| `BINARY_FLOAT`, `BINARY_DOUBLE` | `FLOAT`, `DOUBLE` | |
| `CLOB`, `NCLOB` | `VARCHAR` | See §4 |
| `BLOB` | `BLOB` | See §4 |

The third row is the one people meet in practice. A column declared plain
`NUMBER` reads as `VARCHAR`, and on schemas generated by ETL or integration
tooling — where nearly every column is declared that way — a whole table comes
back without a numeric column. This is not a gap to be filled later: Oracle's
`NUMBER` is a base-100 decimal of up to 38 significant digits, `DOUBLE` cannot
hold one exactly (200,000 summed invoice amounts drift by about two cents), and
a fixed `DECIMAL(38,s)` has to choose an `s` and round anything longer. Text is
the only lossless form, so the value is handed over intact and the caller casts:
`CAST(col AS DECIMAL(38,6))` for money and anything reconciled, `CAST(col AS
BIGINT)` for keys, `CAST(col AS DOUBLE)` where a ratio is enough. Declaring the
column as `NUMBER(p[,s])` in Oracle removes the need entirely, and does so for
every client, not just this one.

There is no setting that changes this mapping. One was considered and refused:
a mode that silently narrowed unconstrained `NUMBER` would make correctness
depend on a flag, and a reconciliation that is exact in one session and two
cents off in another is worse than one that always asks for a cast.

**Refused while binding**, before any fetch, each naming its reason:

| Type | Why |
| --- | --- |
| `NCHAR`, `NVARCHAR2` | UTF-16 in the row itself, and not decoded |
| `TIMESTAMP WITH LOCAL TIME ZONE` | Relative to a session time zone this client never negotiates |
| `INTERVAL YEAR TO MONTH`, `DAY TO SECOND` | No decoder |
| `BFILE` | No read path |
| Object, `VARRAY`, nested table, `XMLTYPE`, `REF` | Outside this version |

A refusal happens at bind time, so a query either runs correctly or fails
immediately — it never returns a column decoded into something wrong.

An **attached** table (§5) still *lists* a column of an unsupported type — it
appears in `duckdb_columns()` with a nominal type — so the table is browsable.
Selecting that column raises, and so does `SELECT *` over the table. Name the
columns you can read and the rest of the table stays usable.

### Empty string

Oracle has no empty `VARCHAR2`: `''` is NULL. It does not round-trip — what goes
in as `''` comes back as NULL. That is Oracle's behavior, faithfully reproduced.

---

## 4. LOBs

`CLOB`, `NCLOB`, and `BLOB` are **read**. `BFILE` is not, and no LOB can be
**written**.

A LOB column carries only a locator in the row, so every value costs its own
round trips: one length call, then a read per 32 767 characters or 65 536 bytes.
Measured on a local 19c, 2 000 rows each holding a 2 000-character CLOB — 4 MB —
took **1.22 s**, against **0.004 s** for the same 2 000 rows with the LOB column
left out of the selection. That is round-trip bound, not bandwidth bound.

**Select a LOB column only when you need it.** No other column type has a cost
profile remotely like this.

Verified live on all three servers: ASCII and non-Latin content, NULL against
empty (they stay distinct, as in Oracle), a 240 000-character CLOB and a
240 007-byte BLOB compared byte for byte against values rebuilt in DuckDB, and a
40 000-character NCLOB.

Character LOB content arrives as AL16UTF16 whatever the database character set
is, and is converted to UTF-8 here. That is why `NCLOB` reads while `NCHAR` and
`NVARCHAR2` do not: their values travel in the row, not through a LOB read.

---

## 5. `ATTACH` — Oracle as a DuckDB catalog

```sql
ATTACH 'ora' AS o (TYPE oracle_scanner);
SELECT * FROM o.ITEMS WHERE id > 100;
```

The path is the **secret name**, not a connection string. One attachment exposes
one schema: the connected user's own tables and views, resolved lazily from
`USER_TABLES`, `USER_VIEWS`, and `USER_TAB_COLUMNS`.

| Operation | Status |
| --- | --- |
| `SELECT` | Works |
| `INSERT`, `UPDATE`, `DELETE` | Works — see §6 |
| `INSERT … RETURNING` | Works |
| `UPDATE … RETURNING`, `DELETE … RETURNING` | **Refused** |
| `CREATE TABLE`, `CREATE TABLE AS` | Refused — this extension issues no DDL |
| `DROP TABLE` | Refused |
| `CREATE SCHEMA`, `DROP SCHEMA` | Refused — one schema, and it is Oracle's |
| Another user's schema | Not exposed; use `oracle_query` with a qualified name |

Identifiers arrive as Oracle stores them, which is upper case unless they were
created quoted: `o.ITEMS`, not `o.items`.

### Filter pushdown

Off by default. `SET oracle_filter_pushdown = true` sends `WHERE` predicates to
Oracle.

It is opt-in because DuckDB removes a filter from the plan once it hands it to
a scan, so the scan must then apply it *exactly*. This translator refuses
anything whose Oracle meaning it cannot prove identical — and with pushdown on,
a refusal is an error rather than a slower plan. Translated: `=`, `<>`, `<`,
`<=`, `>`, `>=`, `IS NULL`, `IS NOT NULL`, `IN` (up to 1 000 values), and
`AND`/`OR` over those, on integer, decimal, date, and timestamp columns.
Anything else — and any `IN` list with one unprovable member — raises.

---

## 6. Writing and transactions

Two separate paths, with different rules.

### Through `ATTACH`

`INSERT`, `UPDATE`, and `DELETE` on an attached table participate in the DuckDB
transaction. One Oracle session is pinned to that transaction, so:

- A scan of the attached catalog inside the transaction **sees its own
  uncommitted rows**.
- `COMMIT` and `ROLLBACK` in DuckDB commit and roll back in Oracle. Verified:
  a row inserted inside a transaction is visible to a count in that same
  transaction and gone after `ROLLBACK`.

`UPDATE` and `DELETE` address rows by Oracle's `ROWID`, read as text — so the
target table needs no primary key, but the rows must still exist when the write
runs.

Values are encoded from the **Oracle** column type, never from the DuckDB type
alone, so nothing reaches Oracle as text for a session `NLS` setting to
reinterpret.

Writable column types: `VARCHAR2`, `CHAR`, `NUMBER`, `DATE`, `TIMESTAMP`,
`TIMESTAMP WITH TIME ZONE`, `RAW`, `BINARY_FLOAT`, `BINARY_DOUBLE`. Everything
else — LOBs included — is refused by name. `FLOAT`/`DOUBLE` into a `NUMBER`
column is refused too: cast to `DECIMAL` or text first, because binary floats
are not exact.

### Through `oracle_execute`

```sql
SELECT * FROM oracle_execute('ora', 'UPDATE t SET label = :1 WHERE id = :2', ['x', 7]);
SELECT * FROM oracle_execute_many('ora', 'INSERT INTO t VALUES (:1, :2)',
    [{'1': 1, '2': 'a'}, {'1': 2, '2': 'b'}]);
```

Both return `affected_rows`. **Both refuse to run inside an explicit DuckDB
transaction** — they autocommit in Oracle, which a DuckDB `ROLLBACK` could not
undo, so the mismatch is refused rather than hidden.

`oracle_execute_many` uses Oracle array DML: one execute carrying every
iteration, not one round trip per row. A row that fails reports its position.

---

## 7. Calling procedures and functions

`oracle_call_auto` reads the signature from `ALL_ARGUMENTS` and binds
accordingly; the rest of the family is for callers who want to state the shape
themselves.

```sql
SELECT * FROM oracle_call_auto('ora', 'PKG.PROC', ['arg1', 'arg2']);
SELECT * FROM oracle_arguments('ora', 'PKG.PROC');   -- inspect the signature
```

**Works:** `IN`, `OUT`, and `IN OUT` arguments of `NUMBER`, `VARCHAR2`, `CHAR`,
`DATE`, and `TIMESTAMP`; functions with a return value; `SYS_REFCURSOR` returns,
read through `oracle_cursor` and released with `oracle_close_call`; names
reached through a synonym; packaged and standalone callables.

**Refused:** arguments of LOB, `NCHAR`/`NVARCHAR2`, object, record, collection,
`REF`, `XMLTYPE`, `PL/SQL BOOLEAN`, `INTERVAL`, or `TIMESTAMP WITH [LOCAL] TIME
ZONE` type; a name that matches more than one object; and an overload set with
two candidates of the same arity — only the caller can say which was meant.

A LOB is therefore **readable as a column but not passable as an argument.**

A procedure that commits internally is outside DuckDB's rollback guarantee, and
runs in its own call scope for that reason.

---

## 8. Parallel scan

```sql
SELECT * FROM oracle_scan_parallel('ora', 'BIG_TABLE', 'ID', shards := 8);
```

Splits one table across several sessions by ranges of a numeric key. Every shard
reads `AS OF SCN` at one change number taken at bind time, so the shards are one
snapshot rather than several moments. A database that will not hand out a change
number is refused rather than scanned unpinned; if the snapshot predates a DDL
change to the table, Oracle's ORA-01466 is reported as such.

Requires a `NUMBER` key column with integral bounds. Rows whose key is NULL get
their own shard, so nothing is dropped.

---

## 9. Settings

| Setting | Default | Effect |
| --- | --- | --- |
| `oracle_session_pool_size` | `4` | Sessions pooled per DuckDB connection per secret identity, for reads. `0` disables pooling. |
| `oracle_filter_pushdown` | `false` | See §5. |

Pooling matters more than it looks: opening a session costs a full TNS handshake
and authentication. Writes and callables always open their own session.

---

## 10. Never, by construction

- **No Oracle client.** No OCI, Instant Client, ODPI-C, ODBC, JDBC, Python
  runtime, or helper process is linked or loaded. CI proves this on every build
  by inspecting the shipped binary.
- **No credential ever logged or persisted** — not passwords, verifier material,
  wallet passwords, keys, or bind values.
- **No wallet written to disk.** ZIPs are read bounded, in memory.
- **No TLS verification bypass.**

## 11. Not supported, in one list

Anonymous PL/SQL blocks · DDL except through `DBMS_UTILITY.EXEC_DDL_STATEMENT` ·
LOB writing · `BFILE` · `NCHAR`/`NVARCHAR2` · `INTERVAL` ·
`TIMESTAMP WITH LOCAL TIME ZONE` · object, collection, record and `XMLTYPE`
types · `UPDATE`/`DELETE … RETURNING` · schemas other than the connected user's ·
`CREATE`/`DROP` through `ATTACH` · Native Network Encryption · the 11g SHA-1
verifier · SEPS · IAM · RAC failover · Application Continuity · AQ ·
distributed two-phase commit · WebAssembly builds (no TCP socket; see section 1)
· statement cancellation over TCPS (no capture-backed evidence for its shape;
unimplemented rather than guessed).
