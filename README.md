# oracle_scanner

`oracle_scanner` is an experimental DuckDB extension for connecting directly
to Oracle Database over TNS/TTC. Its defining constraint is that it does not
load Oracle Instant Client, OCI, ODPI-C, ODBC, JDBC, or a helper process.

The repository is in active protocol development. It currently includes
native TCP TNS/TTC authentication, streaming `oracle_query`, isolated
`oracle_execute` and atomic `oracle_execute_many`, scalar and typed named procedure/function calls, explicit
and implicit `SYS_REFCURSOR` handles, exact `NUMBER` and date/time codecs,
and standalone protocol tests. TCP is live-verified against Oracle 19c and
Free 23ai. TCPS is live-verified against OCI Autonomous Database with mutual
TLS; it uses mandatory certificate/hostname verification and accepts an
`ewallet.pem`-compatible PEM bundle.
DuckDB `ATTACH` maps `main` to the authenticated Oracle schema and resolves
tables or views lazily.

## Build and test

Clone with submodules, then build the debug extension and run its tests:

```sh
make debug
make test_debug
ctest --test-dir build/debug/extension/oracle_scanner --output-on-failure
```

`ctest` runs both C++ suites: `oracle_scanner_protocol_test` for the protocol
and codec layers, and `oracle_scanner_adapter_test`, which drives the DuckDB
adapter against a fake Oracle session and therefore needs no database, network,
or credentials. Either binary can also be run directly from
`build/debug/extension/oracle_scanner/`.

For a fast protocol-only check that does not build DuckDB:

```sh
scripts/build_protocol_test.sh
```

The script derives its source list from the `oracle_scanner_protocol_test`
target in `CMakeLists.txt`, so that target stays the single place a new
protocol source is registered. It builds this project's sources with
`-Wall -Wextra -Werror`, compiles the vendored `duckdb_miniz` separately with
warnings off, then runs the resulting binary. Pass an output path to keep the
binary, and override `CXX` or `OPENSSL_FLAGS` when pkg-config is not the right
resolver.

OpenSSL is resolved through vcpkg in Community builds and may be resolved from
the system for local builds.

## SQL surface

Create a secret once per DuckDB connection, then bind named values with a
`STRUCT` (or positional values with a `LIST`). `oracle_execute_many` commits
its complete batch atomically and returns the sum of Oracle `SQL%ROWCOUNT`:

```sql
CREATE SECRET ora (TYPE oracle, HOST '127.0.0.1', PORT 1527,
                   SERVICE_NAME 'ORCLPDB1', USER 'system', PASSWORD '...');

SELECT * FROM oracle_execute_many(
  'ora', 'INSERT INTO app.items (id, label) VALUES (:id, :label)',
  [{id: 1, label: 'one'}, {id: 2, label: 'two'}]
);
```

For positional placeholders, pass a list per row:

```sql
SELECT * FROM oracle_execute_many('ora', 'INSERT INTO app.item_ranks VALUES (:1, :2)',
                                  [[3, 30], [4, 40]]);
```

DuckDB `LIST` values have one element type, so use named `STRUCT` rows for a
batch whose columns need different DuckDB types.

Use `:1`, `:2`, … placeholders with a `LIST`, and named placeholders such as
`:id` with a `STRUCT`; the two styles cannot be mixed. For a NULL bind, cast
the DuckDB value to the intended type, for example `CAST(NULL AS VARCHAR)`.

Oracle does not distinguish an empty character value from NULL, and this
extension follows that rather than hiding it: binding `''` stores NULL, and a
zero-length Oracle value is returned as NULL. An empty string does not round
trip.

Attach an Oracle secret as a read-only catalog. `main` maps to the
authenticated Oracle schema, and table/view entries are resolved lazily on
first use:

```sql
ATTACH 'ora' AS ora (TYPE oracle_scanner);
SELECT * FROM ora.main.orders;
```

The catalog enumerates at most 65,536 `USER_TABLES`/`USER_VIEWS` entries and
reads column metadata for the whole schema in one `USER_TAB_COLUMNS` query. The
bound is that high because enumeration no longer costs a dictionary round trip
per object. Attached tables also carry their `NOT NULL` columns and their
primary key, so `DESCRIBE` and `duckdb_constraints()` show them; only keys
Oracle actually enforces (`ENABLED` and `VALIDATED`) are reported, since a
disabled one can have rows that violate it. A
scan selects only the columns the query reads, so the projection is pushed into
Oracle rather than applied after fetching every column. The current release gate
is a live `SHOW TABLES` and scan on both supported Oracle versions.

`INSERT` into an attached table is supported. The write runs on one Oracle
session pinned to the DuckDB transaction, so `COMMIT` and `ROLLBACK` mean what
they say, and a scan of the same attached catalog inside that transaction reads
through the same session — so it sees the transaction's own uncommitted rows,
which Oracle shows to no other session. Each
value is encoded from the Oracle column's own type rather than handed over as
text, so nothing depends on `NLS_NUMERIC_CHARACTERS` or `NLS_DATE_FORMAT`, and a
`TIMESTAMP(9)` keeps its nanoseconds. Columns the statement does not name are
left out of it, so an Oracle `DEFAULT` still applies.

`UPDATE` and `DELETE` address rows by Oracle's own ROWID, which the table
exposes as the `rowid` virtual column and the scan selects through
`ROWIDTOCHAR`. `SET col = DEFAULT` is passed to Oracle as `DEFAULT`, so the
column's own default applies rather than NULL. `INSERT ... RETURNING` is supported and asks Oracle for the row it stored, so a
column left to its `DEFAULT`, an identity value or a trigger's work comes back
rather than the NULL that was sent. It runs one statement per row, because
Oracle's array form of RETURNING has no capture-backed evidence here; an insert
without the clause still goes as array DML. `UPDATE` and `DELETE` do not support
`RETURNING`.

When a batch fails, the error names the row: Oracle reports the iteration it was
on, and the count is from the start of the batch rather than from the start of
the request that happened to contain it.

A batch of rows — from `INSERT ... SELECT`, or from an `UPDATE` or `DELETE`
that matches many rows — is sent as Oracle array DML: one parse, one block of
bind metadata, and one row of values per iteration, so a round trip covers up to
1,024 rows rather than one. `RETURNING` and per-row batch error reporting are
not supported.
Every form of DDL is refused, including `CREATE TABLE` and `DROP TABLE`.

Filter pushdown is off by default and enabled with
`SET oracle_filter_pushdown = true`. Once DuckDB hands a filter to a scan it
removes it from the plan, so the scan must apply it exactly; only filters whose
Oracle meaning is provably identical are translated, and anything else raises
rather than being approximated. Translated today: `IS NULL`, `IS NOT NULL`, any
comparison on a `NUMBER` column, equality on a `VARCHAR2` column against a
non-empty constant, `IN` lists of such values up to Oracle's own limit of 1,000,
and conjunctions of those. Refused, with the reason named: comparisons against
`''` (Oracle treats it as NULL, so the predicate is not the same one), any
comparison on `CHAR` (Oracle compares it blank-padded), and ordered comparisons
on character columns (their ordering follows `NLS_SORT` and `NLS_COMP`, which
this client does not negotiate). An `IN` list containing one unprovable value is
refused as a whole rather than partly applied.

An optional filter — DuckDB's marker for one it does not need for correctness —
is dropped instead of raising when it cannot be translated; the same filter
arriving as a required one still raises. That is what makes an `IN` list fall
back to DuckDB rather than failing the query, since `IN` arrives wrapped in one.

Date and timestamp filters push down as `TO_DATE('…', 'YYYY-MM-DD HH24:MI:SS')`
and `TO_TIMESTAMP('…', 'YYYY-MM-DD HH24:MI:SS.FF9')`. The format is written into
the statement, so `NLS_DATE_FORMAT` cannot change what the literal means.
Ordered comparisons are allowed on them, since chronological order depends on
nothing a session sets. A text constant against a date column is refused, and so
is a sub-second constant against a `DATE` column, which stores whole seconds.

`oracle_scan_parallel(secret, table, key_column [, shards := N])` reads one
table through several sessions at once, splitting it into ranges of a numeric
key. It exists because a single scan is one session and one thread: the pipeline
streams either way, but at one session's throughput.

Every shard reads `AS OF SCN` at one system change number taken before any of
them start, so the shards are one snapshot rather than several moments — without
that, a row inserted mid-scan could land in one shard's view and not another's,
and a row whose key moved could be read twice or not at all. If the database
will not give out a change number the scan is refused rather than run unpinned.
That needs `EXECUTE` on `SYS.DBMS_FLASHBACK` and `FLASHBACK` on the table, and a
table created or altered moments ago cannot be read as of an earlier moment at
all (Oracle's ORA-01466).

The key must be `NUMBER` with integral values, because a boundary computed by
rounding can fall between two keys. Rows whose key is NULL are in no range and
get a shard of their own, so none is lost. `shards` defaults to the DuckDB
thread count.

Reads reuse an authenticated Oracle session. The pool is per DuckDB connection
and per secret, sized by `SET oracle_session_pool_size` (default 4; 0 opens a
fresh session for every statement). Opening one costs a TCP connect, a TLS
handshake and an authentication round trip — against a cloud endpoint that was
1.57 s per statement, and 0.18 s reusing one. Writes and procedure calls open
their own session, and a statement that fails never returns its session to the
pool.

Readable column types are `VARCHAR2`, `CHAR`, `NUMBER`, `DATE`, `TIMESTAMP`,
`TIMESTAMP WITH TIME ZONE`, `RAW`, `BINARY_FLOAT`, and `BINARY_DOUBLE`. An
Oracle `DATE` reads back as a DuckDB `TIMESTAMP`, not a `DATE`, because it
carries a time to the second; a `TIMESTAMP(0..6)` reads back as `TIMESTAMP` and
a `TIMESTAMP(7..9)` as `TIMESTAMP_NS`, chosen from the column's declared scale.
`TIMESTAMP WITH TIME ZONE` stays textual: it carries an offset that DuckDB's
`TIMESTAMPTZ`, an instant in UTC, does not keep. Anything
else is refused while the query is bound, with a message naming the column and
the reason, rather than being decoded into something wrong. In particular
`NCHAR` and `NVARCHAR2` are UTF-16 on the wire and are not decoded;
`INTERVAL` has no decoder; and
`TIMESTAMP WITH LOCAL TIME ZONE` is refused because its value is relative to a
session time zone this client does not negotiate, while `TIMESTAMP WITH TIME
ZONE` is readable because the value carries its own offset.

`CLOB` and `NCLOB` read as `VARCHAR`, `BLOB` as `BLOB`. A LOB column carries only
a locator in the row, so each value costs its own round trips — a length call and
then reads of at most 32 767 characters or 65 536 bytes — which makes a LOB scan
much more expensive per row than any other column. Oracle serves character LOB
content as AL16UTF16 whatever the database character set is, and it is converted
to UTF-8 here; that is why `NCLOB` is readable while `NCHAR` and `NVARCHAR2`,
which arrive UTF-16 in the row itself, are not. `BFILE` stays refused, and no LOB
can be written: an `INSERT` or `UPDATE` into a LOB column is refused rather than
truncated.

For TCPS, declare the transport explicitly. Certificate and hostname
verification are always enabled; `WALLET_FILE` accepts either an
ewallet.pem-compatible PEM bundle or a bounded OCI wallet ZIP containing one
root-level `ewallet.pem`. Both formats are read with bounded in-memory paths
and do not create temporary wallet files:

```sql
CREATE SECRET ora_tls (
  TYPE oracle, HOST 'db.example.com', PORT 2484, SERVICE_NAME 'service',
  USER 'app_user', PASSWORD '...', PROTOCOL 'tcps',
  TLS_SERVER_NAME 'db.example.com', WALLET_FILE '/secure/ewallet.pem',
  WALLET_PASSWORD '...'
);
```

`TLS_SNI_NAME` is optional. Use it only when the network endpoint is an IP
literal or a different virtual-host name; `TLS_SERVER_NAME` remains the name
validated against the server certificate.

`TLS_CA_FILE` is optional and supplies an explicit PEM trust allow-list for
wallet-free TLS. When it is set, system trust roots are not added.

`TLS_SERVER_CERT_DN` requires the server certificate's subject to be exactly
that distinguished name. A TNS descriptor's `(security=(ssl_server_cert_dn=…))`
supplies the same value, and when both name one they must agree. The DN is
checked in addition to the hostname, never instead of it, and the components may
be written in either order — Oracle and OpenSSL render a DN in opposite orders,
so the comparison is between identities rather than strings. A descriptor's
`ssl_server_dn_match=no` is recorded and does nothing: there is no insecure mode
to fall back to.

TLS fields with TCP (including an omitted `PROTOCOL`) are rejected rather than
ignored. Alternatively, `TNS_ALIAS` resolves one `DESCRIPTION` from the
root-level `tnsnames.ora` in the same wallet ZIP. The requested alias must be
defined exactly once, and it cannot be combined with manual `HOST`, `PORT`, or
`SERVICE_NAME` fields. When the alias resolves to TCPS, `PROTOCOL` may be
omitted and is inferred from that descriptor; an explicit protocol must match:

```sql
CREATE SECRET ora_wallet_alias (
  TYPE oracle, TNS_ALIAS 'mydb_low', USER 'app_user', PASSWORD '...',
  PROTOCOL 'tcps', TLS_SERVER_NAME 'db.example.com',
  WALLET_FILE '/secure/Wallet_mydb.zip', WALLET_PASSWORD '...'
);
```

To run the protected TCPS protocol lane, keep the wallet outside the
repository and set `ORACLE_SCANNER_LIVE=1`, the existing `ORA19C_HOST`,
`ORA19C_PORT`, `ORA19C_SERVICE`, `ORA19C_USER`, and `ORA19C_PASSWORD` values,
plus `ORACLE_SCANNER_LIVE_PROTOCOL=tcps`,
`ORACLE_SCANNER_LIVE_TLS_SERVER_NAME`,
`ORACLE_SCANNER_LIVE_WALLET_FILE`, and
`ORACLE_SCANNER_LIVE_WALLET_PASSWORD`. The test accepts an `ewallet.pem` file
or a wallet ZIP, reads ZIP contents only in memory, and never persists those
values. Set optional `ORACLE_SCANNER_LIVE_TLS_SNI_NAME` when the endpoint and
SNI name differ. Set `ORACLE_SCANNER_LIVE_STAGE=tcps_negative`
and provide an unrelated PEM certificate through
[docs/CAPABILITIES.md](docs/CAPABILITIES.md) is the precise support boundary:
which Oracle types read and write, what `ATTACH` can and cannot do, why SQL
terminators and anonymous PL/SQL blocks are refused and how to issue DDL anyway,
and the full list of what is not supported.

[docs/RELEASING.md](docs/RELEASING.md) covers where the version lives, why a
locally built artifact must not be published, and what a Community Extensions
submission needs from this repository.

[PROVENANCE.md](PROVENANCE.md) is the reuse and capture ledger: what this
project takes from where, and every byte of recorded wire traffic in the tree
with its SHA-256. `scripts/capture_inventory.sh` recomputes those hashes and CI
compares them, so a fixture cannot drift unnoticed.

`scripts/run_live_stages.sh` runs every live wire stage against one endpoint and
is what the manual CI lane calls; `scripts/check_no_oracle_client.sh` proves a
built extension links and imports nothing from an Oracle client, and fails
rather than reporting success if it cannot inspect the binary.

`ORACLE_SCANNER_LIVE_UNTRUSTED_CA_FILE` to verify rejection of a wrong server
name, wallet password, and CA.

For procedures and functions use `oracle_call_named` and
`oracle_call_named_function` with
`LIST<STRUCT(name, direction, type, value)>`. Scalar types are `number`,
`varchar`, `date`, `timestamp`, `raw` (uppercase hex), `float`, and `double`;
`cursor` is an `OUT` type, and it is also a valid return type for
`oracle_call_named_function` — a function returning `SYS_REFCURSOR` comes back
as a handle rather than a value. Cursor handles are connection-local and are consumed
once with `oracle_cursor('oracle:…')`.

`oracle_arguments(secret, callable)` answers what those arguments should be,
reading `ALL_ARGUMENTS`: one row per argument with its overload, position, name,
direction, Oracle type, the `oracle_call_named` spelling of that type, and — for
an argument this version cannot bind — the reason. Position 0 is a function's
return value, and `overload` is NULL unless the callable has more than one. A
name reached through a synonym is resolved (`DBMS_UTILITY` resolves to
`SYS.DBMS_UTILITY`); a name matching more than one object is refused, since only
the caller can say which they meant.

LOB, `NCHAR`/`NVARCHAR2`, object, record and collection types, `PL/SQL
BOOLEAN`, `INTERVAL`, and `TIMESTAMP WITH [LOCAL] TIME ZONE` arguments are
refused with the reason named, matching the column support policy above. A LOB
is readable as a column but not passable as an argument or a bind.

`oracle_call_auto(secret, callable, values)` calls a procedure or function from
that resolved signature, so only the values are supplied — a `LIST` of VARCHAR,
one per argument in declaration order, with NULL in an OUT argument's slot. An
overloaded callable is chosen by how many values are supplied; when none of the
overloads takes that many the error names the ones that do, and when two share
an arity it is refused, since nothing in a list of values says which was meant. It
returns the same `(name, value, cursor_handle)` rows as `oracle_call_named`,
with a function's return value first under the name `return_value`. Values are
encoded exactly as `oracle_call_named` encodes them; it is the same code.

## Security and provenance

Never commit database credentials, wallets, production descriptors, or raw
captures. Protocol evidence carried over from elsewhere keeps its provenance in
[PROVENANCE.md](PROVENANCE.md), which also inventories every captured byte in
this repository by SHA-256; sensitive capture material is not redistributed.

This is an independent community project and is not affiliated with Oracle or
DuckDB Labs.
