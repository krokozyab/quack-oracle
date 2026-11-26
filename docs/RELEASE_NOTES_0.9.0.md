# oracle_scanner 0.9.0

Built for DuckDB v2.0.1. Install with `INSTALL oracle_scanner FROM community;`
once the release is published; DuckDB v2.0.0 keeps
[0.8.3](RELEASE_NOTES_0.8.3.md). This release fixes the findings of a full audit
of the extension, reads faster in one session, and changes how a few values
cross between DuckDB and Oracle: read **Behaviour changes** before upgrading.

## Behaviour changes

- **Dates before 1582-10-15 and BC dates now keep their day.** Oracle keeps those
  dates in the Julian calendar, DuckDB in the proleptic Gregorian one. Such a date
  used to read about ten days off, a Julian leap day (1500-02-29) failed the whole
  scan, and BC dates were a year off. Values now cross at the day Oracle's
  `TO_CHAR(d, 'J')` numbers, in reads, writes, binds and pushed filters, so date
  arithmetic agrees on both sides. DuckDB labels a BC date one year earlier than
  Oracle prints it (Oracle has no year 0); the README explains.
- **An attached `INTEGER` / `NUMBER(*,0)` column reads as `DECIMAL(38,0)`.** Every
  scan of such a column used to fail as a changed wire type.
- **`oracle_call_*` commits a successful call**, as `oracle_execute` and
  `oracle_plsql` already did. The procedure's work used to be discarded when the
  session closed.
- **Text with a time zone is refused for a `DATE` or `TIMESTAMP`.** A callable
  timestamp argument, or text written to such a column, with an offset or zone
  used to lose it silently.
- **`UPDATE ... SET col = DEFAULT` through `ATTACH` is refused.** It stored `NULL`;
  `INSERT` with an explicit `DEFAULT` was already refused.

## Reading

- **`oracle_scan_parallel` no longer drops rows.** A plain `NUMBER` key between
  two whole numbers (1.5) fell between two shards; ranges are now half-open with
  an open last shard.
- **Faster single-session scans.** The next batch is fetched while DuckDB stores
  the current one, and fetch sizes follow the 64 MiB response limit instead of
  8 MiB. On 19c, 1M rows by 50 columns in one session took 11.1 s and now take
  8.4 s.
- **Faster LOB columns.** A LOB prefetch fetch carries up to 2048 rows, and a
  `CHAR` column beside the LOB no longer turns prefetch off. On the same table
  with a CLOB, one session took 15.5–18.2 s and now takes 11.7–12.0 s.
- **A pooled session idle for 30 s is checked before reuse**, so the first query
  after a pause no longer fails on a connection a firewall closed.
- **`CREATE OR REPLACE SECRET` takes effect for reads.** The read pool kept
  logging in with the old password, which can lock the account.
- **No reconnect per scan for a user without the parallel grants.** Without
  `EXECUTE` on `DBMS_FLASHBACK`, `SELECT` on `DBA_EXTENTS` or `FLASHBACK` on
  the table, every scan of a large table logged in again before reading in one
  session. On Free 23ai a 1M-row copy took 415–442 ms and now takes 254 ms.
  `EXPLAIN ANALYZE` names the refusal in `Oracle parallel refused`.
- **Ctrl-C stops a plain scan at once**, instead of waiting for Oracle or
  `read_timeout` and ending in an IO error.
- **Fixed reads:**
  - an attached `LONG` column, which failed every read as a changed wire type;
  - a `TIMESTAMP(7..9)` value past 2262, which now raises a range error instead
    of wrapping to 1677;
  - more than 4096 lookups of names that are not schemas, which made every later
    lookup fail.
- **`oracle_query ... FOR UPDATE` closes its session after the scan**, instead of
  returning it to the pool with the row locks held.
- **A prepared `oracle_query` or `oracle_vector_search` binds again on each
  `EXECUTE`.**

## Pushdown

- **On a database whose character set is not AL32UTF8 or UTF8,** a text constant
  with non-ASCII characters stays in DuckDB, since Oracle would turn what that
  character set cannot hold into `?`.
- **Other text constants that stay in DuckDB:** one longer than 4000 bytes
  (ORA-01704 in Oracle), and one containing `/*SCN*/`.
- **`COUNT(col)` goes to Oracle only for columns Oracle can count by value:**
  not `LONG`, LOB, JSON, `VECTOR` or XML.

## Connecting

- **Program paths with spaces or parentheses connect through redirecting
  listeners.** A path such as `C:\Program Files (x86)\...` used to make every
  connect through SCAN, RAC or Autonomous Database fail. The program, host and
  user names in the connect request are now sanitized as python-oracledb does.
- **A `tnsnames.ora` entry with several names** (`a, b = (...)`) is found by any
  of them.
- **A server certificate with non-ASCII characters in its subject** is compared as
  written.

## Transactions and calls

- **The `oracle_*_transaction` writers mark the catalog as modified,** so
  `READ ONLY` transactions and the one-database-per-transaction rule apply to
  them.
- **`oracle_call_auto` and `oracle_arguments` find procedures with no
  arguments.**

## Verification

- **Offline suites:** the protocol, LOB reader, adapter and SQL suites against
  DuckDB v2.0.1, and the adapter suite under ASan and UBSan.
- **Live protocol stages:** all 18 against Oracle 19c and Free 23ai over TCP, and
  17 against an OCI Autonomous Database (26ai) over TCPS with a wallet;
  cancellation over TLS is not implemented.
- **Live results:** the same results as 0.8.3 on a 1M-row benchmark schema on
  Free 23ai.
- **Clean-machine check:** no Oracle client in the built extension.
