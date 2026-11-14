# oracle_scanner 0.6.3

Built for DuckDB v2.0.0. Install with `INSTALL oracle_scanner FROM community;`
once the release is published. Corrections, each reproduced against Oracle 19c
or Free 23ai, fixed and covered by a test, and four speed-ups.

## Results that were wrong

- **An `UPDATE` or `DELETE` could undo another session's commit.** The scan
  that finds the rows to change read them without a lock, on a session of its
  own. A change another session committed between that read and the write by
  ROWID was overwritten: with a concurrent `x = x + 100` committed meanwhile,
  `UPDATE ... SET x = x + 1` left 1 instead of 101, and `DELETE ... WHERE x < 50`
  removed a row that held 100 by then. That scan now reads `FOR UPDATE` on the
  transaction's own session, so Oracle waits for the other transaction and the
  committed row is what DuckDB sees and changes, as Oracle's own `UPDATE` does.
  Rows DuckDB reads and then filters out itself stay locked until the
  transaction ends.
- **Text equality could match more than DuckDB would.** `=`, `IN` and join keys
  on a `VARCHAR2` were sent to Oracle on the grounds that equality does not
  depend on collation. It does: under `NLS_COMP = LINGUISTIC` with a
  case-insensitive `NLS_SORT` (a logon trigger or the instance can set it), or on
  a column declared `COLLATE BINARY_CI` (possible where `MAX_STRING_SIZE =
  EXTENDED`, as on Autonomous Database), `'shipped' = 'SHIPPED'` holds in Oracle.
  `WHERE status = 'shipped'` over a table holding only `'SHIPPED'` returned
  900,000 rows instead of none. `ATTACH` now reads the session's `NLS_COMP` and
  each column's collation, and sends text equality only for a column Oracle
  compares byte by byte; the rest stays in DuckDB.
- **`TIMESTAMP WITH LOCAL TIME ZONE` read hours off when `DBTIMEZONE` is not
  UTC.** Oracle sends such a value on the wall clock of the database time zone,
  not the session's: with `DBTIMEZONE` `+03:00`, a value holding 12:00 UTC read
  as 15:00 UTC, through `ATTACH`, `oracle_query` and a REF CURSOR alike. A
  session that meets such a column now asks for `DBTIMEZONE` once and reads the
  instant. A `DBTIMEZONE` that names a region has no single offset, and its
  values are refused with `SYS_EXTRACT_UTC` as the way round. Writing was right
  and is unchanged.

## Errors that did not need to happen

- **`COMMIT` on a service with Transaction Guard reported an unknown outcome.**
  Such a service, as Application Continuity needs, sends the transaction's
  logical id ahead of every commit's acknowledgement, and this client
  understood one kind of server message out of nine. A write through `ATTACH`
  committed and still failed with "COMMIT outcome is unknown", and
  `oracle_execute` failed with "expected TTC STATUS transaction
  acknowledgement". All nine are now read as python-oracledb
  reads them, and writes, commits and rollbacks complete on such a service.
- **`ALTER TABLE` on an attached table broke the DuckDB database.** It reached
  a DuckDB internal error that invalidated the database until a restart. It is
  now refused, and every DDL refusal on an attached catalog (`CREATE TABLE`,
  `DROP TABLE`, `ALTER TABLE`, `DROP SCHEMA`) says to run the statement with
  `oracle_execute_admin` and to `DETACH` and `ATTACH` again. The README no
  longer says the extension issues no DDL.

## Faster

- **Parallel scans copy in parallel.** A statement that keeps insertion order,
  which `CREATE TABLE ... AS`, `INSERT ... SELECT` and `COPY` do by default, read
  the ROWID ranges of a parallel scan one after another on one thread. Each
  range is now a batch in ROWID order: copying a 1,000,000-row, seven-column
  table took 0.46 s through four sessions instead of 1.06 s.
- **Parallel scans need only `DBA_EXTENTS`, as documented.** They also read
  `DBA_OBJECTS`, and a user granted only `DBA_EXTENTS` was read through one
  session without a word. The object number now comes from `ALL_OBJECTS`.
- **A selective filter reads through one session.** An automatic parallel scan
  now estimates from the optimizer statistics how many rows the filters sent to
  Oracle leave (`NUM_DISTINCT` for `=` and `IN`, `LOW_VALUE`/`HIGH_VALUE` for a
  range on a number, date or timestamp), and below 100,000 reads one stream: one
  customer's 50 orders out of a million take 0.015 s instead of 0.18 s, a
  month of them 0.084 s instead of 0.21 s. A number of sessions set by hand is
  used as set.
- **`GROUP BY` a text column runs in Oracle** where Oracle compares that column
  byte by byte: `GROUP BY status` over a million rows returns three rows in
  47 ms instead of reading every row.
