# oracle_scanner 0.6.2

Built for DuckDB v2.0.0. Install with `INSTALL oracle_scanner FROM community;`
once the release is published. A correction release: defects found in review
of [0.6.1](RELEASE_NOTES_0.6.1.md) and while checking that review, each
reproduced against Oracle 19c or Free 23ai, fixed and covered by a test.
Nothing was added.

## Values that read wrong, or did not read

- **A REF CURSOR with a NULL failed on Oracle 19c.** Reading a cursor that
  PL/SQL opened (`oracle_call`, `oracle_call_implicit`, `oracle_call_auto`,
  a cursor from `oracle_plsql`) stopped with `ORA-01405: fetched column value
  is NULL` at the first NULL in a column that is not a LOB, in 0.6.0 and 0.6.1
  alike. Such a cursor is now fetched the way python-oracledb fetches one, and
  2,000 rows of NULL-bearing `VARCHAR2`, `NUMBER`, `DATE`, `CLOB`, `BLOB` and
  `NCLOB` columns read the same through a cursor as through a query, on 19c
  and on Free 23ai.

- **`TIMESTAMP WITH TIME ZONE` read the UTC time beside the local offset.**
  Oracle sends the date and time of such a value as UTC with the offset next
  to it, and the column printed the two together: `15:30 +03:00` read as
  `2026-03-28 12:30:00+03:00`. It now reads `2026-03-28 15:30:00+03:00`, the
  way Oracle prints it, across midnight and month and year ends. The same value
  inside a JSON document was already right and is unchanged.
- **A rounded `NUMBER` was compared in Oracle.** With
  `oracle_unconstrained_number` set to a `DECIMAL` or `'double'`, a `NUMBER`
  with no declared precision reads as a rounding of what Oracle stores. Filters,
  `GROUP BY` keys, join keys and `ORDER BY ... LIMIT` keys on such a column were
  still sent to Oracle, which compares the stored values: under
  `'decimal(10,1)'`, 1.21 and 1.24 came back as two groups of 1.2, and
  `WHERE x > 1.2` kept both. All of these now run in DuckDB for such a column.
  Columns with a declared precision, and the default `'varchar'`, are pushed down
  as before.

## Consistency

- **A sample left the statement's change number.** With
  `oracle_consistent_read = true`, a `TABLESAMPLE SYSTEM` scan was sent without
  `AS OF SCN`, so it read the present and not the moment the rest of the
  statement read. It is now `SAMPLE (p) AS OF SCN n` (Oracle accepts the sample
  clause only in that order).
- **Refreshing a snapshot could replace another table.** `oracle_snapshots()`
  lists tables from every attached database, but `oracle_snapshot_refresh`
  rebuilt the snapshot by schema and name in the default database: a snapshot
  in an attached database file replaced an ordinary table of the same name in
  the default one and stayed as it was. A refresh now rebuilds the table where
  it is, takes `table`, `schema.table` or `database.schema.table`, and refuses
  a name two snapshots share. `oracle_snapshot` now creates its table where
  this session's `USE` points; it used the instance's default database.
  `oracle_snapshots()` has a new first column, `database_name`.

## Network waits

- **A signal ended a wait for Oracle.** A read or write waiting on the socket
  reported a timeout when a signal interrupted the wait (a profiler, a terminal
  resize, a language runtime), and the statement and its session were lost. The
  wait now resumes for the time it has left.
- **A socket descriptor past 1023 broke the wait.** On Linux and macOS the wait
  used `select()`, which cannot watch a descriptor at or above `FD_SETSIZE`:
  a process holding many open files could not connect, or wrote past a fixed
  buffer. Linux and macOS now wait with `poll()`.

## Stricter reading

- An `INTERVAL` whose components carry different signs is refused as
  malformed instead of being summed into a different value. Oracle never sends
  one; every interval it does send, negative and computed ones included, reads
  as before.
