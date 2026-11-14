# oracle_scanner 0.7.0

Built for DuckDB v2.0.0. Install with `INSTALL oracle_scanner FROM community;`
once the release is published. Table DDL, upserts and several Oracle schemas
through one `ATTACH`; more work sent to Oracle; a faster fetch path; and two
corrections. Everything below was verified against Oracle 19c and Free 23ai and
is covered by tests.

## New through `ATTACH`

- **Create, change and drop Oracle tables.** `CREATE TABLE`, `CREATE TABLE … AS
  SELECT`, `DROP TABLE` and `ALTER TABLE` (`ADD`, `DROP` and `RENAME COLUMN`,
  `RENAME TO`) now run in Oracle, and the attached catalog sees the result at
  once, without `DETACH` and `ATTACH`. Prepared statements over a changed table
  are bound again. Oracle commits DDL on its own, so the DDL runs on a separate
  session: it does not commit the DML of your open transaction, and `ALTER` and
  `DROP` stay done after a DuckDB `ROLLBACK`. A table created inside a
  transaction that rolls back, fails or is closed is dropped again, after its
  object id has been checked, so a table someone else put under that name is
  left alone. This is compensation, not atomic DDL: if the cleanup itself fails,
  the table stays and the error says so. A table locked by uncommitted DML,
  including your own, is refused at once with ORA-00054 rather than waited on.
  The DuckDB-to-Oracle type mapping and what is refused (`TEMPORARY`,
  `OR REPLACE`, `CHECK` and foreign keys, generated columns, expression defaults,
  `CASCADE`) are in the README.
- **Upserts.** `INSERT … ON CONFLICT DO NOTHING`, `ON CONFLICT … DO UPDATE SET
  col = excluded.col` (or a constant), `INSERT OR REPLACE` and a `MERGE INTO`
  statement run as one Oracle `MERGE` with array binds. Attached tables now show
  their enforced primary and unique keys to DuckDB, which is what the conflict
  target needs. Columns you leave out keep their Oracle defaults. A source that
  repeats a key, also after conversion to the column type (`'70'` and `'070'`
  into a NUMBER key), is refused before anything is written. Refused, with
  `oracle_execute` and your own `MERGE` as the way round: conditions on the
  actions, expressions over the old row, changing a key, `RETURNING`, `NULL` keys,
  an explicit `DEFAULT` in the source, and keys whose Oracle equality is not
  byte equality (`CHAR`/`NCHAR`, text compared by a collation, `BINARY_FLOAT`
  and `BINARY_DOUBLE`). Oracle's `MERGE` is not an atomic upsert: two sessions
  merging the same new key at once can end with ORA-00001 in the second.
- **Several Oracle schemas in one attachment.** `o.hr.employees` and
  `o.sales.orders` work side by side, `USE o.hr` too, and writes to several
  schemas share one Oracle transaction. `main` stays the owner chosen by
  `SCHEMA` (or the signed-in user). Oracle grants still decide what can be read.
  Owners are discovered at `ATTACH` without `SCHEMA`, at most 4,096 of them;
  a schema created or granted later needs a new `ATTACH`.

## More of the query runs in Oracle

- **`LIMIT` without `ORDER BY`.** `SELECT … FROM o.big LIMIT 5` used to plan a
  parallel ROWID-range read of the whole table for five rows. A constant `LIMIT`
  (with `OFFSET`, `limit + offset`) is now sent as `FETCH FIRST n ROWS ONLY` and
  read through one session, unless a filter stays in DuckDB, the scan is sampled
  or it locks rows for an `UPDATE`. `oracle_top_n_pushdown = false` turns it off.
- **`count(DISTINCT col)`.** Counted entirely by Oracle for exact numbers,
  `BINARY_FLOAT`/`BINARY_DOUBLE`, `DATE` and `TIMESTAMP` without a time zone, and
  text Oracle compares byte by byte, so one row comes back instead of every
  distinct value. `avg` still runs in DuckDB.
- **`MERGE` in `oracle_execute`**, `oracle_execute_transaction` and
  `oracle_execute_many`, with Oracle's affected-row count.

## Faster

- **Fetching.** Fetched values now share one buffer per batch instead of one
  allocation per cell, and exact `NUMBER` values go straight into DuckDB
  `DECIMAL` storage without passing through text. Reading a 1M-row, 7-column
  table through one session took 0.94 s and now takes 0.76 s on the local test
  machine, with 28% less client CPU. A batch over 64 MiB, which only a select
  list of thousands of columns reaches, is decoded the old way.

## Results that were wrong

- **`INSERT … VALUES (1, DEFAULT)` wrote `NULL`.** An explicit `DEFAULT` through
  `ATTACH` was sent as `NULL` instead of the column's Oracle default. It is now
  refused; leave the column out and Oracle fills it in, as before.
- **`DELETE … RETURNING rowid` returned empty or broken values.** The returned
  chunk left DuckDB 2.0's virtual ROWID column uninitialized. It now holds the
  deleted rows' ROWIDs.

## Behaviour changes

- **`NUMBER(19)` to `NUMBER(38)` read as `DECIMAL(p,0)`, not text.** Arithmetic,
  `sum` and joins now work on them without a cast. A negative scale with 19 to
  38 significant digits becomes `DECIMAL(p-s,0)`. `NUMBER` without a precision
  keeps the `oracle_unconstrained_number` setting. A query that relied on these
  columns being `VARCHAR` needs a change.
- **`SCHEMA` in `ATTACH` picks the owner behind `main`; it no longer limits the
  attachment to that owner.** See the schema item above. `READ_ONLY` applies to
  every schema.
- **`MERGE INTO` and `INSERT OR REPLACE` through `ATTACH`** no longer fail with a
  message about DDL; they run or are refused as described above.
