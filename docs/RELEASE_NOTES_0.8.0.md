# oracle_scanner 0.8.0

Built for DuckDB v2.0.0. Install with `INSTALL oracle_scanner FROM community;`
once the release is published. Faster scans and copies, more of the query
sent to Oracle (AVG, joins of three or more tables), reuse of parsed cursors
and range plans, and safer handling of tables changed outside DuckDB. Verified
against Oracle 19c and Free 23ai and covered by tests.

## More of the query runs in Oracle

- **AVG of exact numbers.** For `NUMBER(p,s)` with `p <= 18` and
  `0 <= s <= p`, Oracle returns a sum and a non-NULL count; DuckDB performs the
  final division using its decimal rounding rules. Other inputs stay local.
  An empty input returns NULL. Invalid or overflowing partial results fail.
- **More joins in one query.** Eligible inner joins across three or more
  tables in one attachment, including tables from different Oracle schemas,
  can run in Oracle with an aggregate above them. Filters and reads of your
  transaction's own writes retain their usual visibility.
- **Parallel COUNT, when requested.** `SET oracle_parallel_count = true` lets
  eligible `COUNT(*)` and `COUNT(column)` use readers at one snapshot. DuckDB
  combines their counts with overflow checks. This is off by default: one
  Oracle count, particularly through an index, can be faster. Missing privileges
  or an active write transaction use one reader.

## Faster repeated reads and copies

- **One query for source-schema checks.** GROUP BY and JOIN use one empty
  SELECT for all their source tables, on the connection used by the query. A
  write transaction uses its own connection. Repeated checks reuse cursors and
  still refuse stale precision/scale after external DDL. Empty plans skip the
  check. EXPLAIN ANALYZE includes its traffic in `Oracle network` and also shows
  it as `Oracle schema check`; the separate line is part of the total.
  On Free and 19c, checks for a three-table JOIN fell from three exchanges to
  one; GROUP BY kept one. Including previously hidden checks, those complete
  queries used 5 → 3 and 3 → 3 exchanges respectively. No speedup is claimed.

- Repeated parallel scans reuse checked range plans and pooled connections.
  Each execution still obtains a new snapshot and checks table identity and
  access. `oracle_scan_plan_cache = false` disables plan reuse for comparisons.
- Scalar scans request up to **16,384 rows** at a time, returning DuckDB vectors
  of at most 2,048 rows. Wide selected columns reduce the request. A LOB you do
  not select no longer reduces it. Small bounded reads can return their first
  rows with the initial query response.
- Number, date, timestamp, binary float, BOOLEAN and short text/RAW scans can
  convert values directly while fetching. Wide results choose the previous
  buffered path before reading, rather than failing partway through a response.
  `oracle_direct_scan = false` selects that buffered path for comparisons.
- Other fetch paths avoid a separate byte allocation for every value. SQL types
  and NULL semantics are unchanged. These changes do not impose a query-wide
  memory limit.
- `EXPLAIN ANALYZE` separates query-open time, subsequent fetch time and range
  planning. Parallel times are summed across readers and can exceed wall time.
  Final parallel counters are published only after every range finishes.

## Behaviour changes

- **Positive reader counts override size estimates.** `oracle_parallel_scan = -1`
  chooses automatically, targeting roughly 16 MiB or 250,000 returned rows per
  reader, up to eight readers and DuckDB's thread count. A positive value above
  one requests that many readers even with stale or selective statistics;
  thread limits, available ranges, privileges and transaction safeguards still
  apply. `0` and `1` select one reader. A 600,000-row test with statistics claiming
  1,000 rows used four readers with `4` and one with `-1` on both supported lanes.
- **Automatic ranked reads.** `oracle_parallel_top_n` is now a VARCHAR setting
  with default `auto`. It starts with two serial measurements before comparing
  serial and parallel costs. Existing `true`/`false` values still force a choice;
  reported values are `auto`, `true`, `false`. Calibration can make the first
  executions slower. Ordinary LIMIT keeps its separate path.
- **Cursor reuse is on by default.** `oracle_statement_cache` retains at most
  **20** idle scalar query cursors per session. Snapshot SQL (`AS OF SCN`) and
  ROWID ranges are not cached. Different filter literals remain different keys;
  use binds for repeated SQL. Writes and administrative statements invalidate
  idle entries. Set the setting to false to disable reuse without disabling
  connection pooling.
- A cached read receiving ORA-01007 or ORA-00932 before returning any rows is
  reparsed and executed once with its current binds. There is no retry after
  returned rows, cancellation or another error, and no second retry if the full
  execution fails. This does not replay writes. Oracle may instead return an
  updated description directly.
- **External schema changes fail safely.** A changed Oracle type, NUMBER
  precision/scale, timestamp/interval scale or text character form is refused
  before values or pushed aggregates use the old attached schema. DETACH and
  ATTACH again to refresh it. This prevents fractional NUMBER values being
  silently truncated after external DDL.
- `SET oracle_fetch_rows` immediately rejects NULL and values outside
  **1..65,536**. Responses returning more rows than requested are rejected
  before decoding extra rows, including rows in the initial query response.
- A direct-path value outside DuckDB's representable range reports a conversion
  error. If the complete Oracle response was consumed, the connection remains
  usable. Incomplete or malformed responses still discard it.
- Partial AVG of DECIMAL widths up to four rejects counts above
  922,337,203,685,477 so its sum stays within DuckDB's accumulator range.

## Limitations

- An upstream operator stopping a parallel scan early can leave runtime Oracle
  details, including the scan's parameter map, absent from `EXPLAIN ANALYZE`.
  Completed scans retain final totals regardless of worker completion order.
- Reader selection is a heuristic. Compare explicit reader counts and serial
  execution on your server; these notes make no universal speedup claim.
- LOB reads can still allocate temporary content buffers. Fetch sizing and the
  cursor cache have separate bounds; neither is a limit on total query memory.
