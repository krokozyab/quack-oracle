# 0.8.0 (draft)

## Added

- Bounded range-plan cache (`oracle_scan_plan_cache`, default true): reuse
  ROWID boundaries and projected wire descriptions after checking table
  identity, heap kind and the attachment's DDL epoch. Every execution takes
  a fresh SCN and checks flashback access. Worker descriptions are validated
  before decoding. Planning time, round trips and cache hits appear separately
  in EXPLAIN ANALYZE. Cold planning combines metadata and describe exchanges.

- Opt-in `oracle_parallel_count`: compute scalar COUNT(*) and COUNT(column)
  over disjoint ROWID ranges at one SCN and sum them in DuckDB with a checked
  BIGINT result. Empty inputs return zero. Uses reader/thread caps and falls
  back to one count for missing privileges or write-pinned reads. DISTINCT,
  grouping, mixed aggregates, samples and local filters retain their paths.
  Defaults to false because range planning and multiple counts can be slower
  than one Oracle count. Invalid or missing partial replies fail the query.

- Opt-in `oracle_parallel_top_n`: rank candidates per ROWID range at one SCN,
  then retain DuckDB's global Top-N for the final result, including OFFSET and
  NULL ordering. Uses the ordinary reader cap and privilege fallback. Defaults
  to false because additional exchanges can be slower on remote connections.

- Partial AVG pushdown for exact NUMBER(p,s), p <= 18 and 0 <= s <= p:
  Oracle computes the scaled sum and non-NULL count; DuckDB finalizes the
  result with the pinned engine's integer/decimal rounding rules. Other AVG
  inputs retain local execution.

- Compose eligible inner joins across three or more attached tables in one
  Oracle catalog, and push eligible aggregates over their result. Each base
  table keeps its owner, filters and transaction snapshot.

## Behaviour changes

- Reject attached scans when Oracle's wire type no longer matches the cached
  table schema. An external NUMBER-to-VARCHAR2 change could previously decode
  text as a number. DETACH and ATTACH refresh the schema before another read.

- Eligible AVG queries can return groups instead of all input rows. An
  oversized remote COUNT or invalid sum fails instead of silently rounding.
  `oracle_aggregate_pushdown = false` retains local execution.

- Partial AVG of DECIMAL widths <=4 refuses counts above 922337203685477,
  ensuring every partial sum fits the pinned DuckDB INT64 accumulator.

- Reject scalar fetch responses exceeding the requested row count before
  materializing them, including compressed repeats and legacy fallback.

- Scalar attached scans fetch up to 16384 rows and retain unread rows while
  returning DuckDB vectors of at most 2048 rows. `oracle_fetch_rows` controls
  the maximum (1..65536); declared widths reduce the request toward an 8 MiB
  estimate. This estimate is not a hard limit on all scan memory.
- A positive `oracle_parallel_scan` is a maximum: known small tables and
  selective filters stay sequential.

- Decode eligible scalar scans into typed vectors during fetch, avoiding a
  batched intermediate wire-cell arena. NUMBER, dates/timestamps, binary floats,
  BOOLEAN and short text/RAW are eligible; wider text, LOB and deferred paths
  retain their existing implementation. `oracle_direct_scan=false` selects the
  previous path. Output types are unchanged.
- Direct batches use a conservative 64 MiB retained-data budget. Borrowed wire
  values are consumed synchronously; the last-row snapshot survives fetches.
  Value-conversion failures poison the active read handle and retain their
  original exception, without being mistaken for incomplete network framing.
- Auto parallelism estimates the selected columns and filtered row count,
  targeting approximately 16 MiB or 250,000 returned rows per reader, up to
  eight readers and DuckDB's thread count. The row budget accounts for framing
  and decoding work even when the selected columns are narrow. Existing small
  table and selective-filter guards still apply.

- Native result rows now use a response-owned byte arena with offset/NULL
  descriptors, including execute prefetch, ROWID and LOB paths. Row continuations
  share unchanged bytes, incomplete rows roll back arena appends, and fetch
  snapshots use independent storage. Converters consume byte views without
  materializing temporary wire-cell vectors. SQL result types are unchanged;
  LOB I/O may still allocate temporary content buffers.

- Reuse pooled read sessions for ROWID planning instead of authenticating a new
  dictionary session for each parallel scan. Failed planning exchanges discard
  the lease before serial fallback.

- Add `ORACLE_SCANNER_STATIC_LINK=OFF` for measuring loadable builds and a guard
  that rejects an already loaded built-in copy before explicit loading.

- Prefetch up to 32 rows for known narrow bounded scalar reads and aggregates,
  using an 8 KiB estimated initial payload budget. Small results can finish in
  one exchange; wide/unknown values, LOB and write-locked scans retain their
  ordinary initial query fetch. Exact AVG still finishes in DuckDB.

- Resume incomplete short scalar rows without exception unwinding in the direct
  decoder. Rows are emitted only when complete; existing malformed-input and
  size checks remain in force. Chunked values retain their existing parser.

- Finish sequential scans after consuming an exhausted batch, avoiding an extra
  cursor fetch and interrupt watcher. Buffered rows and parallel ROWID ranges
  retain their normal traversal.

- `EXPLAIN ANALYZE` reports cursor execution and initial-row latency as
  `Oracle query open time`, separately from subsequent fetches. Parallel scans
  now charge range opens to this metric instead of fetch time. Durations are
  summed across readers and can exceed wall time.

- Publish parallel scan totals only after all ranges finish, preventing an
  early worker's snapshot from overwriting final `EXPLAIN ANALYZE` counters.
  Runtime Oracle details are omitted when an upstream operator stops a parallel scan early.
