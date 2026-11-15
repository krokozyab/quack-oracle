# 0.8.0 (draft)

## Added

- Partial AVG pushdown for exact NUMBER(p,s), p <= 18 and 0 <= s <= p:
  Oracle computes the scaled sum and non-NULL count; DuckDB finalizes the
  result with the pinned engine's integer/decimal rounding rules. Other AVG
  inputs retain local execution.

- Compose eligible inner joins across three or more attached tables in one
  Oracle catalog, and push eligible aggregates over their result. Each base
  table keeps its owner, filters and transaction snapshot.

## Behaviour changes

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
  targeting approximately 16 MiB per reader, up to eight readers. Small narrow
  copies therefore avoid paying for unnecessary range planning and sessions.

- Native result rows now use a response-owned byte arena with offset/NULL
  descriptors, including execute prefetch, ROWID and LOB paths. Row continuations
  share unchanged bytes, incomplete rows roll back arena appends, and fetch
  snapshots use independent storage. Converters consume byte views without
  materializing temporary wire-cell vectors. SQL result types are unchanged;
  LOB I/O may still allocate temporary content buffers.

- Reuse pooled read sessions for ROWID planning instead of authenticating a new
  dictionary session for each parallel scan. Failed planning exchanges discard
  the lease before serial fallback.
