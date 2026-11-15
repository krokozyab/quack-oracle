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
