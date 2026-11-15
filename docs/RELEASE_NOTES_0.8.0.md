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
