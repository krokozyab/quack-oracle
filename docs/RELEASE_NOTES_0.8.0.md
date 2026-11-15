# 0.8.0 (draft)

## Added

- Partial AVG pushdown for exact NUMBER(p,s), p <= 18 and 0 <= s <= p:
  Oracle computes the scaled sum and non-NULL count; DuckDB finalizes the
  result with the pinned engine's integer/decimal rounding rules. Other AVG
  inputs retain local execution.

## Behaviour changes

- Eligible AVG queries can return groups instead of all input rows. An
  oversized remote COUNT or invalid sum fails instead of silently rounding.
  `oracle_aggregate_pushdown = false` retains local execution.
