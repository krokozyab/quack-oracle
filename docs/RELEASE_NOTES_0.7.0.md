# 0.7.0 (draft)

## Fixes

- Unsupported operations requiring DuckDB-local storage now distinguish unsupported
  MERGE/upsert from the administrative SQL route for DROP and ALTER.

## Behaviour changes

- Declared `NUMBER(19..38,0)` now reads as `DECIMAL(p,0)` instead of text.
  Negative-scale declarations with 19..38 effective digits use `DECIMAL(p-s,0)`.
  Unconstrained NUMBER and values exceeding 38 effective digits retain their mapping.
- Eligible constant LIMIT/OFFSET scans now bound the Oracle result and avoid
  parallel range planning. Local filters, samples and locked scans retain local limits.
