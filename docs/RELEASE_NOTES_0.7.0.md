# 0.7.0 (draft)

## Fixes

- DELETE RETURNING initializes DuckDB 2.0's virtual ROWID output, preventing
  empty identities and uninitialized string data in returned chunks.

- Unsupported operations requiring DuckDB-local storage now distinguish unsupported
  MERGE/upsert from the administrative SQL route for DROP and ALTER.

## Behaviour changes

- Attached CREATE/CTAS, DROP and ALTER (ADD/DROP/RENAME COLUMN, RENAME TO)
  now execute Oracle DDL on separate sessions and refresh the local catalog.
  ALTER/DROP commit immediately and survive DuckDB rollback. Conflicting locks
  are checked with LOCK TABLE NOWAIT; caller DML is not committed by DDL.
- CREATE/CTAS rollback attempts a compensating DROP after identity verification,
  including statement failures and connection close. This is not atomic DDL;
  failed cleanup or lost acknowledgements can require manual reconciliation.
  Unknown COMMIT outcomes preserve tables. Existing IF NOT EXISTS targets are retained.
- DuckDB-to-Oracle DDL types, literal defaults, supported constraints and limits
  are documented in README. Read-back types follow Oracle metadata; BOOLEAN
  becomes NUMBER(1,0), and TIMESTAMPTZ uses WITH LOCAL TIME ZONE.

- Declared `NUMBER(19..38,0)` now reads as `DECIMAL(p,0)` instead of text.
  Negative-scale declarations with 19..38 effective digits use `DECIMAL(p-s,0)`.
  Unconstrained NUMBER and values exceeding 38 effective digits retain their mapping.
- Eligible constant LIMIT/OFFSET scans now bound the Oracle result and avoid
  parallel range planning. Local filters, samples and locked scans retain local limits.

## Additions

- MERGE is accepted as DML by the raw execution APIs, with Oracle affected-row counts
  and the same transaction ownership as INSERT, UPDATE and DELETE.

- Attached tables expose enforced PRIMARY KEY and UNIQUE keys to DuckDB's conflict binder.
- ON CONFLICT DO NOTHING, restricted DO UPDATE and INSERT OR REPLACE with one
  unique key use native Oracle MERGE array DML. Missing columns keep Oracle defaults.
- The attached MERGE operator supports equality on enforced keys, one INSERT
  and optional source-column/constant UPDATE. Conditional actions, old-row
  expressions, key changes, RETURNING and NULL source keys are refused.
- Concurrent merges of the same new key can fail with ORA-00001; no automatic
  replay is added. Source deduplication follows DuckDB's conflict binder.
