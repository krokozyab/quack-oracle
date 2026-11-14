# 0.7.0 (draft)

## Fixes

- CREATE compensation locks, verifies OBJECT_ID and drops in one server block,
  removing the gap between client sessions. Concurrent external DDL remains
  outside the compensation guarantee because Oracle DDL implicitly commits.

- oracle_top_n_pushdown=false also disables unordered LIMIT pushdown.

- Schema discovery truncates at 4,096 owners instead of failing ATTACH. Explicit
  SCHEMA skips discovery; missing named owners are cached until reattachment.

- A commit rejected before the remote COMMIT starts compensates acknowledged
  CREATEs. Only an attempted remote COMMIT retains tables for reconciliation.

- Incomplete dictionary loads verify missing names with a per-table describe;
  CREATE/DROP IF EXISTS decisions no longer assume the requested object exists.

- Skipping protocol bytes checks bounds and advances without allocating or copying.

- Attached MERGE rejects duplicate source keys after target-type conversion,
  before issuing remote writes, including duplicates across source batches.

- Updating an indexed column writes only explicitly assigned columns; unchanged
  values are not read back through potentially lossy mappings or rewritten.

- Renaming a table back to a previously cached name restores its catalog entry,
  including alias lookups and catalog inspection, without reattachment.

- DELETE RETURNING initializes DuckDB 2.0's virtual ROWID output, preventing
  empty identities and uninitialized string data in returned chunks.

- Unsupported operations requiring DuckDB-local storage now distinguish unsupported
  MERGE/upsert from the administrative SQL route for DROP and ALTER.

## Behaviour changes

- Plain attached INSERT refuses explicit DEFAULT before writing instead of
  silently inserting NULL. Omitted columns retain Oracle defaults; use the raw
  Oracle INSERT API when explicit DEFAULT values are required.

- SCHEMA selects the owner behind `main`; it no longer limits the attachment to
  one owner. Oracle grants still control access. Schema discovery lists visible
  non-Oracle-maintained owners. `main` is reserved; case-colliding owner aliases
  are refused, and discovery/named lookup are bounded to 4,096 names. Reattach
  after external schema/grant changes. READ_ONLY applies to every owner.

- Packed scalar storage is bounded to 64 MiB including cell descriptors and
  validity metadata. A response exceeding that budget is decoded through the
  ordinary path without another remote fetch. Both paths allow scalar values
  through 16 MiB; response reassembly bounds remain enforced.

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

- One ATTACH exposes multiple accessible Oracle owners as schemas, including
  cross-schema joins, transactional writes and supported table DDL. Owner caches
  are isolated; transaction sessions and DDL invalidation are shared per catalog.
  Named-owner CTAS and schema-scoped CREATE rollback are supported.

- Exact NUMBER-to-DECIMAL reads decode directly into portable scaled integers
  through 38 digits. Values needing rounding or error reporting retain the
  existing conversion semantics.

- Scalar scans use batch-owned byte storage and cell descriptors, preserving
  NULLs and compressed-row continuation across packets and fetches. LOB/LONG/
  binary ROWID and deferred reads retain their existing path.

- Eligible COUNT(DISTINCT column) is computed entirely in Oracle and returns
  BIGINT. Supports exact numbers, BINARY_FLOAT/DOUBLE, DATE/TIMESTAMP without a
  time zone and VARCHAR2 compared as bytes. NULL and empty-input semantics match
  DuckDB. Rounded NUMBER mappings, unsafe text, local filters, samples, aggregate
  FILTER/ORDER BY and expressions keep local execution. AVG remains local.

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
