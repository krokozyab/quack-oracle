# oracle_scanner 0.8.2

Built for DuckDB v2.0.0 and v2.0.1. Install with
`INSTALL oracle_scanner FROM community;` once the release is published. The
extension itself is unchanged from [0.8.1](RELEASE_NOTES_0.8.1.md); this
release exists so that it builds for DuckDB v2.0.1.

## DuckDB v2.0.1

- **The build for v2.0.1 failed in the live test programs.** DuckDB v2.0.1
  added a `duckdb::Literal` type that `duckdb.hpp` now brings in, and five live
  test programs had a helper function of the same name, which made every call to
  it ambiguous. The helper is renamed. The extension's own sources did not use
  the name and built unchanged, but the test programs build in the same step, so
  no v2.0.1 binary was published for 0.8.1.

## Verification

Built against DuckDB v2.0.1 and v2.0.0; offline protocol, adapter and SQL
suites pass on both.
