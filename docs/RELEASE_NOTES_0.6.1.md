# oracle_scanner 0.6.1

Built for DuckDB v2.0.0. Install with `INSTALL oracle_scanner FROM community;`
once the release is published. A performance release: nothing was added or
removed since [0.6.0](RELEASE_NOTES_0.6.0.md), and every value is written
exactly as before.

## Faster INSERT

`INSERT` into an attached table now encodes the values of the common column
types straight from DuckDB's vectors (`VARCHAR2`, `CHAR`, integers and
`DECIMAL` into `NUMBER`, `DATE`, `TIMESTAMP`, `BINARY_DOUBLE`, `BINARY_FLOAT`,
`BOOLEAN`), and checks the rows of a batch against its first row instead of
validating each one whole. Other types are written as before.

Measured with 1,000,000 rows from a DuckDB table into a local Oracle 19c:

| Columns | 0.6.0 | 0.6.1 |
| --- | --- | --- |
| 50 | 44 s | 10–12 s |
| 20 | 16.5 s | 4.6–5.1 s |
| 5 | 12–13 s | 7–8 s |

Rows written by 0.6.0 and 0.6.1 from the same source compare equal in Oracle,
byte for byte (`DUMP`), including edge values of every type above.
