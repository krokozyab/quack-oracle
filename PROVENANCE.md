# Provenance and reuse ledger

This project speaks Oracle's TNS/TTC protocol without any Oracle client, so two
questions have to have written answers: where the protocol knowledge came from,
and what evidence is stored in this repository. A rule that no wire behavior
ships without capture-backed evidence carries the obligation to account for the
evidence itself.

## What is reused, and under what terms

| Source | What is taken | Terms |
| --- | --- | --- |
| DuckDB extension template and `extension-ci-tools` | the build system, the loadable-extension scaffolding, and the CI distribution pipeline | MIT |
| DuckDB itself (submodule, pinned `v1.5.5`) | linked as a library; `duckdb_miniz` is compiled from its vendored copy for bounded in-memory wallet ZIP reading | MIT |
| OpenSSL | linked, not vendored: TLS transport and the digest and cipher primitives O5LOGON needs | Apache-2.0 |
| python-oracledb Thin | **reasoning and invariants, not code and not bytes.** It is the upstream of the protocol invariants recorded in comments throughout `src/`: which field, bit or length a client sends, and what breaks otherwise. | Apache-2.0 / UPL |

**No Oracle client software is used or distributed.** No OCI, Instant Client,
ODPI-C, ODBC, JDBC, Python runtime, or helper process is linked, loaded, or
shipped. `scripts/check_no_oracle_client.sh` inspects the built extension for
exactly that and fails if it cannot perform the inspection.

A protocol invariant carried over from elsewhere is evidence, not a
specification: anything load-bearing is confirmed against a live 19c or 23ai
database, or against an independent control, before it ships. Where a capture
disagreed with the source it came from, the disagreement is written down —
including the cases where the source was right, since knowing which side was
correct is worth as much as the defect.

## Captured bytes stored in this repository

Every byte sequence below was recorded from a server this project was tested
against. None contains a credential, a verifier, a wallet, a service name, a
host, or a port: the fetch and DML captures carry only test-table values and
Oracle-internal row addresses, and the negotiation template is a client request
sent before authentication.

Hashes are produced by `scripts/capture_inventory.sh`, which parses the byte
literals out of the source and digests them. If a hash below stops matching,
that is a fixture that changed — say why here rather than replacing the number,
because a fixture edited to make a test pass is otherwise indistinguishable from
one that records what a server sent.

| Capture | Bytes | Recorded from | SHA-256 |
| --- | --- | --- | --- |
| `zero_width_two_columns` | 14 | Oracle 19c, fetch response for `SELECT '' AS e, 'x' AS f FROM dual` | `fd8bd44b1c49811c5cd23743e20a315e0a56e7125d73d8339282375743595fba` |
| `zero_width_one_column` | 12 | Oracle 19c, fetch response for `SELECT '' AS e FROM dual` | `18d850b22a30ee38120ec1b3e9cf4c50e7b891034fcb6e2f16785efec1a98894` |
| `repeated_rows_fetch` | 85 | Oracle 19c, the second OFETCH of a one-column scan whose consecutive rows repeat | `e25dd1c6dbbd907ec2ac79b0ef7463555d960898723621241005c1251b77fda7` |
| `dml_end_of_call_one_row` | 59 | Oracle 19c, the end-of-call of `INSERT INTO t (id, label) VALUES (:1, :2)` run once | `d0ab7d8deca67ff7128421c88549b207001da719618ddfebd3349a785a1ba6c5` |
| `dml_end_of_call_three_rows` | 61 | Oracle 19c, the same statement run as three array-DML iterations | `a65853b671faf597dc98ff07266a5403f4c966fe5e8b9a7798ced2a36d232668` |
| `ttidty_negotiation_table` | 2642 | Oracle 19c, the TTIDTY/FDO capability request of a python-oracledb Thin pre-auth connection | `f264d0cdacb3465e48fe5cd71be86a42318f9a4056bf91bc776018323b367320` |
| `lob_row_one_clob` | 196 | Oracle 19c, fetch response for a single-row `SELECT` of one CLOB column | `b093b740172362a0c1db3493f07b67e02d0423f284bf4fdaa0c204e7642f758e` |
| `lob_rows_with_bit_vector` | 558 | Oracle 19c, fetch response for four rows of one CLOB column, where every row after the first arrives behind a BIT_VECTOR | `883809d2ce8d76825afcebf4cdc61fc4bd793f621a00035eb5065fa6c5891dde` |
| `lob_get_length_response` | 151 | Oracle 19c, the LOB_OP GET_LENGTH response for a ten-character CLOB | `79ca06d9b2b0e87a50d055cf9247c91aeed04705fcd32e83c1fa03c33e6f40a0` |
| `lob_read_clob_response` | 176 | Oracle 19c, the LOB_OP READ response for the same CLOB, ten Cyrillic characters in AL16UTF16 | `be443b3bcbabcb9d54ade98ff875d674e107175c0b566474b37d4bbd20c12d0f` |
| `lob_read_blob_response` | 157 | Oracle 19c, the LOB_OP READ response for a one-byte BLOB | `25ce01892864c504fd42ff03a9c0ccf3bd70bd6078260411dc0ea04af6dc8401` |

Live test databases are external and are named here only by the environment
variables that supply them; see [README.md](README.md). Nothing about an
endpoint is recorded in this repository.
