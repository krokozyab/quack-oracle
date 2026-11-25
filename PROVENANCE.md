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
| DuckDB itself (submodule, pinned `v1.5.6`) | linked as a library; `duckdb_miniz` is compiled from its vendored copy for bounded in-memory wallet ZIP reading | MIT |
| OpenSSL | linked, not vendored: TLS transport and the digest and cipher primitives O5LOGON needs | Apache-2.0 |
| python-oracledb Thin | **reasoning and invariants, not code and not bytes.** It is the upstream of the protocol invariants recorded in comments throughout `src/`: which field, bit or length a client sends, and what breaks otherwise. | Apache-2.0 / UPL |
| go-ora (`github.com/sijms/go-ora`, commit `360b4b7ac9e96cee3e443180f2d6412bcacee62a`) | **reasoning, not code and not bytes.** A second reading of the listener exchange for multi-address connects: where REDIRECT data sits (inline after a UB2 length, or in the next DATA packet), its NUL between address and reconnect data and the 0x02 flag that announces it, the 0x04 flag on a re-CONNECT, and `(ERR=...)` in a REFUSE. Checked against python-oracledb Thin at commit `4a6d3b393232f6c5d66a497b7d137aa427f289d8` (`connect.pyx`, `connection.pyx`, `connect_params.pyx`), which is also where the FAILOVER / LOAD_BALANCE selection rules come from. Where the two differ, the code says which it follows and why. | MIT |

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
| `jdbc_lob_prefetch_define_char` | 126 | Oracle JDBC Thin 23.7.0.25.01 against Oracle 19c, `setLobPrefetchSize(4096)` and fetch size 10: the LOB prefetch define for `SELECT id, ch5, c` (NUMBER, CHAR(5), CLOB), recorded after login through a forwarding proxy; the CHAR column is defined as VARCHAR2 | `122b53a9116f47ffaf87aa58e5b25d053c5e591acb475290f576af9f426420fa` |
| `lob_row_one_clob` | 196 | Oracle 19c, fetch response for a single-row `SELECT` of one CLOB column | `b093b740172362a0c1db3493f07b67e02d0423f284bf4fdaa0c204e7642f758e` |
| `lob_rows_with_bit_vector` | 558 | Oracle 19c, fetch response for four rows of one CLOB column, where every row after the first arrives behind a BIT_VECTOR | `883809d2ce8d76825afcebf4cdc61fc4bd793f621a00035eb5065fa6c5891dde` |
| `lob_get_length_response` | 151 | Oracle 19c, the LOB_OP GET_LENGTH response for a ten-character CLOB | `79ca06d9b2b0e87a50d055cf9247c91aeed04705fcd32e83c1fa03c33e6f40a0` |
| `lob_read_clob_response` | 176 | Oracle 19c, the LOB_OP READ response for the same CLOB, ten Cyrillic characters in AL16UTF16 | `be443b3bcbabcb9d54ade98ff875d674e107175c0b566474b37d4bbd20c12d0f` |
| `lob_read_blob_response` | 157 | Oracle 19c, the LOB_OP READ response for a one-byte BLOB | `25ce01892864c504fd42ff03a9c0ccf3bd70bd6078260411dc0ea04af6dc8401` |
| `plain_rowid_fetch` | 78 | Oracle 19c, fetch response for `SELECT id, r` over a ROWID column: one row, then a NULL ROWID. The text decoded from the first row matches `ROWIDTOCHAR` of the same row on 19c and Free | `daf4a79391f84d674c60351db0cae2b0d343bc23eb20b72475317e5e9fc2c1c5` |
| `physical_urowid_fetch` | 82 | Oracle 19c, the same for a UROWID column holding a physical rowid, then a NULL | `a5406773617217035a2ce9d45310fa729c0f7552e7b932746097c33c00a529b5` |
| `logical_urowid_fetch` | 93 | Oracle 19c, the same for a UROWID column holding the rowids of an index-organized table. It frames like a physical one and is not decoded | `794ddd566c13a80c9ab55e7db2e9410d219e3ed910d328d3d7a150ae277b1346` |
| `long_fetch` | 92 | Oracle 19c, fetch response for `SELECT id, l` over a LONG column: `short`, then NULL, which arrives as an indicator of -1 and return code 1405 | `9acd33da9a3f85cb107a61c8dcfc491bbaf1ff7fc3ff4222ad2b0dd10fe07aac` |
| `long_raw_fetch` | 81 | Oracle 19c, the same for a LONG RAW column holding `DEADBEEF` | `96283a6c136e129b211d2245378f5a1d39290c6b707b5fe5499e1f5e6447874a` |
| `long_middle_fetch` | 109 | Oracle 19c, fetch response for `SELECT a, l, b` over three rows where the LONG sits between two other columns and holds a value, NULL and a value, the third row behind a BIT_VECTOR | `809f7b2d1d83a1c49ce4f1c4e2e4029b8bca5e2bcffd812f68fed3d22055d06e` |
| `interval_ym_value_bytes` | 15 | Oracle 19c and Free, three INTERVAL YEAR TO MONTH values: `2-3`, `-5-11`, `0-0` | `3b1f11e0c16f787be39958da84045a434a4d0a86e3325c38bc51dce8c6d9a0d5` |
| `interval_ds_value_bytes` | 33 | Oracle 19c and Free, three INTERVAL DAY TO SECOND values: `3 04:05:06.789012345`, `-12 23:59:59.5`, `0 0:0:0` | `0fa30cc86aff9f31922dba84155fa5c923a59cf688758fc7a452db6b2a0e8a09` |
| `nvarchar_value_bytes` | 30 | Oracle 19c and Free, one NVARCHAR2 value in UTF-16BE, ending in a surrogate pair | `4b91f33a7bdcccc78e7faeedae3566cbd49c6be8842dbe1920f098db696e3ee0` |
| `boolean_value_bytes` | 2 | Free 23ai, a BOOLEAN column's TRUE then FALSE as sent for type 252 to a client advertising TTC field version 17: one byte each | `47dc540c94ceb704a23875c11273e16bb0b8a87aed84de911f2133568115f254` |
| `ltz_value_bytes` | 11 | Free 23ai, one TIMESTAMP(6) WITH LOCAL TIME ZONE (2026-03-04 05:06:07.123456) read from a session whose time zone is +00:00 | `adc7213e52613cb8b6748b14bb0388ec7f4b7af8594e2364bdb881a6e8f95e50` |
| `python_nchar_bind` | 23 | python-oracledb 4.0.1 Thin against Free 23ai: the bind metadata and value of an NCHAR `'ab'` (type 96, form 2, UTF-16BE) | `f4926f5de9166b2e27dfc29f9d2cdda8209588b772acacf046b3f31c62cd7c81` |
| `python_nvarchar_bind` | 27 | the same client, an NVARCHAR2 value (type 1, form 2, UTF-16BE) | `aa6cfe87eddc1be2deb3d8af742f23f418b5fe020a582fd60ab388436934418e` |
| `python_boolean_bind` | 18 | the same client, a BOOLEAN TRUE (type 252, value `01 01`) | `895c6cdc5cbbad2864bcf18d02887a71446805c5a9c1bcaabea6dff87a0f989d` |
| `python_long_bind_row` | 61 | python-oracledb 4.0.1 Thin against Free 23ai, an insert of `(id, clob, nclob)` where the CLOB is 40000 characters: the three binds' metadata and the start of the row, which carries the id, then the short NCLOB, then the CLOB's first chunk header: a bind with a buffer past 32767 bytes has its value sent after the others | `13a0e56ae1a03ffbbb7cd43e1ca3693e016736a3bb39487924486d3a4e6f7b32` |
| `python_interval_ds_bind` | 27 | the same client, an INTERVAL DAY TO SECOND `3 4:5:6.000007` (type 183, 11 bytes) | `462ed8316388b543137054e1836096601a1dab5560865fd22f6a247bed51e357` |
| `oson_nested_object` | 59 | Free 23ai, a JSON column holding `{"a":{"b":[1,2,{"c":"x"}]}}`: an OSON image, the form a JSON column is stored and sent in | `3d0320d7a43b2bcbc4bf0d0acf94e384a38cf9146b1839aa88d8b6dacf4d6c2d` |
| `oson_shared_fields` | 72 | the same, `[{"a":1,"b":2},{"a":3,"b":4},{"b":5,"a":6}]`, whose objects share one list of field numbers | `85ae4512830a444808aa5337513313ada3d8f1a3af1ac4f71c74930158c965f8` |
| `oson_u16_count` | 532 | the same, an array of 256 nulls: a child count of two bytes | `8517a8d570fc3666a0f5d0ee2e362653dab273c0bfee4db8b0d4fd7949f3a47f` |
| `oson_text_and_numbers` | 112 | the same, an object with a non-ASCII key and string, escapes, a negative decimal, true, false, null and a 30-digit NUMBER | `68316e3b3cfa8888454f169b93dc9e725e7328ad1502ba68c6e8f7a765aa2b6e` |
| `oson_native_scalars` | 159 | the same, `json_object()` over a TIMESTAMP, DATE, BINARY_DOUBLE, BINARY_FLOAT, RAW, INTERVAL YEAR TO MONTH, INTERVAL DAY TO SECOND and TIMESTAMP WITH TIME ZONE | `0e27ac65cd33f302bccbe86749aca7cc4c6228f20fc3cf33bfaf26657df6a7c4` |
| `oson_long_field_name` | 304 | the same, an object with a 256-byte field name and a short one: image version 3 | `235ed4e632ad1de388157202d24b943bc9aa6d2c654bfd29584ab5272d7c3f3c` |
| `oson_embedded_vectors` | 107 | the same, `json_object()` over a dense FLOAT32 and a sparse FLOAT32 VECTOR | `088e9d42138c95a43b6e8d5eb156f314559a25c1a4932a2e242157e6aa23d3d3` |
| `vector_float32_value` | 29 | Free 23ai, a VECTOR(3,FLOAT32) `[1.5, 2, 3]` as the locator's content holds it | `a323decaeb1869fc56681b68efa098ed95a4f097cc7934e505b7472e96d38811` |
| `vector_int8_value` | 21 | the same, a VECTOR(4,INT8) `[1, 2, 3, 4]` | `1b5c6cf9cd4b654885441039f14abc9394d717e2cb4dbb37e981cb82d5aebe49` |
| `vector_binary_value` | 18 | the same, a VECTOR(8,BINARY) `[5]` | `7992f76ed8c95c60c807726656d46619d4faa1531a37107014b5a1a96c52e1ca` |
| `vector_float64_value` | 41 | the same, a VECTOR(3,FLOAT64) `[1.5, -2, 0.1]` | `30970684fa92902a6967236582300485d6b4ee9b4a0ab17f163e04755caf30c5` |
| `vector_sparse_value` | 35 | the same, a VECTOR(5,FLOAT32,SPARSE) `[5,[1,3],[1.5,2.5]]` | `3a9a43ed90245e8115a0168be1f27967611643d678e190c70645e2a34e84de7f` |
| `python_inline_define_json` | 106 | python-oracledb 4.0.1 Thin against Free 23ai: the define-and-fetch it sends for `select id, j from QO_J` after the describe (sequence 4, cursor 2, two rows, a NUMBER column and a JSON column), the JSON column asking for 32 MiB of prefix | `c1a405132313dc71c0107a9a6cf6737ac2f8c53787c909a4de43fcab601b5be2` |
| `python_inline_define_mixed` | 438 | the same client's define for a 23-column query: NUMBER, VARCHAR2, CHAR, DATE, the TIMESTAMP family, RAW, BINARY_FLOAT and DOUBLE, NVARCHAR2, NCHAR, BOOLEAN, both intervals, CLOB, BLOB, NCLOB, JSON and VECTOR | `9dc9e6328b00c5090bda5888d21b38f694ee4868cde39dd7ecda1a73c090b182` |
| `python_inline_rows_mixed` | 729 | the server's answer to it: two rows, the first with every column set (a CLOB, BLOB and NCLOB cell carry a size and a locator; JSON and VECTOR carry their first bytes too), the second NULL but for its first column | `9d34dcb19187dcb72d04b5e16b1df4820c820edd4b8c77e6625c5d9cc8e50f1c` |
| `python_vector_float32_bind` | 1 | python-oracledb 4.0.1 Thin against Free 23ai, an insert of one VECTOR column, `array('f', [1.5, 2, 3])`: the bind's metadata, then the row (a locator that states the image's length, then the image) | `6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d` |
| `python_vector_int8_bind` | 1 | the same, `array('b', [1, -2, 3])` | `084fed08b978af4d7d196a7446a86b58009e636b611db16211b65a9aadff29c5` |
| `python_vector_sparse_bind` | 1 | the same, `SparseVector(5, [1, 3], array('f', [1.5, 2.5]))` | `6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d` |
| `python_vector_update_row` | 441 | the same client's UPDATE that sets six VECTOR columns, a JSON text, the id and a rowid: the row, in which the six vectors come first, in the order the binds are declared, ahead of the short binds declared after them | `4decf7532e14622ab49332b9a7462215ccb6beaead4e3823171cee3360c546e0` |
| `python_lob_create_temp_clob` | 1 | python-oracledb 4.0.1 Thin against Free 23ai, `createlob(DB_TYPE_CLOB)`: the LOB_OP that creates a temporary CLOB (a zeroed 40-byte locator, duration 10, the character-set form and type number, UTF-8) | `c25af6183356814199aad6bf078c6d5b1f2773754523e6a664fdbb6dfe666648` |
| `python_lob_create_temp_blob` | 1 | the same for `DB_TYPE_BLOB` | `503b15401064a5acdbb9de23c5211d932e8f6de9413eed8701485ed17e90fa3e` |
| `python_lob_create_temp_response` | 1 | the server's answer to the CLOB create: the new locator, the character set and a flags byte, then the end-of-call | `db876c6c4b1484e2a522d94b948e7ca0b75f9b7bc20b5a99bbe3352be8907f95` |
| `python_lob_write_clob_request` | 1 | the same client's `write("x" * 100)` to that CLOB: the locator, then the content as 200 bytes of UTF-16BE in one LOB_DATA message | `3c8014ac0f2d86f41e6cd77b337253a54083af1a7d8ad0a70c2a52939cb2267f` |
| `python_lob_write_response` | 1 | the answer to that write: the updated locator and the end-of-call | `5807368bddbf13fdaeeba1d670c2e85092201844d708a06be5527c9223709a28` |
| `python_lob_free_piggyback` | 1 | the same client, one call after an INSERT that bound two temporary LOBs, releasing both: a piggybacked LOB_OP with operation FREE_TEMP and the array flag, the two locators concatenated | `6188705038d4520d6cf2ac3198a77690834915779d196de7be1831ec60e177dd` |
| `python_lob_locator_binds` | 1 | the INSERT (id, CLOB, BLOB) that bound those two temporary LOBs: the bind metadata (size 112, the prefetch flag, UTF-8 for the CLOB) and the row (each locator as a length and a length-prefixed 40 bytes) | `25a056126d38f7a89ea49d77df9f7e0b51cc09d916de2c8c2663b421ab4e0071` |
| `python_end_to_end_module` | 1 | python-oracledb 4.0.1 Thin against Free 23ai, `connection.module = "m"` then a query: the SET_END_TO_END_ATTR piggyback in front of it (the action is sent too, empty, because setting a module clears it) | `6c681ddf789f35eff4140e891ac2d0c5bb773afdfee466f207261a83f3536e29` |
| `python_end_to_end_all` | 1 | the same with `module`, `action`, `client_identifier` and `clientinfo` all set | `ff216a1a9df63e72593d366cb1cbd6e764e898a0f270ad7b9af161b3be4c8c08` |
| `python_end_to_end_client_info` | 1 | the same with only `clientinfo` | `e073981de0db60f4ed2984e8a0b5345dbb21c8c2da107fd9ddfd7bbd5f8e86ab` |
| `python_server_piggyback` | 1 | the server's session-return report in the answer to python-oracledb 4.0.1 Thin's ping after `module`, `action`, `client_identifier` and `clientinfo` were set: type 23, four entries, no session change | `1fad90e2ade6ae67650ffc1bbb20aa7567a65e1a1c1b83a2ac064989351d4caa` |

The python-oracledb binds carry the buffer size python chose, which is larger than the value; the test that uses them swaps in this client's size and requires every other byte to match. The TTIDTY negotiation template above is unchanged: this client advertises TTC field version 24 by overwriting that one byte of the request at run time, so its recorded hash still describes the capture. The python-oracledb defines above ask for more of a JSON or VECTOR value than this client does (32 MiB and 1 MiB where it asks for 64 KiB); the test that uses them compares those two column records by their fields and everything before them byte for byte.

Live test databases are external and are named here only by the environment
variables that supply them; see [README.md](README.md). Nothing about an
endpoint is recorded in this repository.

## Synthetic fixtures

Prepared scalar query reexecution uses `REEXECUTE_AND_FETCH` (function 78):
cursor ID, prefetch row count, execute option 0x20, zero second option, then
current scalar IN values. This layout was read from python-oracledb Thin at
commit `db085e51783ea1fc6884b451a99c693fe0761703`,
`messages/execute.pyx::_write_reexecute_message` and `constants.pxi`, and
cross-checked against the sibling protocol reference's reexecute parser.
Only protocol invariants were used. The byte expectations in
`TestPreparedQueryReexecuteWireAndState` are synthetic, not recorded packets.
The native path was exercised against Oracle 19c and Free, including changed
binds, repeated/empty results, eviction, and external table/type/precision DDL.
External revalidation can return a new describe; it must replace the saved
shape before row decoding. Review of `messages/base.pyx` at the same revision
(lines around 1344 and 1365) also established two invariants: a nonzero returned
cursor ID supersedes the old ID, and ORA-01007/ORA-00932 before returned rows can
request a full parse. The sibling `orawire/execute.go` reference was checked for
the cursor field layout. The native registry accepts a replacement only if it
is nonzero and does not collide with another active cursor.

`query_retry_fixture.hpp` creates all reexecute/error/describe replies in code;
none is a captured packet. Tests permit exactly one full query execution with
current SQL and binds after a completely consumed ORA-01007 or ORA-00932 reply
with no rows. They reject retries after rows, cancellation, any other error or
a failed retry. Protocol and adapter tests exercise the production helper and
transaction-session reuse. Live external ADD/MODIFY checks on Free and 19c
returned fresh descriptions rather than these invalidation errors; the error
branches are therefore covered synthetically, not claimed as live reproductions.

The multi-address and redirect tests in `test/cpp/protocol_test.cpp` build
their REDIRECT, REFUSE, ACCEPT and DATA packets in the test from the field
layouts named above. They are not captures, carry no bytes from any server or
client, and so are not inventoried with a hash; the tests say so where they
are defined. None of them has been checked against a live RAC or SCAN listener.
