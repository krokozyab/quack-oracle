# oracle_scanner 0.8.1

Built for DuckDB v2.0.0. Install with `INSTALL oracle_scanner FROM community;`
once the release is published. Two fixes, contributed by
[@goraj](https://github.com/goraj): connecting to Oracle 19c servers that leave
the out-of-band check unanswered, and stopping interrupted calls on the server
as well as in DuckDB. Everything else is as in [0.8.0](RELEASE_NOTES_0.8.0.md).

## Connecting

- **19c servers that leave the out-of-band check unanswered.** When a listener
  asks for the out-of-band check after ACCEPT, the client sends it and then
  waited for an acknowledgement. Some 19c servers (seen on 19.29) never send
  one: they wait for the client's next message, so every connect failed with
  `Oracle TCP read timed out` after 30 s. The client now goes on at once and
  skips the acknowledgement when a server does send one, as servers verified
  earlier do.

## Cancelling

- **Cancel on those servers.** A server that never acknowledged the check
  ignored the in-band interrupt for the whole call: the read timed out and the
  session could not be used again. A cancel on such a connection is now sent as
  a TCP urgent byte, and Oracle stops the call with ORA-01013. Servers that
  acknowledge the check still get the in-band interrupt. TCPS is unchanged, and
  cancelling over TCPS remains unsupported.
- **Ctrl+C stops the call on the server.** `oracle_query`, `oracle_plsql`,
  `oracle_execute`, `oracle_execute_many`, `oracle_execute_admin` and the
  `oracle_call_*` functions waited for Oracle to finish whatever the interrupt.
  The transactional functions stopped reading but left the statement running in
  Oracle. An interrupt now asks Oracle to cancel the call, waits up to 2 s for
  ORA-01013, and stops waiting after that. The query ends with DuckDB's
  `Interrupted` error rather than an Oracle or network error, and the connection
  can be used again.

  On a server that acknowledges the check, a CPU-bound statement stopped on the
  server within the interrupt; a `dbms_session.sleep` in PL/SQL was still
  running when DuckDB returned after the 2 s wait and ended on its own a few
  seconds later.

## Verification

Offline protocol, adapter and SQL suites, and all 18 live stages against Oracle
19c and Free 23ai, both of which acknowledge the check. The contributor verified
the unacknowledged path live on 19.29.
