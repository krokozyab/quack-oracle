# oracle_scanner 0.8.3

Built for DuckDB v2.0.0 and v2.0.1. Install with
`INSTALL oracle_scanner FROM community;` once the release is published. One
fix on top of [0.8.2](RELEASE_NOTES_0.8.2.md), contributed by
[@goraj](https://github.com/goraj).

## Connecting

- **The out-of-band acknowledgement is accepted only where servers send it.**
  Since 0.8.1 a server's acknowledgement of the out-of-band check was accepted
  once per call rather than once per connection, so a stray two-byte control
  packet later in a session was skipped without complaint and switched
  out-of-band breaks off; a cancel on that connection would then go in-band to a
  server that does not read it during a call. The acknowledgement is now
  accepted once, ahead of the first response, and any other control packet is
  refused as a protocol error.

## Verification

Offline protocol, adapter and SQL suites against DuckDB v2.0.0 and v2.0.1, and
all 18 live stages against Oracle 19c and Free 23ai, both of which send the
acknowledgement.
