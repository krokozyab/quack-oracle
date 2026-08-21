# Releasing

## Where the version comes from

The extension's own version is `EXTENSION_VERSION` in
[extension_config.cmake](../extension_config.cmake), and it is what the built
artifact carries. Nothing derives it from Git, so a release is two edits and a
tag rather than a tag alone:

1. Set `EXTENSION_VERSION` to the release version, without the `-dev` suffix.
2. Tag the commit `v<version>`, matching what `EXTENSION_VERSION` now says.
3. Set `EXTENSION_VERSION` back to the next `-dev` version.

The DuckDB version an artifact is built against is pinned in three places that
must agree: the `duckdb` submodule, `duckdb_version` in
[the workflow](../.github/workflows/MainDistributionPipeline.yml), and the
`extension-ci-tools` branch the workflow reuses. `docs/UPDATING.md` covers
moving all three.

## Never publish a locally built artifact

A local checkout usually has no tags in the `duckdb` submodule, so DuckDB
reports its own version as `v0.0.1` and stamps that into anything built here:

```
$ ./build/release/duckdb -c "select version()"
v0.0.1
```

An extension refuses to load into a DuckDB whose version does not match the one
it was built against, so such an artifact loads nowhere but the tree that
produced it. Release binaries come from the distribution workflow, which checks
out a tagged DuckDB. Locally this is noise, not a defect — but it is the reason
`make release` output is for testing only.

## Before tagging

Everything below runs without a database:

```sh
make release
ctest --test-dir build/release/extension/oracle_scanner --output-on-failure
scripts/check_no_oracle_client.sh
scripts/capture_inventory.sh   # hashes must match PROVENANCE.md
```

And with one, against every endpoint the release is claimed to support:

```sh
scripts/run_live_stages.sh
```

## Community Extensions submission

The submission is a pull request against
[`duckdb/community-extensions`](https://github.com/duckdb/community-extensions),
not a change in this repository: a descriptor file under `extensions/` naming
this repository and the exact commit to build. **Take the descriptor's schema
from that repository's template rather than from here** — it is theirs and it
changes. What this project has to supply it with:

| They ask for | This project's answer |
| --- | --- |
| extension name | `oracle_scanner` |
| license | Apache-2.0, see [LICENSE](../LICENSE) |
| repository and ref | this repository at the release tag |
| a one-line description | reads Oracle over TNS/TTC with no Oracle client |
| a smoke test that runs in their CI | see below |

Their CI has no Oracle, so the smoke test cannot connect to one. It has to
prove the extension loads and registers its surface:

```sql
SELECT loaded FROM duckdb_extensions() WHERE extension_name = 'oracle_scanner';
SELECT count(*) FROM duckdb_functions() WHERE function_name LIKE 'oracle%';
```

Anything that reaches a database belongs in the live lanes, which are triggered
by hand and need credentials that exist nowhere but the maintainer's own
environment.
