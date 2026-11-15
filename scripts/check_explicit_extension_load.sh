#!/usr/bin/env bash
# Verify that a CLI can measure a chosen loadable build without a built-in copy.
set -euo pipefail
if [[ $# != 2 || $2 != /* ]]; then
    echo "usage: $0 /path/to/duckdb /absolute/path/to/oracle_scanner.duckdb_extension" >&2
    exit 2
fi
extension_path=${2//\'/\'\'}
"$1" -no-agent -unsigned -batch <<SQL
.bail on
SELECT CASE WHEN EXISTS (SELECT 1 FROM duckdb_extensions()
    WHERE extension_name = 'oracle_scanner' AND loaded)
    THEN error('oracle_scanner is already loaded; rebuild with ORACLE_SCANNER_STATIC_LINK=OFF')
    ELSE 'No preloaded oracle_scanner' END;
LOAD '${extension_path}';
SELECT CASE WHEN EXISTS (SELECT 1 FROM duckdb_extensions()
    WHERE extension_name = 'oracle_scanner' AND loaded)
    THEN 'Explicit oracle_scanner load succeeded'
    ELSE error('Explicit oracle_scanner load did not register the extension') END;
SQL
