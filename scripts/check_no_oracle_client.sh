#!/usr/bin/env bash
#
# Clean-machine acceptance: prove the built extension carries no Oracle client.
#
# The defining constraint of this project is that it never links or loads OCI,
# Instant Client, ODPI-C, ODBC, JDBC, a Python runtime, or a helper process. A
# violation would not announce itself — the extension would keep working on a
# developer machine that happens to have those libraries installed, and fail
# only for a user who does not. So the binary is inspected directly: every
# shared library it names, and every symbol it imports from outside itself.
#
# Usage: scripts/check_no_oracle_client.sh [path-to-extension-or-binary ...]
# With no arguments it checks whatever loadable extensions the build produced.

set -euo pipefail

targets=("$@")
if [ ${#targets[@]} -eq 0 ]; then
    while IFS= read -r found; do
        targets+=("$found")
    done < <(find build -name 'oracle_scanner.duckdb_extension' -type f 2>/dev/null || true)
fi

if [ ${#targets[@]} -eq 0 ]; then
    echo "check_no_oracle_client: no built extension found; run 'make release' or pass a path" >&2
    exit 2
fi

# Library names an Oracle client would arrive under. ODPI-C and node-oracledb
# both link OCI, so catching libclntsh catches them too; the rest are the other
# ways a driver could be pulled in.
library_pattern='libclntsh|libociei|libocijdbc|libnnz|libodpic|libodbc|libiodbc|libjvm|libpython|libsqlplus|instantclient'
# Symbols only an Oracle client exports. OCI* is the OCI entry-point prefix,
# dpi* is ODPI-C, SQLDriverConnect is ODBC, JNI_CreateJavaVM is JDBC's.
symbol_pattern='^_?OCI[A-Z]|^_?dpi[A-Z_]|SQLDriverConnect|JNI_CreateJavaVM|Py_Initialize'

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "check_no_oracle_client: $1 is required to inspect the binary and was not found" >&2
        exit 2
    fi
}

status=0
for target in "${targets[@]}"; do
    clean=1
    if [ ! -f "$target" ]; then
        echo "check_no_oracle_client: $target does not exist" >&2
        exit 2
    fi

    # A missing inspection tool must not look like a clean binary. The whole
    # point of this gate is that a violation is invisible from the outside, so
    # an inspection that produced nothing is a failure to check, not a pass.
    case "$(uname -s)" in
    Darwin)
        require_tool otool
        libraries="$(otool -L "$target" | tail -n +2)"
        ;;
    MINGW* | MSYS* | CYGWIN*)
        require_tool dumpbin
        libraries="$(dumpbin //dependents "$target")"
        ;;
    *)
        require_tool objdump
        libraries="$(objdump -p "$target" | grep NEEDED || true)"
        ;;
    esac
    if [ -z "$libraries" ]; then
        echo "check_no_oracle_client: $target reported no linked libraries at all; the inspection did not work" >&2
        exit 2
    fi
    if printf '%s' "$libraries" | grep -Eiq "$library_pattern"; then
        echo "check_no_oracle_client: $target links an Oracle client library:" >&2
        printf '%s\n' "$libraries" | grep -Ei "$library_pattern" >&2
        status=1
        clean=0
    fi

    # Undefined symbols are what the loader would resolve from somewhere else;
    # a defined symbol of the same name would be this project's own code.
    case "$(uname -s)" in
    Darwin)
        require_tool nm
        symbols="$(nm -u "$target")"
        ;;
    MINGW* | MSYS* | CYGWIN*)
        require_tool dumpbin
        symbols="$(dumpbin //imports "$target")"
        ;;
    *)
        require_tool nm
        symbols="$(nm -D --undefined-only "$target")"
        ;;
    esac
    if [ -z "$symbols" ]; then
        echo "check_no_oracle_client: $target reported no imported symbols at all; the inspection did not work" >&2
        exit 2
    fi
    if printf '%s' "$symbols" | grep -Eq "$symbol_pattern"; then
        echo "check_no_oracle_client: $target imports Oracle client symbols:" >&2
        printf '%s\n' "$symbols" | grep -E "$symbol_pattern" >&2
        status=1
        clean=0
    fi

    if [ $clean -eq 1 ]; then
        # Said per target: one dirty binary must not make a later clean one
        # look unchecked.
        echo "check_no_oracle_client: $target carries no Oracle client"
    fi
done

exit $status
