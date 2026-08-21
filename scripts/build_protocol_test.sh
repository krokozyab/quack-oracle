#!/usr/bin/env bash
# Builds and runs test/cpp/protocol_test.cpp standalone, without configuring or
# compiling DuckDB. Seconds instead of the tens of minutes `make debug` needs,
# so it is the inner loop for any change below the DuckDB adapter.
#
# The source list is derived from the oracle_scanner_protocol_test target in
# CMakeLists.txt rather than duplicated here, so adding a source file to that
# target is enough to keep this path working.
#
# Usage: scripts/build_protocol_test.sh [output-binary]
# OpenSSL is resolved through pkg-config; override with CXX / OPENSSL_FLAGS.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

output="${1:-${TMPDIR:-/tmp}/oracle_scanner_protocol_test}"

sources=()
while IFS= read -r source; do
    if [[ ! -f "${source}" ]]; then
        echo "scripts/build_protocol_test.sh: ${source} is listed in CMakeLists.txt but missing" >&2
        exit 1
    fi
    sources+=("${source}")
done < <(awk '/add_executable\(oracle_scanner_protocol_test/,/\)$/' CMakeLists.txt |
             grep -o 'src/[a-z0-9_]*\.cpp')

if [[ ${#sources[@]} -eq 0 ]]; then
    echo "scripts/build_protocol_test.sh: no sources parsed from CMakeLists.txt" >&2
    exit 1
fi

read -r -a openssl_flags <<<"${OPENSSL_FLAGS:-$(pkg-config --cflags --libs openssl)}"

scratch="$(mktemp -d)"
trap 'rm -rf "${scratch}"' EXIT

# duckdb_miniz is vendored third-party code and does not build clean under this
# project's warning settings, so it is compiled on its own with warnings off.
"${CXX:-c++}" -std=c++17 -w -c duckdb/third_party/miniz/miniz.cpp -o "${scratch}/miniz.o"

"${CXX:-c++}" -std=c++17 -Wall -Wextra -Werror \
    -Isrc/include -Iduckdb/third_party/miniz \
    test/cpp/protocol_test.cpp "${sources[@]}" "${scratch}/miniz.o" \
    "${openssl_flags[@]}" \
    -o "${output}"

echo "scripts/build_protocol_test.sh: built ${output} from ${#sources[@]} sources"

# Second pass: the same sources with the macros <windows.h> defines that collide
# with ordinary identifiers — min, max, IN, OUT. Those are pure preprocessor, so
# a compiler here reproduces that Windows breakage exactly, in seconds. This
# project spent four release-matrix runs discovering them one at a time. Only
# syntax is checked; nothing is linked or run.
if ! "${CXX:-c++}" -std=c++17 -fsyntax-only \
    -include scripts/windows_macros_stub.h \
    -Isrc/include -Iduckdb/third_party/miniz \
    test/cpp/protocol_test.cpp "${sources[@]}" \
    "${openssl_flags[@]}" 2>"${scratch}/windows_macros.log"; then
    echo "scripts/build_protocol_test.sh: the sources do not survive the Windows min/max/IN/OUT macros:" >&2
    head -20 "${scratch}/windows_macros.log" >&2
    exit 1
fi
echo "scripts/build_protocol_test.sh: sources also compile with the Windows min/max/IN/OUT macros defined"

exec "${output}"
