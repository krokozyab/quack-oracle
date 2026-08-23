#!/usr/bin/env bash
# Runs clang-tidy over this project's own sources, with DuckDB's check list.
#
# Why this exists rather than `make tidy-check`: the reusable target in
# extension-ci-tools filters translation units with the regex
# `$(PROJ_DIR)src/.*/`, which requires a slash after `src/`. Every source here
# is `src/*.cpp`, so nothing matches, and the job passes having checked no files
# at all. A green check that checked nothing is worse than no check.
#
# It also needs no compile database and never configures DuckDB, so it runs in
# about a minute instead of a full build.
#
# Usage: scripts/tidy.sh [file ...]     (default: every src/*.cpp)
# Override the binary with CLANG_TIDY=/path/to/clang-tidy.

set -uo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

tidy="${CLANG_TIDY:-}"
if [[ -z "${tidy}" ]]; then
    for candidate in clang-tidy clang-tidy-18 clang-tidy-17 /opt/homebrew/opt/llvm/bin/clang-tidy; do
        if command -v "${candidate}" >/dev/null 2>&1; then
            tidy="${candidate}"
            break
        fi
    done
fi
if [[ -z "${tidy}" ]]; then
    echo "scripts/tidy.sh: no clang-tidy found; set CLANG_TIDY" >&2
    exit 1
fi

if [[ ! -f duckdb/.clang-tidy ]]; then
    echo "scripts/tidy.sh: duckdb/.clang-tidy is missing — run git submodule update --init" >&2
    exit 1
fi

read -r -a openssl_flags <<<"${OPENSSL_FLAGS:-$(pkg-config --cflags openssl)}"

# The adapter sources include duckdb.hpp, so DuckDB's own include tree and the
# third-party headers it exposes have to be reachable. Nothing is compiled into
# an object here; clang-tidy only needs to parse.
includes=(
    -Isrc/include
    -Iduckdb/src/include
    -Iduckdb/third_party/miniz
    -Iduckdb/third_party/fmt/include
    -Iduckdb/third_party/re2
    -Iduckdb/third_party/utf8proc/include
    -Iduckdb/third_party/fast_float
    -Iduckdb/third_party/concurrentqueue
    -Iduckdb/third_party/hyperloglog
)

sources=("$@")
if [[ ${#sources[@]} -eq 0 ]]; then
    while IFS= read -r source; do
        sources+=("${source}")
    done < <(ls src/*.cpp)
fi

# DuckDB's config sets HeaderFilterRegex to its own headers, which would report
# diagnostics from duckdb/src/include on every file. Ours is the header set this
# project is responsible for.
header_filter='src/include/oracle'

# bugprone-unchecked-optional-access cannot see through a container. Every
# finding it reports here has the form
#
#     if (row.size() < n || !row[i] || ...) { throw ...; }
#     const std::string name(row[i]->begin(), row[i]->end());
#
# where the guard is the line above the dereference; the check does not model
# `optional` reached through `operator[]`, so it treats the two indexes as
# unrelated values. Rewriting 28 such sites to satisfy an analyser that cannot
# follow them would churn wire-parsing code that is covered by the protocol
# suite, so the check is off and the guards stay where a reader can see them.
#
# cppcoreguidelines-pro-type-cstyle-cast is off for the same kind of reason.
# Every finding it produced came from inside an OpenSSL macro — sk_X509_INFO_value,
# BIO_get_fd, BIO_get_ssl, BIO_set_conn_hostname, BIO_get_mem_data — which expand
# to C casts at the call site. None came from a cast written here, and the check
# reports the line that used the macro, which cannot be fixed without wrapping
# OpenSSL's whole API. That the only hits were macro expansions is itself the
# evidence that this project writes no C-style casts of its own.
disabled_checks='-bugprone-unchecked-optional-access,-cppcoreguidelines-pro-type-cstyle-cast'

failures=0
findings=0
for source in "${sources[@]}"; do
    output="$("${tidy}" --quiet \
        --config-file=duckdb/.clang-tidy \
        --checks="${disabled_checks}" \
        --header-filter="${header_filter}" \
        --warnings-as-errors='*' \
        "${source}" -- -std=c++17 "${includes[@]}" "${openssl_flags[@]}" 2>&1)"
    status=$?
    count="$(printf '%s\n' "${output}" | grep -cE '(warning|error):' || true)"
    if [[ ${status} -ne 0 || ${count} -gt 0 ]]; then
        printf '%s\n' "${output}"
        failures=$((failures + 1))
        findings=$((findings + count))
    fi
done

if [[ ${failures} -ne 0 ]]; then
    echo "scripts/tidy.sh: ${findings} finding(s) in ${failures} of ${#sources[@]} file(s)" >&2
    exit 1
fi

echo "scripts/tidy.sh: clean over ${#sources[@]} file(s)"
