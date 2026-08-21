#!/usr/bin/env bash
#
# Runs the live wire stages against one Oracle endpoint.
#
# The stages live in test/cpp/protocol_test.cpp and each is selected by
# ORACLE_SCANNER_LIVE_STAGE. Keeping the list here rather than in a shell
# history is the point: a lane that only exists as something somebody types is
# a lane nobody else can reproduce, and the list drifts silently as stages are
# added.
#
# Everything comes from the environment; nothing is defaulted and nothing is
# written down. See README.md for the variables.
#
#   ORACLE_SCANNER_LIVE=1
#   ORA19C_HOST / ORA19C_PORT / ORA19C_SERVICE / ORA19C_USER / ORA19C_PASSWORD
#   ORACLE_SCANNER_LIVE_PROTOCOL=tcps plus the TLS/wallet variables, for TCPS
#   ORACLE_SCANNER_LIVE_UNTRUSTED_CA_FILE, to add the certificate-rejection lane
#
# Usage: scripts/run_live_stages.sh [path-to-protocol-test]

set -uo pipefail

binary="${1:-build/debug/extension/oracle_scanner/oracle_scanner_protocol_test}"
if [ ! -x "$binary" ]; then
    echo "run_live_stages: $binary is not executable; build it with 'make debug'" >&2
    exit 2
fi
if [ "${ORACLE_SCANNER_LIVE:-}" != "1" ]; then
    echo "run_live_stages: set ORACLE_SCANNER_LIVE=1 to opt in" >&2
    exit 2
fi

stages=(
    connect
    auth
    execute
    fetch
    close_cursor
    transaction_control
    native_session
    native_interleaved_cursors
    native_zero_row
    native_wide_row
    native_wide_row_continuation
    native_cancel
    native_session_binds
    native_session_numeric_bind
    native_session_close_first
    plsql_cursor_fetch
    plsql_scalar
    plsql_implicit_fetch
)

is_tcps=0
if [ "${ORACLE_SCANNER_LIVE_PROTOCOL:-tcp}" = "tcps" ]; then
    is_tcps=1
    # Cancellation over TLS is deliberately unimplemented: the interrupt is an
    # out-of-band TCP byte and no capture shows what TCPS puts in its place.
    stages=("${stages[@]/native_cancel/}")
fi
if [ -n "${ORACLE_SCANNER_LIVE_UNTRUSTED_CA_FILE:-}" ] && [ "$is_tcps" = "1" ]; then
    stages+=(tcps_negative)
fi

failed=()
passed=0
for stage in "${stages[@]}"; do
    [ -z "$stage" ] && continue
    # One retry: a stage that fails twice is a defect, and a stage that fails
    # once against a cloud endpoint usually is not.
    if ORACLE_SCANNER_LIVE_STAGE="$stage" "$binary" >/dev/null 2>&1 ||
        ORACLE_SCANNER_LIVE_STAGE="$stage" "$binary" >/dev/null 2>&1; then
        passed=$((passed + 1))
    else
        failed+=("$stage")
        # Show why, once, so a failure in CI is actionable without a rerun.
        ORACLE_SCANNER_LIVE_STAGE="$stage" "$binary" 2>&1 | tail -3 >&2
        if [ "$stage" = "connect" ]; then
            # Nothing after this can succeed if the endpoint is not reachable,
            # and every remaining stage would spend its own connect timeout
            # proving the same thing.
            echo "run_live_stages: the endpoint is not reachable; skipping the rest" >&2
            break
        fi
    fi
done

if [ ${#failed[@]} -ne 0 ]; then
    echo "run_live_stages: $passed passed, failed:${failed[*]}" >&2
    exit 1
fi
echo "run_live_stages: $passed stages passed"
