#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/jsvar-hunter.sh"

PASS=0
FAIL=0

run_test() {
    local name="$1"
    shift

    printf '[TEST] %s\n' "$name"

    if "$@"; then
        printf '[PASS] %s\n\n' "$name"
        PASS=$((PASS + 1))
    else
        printf '[FAIL] %s\n\n' "$name"
        FAIL=$((FAIL + 1))
    fi
}

test_syntax() {
    bash -n "$SCRIPT"
}

test_help() {
    "$SCRIPT" --help >/dev/null
}

test_version() {
    "$SCRIPT" --version >/dev/null
}

test_invalid_format() {
    ! "$SCRIPT" example.com --format invalid >/dev/null 2>&1
}

test_invalid_timeout() {
    ! "$SCRIPT" example.com --timeout 0 >/dev/null 2>&1
}

test_missing_timeout_value() {
    ! "$SCRIPT" example.com --timeout >/dev/null 2>&1
}

test_missing_output_value() {
    ! "$SCRIPT" example.com --output >/dev/null 2>&1
}

test_unknown_argument() {
    ! "$SCRIPT" example.com --this-does-not-exist >/dev/null 2>&1
}

run_test "Bash syntax" test_syntax
run_test "Help command" test_help
run_test "Version command" test_version
run_test "Invalid format rejected" test_invalid_format
run_test "Invalid timeout rejected" test_invalid_timeout
run_test "Missing timeout rejected" test_missing_timeout_value
run_test "Missing output rejected" test_missing_output_value
run_test "Unknown argument rejected" test_unknown_argument

printf '%s\n' '========================================'
printf 'Passed: %d\n' "$PASS"
printf 'Failed: %d\n' "$FAIL"
printf '%s\n' '========================================'

if [[ "$FAIL" -ne 0 ]]; then
    exit 1
fi

printf 'All tests passed.\n'
