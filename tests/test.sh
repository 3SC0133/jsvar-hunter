#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

SCRIPT="$SCRIPT_DIR/jsvar-hunter.sh"
ANALYZER="$SCRIPT_DIR/lib/js_analyzer.py"
FIXTURE="$SCRIPT_DIR/tests/fixtures/sample.js"

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


# ============================================================================
# Core CLI tests
# ============================================================================

test_script_exists() {
    [[ -f "$SCRIPT" ]]
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


# ============================================================================
# Analyzer tests
# ============================================================================

test_analyzer_exists() {
    [[ -f "$ANALYZER" ]]
}


test_analyzer_syntax() {
    python3 -m py_compile "$ANALYZER"
}


test_fixture_exists() {
    [[ -f "$FIXTURE" ]]
}


test_analyzer_fixture() {
    PYTHONPATH="$SCRIPT_DIR/lib" \
        python3 - "$FIXTURE" <<'PY'
import sys

from js_analyzer import analyze_file


fixture = sys.argv[1]
result = analyze_file(__import__("pathlib").Path(fixture))
findings = result["findings"]


assert "/api/v1/users" in findings["api_endpoint"]

assert "/api/account/profile" in findings["api_endpoint"]

assert "/graphql" in findings["api_endpoint"]

assert "wss://socket.example.test/ws" in findings["websocket"]

assert any(
    "api.example.test" in value
    for value in findings["absolute_url"]
)

assert any(
    "TEST_ONLY_FAKE_API_KEY" in value
    for value in findings["secret_candidate"]
)

assert any(
    "TEST_ONLY_FAKE_TOKEN" in value
    for value in findings["secret_candidate"]
)

assert findings["http_call"]

assert findings["console"]

assert findings["source_map"]
PY
}


test_analyzer_json() {
    python3 "$ANALYZER" "$FIXTURE" --format json |
        python3 -c '
import json
import sys

data = json.load(sys.stdin)

assert data["type"] == "javascript_analysis"
assert "findings" in data
assert "api_endpoint" in data["findings"]
'
}


test_analyzer_text() {
    python3 "$ANALYZER" "$FIXTURE" --format text |
        grep -q '\[api_endpoint\]'
}


test_analyzer_missing_file() {
    ! python3 "$ANALYZER" \
        "$SCRIPT_DIR/tests/fixtures/does-not-exist.js" \
        >/dev/null 2>&1
}


# ============================================================================
# Test execution
# ============================================================================

run_test "Main script exists" test_script_exists
run_test "Bash syntax" test_syntax
run_test "Help command" test_help
run_test "Version command" test_version
run_test "Invalid format rejected" test_invalid_format
run_test "Invalid timeout rejected" test_invalid_timeout
run_test "Missing timeout rejected" test_missing_timeout_value
run_test "Missing output rejected" test_missing_output_value
run_test "Unknown argument rejected" test_unknown_argument

run_test "Analyzer exists" test_analyzer_exists
run_test "Analyzer Python syntax" test_analyzer_syntax
run_test "JavaScript fixture exists" test_fixture_exists
run_test "Analyzer detects fixture content" test_analyzer_fixture
run_test "Analyzer JSON output" test_analyzer_json
run_test "Analyzer text output" test_analyzer_text
run_test "Analyzer rejects missing file" test_analyzer_missing_file


# ============================================================================
# Summary
# ============================================================================

printf '%s\n' '========================================'
printf 'Tests passed: %d\n' "$PASS"
printf 'Tests failed: %d\n' "$FAIL"
printf '%s\n' '========================================'

if [[ "$FAIL" -ne 0 ]]; then
    exit 1
fi

printf 'All tests passed.\n'
