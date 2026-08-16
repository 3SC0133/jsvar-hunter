VERSION="2.0.0"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ANALYZER="$SCRIPT_DIR/lib/js_analyzer.py"

VERBOSE=false
IGNORE_CHECK=false

#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

VERSION="2.0.0"

VERBOSE=false
IGNORE_CHECK=false
INSECURE=false

TIMEOUT=20
FORMAT="txt"

OUTPUT_FILE="js_analysis_$(date +%Y%m%d_%H%M%S).txt"

USER_AGENT="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36"

TEMP_DIR=""
TARGET_INPUT=""
TARGET_HOST=""
TARGET_BASE=""

CURL_ARGS=()

# ============================================================================
# Cleanup
# ============================================================================

cleanup() {
    if [[ -n "${TEMP_DIR:-}" && -d "$TEMP_DIR" ]]; then
        rm -rf "$TEMP_DIR"
    fi
}

trap cleanup EXIT INT TERM

# ============================================================================
# Logging
# ============================================================================

log() {
    if [[ "$VERBOSE" == true ]]; then
        printf '[*] %s\n' "$*" >&2
    fi
}

info() {
    printf '[+] %s\n' "$*"
}

warn() {
    printf '[!] %s\n' "$*" >&2
}

error() {
    printf '[ERROR] %s\n' "$*" >&2
}

# ============================================================================
# Help
# ============================================================================

show_help() {
    cat <<EOF_HELP
JSVar Hunter v${VERSION}

JavaScript attack-surface discovery for authorized security testing.

Usage:
  $0 <domain|url> [options]

Options:
  --timeout N       HTTP timeout in seconds (default: 20)
  --output FILE     Output report path
  --format FORMAT   txt or jsonl (default: txt)
  --ignore-check    Skip HTTP accessibility validation
  --insecure        Disable TLS certificate verification
  -v, --verbose     Enable verbose output
  -h, --help        Show this help
  --version         Show version

Examples:
  $0 example.com
  $0 https://example.com --timeout 15
  $0 example.com --format jsonl --output results.jsonl
  $0 example.com --ignore-check

Dependencies:
  assetfinder, gau, waybackurls, curl, python3

Only scan systems you are authorized to test.
EOF_HELP
}

show_version() {
    printf 'JSVar Hunter v%s\n' "$VERSION"
}

# ============================================================================
# Dependency check
# ============================================================================

check_dependencies() {
    local missing=0
    local cmd

    for cmd in assetfinder gau waybackurls curl python3; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            error "Required command not found: $cmd"
            missing=1
        fi
    done

    if [[ "$missing" -ne 0 ]]; then
        exit 1
    fi
}

# ============================================================================
# Argument parsing
# ============================================================================

parse_args() {
    if [[ $# -eq 0 ]]; then
        show_help
        exit 1
    fi

    case "${1:-}" in
        -h|--help)
            show_help
            exit 0
            ;;

        --version)
            show_version
            exit 0
            ;;
    esac

    TARGET_INPUT="$1"
    shift

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --timeout)
                [[ $# -ge 2 ]] || {
                    error "--timeout requires a value"
                    exit 1
                }

                TIMEOUT="$2"
                shift 2
                ;;

            --output)
                [[ $# -ge 2 ]] || {
                    error "--output requires a value"
                    exit 1
                }

                OUTPUT_FILE="$2"
                shift 2
                ;;

            --format)
                [[ $# -ge 2 ]] || {
                    error "--format requires a value"
                    exit 1
                }

                FORMAT="$2"
                shift 2
                ;;

            --ignore-check)
                IGNORE_CHECK=true
                shift
                ;;

            --insecure)
                INSECURE=true
                shift
                ;;

            -v|--verbose)
                VERBOSE=true
                shift
                ;;

            -h|--help)
                show_help
                exit 0
                ;;

            --version)
                show_version
                exit 0
                ;;

            *)
                error "Unknown argument: $1"
                show_help
                exit 1
                ;;
        esac
    done

    if ! [[ "$TIMEOUT" =~ ^[1-9][0-9]*$ ]]; then
        error "--timeout must be a positive integer"
        exit 1
    fi

    case "$FORMAT" in
        txt|jsonl)
            ;;
        *)
            error "--format must be txt or jsonl"
            exit 1
            ;;
    esac
}

# ============================================================================
# Target normalization
# ============================================================================

normalize_target() {
    local parsed

    parsed="$(
        python3 - "$TARGET_INPUT" <<'PY_TARGET'
from urllib.parse import urlparse
import sys

raw = sys.argv[1].strip()

if not raw:
    raise SystemExit(1)

if "://" not in raw:
    raw = "https://" + raw

parsed = urlparse(raw)

if parsed.scheme not in {"http", "https"} or not parsed.hostname:
    raise SystemExit(1)

print(parsed.hostname.lower())
print(f"{parsed.scheme}://{parsed.netloc}")
PY_TARGET
    )" || {
        error "Invalid target: $TARGET_INPUT"
        exit 1
    }

    TARGET_HOST="$(printf '%s\n' "$parsed" | sed -n '1p')"
    TARGET_BASE="$(printf '%s\n' "$parsed" | sed -n '2p')"
}

# ============================================================================
# Curl configuration
# ============================================================================

build_curl_args() {
    CURL_ARGS=(
        --silent
        --show-error
        --location
        --max-time "$TIMEOUT"
        --user-agent "$USER_AGENT"
    )

    if [[ "$INSECURE" == true ]]; then
        CURL_ARGS+=(--insecure)
    fi
}

# ============================================================================
# JavaScript URL normalization and scope filtering
# ============================================================================

normalize_and_filter_js() {
    local input_file="$1"

    python3 - "$TARGET_BASE" "$TARGET_HOST" "$input_file" <<'PY_FILTER'
from urllib.parse import urljoin, urlparse
import sys

base = sys.argv[1]
target = sys.argv[2].lower()
input_file = sys.argv[3]

with open(input_file, "r", encoding="utf-8", errors="ignore") as handle:
    for raw in handle:
        value = raw.strip()

        if not value:
            continue

        url = urljoin(base + "/", value)
        parsed = urlparse(url)

        host = (parsed.hostname or "").lower()
        path = parsed.path.lower()

        if parsed.scheme not in {"http", "https"}:
            continue

        if not (host == target or host.endswith("." + target)):
            continue

        if not (
            path.endswith(".js")
            or ".js?" in url.lower()
            or ".js#" in url.lower()
        ):
            continue

        print(url)
PY_FILTER
}

# ============================================================================
# Homepage discovery
# ============================================================================

discover_homepage_js() {
    local html_file="$TEMP_DIR/homepage.html"

    log "Fetching homepage: $TARGET_BASE"

    if ! curl "${CURL_ARGS[@]}" "$TARGET_BASE" -o "$html_file"; then
        warn "Unable to fetch homepage."
        return 0
    fi

    python3 - "$TARGET_BASE" "$html_file" <<'PY_HTML'
from html.parser import HTMLParser
from urllib.parse import urljoin
import sys

base = sys.argv[1]
filename = sys.argv[2]


class Parser(HTMLParser):
    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)

        if tag.lower() == "script" and attributes.get("src"):
            print(urljoin(base + "/", attributes["src"]))

        elif tag.lower() == "link" and attributes.get("href"):
            href = attributes["href"]

            if ".js" in href.lower():
                print(urljoin(base + "/", href))


parser = Parser()

with open(filename, "r", encoding="utf-8", errors="ignore") as handle:
    parser.feed(handle.read())
PY_HTML
}

# ============================================================================
# Historical discovery
# ============================================================================

discover_historical_js() {
    log "Running assetfinder + gau..."

    assetfinder "$TARGET_HOST" 2>/dev/null |
        sort -u |
        gau 2>/dev/null ||
        true

    log "Running waybackurls..."

    waybackurls "$TARGET_HOST" 2>/dev/null ||
        true
}

# ============================================================================
# JavaScript discovery
# ============================================================================

discover_js() {
    local raw_file="$TEMP_DIR/raw_urls.txt"
    local output_file="$TEMP_DIR/all_js_files.txt"
    local count

    : > "$raw_file"
    : > "$output_file"

    info "Collecting JavaScript URLs..."

    discover_historical_js >> "$raw_file"
    discover_homepage_js >> "$raw_file"

    normalize_and_filter_js "$raw_file" |
        sort -u > "$output_file"

    count="$(wc -l < "$output_file" | tr -d ' ')"

    info "Discovered $count unique in-scope JavaScript URLs."

    if [[ "$count" -eq 0 ]]; then
        warn "No JavaScript files discovered."
        return 1
    fi
}

# ============================================================================
# HTTP validation
# ============================================================================

validate_url() {
    local url="$1"

    local result
    local status
    local content_type
    local effective_url
    local size

    if [[ "$IGNORE_CHECK" == true ]]; then
        printf '%s\t%s\t%s\t%s\t%s\n' \
            "$url" \
            "000" \
            "unknown" \
            "$url" \
            "0"

        return 0
    fi

    result="$(
        curl "${CURL_ARGS[@]}" \
            -o /dev/null \
            -w '%{http_code}\t%{content_type}\t%{url_effective}\t%{size_download}' \
            "$url" 2>/dev/null
    )" || return 1

    IFS=$'\t' read -r \
        status \
        content_type \
        effective_url \
        size <<< "$result"

    [[ "$status" =~ ^[23][0-9][0-9]$ ]] ||
        return 1

    printf '%s\t%s\t%s\t%s\t%s\n' \
        "$url" \
        "$status" \
        "$content_type" \
        "$effective_url" \
        "$size"
}

validate_js_files() {
    local input="$TEMP_DIR/all_js_files.txt"
    local output="$TEMP_DIR/validated.tsv"

    local url
    local count

    : > "$output"

    info "Validating JavaScript resources..."

    while IFS= read -r url; do
        [[ -n "$url" ]] || continue

        if ! validate_url "$url" >> "$output"; then
            log "Inaccessible: $url"
        fi
    done < "$input"

    count="$(wc -l < "$output" | tr -d ' ')"

    if [[ "$count" -eq 0 ]]; then
        warn "No accessible JavaScript resources found."

        if [[ "$IGNORE_CHECK" == false ]]; then
            warn "Try --ignore-check to skip HTTP validation."
        fi

        return 1
    fi

    info "$count JavaScript resources available for analysis."
}

# ============================================================================
# JavaScript analysis
# ============================================================================

analyze_js() {
    local url="$1"
    local status="$2"
    local content_type="$3"
    local effective_url="$4"
    local size="$5"

    local safe_id
    local js_file

    safe_id="$(
        printf '%s' "$url" |
            sha256sum |
            awk '{print $1}'
    )"

    js_file="$TEMP_DIR/js_${safe_id}.js"

    if ! curl "${CURL_ARGS[@]}" "$url" -o "$js_file" 2>/dev/null; then
        warn "Unable to download: $url"
        return 0
    fi

    [[ -s "$js_file" ]] || return 0

    {
        printf '\n============================================================\n'
        printf 'JS: %s\n' "$url"
        printf 'HTTP: %s\n' "$status"
        printf 'Content-Type: %s\n' "$content_type"
        printf 'Final URL: %s\n' "$effective_url"
        printf 'Size: %s bytes\n' "$size"
        printf '============================================================\n'

        python3 - "$js_file" <<'PY_ANALYZE'
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])

text = path.read_text(
    encoding="utf-8",
    errors="ignore",
)

patterns = [
    (
        "Absolute URLs",
        r'https?://[^"\'\s<>]+|wss?://[^"\'\s<>]+',
    ),
    (
        "Relative API Endpoints",
        r'/(?:api(?:/v\d+)?|graphql)(?:/[A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%-]*)?',
    ),
    (
        "GraphQL Indicators",
        r'graphql|mutation\s+[A-Za-z_][A-Za-z0-9_]*|'
        r'subscription\s+[A-Za-z_][A-Za-z0-9_]*|'
        r'query\s+[A-Za-z_][A-Za-z0-9_]*',
    ),
    (
        "WebSocket URLs",
        r'wss?://[^"\'\s<>]+',
    ),
    (
        "HTTP API Calls",
        r'(?:fetch|axios\.(?:get|post|put|patch|delete)|'
        r'XMLHttpRequest|jQuery\.(?:ajax|get|post))[^;]{0,300}',
    ),
    (
        "Source Maps",
        r'sourceMappingURL\s*=\s*[^\s]+',
    ),
    (
        "Potential Secret Candidates",
        r'(?:api[_-]?key|access[_-]?key|secret[_-]?key|'
        r'client[_-]?secret|private[_-]?key|authorization|bearer|'
        r'password|token)\s*[:=]\s*["\'][^"\']{8,}["\']',
    ),
    (
        "Console / Debug Statements",
        r'console\.(?:log|warn|error|debug)\s*\([^)]{0,300}\)',
    ),
]

for title, pattern in patterns:
    print(f"\n[{title}]")

    matches = sorted(
        set(re.findall(pattern, text, re.IGNORECASE))
    )

    for match in matches[:100]:
        print(match)
PY_ANALYZE
    } >> "$OUTPUT_FILE"
}

# ============================================================================
# TXT report
# ============================================================================

generate_txt_report() {
    local validated="$TEMP_DIR/validated.tsv"

    local url
    local status
    local content_type
    local effective_url
    local size

    {
        printf 'JSVar Hunter v%s\n' "$VERSION"
        printf 'Target: %s\n' "$TARGET_BASE"
        printf 'Host: %s\n' "$TARGET_HOST"
        printf 'Generated: %s\n' "$(date -Is)"

        printf '\nJavaScript inventory\n'
        printf '%s\n' '--------------------'

        while IFS=$'\t' read -r \
            url \
            status \
            content_type \
            effective_url \
            size; do

            printf '[%s] %s | %s | %s bytes\n' \
                "$status" \
                "$url" \
                "$content_type" \
                "$size"

            if [[ "$effective_url" != "$url" ]]; then
                printf '    -> Final URL: %s\n' "$effective_url"
            fi

        done < "$validated"

        while IFS=$'\t' read -r \
            url \
            status \
            content_type \
            effective_url \
            size; do

            analyze_js \
                "$url" \
                "$status" \
                "$content_type" \
                "$effective_url" \
                "$size"

        done < "$validated"

    } > "$OUTPUT_FILE"

    info "TXT report saved to: $OUTPUT_FILE"
}

# ============================================================================
# JSONL report
# ============================================================================

generate_jsonl_report() {
    local validated="$TEMP_DIR/validated.tsv"

    local url
    local status
    local content_type
    local effective_url
    local size

    : > "$OUTPUT_FILE"

    while IFS=$'\t' read -r \
        url \
        status \
        content_type \
        effective_url \
        size; do

        python3 \
            - "$url" "$status" "$content_type" "$effective_url" "$size" \
            <<'PY_JSON' >> "$OUTPUT_FILE"

import json
import sys

url, status, content_type, effective_url, size = sys.argv[1:]

print(
    json.dumps(
        {
            "type": "javascript",
            "url": url,
            "http_status": int(status),
            "content_type": content_type,
            "effective_url": effective_url,
            "size": int(size),
        },
        ensure_ascii=False,
    )
)
PY_JSON

    done < "$validated"

    info "JSONL inventory saved to: $OUTPUT_FILE"
}

# ============================================================================
# Main
# ============================================================================

main() {
    parse_args "$@"
    check_dependencies

    TEMP_DIR="$(mktemp -d)"

    normalize_target
    build_curl_args

    info "JSVar Hunter v${VERSION}"
    info "Target: $TARGET_BASE"
    info "Timeout: ${TIMEOUT}s"

    if [[ "$INSECURE" == true ]]; then
        warn "TLS certificate verification disabled."
    fi

    discover_js || exit 1
    validate_js_files || exit 1

    case "$FORMAT" in
        txt)
            generate_txt_report
            ;;

        jsonl)
            generate_jsonl_report
            ;;
    esac

    info "Analysis completed."
}

main "$@"
