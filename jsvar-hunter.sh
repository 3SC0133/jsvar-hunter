#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

# ============================================================================
# JSVar Hunter
# JavaScript attack-surface discovery for authorized security testing
#
# Requirements:
#   assetfinder
#   gau
#   waybackurls
#   curl
#   python3
#
# Author: 3SC0133
# License: MIT
# ============================================================================

VERSION="2.0.0"

# ----------------------------------------------------------------------------
# Defaults
# ----------------------------------------------------------------------------

VERBOSE=false
IGNORE_CHECK=false
INSECURE=false

THREADS=5
TIMEOUT=20

OUTPUT_FILE="js_analysis_$(date +%Y%m%d_%H%M%S).txt"
FORMAT="txt"

USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36"

TEMP_DIR=""

TARGET_INPUT=""
TARGET_HOST=""
TARGET_BASE=""

# ----------------------------------------------------------------------------
# Cleanup
# ----------------------------------------------------------------------------

cleanup() {
    if [[ -n "${TEMP_DIR:-}" && -d "$TEMP_DIR" ]]; then
        rm -rf "$TEMP_DIR"
    fi
}

trap cleanup EXIT INT TERM

# ----------------------------------------------------------------------------
# Logging
# ----------------------------------------------------------------------------

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

# ----------------------------------------------------------------------------
# Help
# ----------------------------------------------------------------------------

show_help() {
    cat <<EOF
JSVar Hunter v${VERSION}

JavaScript attack-surface discovery tool for penetration testing,
bug bounty and authorized security research.

Usage:
  $0 <domain|url> [options]

Examples:
  $0 example.com
  $0 https://example.com
  $0 example.com --threads 10
  $0 example.com --format jsonl --output results.jsonl

Options:
  --threads N       Number of parallel analysis workers (default: 5)
  --timeout N       HTTP timeout in seconds (default: 20)
  --output FILE     Output file
  --format FORMAT   txt or jsonl (default: txt)
  --ignore-check    Skip JS accessibility validation
  --insecure        Disable TLS certificate verification
  -v, --verbose     Enable verbose output
  -h, --help        Show this help
  --version         Show version

Discovery sources:
  - assetfinder
  - gau
  - waybackurls
  - target homepage

Analysis:
  - JavaScript inventory
  - absolute URLs
  - relative endpoints
  - API paths
  - GraphQL indicators
  - WebSocket URLs
  - fetch / axios / XHR calls
  - sourceMappingURL
  - secret candidates
  - configuration candidates

Output:
  TXT     Human-readable report
  JSONL   Machine-readable output for pipeline integration

Only scan systems you are authorized to test.

EOF
}

# ----------------------------------------------------------------------------
# Version
# ----------------------------------------------------------------------------

show_version() {
    printf 'JSVar Hunter v%s\n' "$VERSION"
}

# ----------------------------------------------------------------------------
# Dependency check
# ----------------------------------------------------------------------------

check_dependencies() {
    local missing=0

    for cmd in assetfinder gau waybackurls curl python3; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            error "Required command not found: $cmd"
            missing=1
        fi
    done

    if [[ "$missing" -ne 0 ]]; then
        error "Install the missing dependencies and try again."
        exit 1
    fi
}

# ----------------------------------------------------------------------------
# Argument parsing
# ----------------------------------------------------------------------------

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
            --threads)
                [[ $# -ge 2 ]] || {
                    error "--threads requires a value"
                    exit 1
                }
                THREADS="$2"
                shift 2
                ;;

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

    if ! [[ "$THREADS" =~ ^[1-9][0-9]*$ ]]; then
        error "--threads must be a positive integer"
        exit 1
    fi

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

# ----------------------------------------------------------------------------
# Target normalization
# ----------------------------------------------------------------------------

normalize_target() {
    local parsed

    parsed="$(
        python3 - "$TARGET_INPUT" <<'PY'
from urllib.parse import urlparse
import sys

raw = sys.argv[1].strip()

if not raw:
    raise SystemExit(1)

if "://" not in raw:
    raw = "https://" + raw

p = urlparse(raw)

if p.scheme not in ("http", "https") or not p.hostname:
    raise SystemExit(1)

host = p.hostname.lower()

base = f"{p.scheme}://{p.netloc}"

print(host)
print(base)
PY
    )" || {
        error "Invalid target: $TARGET_INPUT"
        exit 1
    }

    TARGET_HOST="$(printf '%s\n' "$parsed" | sed -n '1p')"
    TARGET_BASE="$(printf '%s\n' "$parsed" | sed -n '2p')"

    log "Target input: $TARGET_INPUT"
    log "Target host:  $TARGET_HOST"
    log "Target base:  $TARGET_BASE"
}

# ----------------------------------------------------------------------------
# URL normalization
# ----------------------------------------------------------------------------

normalize_url() {
    local url="$1"

    python3 - "$TARGET_BASE" "$url" <<'PY'
from urllib.parse import urljoin
import sys

base = sys.argv[1]
value = sys.argv[2].strip()

if not value:
    raise SystemExit(0)

print(urljoin(base + "/", value))
PY
}

# ----------------------------------------------------------------------------
# Scope validation
# ----------------------------------------------------------------------------

in_scope() {
    local url="$1"

    python3 - "$TARGET_HOST" "$url" <<'PY'
from urllib.parse import urlparse
import sys

target = sys.argv[1].lower()
url = sys.argv[2]

try:
    host = (urlparse(url).hostname or "").lower()
except Exception:
    raise SystemExit(1)

if not host:
    raise SystemExit(1)

if host == target or host.endswith("." + target):
    raise SystemExit(0)

raise SystemExit(1)
PY
}

# ----------------------------------------------------------------------------
# HTTP options
# ----------------------------------------------------------------------------

curl_common_args() {
    printf '%s\n' \
        "--silent" \
        "--show-error" \
        "--location" \
        "--max-time" "$TIMEOUT" \
        "--user-agent" "$USER_AGENT"
    
    if [[ "$INSECURE" == true ]]; then
        printf '%s\n' "--insecure"
    fi
}

# ----------------------------------------------------------------------------
# Homepage discovery
# ----------------------------------------------------------------------------

discover_homepage_js() {
    local html_file="$TEMP_DIR/homepage.html"

    log "Fetching homepage: $TARGET_BASE"

    local args=()
    while IFS= read -r arg; do
        args+=("$arg")
    done < <(curl_common_args)

    curl "${args[@]}" "$TARGET_BASE" -o "$html_file" 2>/dev/null || {
        warn "Unable to fetch homepage."
        return 0
    }

    python3 - "$TARGET_BASE" "$html_file" <<'PY'
from html.parser import HTMLParser
from urllib.parse import urljoin
import sys

base = sys.argv[1]
filename = sys.argv[2]

class Parser(HTMLParser):
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)

        if tag.lower() == "script" and attrs.get("src"):
            print(urljoin(base + "/", attrs["src"]))

        if tag.lower() == "link":
            href = attrs.get("href", "")
            if ".js" in href.lower():
                print(urljoin(base + "/", href))

parser = Parser()

with open(filename, "r", encoding="utf-8", errors="ignore") as f:
    parser.feed(f.read())
PY
}

# ----------------------------------------------------------------------------
# Historical discovery
# ----------------------------------------------------------------------------

discover_historical_js() {
    log "Running assetfinder..."

    assetfinder "$TARGET_HOST" 2>/dev/null |
        sort -u |
        while IFS= read -r host; do
            [[ -n "$host" ]] || continue

            log "Querying gau for: $host"

            gau "$host" 2>/dev/null || true
        done

    log "Running gau directly against target..."

    gau "$TARGET_HOST" 2>/dev/null || true

    log "Running waybackurls..."

    waybackurls "$TARGET_HOST" 2>/dev/null || true
}

# ----------------------------------------------------------------------------
# JS URL filtering
# ----------------------------------------------------------------------------

filter_js_urls() {
    python3 - "$TARGET_HOST" <<'PY'
from urllib.parse import urlparse
import sys
import re

target = sys.argv[1].lower()

for raw in sys.stdin:
    url = raw.strip()

    if not url:
        continue

    if not re.match(r"^https?://", url, re.I):
        continue

    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
    except Exception:
        continue

    if not host:
        continue

    if not (host == target or host.endswith("." + target)):
        continue

    path = parsed.path.lower()

    if path.endswith(".js") or ".js?" in url.lower() or ".js#" in url.lower():
        print(url)
PY
}

# ----------------------------------------------------------------------------
# Discovery
# ----------------------------------------------------------------------------

discover_js() {
    local raw_file="$TEMP_DIR/raw_urls.txt"
    local normalized_file="$TEMP_DIR/normalized_urls.txt"

    : > "$raw_file"
    : > "$normalized_file"

    info "Collecting JavaScript URLs..."

    discover_historical_js >> "$raw_file" || true
    discover_homepage_js >> "$raw_file" || true

    log "Normalizing and filtering discovered URLs..."

    while IFS= read -r url; do
        [[ -n "$url" ]] || continue

        if [[ "$url" =~ ^https?:// ]]; then
            printf '%s\n' "$url"
        else
            normalize_url "$url" 2>/dev/null || true
        fi
    done < "$raw_file" |
        sort -u |
        filter_js_urls |
        sort -u > "$normalized_file"

    local count
    count="$(wc -l < "$normalized_file" | tr -d ' ')"

    info "Discovered $count unique in-scope JavaScript URLs."

    if [[ "$count" -eq 0 ]]; then
        warn "No JavaScript files discovered."
        return 1
    fi

    cp "$normalized_file" "$TEMP_DIR/all_js_files.txt"
}

# ----------------------------------------------------------------------------
# URL validation
# ----------------------------------------------------------------------------

validate_url() {
    local url="$1"

    if [[ "$IGNORE_CHECK" == true ]]; then
        printf '%s\n' "$url"
        return 0
    fi

    local result
    local status
    local content_type
    local effective_url
    local size

    local args=()
    while IFS= read -r arg; do
        args+=("$arg")
    done < <(curl_common_args)

    result="$(
        curl "${args[@]}" \
            -o /dev/null \
            -w '%{http_code}\t%{content_type}\t%{url_effective}\t%{size_download}' \
            "$url" 2>/dev/null
    )" || return 1

    IFS=$'\t' read -r status content_type effective_url size <<< "$result"

    [[ "$status" =~ ^[23][0-9][0-9]$ ]] || return 1

    printf '%s\t%s\t%s\t%s\t%s\n' \
    "$url" \
    "$status" \
    "$content_type" \
    "$effective_url" \
    "$size"
}

# ----------------------------------------------------------------------------
# Validate all JS URLs
# ----------------------------------------------------------------------------

validate_js_files() {
    local input="$TEMP_DIR/all_js_files.txt"
    local output="$TEMP_DIR/validated.tsv"

    : > "$output"

    info "Validating JavaScript resources..."

    export TIMEOUT
    export USER_AGENT
    export INSECURE
    export IGNORE_CHECK

    export -f curl_common_args
    export -f validate_url

    : > "$TEMP_DIR/validation_results.txt"

    while IFS= read -r url; do
        [[ -n "$url" ]] || continue

        validate_url "$url" >> "$TEMP_DIR/validation_results.txt" || true

    done < "$input"

    while IFS=$'\t' read -r url status content_type effective_url size; do
        [[ -n "$url" ]] || continue

        printf '%s\t%s\t%s\t%s\t%s\n' \
            "$url" \
            "$status" \
            "$content_type" \
            "$effective_url" \
            "$size" >> "$output"

    done < "$TEMP_DIR/validation_results.txt"

    local count
    count="$(wc -l < "$output" | tr -d ' ')"

    if [[ "$count" -eq 0 ]]; then
        warn "No accessible JavaScript resources found."

        if [[ "$IGNORE_CHECK" == false ]]; then
            warn "Try --ignore-check if you want to skip HTTP validation."
        fi

        return 1
    fi

    info "$count JavaScript resources available for analysis."

    cp "$output" "$TEMP_DIR/validated.tsv"
}

# ----------------------------------------------------------------------------
# JavaScript analysis
# ----------------------------------------------------------------------------

analyze_js() {
    local url="$1"
    local status="$2"
    local content_type="$3"
    local size="$4"

    local safe_id
    safe_id="$(printf '%s' "$url" | sha256sum | awk '{print $1}')"

    local js_file="$TEMP_DIR/js_${safe_id}.js"
    local result_file="$TEMP_DIR/result_${safe_id}.txt"

    local args=()
    while IFS= read -r arg; do
        args+=("$arg")
    done < <(curl_common_args)

    if ! curl "${args[@]}" "$url" -o "$js_file" 2>/dev/null; then
        return 0
    fi

    [[ -s "$js_file" ]] || return 0

    {
        printf '\n============================================================\n'
        printf 'JS: %s\n' "$url"
        printf 'HTTP: %s\n' "$status"
        printf 'Content-Type: %s\n' "$content_type"
        printf 'Size: %s bytes\n' "$size"
        printf '============================================================\n'

        printf '\n[Absolute URLs]\n'
        grep -Eo 'https?://[^"'\''[:space:]<>]+|wss?://[^"'\''[:space:]<>]+' \
            "$js_file" |
            sort -u || true

        printf '\n[Relative Endpoints]\n'
        grep -Eo '["'\'']/(api|api/v[0-9]+|graphql|auth|login|logout|admin|internal|users|accounts|config|health|status)(/[^"'\'']*)?["'\'']' \
            "$js_file" |
            sed -E 's/^["'\'']|["'\'']$//g' |
            sort -u || true

        printf '\n[GraphQL]\n'
        grep -Eio 'graphql|query[[:space:]]+[A-Za-z_]|mutation[[:space:]]+[A-Za-z_]|subscription[[:space:]]+[A-Za-z_]' \
            "$js_file" |
            sort -u || true

        printf '\n[WebSocket]\n'
        grep -Eo 'wss?://[^"'\''[:space:]<>]+' "$js_file" |
            sort -u || true

        printf '\n[HTTP API Calls]\n'
        grep -Eio \
            '(fetch|axios\.(get|post|put|patch|delete)|XMLHttpRequest|jQuery\.(ajax|get|post))[^;]{0,300}' \
            "$js_file" |
            head -n 100 || true

        printf '\n[Source Maps]\n'
        grep -Eo 'sourceMappingURL[[:space:]]*=[[:space:]]*[^[:space:]]+' \
            "$js_file" |
            sort -u || true

        printf '\n[Potential Secret Candidates]\n'
        grep -Eio \
            '(api[_-]?key|access[_-]?key|secret[_-]?key|client[_-]?secret|private[_-]?key|authorization|bearer|password|token)[[:space:]]*[:=][[:space:]]*["'\''][^"'\'']{8,}["'\'']' \
            "$js_file" |
            head -n 100 || true

        printf '\n[Console / Debug Statements]\n'
        grep -Eio \
            'console\.(log|warn|error|debug)[[:space:]]*\([^)]{0,300}\)' \
            "$js_file" |
            head -n 100 || true

    } > "$result_file"

    printf '%s\n' "$result_file"
}

# ----------------------------------------------------------------------------
# TXT report
# ----------------------------------------------------------------------------

generate_txt_report() {
    local validated="$TEMP_DIR/validated.tsv"

    {
        printf 'JSVar Hunter v%s\n' "$VERSION"
        printf 'Target: %s\n' "$TARGET_BASE"
        printf 'Host: %s\n' "$TARGET_HOST"
        printf 'Generated: %s\n' "$(date -Is)"
        printf '\n'

        printf 'JavaScript inventory\n'
        printf '%s\n' '--------------------'

        while IFS=$'\t' read -r url status content_type effective_url size; do
            printf '[%s] %s | %s | %s bytes\n' \
                "$status" "$url" "$content_type" "$size"
        done < "$validated"

        printf '\n'

        while IFS=$'\t' read -r url status content_type effective_url size; do
            analyze_js "$url" "$status" "$content_type" "$size" || true
        done < "$validated"

    } > "$OUTPUT_FILE"

    info "TXT report saved to: $OUTPUT_FILE"
}

# ----------------------------------------------------------------------------
# JSONL report
# ----------------------------------------------------------------------------

generate_jsonl_report() {
    local validated="$TEMP_DIR/validated.tsv"

    : > "$OUTPUT_FILE"

    while IFS=$'\t' read -r url status content_type effective_url size; do
        python3 - "$url" "$status" "$content_type" "$effective_url" "$size" <<'PY' >> "$OUTPUT_FILE"
import json
import sys

url, status, content_type, effective_url, size = sys.argv[1:]

print(json.dumps({
    "type": "javascript",
    "url": url,
    "http_status": int(status),
    "content_type": content_type,
    "effective_url": effective_url,
    "size": int(size),
}, ensure_ascii=False))
PY
    done < "$validated"

    info "JSONL inventory saved to: $OUTPUT_FILE"
}

# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------

main() {
    parse_args "$@"
    check_dependencies

    TEMP_DIR="$(mktemp -d)"

    normalize_target

    info "JSVar Hunter v${VERSION}"
    info "Target: $TARGET_BASE"
    info "Threads: $THREADS"
    info "Timeout: ${TIMEOUT}s"

    if [[ "$INSECURE" == true ]]; then
        warn "TLS certificate verification disabled."
    fi

    discover_js || exit 1

    if [[ "$IGNORE_CHECK" == true ]]; then
        # Treat discovered URLs as analyzable resources.
        while IFS= read -r url; do
            printf '%s\t%s\t%s\t%s\n' \
                "$url" "000" "unknown" "0"
        done < "$TEMP_DIR/all_js_files.txt" > "$TEMP_DIR/validated.tsv"
    else
        validate_js_files || exit 1
    fi

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
