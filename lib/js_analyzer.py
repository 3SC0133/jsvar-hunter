#!/usr/bin/env python3

"""
JSVar Hunter - JavaScript Analyzer

Offline JavaScript attack-surface analyzer.

This module focuses on discovery of potentially interesting
JavaScript artifacts for authorized security testing.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Iterable


VERSION = "2.0.0"


PATTERNS = {
    "absolute_url": re.compile(
        r'https?://[^"\'\s<>]+',
        re.IGNORECASE,
    ),

    "websocket": re.compile(
        r'wss?://[^"\'\s<>]+',
        re.IGNORECASE,
    ),

    "api_endpoint": re.compile(
        r'/(?:api(?:/v\d+)?|graphql)'
        r'(?:/[A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%-]*)?',
        re.IGNORECASE,
    ),

    "graphql": re.compile(
        r'graphql'
        r'|mutation\s+[A-Za-z_][A-Za-z0-9_]*'
        r'|subscription\s+[A-Za-z_][A-Za-z0-9_]*'
        r'|query\s+[A-Za-z_][A-Za-z0-9_]*',
        re.IGNORECASE,
    ),

    "http_call": re.compile(
        r'(?:'
        r'fetch'
        r'|axios\.(?:get|post|put|patch|delete)'
        r'|XMLHttpRequest'
        r'|jQuery\.(?:ajax|get|post)'
        r')[^;]{0,300}',
        re.IGNORECASE,
    ),

    "source_map": re.compile(
        r'sourceMappingURL\s*=\s*[^\s]+',
        re.IGNORECASE,
    ),

    "secret_candidate": re.compile(
        r'(?:'
        r'api[_-]?key'
        r'|access[_-]?key'
        r'|secret[_-]?key'
        r'|client[_-]?secret'
        r'|private[_-]?key'
        r'|authorization'
        r'|bearer'
        r'|password'
        r'|token'
        r')'
        r'\s*[:=]\s*'
        r'["\'][^"\']{8,}["\']',
        re.IGNORECASE,
    ),

    "console": re.compile(
        r'console\.(?:log|warn|error|debug)\s*\([^)]{0,300}\)',
        re.IGNORECASE,
    ),
}


def unique_matches(pattern: re.Pattern[str], text: str) -> list[str]:
    """Return deterministic, sorted unique regex matches."""
    return sorted(set(pattern.findall(text)))


def analyze_text(text: str) -> dict[str, list[str]]:
    """Analyze JavaScript source and return categorized findings."""
    results: dict[str, list[str]] = {}

    for category, pattern in PATTERNS.items():
        matches = unique_matches(pattern, text)

        if matches:
            results[category] = matches[:100]
        else:
            results[category] = []

    return results


def analyze_file(path: Path) -> dict[str, object]:
    """Analyze a local JavaScript file."""
    if not path.is_file():
        raise FileNotFoundError(path)

    text = path.read_text(
        encoding="utf-8",
        errors="ignore",
    )

    findings = analyze_text(text)

    return {
        "type": "javascript_analysis",
        "file": str(path),
        "bytes": path.stat().st_size,
        "findings": findings,
    }


def print_text(result: dict[str, object]) -> None:
    """Render findings in human-readable form."""
    print(f"JSVar Hunter Analyzer v{VERSION}")
    print(f"File: {result['file']}")
    print(f"Size: {result['bytes']} bytes")

    findings = result["findings"]

    for category, matches in findings.items():
        print(f"\n[{category}]")

        if not matches:
            print("(none)")
            continue

        for value in matches:
            print(value)


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Offline JavaScript attack-surface analyzer."
    )

    parser.add_argument(
        "file",
        type=Path,
        help="JavaScript file to analyze",
    )

    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"JSVar Hunter Analyzer v{VERSION}",
    )

    args = parser.parse_args(argv)

    try:
        result = analyze_file(args.file)
    except FileNotFoundError:
        print(
            f"Error: file not found: {args.file}",
            file=sys.stderr,
        )
        return 1
    except OSError as exc:
        print(
            f"Error reading {args.file}: {exc}",
            file=sys.stderr,
        )
        return 1

    if args.format == "json":
        print(
            json.dumps(
                result,
                ensure_ascii=False,
                indent=2,
            )
        )
    else:
        print_text(result)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
