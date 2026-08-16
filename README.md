# JSVar Hunter

> JavaScript attack-surface discovery and analysis tool for penetration testing, bug bounty and security research.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

JSVar Hunter is a lightweight Bash-based tool designed to discover and analyze JavaScript resources associated with an authorized target.

It combines passive URL discovery with HTTP validation and JavaScript content analysis to help security professionals identify interesting client-side artifacts during reconnaissance.

## Features

- JavaScript URL discovery from multiple sources
- Passive historical URL collection
- Homepage JavaScript extraction
- In-scope URL filtering
- HTTP accessibility validation
- API endpoint discovery
- GraphQL indicators
- WebSocket URL discovery
- Absolute URL extraction
- HTTP client call detection
- Source map detection
- Potential credential/token candidates
- Console and debug statement discovery
- TXT reporting
- JSONL inventory output
- Configurable HTTP timeout
- Optional TLS verification bypass
- Verbose execution mode

## Requirements

The following tools must be available in your `PATH`:

- `assetfinder`
- `gau`
- `waybackurls`
- `curl`
- `python3`

Recommended environment:

- Linux
- Bash 4+
- Python 3

## Installation

Clone the repository:

```bash
git clone https://github.com/3SC0133/jsvar-hunter.git
cd jsvar-hunter
