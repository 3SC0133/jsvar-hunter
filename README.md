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
````

Make the script executable:

```bash
chmod +x jsvar-hunter.sh
```

Verify the installation:

```bash
./jsvar-hunter.sh --version
```

Expected:

```text
JSVar Hunter v2.0.0
```

## Usage

Basic scan:

```bash
./jsvar-hunter.sh example.com
```

Using a full URL:

```bash
./jsvar-hunter.sh https://example.com
```

Verbose mode:

```bash
./jsvar-hunter.sh example.com -v
```

Increase HTTP timeout:

```bash
./jsvar-hunter.sh example.com --timeout 30
```

Skip accessibility validation:

```bash
./jsvar-hunter.sh example.com --ignore-check
```

Disable TLS certificate verification:

```bash
./jsvar-hunter.sh example.com --insecure
```

Save the report to a custom file:

```bash
./jsvar-hunter.sh example.com --output results.txt
```

Generate JSONL inventory:

```bash
./jsvar-hunter.sh example.com \
  --format jsonl \
  --output results.jsonl
```

## Command-line Options

| Option            | Description                          |
| ----------------- | ------------------------------------ |
| `--timeout N`     | HTTP timeout in seconds              |
| `--output FILE`   | Output file path                     |
| `--format txt`    | Human-readable report                |
| `--format jsonl`  | JSON Lines inventory                 |
| `--ignore-check`  | Skip HTTP accessibility validation   |
| `--insecure`      | Disable TLS certificate verification |
| `-v`, `--verbose` | Enable verbose output                |
| `-h`, `--help`    | Show help                            |
| `--version`       | Show version                         |

## Analysis

JSVar Hunter looks for JavaScript artifacts that may be useful during security reconnaissance.

### API endpoints

Examples of indicators:

```text
/api/
/api/v1/
/api/v2/
/graphql
```

### WebSockets

Example:

```text
wss://socket.example.com/ws
```

### HTTP clients

The analyzer looks for common client-side request mechanisms such as:

```javascript
fetch(...)
axios.get(...)
axios.post(...)
XMLHttpRequest
jQuery.ajax(...)
```

### Source maps

Source map references can expose additional application source material and are therefore reported when discovered.

### Potential secrets

The analyzer identifies strings associated with terms such as:

```text
api_key
access_key
secret
token
password
authorization
bearer
private_key
```

These are **candidates only** and must be manually validated.

A detected token-like string is not automatically a vulnerability.

### Console and debug information

Client-side logging statements are reported because they can sometimes expose useful application behavior, identifiers or debugging information.

## Output

The default output is a human-readable TXT report.

Example:

```text
JSVar Hunter v2.0.0
Target: https://example.com
Host: example.com

JavaScript Inventory
====================

[200] https://example.com/static/app.js | application/javascript | 48231 bytes
```

JSONL mode produces one JSON object per JavaScript resource:

```json
{"type":"javascript","url":"https://example.com/static/app.js","http_status":200,"content_type":"application/javascript","effective_url":"https://example.com/static/app.js","size":48231}
```

JSONL is useful when feeding results into other scripts, pipelines or security tooling.

## Workflow

A typical workflow is:

```text
Target
  |
  v
URL discovery
  |
  +-- assetfinder
  +-- gau
  +-- waybackurls
  +-- homepage
  |
  v
JavaScript filtering
  |
  v
Scope validation
  |
  v
HTTP validation
  |
  v
JavaScript analysis
  |
  +-- URLs
  +-- APIs
  +-- GraphQL
  +-- WebSockets
  +-- Source maps
  +-- Token/key candidates
  +-- Debug information
  |
  v
Report
```

## Security Considerations

JSVar Hunter performs active HTTP requests against discovered resources.

The following options can affect how requests are performed:

```text
--ignore-check
--insecure
--timeout
```

Use them carefully and only within an authorized testing scope.

`--insecure` disables TLS certificate verification and should generally be avoided unless there is a specific testing requirement.

## Responsible Use

JSVar Hunter is intended for:

* authorized penetration testing;
* bug bounty programs where the target is explicitly in scope;
* security research on systems you own or have permission to test;
* CTFs and laboratory environments.

Do not use this tool against systems without authorization.

The user is responsible for complying with applicable laws, contractual requirements and the rules of each bug bounty program.

## Limitations

JSVar Hunter is a reconnaissance and attack-surface discovery tool.

It does **not** automatically prove that a discovered artifact is vulnerable.

For example:

```text
API endpoint found
        !=
API vulnerability confirmed
```

and:

```text
token-like string found
        !=
valid secret confirmed
```

All findings should be manually validated within the authorized scope.

## Contributing

Contributions, bug reports and improvements are welcome.

Before submitting changes:

1. Keep the tool lightweight.
2. Avoid unnecessary dependencies.
3. Preserve compatibility with common Linux environments.
4. Document behavioral changes.
5. Test changes against authorized targets or local fixtures.

## License

JSVar Hunter is released under the MIT License.

See [LICENSE](LICENSE).

## Author

**3SC0133**

Security research, penetration testing, bug bounty and CTF.
