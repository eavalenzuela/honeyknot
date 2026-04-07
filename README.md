# honeyknot

A highly-configurable multi-port honeypot for farming malware.

Honeyknot listens on configurable ports, responds to incoming connections with crafted responses (HTTP, HTTPS, or raw TCP), and logs all incoming request data. Captured payloads are automatically analyzed for known file types.

Requires Python 3.11+. No external dependencies (stdlib only).

## Usage

```bash
# Run from CLI
python -m honeyknot -i <bind_ip>

# With options
python -m honeyknot -i 0.0.0.0 -v -tc 10 -hd handlers/ -ld logs/

# Or via the installed script (after pip install)
honeyknot -i 0.0.0.0

# From a Python interactive shell
from honeyknot import run_from_interactive_shell
run_from_interactive_shell("0.0.0.0")
```

**Flags:**
- `-i` / `--bind-ip` — IP to bind sockets to (required)
- `-hd` / `--handler-dir` — directory containing TOML handler definitions (default: `handlers/`)
- `-ld` / `--log-dir` — directory for log output (default: `logs/`)
- `-tc` / `--thread-count` — threads per port process (default: 5)
- `-v` / `--verbose` — enable debug-level logging

## Handler Definitions

Each port is configured by a TOML file in the handlers directory. Example for an HTTP honeypot:

```toml
[service]
port = 80
type = "http"  # "http", "https", or "tcp"

[response_headers]
status_line = "HTTP/1.1 200 OK"
headers = ["Server: Apache/2.4.41", "Content-Type: text/html", "Connection: close"]

[default_response]
body = "<html><body><h1>404 Not Found</h1></body></html>"

[[rules]]
name = "php_request"
pattern = '^GET /.*\.php'
response = '<?php system($_REQUEST["cmd"]); ?>'

[[rules]]
name = "root_get"
pattern = '^GET / '
response = "<html><body><h2>success</h2></body></html>"
```

- **`[service]`** — port number, protocol type, optional encoding
- **`[response_headers]`** — HTTP status line and headers (omit for TCP services)
- **`[default_response]`** — fallback when no rule matches
- **`[[rules]]`** — ordered list of regex pattern / response pairs (first match wins)
- Patterns are Python regex, matched case-insensitively against decoded request data
