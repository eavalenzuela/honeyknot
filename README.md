# honeyknot

A multi-port HTTP/TCP honeypot for farming malware and probing common attack
patterns. Services can be defined either with legacy handler files or a single
consolidated schema.

## Project layout

* `honeyknot.py` – CLI entrypoint that loads services, spawns worker processes,
  and hands them to the scheduler.
* `hk_handler.py` – Protocol-aware service handlers that emit structured JSON
  logs and serve responses defined in the schema.
* `service_loader.py` – Service definition models plus helpers to parse legacy
  handler files or consolidated JSON/YAML schemas.
* `service_runner.py` – Thin socket lifecycle management and scheduling helpers
  for running services in threads.
* `definition_files/` – Example schema files (`services.json`) and legacy TCP
  definition data (`ssh.json`).
* `handlers/` – Legacy INI-style handler definitions that can be migrated into a
  consolidated schema.
* `logs/` – Default location for per-port rotating logs.

## Service schema

Services can be defined in a single JSON or YAML schema file (default:
`definition_files/services.json`). Each entry describes the protocol (`http` or
`tcp`), listener settings, headers, and regex-based response rules. Provide a
different schema at runtime with `--service_schema <path>`.

To migrate legacy `handlers/` INI files into the consolidated format, run:

```
python service_loader.py --from-handlers handlers --definition-dir definition_files --output definition_files/services.migrated.json
```

You can also export during startup with `--export_schema <path>`, which writes
the schema and exits without starting services.

## Logging and capture

Honeyknot emits structured JSON line logs per port that include client IP/port,
protocol, matched rule, and hex-encoded request captures. Log rotation and
retention are configurable. The capture payload is truncated according to the
configured limit to keep log sizes manageable.

### Useful flags

* `--log_directory`: destination folder for log files (default `logs/`).
* `--log_max_bytes`: maximum size in bytes before rotating a log file (default
  1MB).
* `--log_backup_count`: number of rotated log files to retain (default 5).
* `--capture_limit`: maximum number of bytes per request to include in hex dump
  captures (default 4096).
* `--processes`: optional override for the number of worker processes (defaults
  to the number of services loaded).

## Running

Start the honeypot with the default schema:

```
python honeyknot.py
```

Override the bind IP and log directory:

```
python honeyknot.py --bind-ip 0.0.0.0 --log_directory /var/log/honeyknot
```

Run with a custom service schema:

```
python honeyknot.py --service_schema path/to/schema.yaml
```
