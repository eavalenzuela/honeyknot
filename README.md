# honeyknot
a multi-port http honeypot for farming malware

## Logging and capture

Honeyknot now emits structured JSON line logs per port that include timestamps, source IP/port, protocol, matched rule, and error context. Binary-safe request captures are saved as hex dumps with configurable size limits, and log rotation/retention can be tuned via CLI flags.

### Useful flags

* `--log_directory`: destination folder for log files (default `logs/`).
* `--log_max_bytes`: maximum size in bytes before rotating a log file (default 1MB).
* `--log_backup_count`: number of rotated log files to retain (default 5).
* `--capture_limit`: maximum number of bytes per request to include in hex dump captures (default 4096).
