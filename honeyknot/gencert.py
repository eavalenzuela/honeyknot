"""Development helper: mint a self-signed cert + key pair.

Python's stdlib can load PEMs but can't generate them without pulling in
`cryptography`. We shell out to `openssl` instead — universally available
on Linux/BSD/macOS, and this is a dev convenience, not a runtime
dependency of the honeyknot daemon itself. Production deployments should
use real certs (Let's Encrypt, internal PKI, etc.).

Usage:
    python -m honeyknot.gencert                    # writes logs/tls.{cert,key}
    python -m honeyknot.gencert --out /etc/ssl/hk
    python -m honeyknot.gencert --cn honeypot.example --days 90
"""

from __future__ import annotations

import argparse
import logging
import shutil
import subprocess
import sys
from pathlib import Path

logger = logging.getLogger("honeyknot.gencert")


def generate(out_dir: Path, cn: str = "honeyknot.local",
             days: int = 365) -> tuple[Path, Path]:
    openssl = shutil.which("openssl")
    if openssl is None:
        raise RuntimeError(
            "openssl not found on PATH. Install openssl or provide a cert+key "
            "pair manually and set [tls] certfile / keyfile in the handler TOML.",
        )
    out_dir.mkdir(parents=True, exist_ok=True)
    cert = out_dir / "tls.cert"
    key = out_dir / "tls.key"

    subprocess.run(
        [
            openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key),
            "-out", str(cert),
            "-days", str(days),
            "-subj", f"/CN={cn}",
        ],
        check=True,
        capture_output=True,
    )
    # 0600 for the key
    key.chmod(0o600)
    cert.chmod(0o644)
    return cert, key


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate a self-signed TLS cert+key for honeyknot",
    )
    parser.add_argument("--out", default="logs/",
                        help="directory to write tls.cert and tls.key into "
                             "(default: logs/)")
    parser.add_argument("--cn", default="honeyknot.local",
                        help="certificate common name (default: honeyknot.local)")
    parser.add_argument("--days", type=int, default=365,
                        help="validity in days (default: 365)")
    args = parser.parse_args(argv)

    try:
        cert, key = generate(Path(args.out), cn=args.cn, days=args.days)
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.decode("utf-8", errors="replace") if e.stderr else ""
        print(f"openssl failed:\n{stderr}", file=sys.stderr)
        return 1

    print(f"wrote {cert}")
    print(f"wrote {key}")
    print("point [tls] certfile/keyfile in your handler TOMLs at these paths.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
