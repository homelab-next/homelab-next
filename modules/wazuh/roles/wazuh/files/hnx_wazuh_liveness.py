#!/usr/bin/python3 -I
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: wazuh-liveness
#   kind: tool
#   purpose: Write the SIEM manager's liveness as node-exporter textfile metrics - which daemons are live processes and how old the alert stream's last write is - so a manager that is up but not working is loud.
#   owner: platform
#   trigger: [timer:wazuh/hnx-wazuh-liveness, role:wazuh]
#   installs_to: /usr/local/libexec/homelabnext/hnx-wazuh-liveness
#   inputs: "--compose-file FILE --alerts-file FILE --out FILE [--owner USER]; runs docker compose exec for the process check"
#   outputs: "the metrics file (atomic rename, 0600); one line on stdout with the same numbers"
#   exit:
#     "0": the metrics were written (a dead daemon is a metric, not a failure)
#     "2": usage error or an unsafe output path
"""The wazuh role's liveness metrics (modules/wazuh/README.md, "Liveness and the stale-stream alert").

A manager container can be "up" with none of its daemons running (a pid file left by an unclean stop
makes the product's start skip every daemon).  Its own health is not enough to page anyone, so a timer
runs this once a minute and writes ``siem_*`` metrics the host's node exporter serves from its textfile
directory; the monitoring rules page on them.  Only the process table and the alert stream's mtime are
read; nothing is changed.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

DAEMONS = (
    "wazuh-analysisd",
    "wazuh-remoted",
    "wazuh-authd",
    "wazuh-db",
    "wazuh-modulesd",
    "wazuh-monitord",
)
API_DAEMON = "wazuh_apid[.]py"  # a python process, matched on its command line
ABSENT_AGE = 315360000  # a missing stream is ten years old, so one threshold covers it


def render(up: dict[str, bool], alerts_age: float | None, now: float) -> str:
    """The metrics text for the daemon states and the stream's age (None: no stream file)."""
    lines = [
        "# HELP siem_manager_daemon_up 1 when the manager daemon is a live process.",
        "# TYPE siem_manager_daemon_up gauge",
    ]
    for name in sorted(up):
        lines.append(f'siem_manager_daemon_up{{daemon="{name}"}} {1 if up[name] else 0}')
    lines += [
        "# HELP siem_manager_daemons_expected The number of manager daemons that must be live.",
        "# TYPE siem_manager_daemons_expected gauge",
        f"siem_manager_daemons_expected {len(up)}",
        "# HELP siem_manager_daemons_running The number of those that are live processes.",
        "# TYPE siem_manager_daemons_running gauge",
        f"siem_manager_daemons_running {sum(1 for v in up.values() if v)}",
        "# HELP siem_alerts_file_present 1 when the alert stream file exists.",
        "# TYPE siem_alerts_file_present gauge",
        f"siem_alerts_file_present {0 if alerts_age is None else 1}",
        "# HELP siem_alerts_file_age_seconds Seconds since the alert stream was last written.",
        "# TYPE siem_alerts_file_age_seconds gauge",
        f"siem_alerts_file_age_seconds {ABSENT_AGE if alerts_age is None else int(max(alerts_age, 0))}",
        "# HELP siem_manager_check_timestamp_seconds When this check last ran.",
        "# TYPE siem_manager_check_timestamp_seconds gauge",
        f"siem_manager_check_timestamp_seconds {int(now)}",
    ]
    return "\n".join(lines) + "\n"


def alerts_age(path: Path, now: float) -> float | None:
    try:
        return now - path.stat().st_mtime
    except OSError:
        return None


def daemon_up(compose_file: str, name: str, full: bool, timeout: int = 20) -> bool:
    """True when ``pgrep`` inside the manager finds the process (any failure to ask is 'not up')."""
    flag = "-f" if full else "-x"
    argv = ["docker", "compose", "-f", compose_file, "exec", "-T", "manager", "pgrep", flag, name]
    try:
        return (
            subprocess.run(argv, capture_output=True, timeout=timeout, check=False).returncode == 0
        )
    except (OSError, subprocess.SubprocessError):
        return False


def write_atomic(out: Path, text: str, owner: str | None = None) -> None:
    out = out.resolve()
    if len(out.parts) < 4 or out.suffix != ".prom":
        raise ValueError(f"refusing an unsafe output path: {out}")
    fd, tmp = tempfile.mkstemp(prefix=".hnx-liveness-", dir=out.parent)
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(text)
        if owner:
            shutil.chown(tmp, user=owner)  # mkstemp made it 0600: only its owner reads it
        os.replace(tmp, out)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--compose-file", required=True)
    ap.add_argument("--alerts-file", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument(
        "--owner", default=None, help="user that owns the file and reads it (mode 0600)"
    )
    args = ap.parse_args(argv)
    now = time.time()
    up = {d: daemon_up(args.compose_file, d, False) for d in DAEMONS}
    up["wazuh-apid"] = daemon_up(args.compose_file, API_DAEMON, True)
    text = render(up, alerts_age(Path(args.alerts_file), now), now)
    try:
        write_atomic(Path(args.out), text, args.owner)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 2
    print(text.replace("\n", ";"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
