# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: vector-liveness
#   kind: tool
#   purpose: Write the log pipeline's liveness as node-exporter textfile metrics - whether its two containers run, how often they restarted, how old the sidecar's status is and how many rows each route has moved - so a pipeline that is up but delivers nothing is loud.
#   owner: platform
#   trigger: [role:vector]
#   inputs: "--compose-file FILE --status-file FILE --out FILE; runs docker compose ps and docker inspect for the container check"
#   outputs: "the metrics file (atomic rename, 0644); one line on stdout with the same numbers"
#   exit:
#     "0": the metrics were written (a dead container is a metric, not a failure)
#     "2": usage error or an unsafe output path
"""The vector role's liveness metrics (modules/vector/README.md, "Liveness and the stalled-pipeline alert").

The aggregator can crash-loop (or the sidecar can wait for it) while the guest, the manager and the agents all
look fine, and the source census only speaks once a day.  A timer runs this once a minute and writes
``vector_pipeline_*`` metrics the host's node exporter serves from its textfile directory; the monitoring
rules page on them.  Only container state and the sidecar's own status file are read; nothing is changed.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

SERVICES = ("vector", "sidecar")
ABSENT_AGE = 315360000  # a missing status is ten years old, so one threshold covers it
ROUTE_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}/[a-z0-9][a-z0-9_-]{0,63}$")


def read_status(path: Path) -> dict | None:
    """The sidecar's status document, or None when it is missing, unreadable or not an object."""
    try:
        doc = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    return doc if isinstance(doc, dict) else None


def container_state(compose_file: str, service: str, timeout: int = 20) -> dict:
    """{running, healthy, restarts} for one service of the project (any failure to ask is 'not running')."""
    down = {"running": False, "healthy": False, "restarts": 0}
    try:
        ids = subprocess.run(
            ["docker", "compose", "-f", compose_file, "ps", "-a", "-q", service],
            capture_output=True, text=True, timeout=timeout, check=False,
        ).stdout.split()  # fmt: skip
        if not ids:
            return down
        fmt = "{{.State.Running}} {{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}} {{.RestartCount}}"
        out = subprocess.run(
            ["docker", "inspect", "-f", fmt, ids[0]],
            capture_output=True, text=True, timeout=timeout, check=False,
        ).stdout.split()  # fmt: skip
        running, health, restarts = out[0] == "true", out[1], int(out[2])
    except (OSError, subprocess.SubprocessError, ValueError, IndexError):
        return down
    return {
        "running": running,
        "healthy": running and health in ("healthy", "none"),
        "restarts": restarts,
    }


def render(states: dict[str, dict], status: dict | None, now: float) -> str:
    """The metrics text for the containers' states and the sidecar's status (None: no status file)."""
    lines = []

    def block(name: str, help_: str, kind: str, rows: list[str]) -> None:
        lines.extend([f"# HELP {name} {help_}", f"# TYPE {name} {kind}", *rows])

    for name, help_, key in (
        (
            "vector_pipeline_container_running",
            "1 when the pipeline's container is running.",
            "running",
        ),
        (
            "vector_pipeline_container_healthy",
            "1 when the container is running and its health check passes.",
            "healthy",
        ),
    ):
        block(
            name,
            help_,
            "gauge",
            [f'{name}{{service="{s}"}} {int(states[s][key])}' for s in sorted(states)],
        )
    block(
        "vector_pipeline_container_restarts", "How many times the engine restarted the container (a crash loop climbs).",
        "gauge", [f'vector_pipeline_container_restarts{{service="{s}"}} {states[s]["restarts"]}' for s in sorted(states)],
    )  # fmt: skip
    present = status is not None and isinstance(status.get("time"), int | float)
    age = int(max(now - status["time"], 0)) if present else ABSENT_AGE
    block("vector_pipeline_status_present", "1 when the sidecar's status file is readable.", "gauge",
          [f"vector_pipeline_status_present {int(present)}"])  # fmt: skip
    block("vector_pipeline_status_age_seconds", "Seconds since the sidecar last wrote its status.", "gauge",
          [f"vector_pipeline_status_age_seconds {age}"])  # fmt: skip
    block("vector_pipeline_status_listening", "1 when the sidecar reports it is listening.", "gauge",
          [f"vector_pipeline_status_listening {int(bool(present and status.get('listening')))}"])  # fmt: skip
    errors = status.get("errors") if present else None
    block("vector_pipeline_status_errors", "The number of tables the sidecar reports in error.", "gauge",
          [f"vector_pipeline_status_errors {len(errors) if isinstance(errors, dict) else 0}"])  # fmt: skip
    counters = status.get("counters") if present else None
    rows = []
    if isinstance(counters, dict):
        for route in sorted(counters):
            c = counters[route]
            if ROUTE_RE.match(route) and isinstance(c, dict) and isinstance(c.get("rows"), int):
                rows.append(f'vector_pipeline_rows_total{{route="{route}"}} {c["rows"]}')
    block("vector_pipeline_rows_total", "Rows the sidecar has sent on to the aggregator for the route (resets when it restarts).",
          "counter", rows)  # fmt: skip
    block("vector_pipeline_check_timestamp_seconds", "When this check last ran.", "gauge",
          [f"vector_pipeline_check_timestamp_seconds {int(now)}"])  # fmt: skip
    return "\n".join(lines) + "\n"


def write_atomic(out: Path, text: str) -> None:
    out = out.resolve()
    if len(out.parts) < 4 or out.suffix != ".prom":
        raise ValueError(f"refusing an unsafe output path: {out}")
    fd, tmp = tempfile.mkstemp(prefix=".hnx-liveness-", dir=out.parent)
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(text)
        os.chmod(tmp, 0o644)
        os.replace(tmp, out)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--compose-file", required=True)
    ap.add_argument("--status-file", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    now = time.time()
    states = {s: container_state(args.compose_file, s) for s in SERVICES}
    text = render(states, read_status(Path(args.status_file)), now)
    try:
        write_atomic(Path(args.out), text)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 2
    print(";".join(ln for ln in text.splitlines() if not ln.startswith("#")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
