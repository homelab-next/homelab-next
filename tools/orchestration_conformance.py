#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: orchestration-conformance
#   kind: tool
#   purpose: Run the orchestration conformance suite against the repository's own controller binary on loopback, with process-level fault injection.
#   owner: maintainers
#   trigger: [make:orchestration-conformance, ci:ci/orchestration-conformance]
#   inputs: a built orchestrator/cmd/controller; an absolute, empty or missing work directory
#   outputs: the work directory (controller.yaml, controller.log, the state, the session pids); the suite's verdict
#   exit:
#     "0": the suite passed
#     "1": a check did not pass, or the controller did not come up
#     "2": usage error
"""The ``orchestration`` suite against this repository's controller (ADR-0026 stage 2, PR 2.8).

``run`` writes a controller configuration into ``--work`` (authentication off on loopback, the exec
runner running ``conformance/fakes/llm_orchestrator_hermes.py --stdin`` as each session, a profiles
directory the adapter writes into), starts ``--controller`` and runs ``hnx conform run
orchestration --target conformance/targets/orchestration-orchestrator.yml``, with the adapter's
fault injection wired to real processes:

* ``kill(run_id)`` sends SIGKILL to the session: the runner body records its pid in
  ``<work>/pids/<run id>.pid`` (``HNX_CONFORM_PID_DIR``, the one variable the sessions inherit);
* ``restart()`` runs ``restart --work DIR`` (this script): SIGKILL to every recorded session and
  to the controller, as a crash ends them, then the controller started again on the same
  database, which reconciles what the crash left.

It needs no network beyond loopback.  ``--check`` (repeatable) runs single checks, ``--strict``
fails a run on a failing SHOULD check; a check left ``untested`` fails a strict run too.

    go build -o build/controller ./orchestrator/cmd/controller   # (from orchestrator/: ./cmd/controller)
    python3 tools/orchestration_conformance.py run --controller build/controller --work /tmp/oc --strict
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.request
from collections.abc import Callable
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
# the one loopback address, from the runner body this harness runs
from conformance.fakes.llm_orchestrator_hermes import LOOPBACK  # noqa: E402

TARGET = REPO / "conformance" / "targets" / "orchestration-orchestrator.yml"
RUNNER_BODY = REPO / "conformance" / "fakes" / "llm_orchestrator_hermes.py"
START_S = 30.0


def free_port() -> int:
    with socket.socket() as s:
        s.bind((LOOPBACK, 0))
        return s.getsockname()[1]


def write_config(work: Path, port: int) -> Path:
    """The controller's configuration for a conformance run, in ``work``."""
    for sub in ("profiles", "pids", "state"):
        (work / sub).mkdir(mode=0o700, exist_ok=True)
    runner = {
        "kind": "exec",
        "exec": {
            "argv": [sys.executable, "-I", str(RUNNER_BODY), "--stdin"],
            "usage_args": ["--usage-file", "{usage_path}"],
        },
        "timeout_seconds": 120,
        "env_allowlist": ["HNX_CONFORM_PID_DIR"],
    }
    cfg = {
        "db_path": str(work / "state" / "controller.db"),
        "http_addr": f"{LOOPBACK}:{port}",
        "concurrency": 1,
        "runner": runner,
        "backends": {
            "local": {"name": "engine-a", "home": "conformance", "needs_interlock": False}
        },
        "profiles_dir": str(work / "profiles"),
        "lessons_disabled": True,
        "prompt_contracts": [],
        "api_auth": {"enabled": False},
        "scope": {
            "denied_roots": ["owner"],
            "findings_root": "",
            "shared_write": [],
            "reserved_names": [],
        },
    }
    path = work / "controller.yaml"
    path.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")  # JSON is YAML
    (work / "endpoint").write_text(f"http://{LOOPBACK}:{port}\n", encoding="ascii")
    return path


def healthy(url: str) -> bool:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(f"{url}/healthz", timeout=2) as resp:
            return resp.status == 200
    except OSError:
        return False


def start(work: Path) -> int:
    """Start the controller of ``work`` in its own session and wait until it answers."""
    binary = (work / "controller.bin").read_text(encoding="utf-8").strip()
    env = dict(os.environ, HNX_CONFORM_PID_DIR=str(work / "pids"))
    with open(work / "controller.log", "ab") as log:
        proc = subprocess.Popen(
            [binary, "serve", "--config", str(work / "controller.yaml")],
            stdout=log,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            env=env,
            start_new_session=True,
        )
    (work / "controller.pid").write_text(f"{proc.pid}\n", encoding="ascii")
    url = (work / "endpoint").read_text(encoding="ascii").strip()
    deadline = time.monotonic() + START_S
    while not healthy(url):
        if proc.poll() is not None or time.monotonic() > deadline:
            raise SystemExit(
                f"orchestration-conformance: the controller did not come up (see {work}/controller.log)"
            )
        time.sleep(0.1)
    return proc.pid


#: how long a killed controller has to be gone before a restart gives up, loudly
GONE_WAIT_S = 10.0


def _kill(pid: int, still: Callable[[int], bool]) -> bool:
    """SIGKILL ``pid`` if ``still(pid)`` says it is still the process meant, checked and signalled
    through one pidfd, so the number cannot be reused by another process in between. False when
    it was not (gone, or another process now)."""
    try:
        fd = os.pidfd_open(pid)
    except (ProcessLookupError, PermissionError, OSError):
        return False
    try:
        if not still(pid):
            return False
        with contextlib.suppress(ProcessLookupError):
            signal.pidfd_send_signal(fd, signal.SIGKILL)
        return True
    finally:
        os.close(fd)


def _gone(pid: int, wait_s: float | None = None) -> bool:
    """Wait until ``pid`` no longer runs (a zombie of ours is reaped); False when it still runs
    after ``wait_s`` (GONE_WAIT_S)."""
    deadline = time.monotonic() + (GONE_WAIT_S if wait_s is None else wait_s)
    while True:
        with contextlib.suppress(ChildProcessError):
            if os.waitpid(pid, os.WNOHANG)[0] == pid:
                return True
        try:
            with open(f"/proc/{pid}/stat", encoding="ascii") as f:
                if f.read().rsplit(")", 1)[1].split()[0] in ("Z", "X"):
                    return True
        except (OSError, IndexError):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.02)


def _proc_file(pid: int, name: str) -> bytes:
    try:
        with open(f"/proc/{pid}/{name}", "rb") as f:
            return f.read()
    except OSError:
        return b""


def is_session(pid: int, run_id: str) -> bool:
    """Whether ``pid`` is still the session of ``run_id`` (its environment carries the run id):
    a pid file can outlive its process, and the number can be reused by another."""
    return pid > 1 and f"HNX_RUN_ID={run_id}".encode() in _proc_file(pid, "environ").split(b"\0")


def is_controller(pid: int, work: Path) -> bool:
    """Whether ``pid`` is still the controller of ``work``: its command line is exactly the one
    start() gave it (the work directory's binary, ``serve --config`` its configuration)."""
    try:
        binary = (work / "controller.bin").read_text(encoding="utf-8").strip()
    except OSError:
        return False
    want = [binary, "serve", "--config", str(work / "controller.yaml")]
    return pid > 1 and _proc_file(pid, "cmdline") == b"\0".join(a.encode() for a in want) + b"\0"


def stop(work: Path) -> None:
    """SIGKILL the controller, then every recorded session, as a crash ends them. The controller
    goes first and is waited for: a session killed while it still runs would be a failure it
    records (KilledExternally, and an automatic retry), not a crash it reconciles at its next
    start. Only a pid that is still that process is signalled."""
    try:
        pid = int((work / "controller.pid").read_text(encoding="ascii"))
    except (OSError, ValueError):
        pid = 0
    if pid and _kill(pid, lambda p: is_controller(p, work)) and not _gone(pid):
        # its sessions are left alone: killed under a live controller they would be failures it
        # records and retries, which is not the crash a restart stands for
        raise RuntimeError(
            f"the controller (pid {pid}) still runs {GONE_WAIT_S}s after SIGKILL; its sessions are left alone"
        )
    for p in (work / "pids").glob("*.pid"):
        run_id = p.name.removesuffix(".pid")
        with contextlib.suppress(OSError, ValueError):
            _kill(int(p.read_text(encoding="ascii")), lambda q, r=run_id: is_session(q, r))
        p.unlink(missing_ok=True)


def cmd_restart(work: Path) -> int:
    try:
        stop(work)
    except RuntimeError as exc:
        print(f"orchestration-conformance: restart: {exc}", file=sys.stderr)
        return 1
    start(work)
    return 0


def cmd_run(binary: Path, work: Path, checks: list[str], strict: bool, out: Path | None) -> int:
    if not work.is_absolute():
        print("orchestration-conformance: --work must be absolute", file=sys.stderr)
        return 2
    if work.exists() and any(work.iterdir()):
        print("orchestration-conformance: --work must be empty or missing", file=sys.stderr)
        return 2
    if not (binary.is_file() and os.access(binary, os.X_OK)):
        print(
            f"orchestration-conformance: --controller {binary} is not an executable file",
            file=sys.stderr,
        )
        return 2
    work.mkdir(mode=0o700, parents=True, exist_ok=True)
    write_config(work, free_port())
    (work / "controller.bin").write_text(f"{binary.resolve()}\n", encoding="utf-8")
    try:
        start(work)
        url = (work / "endpoint").read_text(encoding="ascii").strip()
        env = dict(
            os.environ,
            HNX_ENDPOINT_ORCHESTRATION=url,
            HNX_ORCHESTRATION_PROFILES_DIR=str(work / "profiles"),
            HNX_ORCHESTRATION_PID_DIR=str(work / "pids"),
            HNX_ORCHESTRATION_RESTART=json.dumps(
                [sys.executable, str(Path(__file__).resolve()), "restart", "--work", str(work)]
            ),
            NO_PROXY=LOOPBACK,
            no_proxy=LOOPBACK,
        )
        argv = [
            sys.executable,
            "-m",
            "homelabnext.cli",
            "conform",
            "run",
            "orchestration",
            "--target",
            str(TARGET),
        ]
        argv += ["--strict"] if strict else []
        for c in checks:
            argv += ["--check", c]
        if out is not None:
            argv += ["--out", str(out)]
        return subprocess.run(argv, cwd=REPO, env=env, check=False).returncode
    finally:
        stop(work)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="start the controller and run the suite")
    r.add_argument("--controller", type=Path, required=True)
    r.add_argument("--work", type=Path, required=True)
    r.add_argument("--check", action="append", default=[])
    r.add_argument("--strict", action="store_true")
    r.add_argument("--out", type=Path)
    s = sub.add_parser(
        "restart",
        help="the adapter's restart: kill the controller and its sessions, start it again",
    )
    s.add_argument("--work", type=Path, required=True)
    a = ap.parse_args(argv)
    if a.cmd == "restart":
        return cmd_restart(a.work)
    return cmd_run(a.controller, a.work, a.check, a.strict, a.out)


if __name__ == "__main__":
    sys.exit(main())
