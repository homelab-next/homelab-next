# SPDX-License-Identifier: Apache-2.0
"""The agent-runner suite's development launcher: the reference for ADR-0051 decisions 6, 8, 9
and 10 on a host with no systemd.

The controller's own launcher (`runner/agent`, ADR-0051 step 3) is held to the same suite. It
isolates nothing, like the controller's `exec` launcher: the body runs as the caller's user. What
it does:

- **Inputs.** It writes the spec and each input as `0600` files in a `0700` directory, the run's
  `$CREDENTIALS_DIRECTORY`, and removes them when the run ends. It sets `$HNX_RUN_DIR` (the
  output directory) and installs the grants file with its pin (`$HNX_GRANTS_FILE`,
  `$HNX_GRANTS_SHA256`). It passes nothing else to the body but `PATH` and `LANG`: no key, token
  or prompt is in the body's argv or environment.
- **Supervision.** Each run is one `agent_runner_supervisor.py`, a child subreaper. Stopping the
  run (cancel, the ceiling, a stall, the stream bound) ends every descendant, as stopping a unit
  ends its cgroup.
- **Liveness.** It stops a run with no progress for `stall_timeout_s`.
  - Progress is `call` records the gateway's records corroborate: the smaller of the stream's
    calls and the gateway's answered calls for the run's tag.
  - While the gateway's records lag (its watermark is more than `gateway_wait_s` behind) or it
    dropped some, it falls back to `cpu` liveness: the run's processes' CPU time.
  - `liveness: cpu` uses CPU time throughout.
- **Classification** (:func:`classify`): from why it stopped the run, how the body exited, the
  stream and the gateway's records, which it waits for up to `gateway_wait_s` (decisions 6 and
  10).
- **Reading.** It opens each output `O_NOFOLLOW|O_NONBLOCK`, accepts only a regular file, and reads
  at most its bound.

`mutant=` builds the suite's defective launchers (`kills-only-process-group`,
`keeps-inputs`, `no-spec-check`).
"""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from conformance.protocols.agent_runner import GatewayView, Outcome, RunInputs

HERE = Path(__file__).resolve().parent
BODY = HERE / "agent_runner_body.py"
SUPERVISOR = HERE / "agent_runner_supervisor.py"
#: the stream's bounds (ADR-0051 decision 4)
MAX_USAGE_BYTES = 1 << 20
MAX_LINE_BYTES = 16 * 1024
MAX_DEPTH = 8
MAX_ANSWER_BYTES = 1 << 20
#: how long classification waits for the gateway's records to cover the run's end
GATEWAY_WAIT_S = 2.0
POLL_S = 0.05
#: the classes an ``end`` record may claim, and which of them the gateway must corroborate
CLAIMABLE = ("ContextExceeded", "ToolCallParse", "TurnCap", "ConcurrencyLimited")


def _depth(v: Any, d: int = 1) -> int:
    if isinstance(v, dict):
        return max([d, *(_depth(x, d + 1) for x in v.values())])
    if isinstance(v, list):
        return max([d, *(_depth(x, d + 1) for x in v)])
    return d


def read_bounded(path: Path, limit: int) -> bytes | None:
    """``limit + 1`` bytes at most of ``path``, or None when it is not a regular file (a link, a
    FIFO, missing): opened ``O_NOFOLLOW|O_NONBLOCK`` so a planted FIFO cannot block the read."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        chunks, left = [], limit + 1
        while left > 0:
            b = os.read(fd, min(left, 65536))
            if not b:
                break
            chunks.append(b)
            left -= len(b)
        return b"".join(chunks)
    finally:
        os.close(fd)


def parse_stream(raw: bytes | None, limit: int = MAX_USAGE_BYTES) -> tuple[list[dict], str]:
    """The stream's records, or ``([], why)`` when it breaks a bound or a record is invalid."""
    if raw is None:
        return [], ""
    if len(raw) > limit:
        return [], f"the usage stream is over {limit} bytes"
    from homelabnext.schema_registry import validator

    v = validator("runner", "usage_record.schema.json")
    out = []
    for n, line in enumerate(raw.splitlines(), 1):
        if len(line) > MAX_LINE_BYTES:
            return [], f"usage line {n} is over {MAX_LINE_BYTES} bytes"
        try:
            rec = json.loads(line)
        except ValueError:
            return [], f"usage line {n} is not JSON"
        if _depth(rec) > MAX_DEPTH:
            return [], f"usage line {n} nests past {MAX_DEPTH}"
        if next(iter(v.iter_errors(rec)), None) is not None:
            return [], f"usage line {n} is not a usage record"
        out.append(rec)
    return out, ""


def _wait_records(gateway: GatewayView, tag: str, end: float, wait_s: float) -> list[dict] | None:
    """The gateway's records for ``tag`` once they cover ``end``, or None when they do not
    within ``wait_s`` or the gateway dropped records (the claim cannot be judged)."""
    deadline = time.monotonic() + wait_s
    while True:
        if gateway.dropped() > 0:
            return None
        if gateway.watermark() >= end:
            return gateway.records(tag)
        if time.monotonic() >= deadline:
            return None
        time.sleep(POLL_S)


def corroborates_context(records: list[dict]) -> bool:
    """A 400 ``upstream_rejected`` record later than every answered call of the run."""
    last_ok = max((i for i, r in enumerate(records) if r.get("status") == 200), default=-1)
    rejected = [
        i
        for i, r in enumerate(records)
        if r.get("status") == 400 and r.get("error_code") == "upstream_rejected"
    ]
    return bool(rejected) and max(rejected) > last_ok


def classify(
    *,
    stopped: str | None,
    ended: Mapping[str, Any],
    records: list[dict],
    why_invalid: str,
    exit_classes: Mapping[int, str],
    gateway: GatewayView,
    tag: str,
    end_time: float,
    wait_s: float = GATEWAY_WAIT_S,
) -> tuple[str | None, str]:
    """The attempt's class and why (ADR-0051 decisions 6 and 10)."""
    if stopped:
        return {
            "cancel": "KilledByController",
            "ceiling": "TimeoutCeiling",
            "stall": "Stalled",
            "resource": "ResourceLimit",
        }[stopped], f"the launcher stopped it ({stopped})"
    if "signal" in ended:
        return "KilledExternally", f"signal {ended['signal']} the launcher did not send"
    if why_invalid:
        return "Internal", why_invalid
    code = int(ended.get("code", -1))
    end = records[-1] if records and records[-1].get("type") == "end" else None
    if end is not None and end.get("budget_exhausted"):
        seen = _wait_records(gateway, tag, end_time, wait_s)
        if seen and any(
            r.get("status") == 403 and r.get("error_code") == "run_budget_exhausted" for r in seen
        ):
            return "BudgetExhausted", f"budget {end['budget_exhausted']}, refused by the gateway"
    claim = (end or {}).get("class")
    if claim == "ContextExceeded":
        seen = _wait_records(gateway, tag, end_time, wait_s)
        if seen is not None and corroborates_context(seen):
            return "ContextExceeded", "corroborated by the gateway's 400 upstream_rejected"
        return "Internal", "ContextExceeded claimed, not corroborated by the gateway's records"
    if claim in CLAIMABLE:
        return claim, "the end record's class"
    if code == 0:
        if end is None:
            return "Internal", "a clean exit with no end record"
        return None, "ok"
    if code in exit_classes:
        return exit_classes[code], f"exit status {code}, mapped"
    return "Internal", f"exit status {code}, not mapped"


@dataclass
class _Run:
    run: RunInputs
    gateway: GatewayView
    root: Path
    proc: subprocess.Popen | None
    started: float = field(default_factory=time.monotonic)
    stopped: str | None = None
    refused: str = ""
    monitor: threading.Thread | None = None
    lock: threading.Lock = field(default_factory=threading.Lock)

    @property
    def indir(self) -> Path:
        return self.root / "in"

    @property
    def outdir(self) -> Path:
        return self.root / "out"


def _cpu_ticks(root: int) -> int:
    total = 0
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            with open(f"/proc/{name}/stat", encoding="ascii", errors="replace") as f:
                fields = f.read().rsplit(")", 1)[1].split()
        except (OSError, IndexError):
            continue
        if int(fields[1]) == root or int(name) == root or _under(int(name), root):
            total += int(fields[11]) + int(fields[12])
    return total


def _under(pid: int, root: int) -> bool:
    for _ in range(64):
        try:
            with open(f"/proc/{pid}/stat", encoding="ascii", errors="replace") as f:
                pid = int(f.read().rsplit(")", 1)[1].split()[1])
        except (OSError, IndexError, ValueError):
            return False
        if pid == root:
            return True
        if pid <= 1:
            return False
    return False


class DevLauncher:
    """The development launcher with a body: the default body is the reference fake runtime."""

    def __init__(
        self,
        body: Sequence[str] | None = None,
        exit_classes: Mapping[int, str] | None = None,
        *,
        mutant: str = "",
        gateway_wait_s: float = GATEWAY_WAIT_S,
        max_usage_bytes: int = MAX_USAGE_BYTES,
    ) -> None:
        from conformance.fakes.agent_runner_body import EXIT_CLASSES

        self.features = frozenset({"body-override"})
        self.exit_classes = dict(EXIT_CLASSES if exit_classes is None else exit_classes)
        self.body = list(body) if body else [sys.executable, "-I", str(BODY)]
        self.mutant = mutant
        self.gateway_wait_s = gateway_wait_s
        self.max_usage_bytes = max_usage_bytes

    # -- the contract ---------------------------------------------------------------------
    def start(
        self, run: RunInputs, gateway: GatewayView, *, body: Sequence[str] | None = None
    ) -> _Run:
        root = Path(tempfile.mkdtemp(prefix="hnx-run-"))
        h = _Run(run, gateway, root, None)
        if self.mutant != "no-spec-check":
            from homelabnext.schema_registry import validator

            errors = list(validator("runner", "session.schema.json").iter_errors(dict(run.spec)))
            if errors:
                h.refused = "the session spec does not validate: " + errors[0].message[:200]
                return h
        for d in (h.indir, h.outdir):
            d.mkdir(mode=0o700)
        files = {"spec": json.dumps(dict(run.spec)).encode(), **run.inputs}
        for name, data in files.items():
            fd = os.open(h.indir / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(data)
        grants = root / "grants.json"
        grants.write_bytes(run.grants)
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "LANG": "C.UTF-8",
            "CREDENTIALS_DIRECTORY": str(h.indir),
            "HNX_RUN_DIR": str(h.outdir),
            "HNX_GRANTS_FILE": str(grants),
            "HNX_GRANTS_SHA256": run.grants_sha256,
        }
        argv = list(body) if body else list(self.body)
        sup = [sys.executable, "-I", str(SUPERVISOR), str(root / "exit.json")]
        if self.mutant == "kills-only-process-group":
            sup.append("--group-only")
        log = open(root / "body.log", "wb")  # noqa: SIM115 - closed with the run
        h.proc = subprocess.Popen(
            [*sup, "--", *argv],
            env=env,
            stdout=log,
            stderr=log,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        )
        log.close()
        h.monitor = threading.Thread(target=self._watch, args=(h,), daemon=True)
        h.monitor.start()
        return h

    def cancel(self, handle: _Run) -> None:
        self._stop(handle, "cancel")

    def wait(self, handle: _Run, timeout_s: float) -> Outcome:
        if handle.refused:
            return Outcome("Internal", None, [], None, handle.refused)
        assert handle.proc is not None
        try:
            handle.proc.wait(timeout_s)
        except subprocess.TimeoutExpired:
            self._stop(handle, "cancel")
            handle.proc.wait(30)
        if handle.monitor is not None:
            handle.monitor.join(5)
        end_time = time.time()
        ended = json.loads(read_bounded(handle.root / "exit.json", 4096) or b"{}")
        records, why = parse_stream(
            read_bounded(handle.outdir / "usage.jsonl", self.max_usage_bytes),
            self.max_usage_bytes,
        )
        answer_raw = read_bounded(handle.outdir / "answer", MAX_ANSWER_BYTES)
        cls, detail = classify(
            stopped=handle.stopped,
            ended=ended,
            records=records,
            why_invalid=why,
            exit_classes=self.exit_classes,
            gateway=handle.gateway,
            tag=str(handle.run.spec.get("gateway_tag", "")),
            end_time=end_time,
            wait_s=self.gateway_wait_s,
        )
        if self.mutant != "keeps-inputs":
            shutil.rmtree(handle.indir, ignore_errors=True)
        answer = answer_raw.decode("utf-8", "replace") if answer_raw is not None else None
        return Outcome(cls, answer, records, ended.get("code"), detail)

    def leftovers(self, handle: _Run) -> list[str]:
        return sorted(str(p) for p in handle.indir.glob("*")) if handle.indir.exists() else []

    def release(self, handle: _Run) -> None:
        shutil.rmtree(handle.root, ignore_errors=True)

    # -- supervision ------------------------------------------------------------------------
    def _stop(self, h: _Run, why: str) -> None:
        with h.lock:
            if h.stopped is None:
                h.stopped = why
        if h.proc is not None and h.proc.poll() is None:
            with contextlib.suppress(ProcessLookupError):
                h.proc.send_signal(signal.SIGTERM)

    def _watch(self, h: _Run) -> None:
        assert h.proc is not None
        limits = h.run.spec["limits"]
        tag = str(h.run.spec["gateway_tag"])
        last, mark = None, time.monotonic()
        while h.proc.poll() is None:
            now = time.monotonic()
            if now - h.started >= limits["timeout_s"]:
                return self._stop(h, "ceiling")
            usage = h.outdir / "usage.jsonl"
            try:
                size = usage.lstat().st_size
            except OSError:
                size = 0
            if size > self.max_usage_bytes:
                return self._stop(h, "resource")
            if limits["stall_timeout_s"]:
                seen = self._progress(h, tag, limits["liveness"], usage)
                if seen != last:
                    last, mark = seen, now
                elif now - mark >= limits["stall_timeout_s"]:
                    return self._stop(h, "stall")
            time.sleep(POLL_S)
        return None

    def _progress(self, h: _Run, tag: str, liveness: str, usage: Path) -> tuple[str, int]:
        g = h.gateway
        fresh = g.dropped() == 0 and g.watermark() >= time.time() - self.gateway_wait_s
        if liveness == "progress" and fresh:
            raw = read_bounded(usage, self.max_usage_bytes) or b""
            calls = raw.count(b'"type":"call"')
            answered = sum(1 for r in g.records(tag) if r.get("status") == 200)
            return ("progress", min(calls, answered))
        assert h.proc is not None
        return ("cpu", _cpu_ticks(h.proc.pid))


def make(**config: Any) -> DevLauncher:
    """The adapter factory a target names (``body``, ``exit_classes``, ``gateway_wait_s``)."""
    return DevLauncher(**config)
