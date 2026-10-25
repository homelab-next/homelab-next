# SPDX-License-Identifier: Apache-2.0
"""Reference code executor: each program in a fresh fork of a warm Python process.  TEST-ONLY.

**THIS IS NOT AN ISOLATION BOUNDARY.  NEVER RUN MODEL-WRITTEN PROGRAMS WITH IT.**  ADR-0031
rejects in-process and plain-subprocess execution as a sandbox; this fake exists only so the
``codemode-executor`` suite has a subject whose checks observe something real in CI without
root, Docker or gVisor.  It has the shape decision 5 asks of the real one -- a long-lived
process that forks a fresh child per run -- and none of its hardening.  Per run
(``conformance/protocols/codemode_executor.py``, rules a-f):

* a fork of the zygote (``code_executor_child.py``: a ``python -I -S -B`` started once, with an
  empty environment, that never runs a program itself) in its own session, with an environment
  built from nothing (``HOME``, ``TMPDIR`` and a locale; not one variable of the caller's) and a
  fresh scratch directory as its working directory, removed when the run ends;
* inside it an address-space cap and an audit hook that refuses connections to anything but the
  broker endpoint, name lookups, opening files outside the scratch directory (the standard
  library stays readable, for imports), new processes, signals to other processes and native
  code;
* from here: the wall clock, CPU seconds (read from ``/proc`` every few milliseconds, with an
  ``RLIMIT_CPU`` backstop where there is no ``/proc``) and printed output are watched, and the
  run is killed at a cap; the value is read up to ``result_bytes`` and no further.

An audit hook does not see C code, and a program that sets out to escape it will.  The real
executor (docs/codemode.md CM-7, CM-8) is a hardened sandbox host that passes the same suite.
POSIX only (``fork``, ``SCM_RIGHTS``).
"""

from __future__ import annotations

import atexit
import contextlib
import json
import math
import os
import select
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from conformance.protocols.codemode_executor import (
    BrokerEndpoint,
    ExecutionResult,
    Limits,
    UnsupportedLanguage,
)

CHILD = Path(__file__).with_name("code_executor_child.py")
_POLL_S = 0.005  # how often the CPU clock and the wall clock are looked at
_HEADER_MAX = 4096  # the child's header line is a few dozen bytes; more is not a header
_REAP_S = 2.0  # how long a killed run's process may take to be reported gone


def _cpu_seconds(pid: int) -> float | None:
    """utime + stime of ``pid`` from ``/proc`` (None where there is no ``/proc``)."""
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return None
    fields = stat.rpartition(")")[2].split()
    return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")


class _Zygote:
    """The warm process every run is forked from, shared by every executor in this process: it
    holds no state of any run (it never runs one), so sharing it shares nothing."""

    _lock = threading.Lock()
    _current: _Zygote | None = None

    def __init__(self) -> None:
        ours, theirs = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        try:
            self.proc = subprocess.Popen(
                [sys.executable, "-I", "-S", "-B", str(CHILD), str(theirs.fileno())],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                cwd="/",
                env={},
                pass_fds=(theirs.fileno(),),
                start_new_session=True,
            )
        finally:
            theirs.close()
        self.ctl = ours

    @classmethod
    def get(cls) -> _Zygote:
        with cls._lock:
            if cls._current is None or cls._current.proc.poll() is not None:
                cls._current = _Zygote()
                atexit.register(cls._current.close)
            return cls._current

    def spawn(self, cfg: dict) -> socket.socket:
        """Ask for one run; returns the run's channel (its pid and pipes, then its exit)."""
        ours, theirs = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        try:
            with self._lock:
                socket.send_fds(self.ctl, [json.dumps(cfg).encode()], [theirs.fileno()])
        except OSError:
            ours.close()
            raise
        finally:
            theirs.close()
        return ours

    def close(self) -> None:
        self.ctl.close()  # the zygote reads end-of-file and exits
        try:
            self.proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()


class ForkingExecutor:
    """Runs Python programs, each in a fresh fork of a warm process behind an audit hook.
    Test-only: NOT a sandbox (see the module docstring)."""

    languages = frozenset({"python"})
    _egress = "broker-only"  # what the child's hook lets the program connect to

    def __init__(self) -> None:
        self._dirs: list[str] = []

    def close(self) -> None:
        for d in self._dirs:
            shutil.rmtree(d, ignore_errors=True)
        self._dirs.clear()

    # ------------------------------------------------------------ the parts a mutant changes
    def _workdir(self) -> str:
        """A scratch directory for one run, removed by :meth:`_release`."""
        d = tempfile.mkdtemp(prefix="hnx-codemode-")
        self._dirs.append(d)
        return d

    def _release(self, workdir: str) -> None:
        shutil.rmtree(workdir, ignore_errors=True)
        with contextlib.suppress(ValueError):
            self._dirs.remove(workdir)

    def _env(self, workdir: str) -> dict[str, str]:
        """The sandbox environment, built from nothing."""
        return {"HOME": workdir, "TMPDIR": workdir, "LC_ALL": "C.UTF-8"}

    def _wall_s(self, limits: Limits) -> float:
        return limits.wall_s

    def _result_budget(self, limits: Limits) -> int | None:
        """How many bytes of the value are read; one past this means truncated."""
        return limits.result_bytes

    # ------------------------------------------------------------ contract
    def run(
        self, program: str, *, language: str, broker: BrokerEndpoint, limits: Limits
    ) -> ExecutionResult:
        if language not in self.languages:
            raise UnsupportedLanguage(
                f"this executor runs {sorted(self.languages)}, not {language!r}"
            )
        workdir = self._workdir()
        try:
            return self._run(program, broker, limits, workdir)
        finally:
            self._release(workdir)

    def _run(
        self, program: str, broker: BrokerEndpoint, limits: Limits, workdir: str
    ) -> ExecutionResult:
        cfg = {
            "program": program,
            "host": broker.host,
            "port": broker.port,
            "token": broker.token,
            "workdir": workdir,
            "env": self._env(workdir),
            "memory_bytes": limits.memory_bytes,
            "cpu_backstop_s": math.ceil(limits.cpu_s) + 1,
            "wall_s": limits.wall_s,
            "egress": self._egress,
        }
        started = time.monotonic()
        chan = _Zygote.get().spawn(cfg)
        fds: list[int] = []  # the run's output and result pipes while they are open
        pid = None
        exit_code: list[int] = []  # the run's exit status once its supervisor has reported it
        try:
            chan.settimeout(_REAP_S)
            msg, fds, _flags, _addr = socket.recv_fds(chan, 4096, 2)
            pid = json.loads(msg)["pid"]
            return self._watch(pid, chan, fds, exit_code, limits, started)
        finally:
            for fd in fds:
                os.close(fd)
            if pid is not None and not exit_code:
                with contextlib.suppress(ProcessLookupError, PermissionError):
                    os.killpg(pid, signal.SIGKILL)
                with contextlib.suppress(OSError):
                    chan.recv(4096)  # the supervisor's report: the process is gone
            chan.close()

    def _watch(
        self,
        pid: int,
        chan: socket.socket,
        fds: list[int],
        exit_code: list[int],
        limits: Limits,
        started: float,
    ) -> ExecutionResult:
        out_fd, r_fd = fds
        deadline = started + self._wall_s(limits)
        budget = self._result_budget(limits)
        output, result = bytearray(), bytearray()
        header: dict | None = None
        truncated = False
        open_fds = {out_fd, r_fd}
        stop: str | None = None  # the cap that ended the run
        while (open_fds or not exit_code) and stop is None:
            now = time.monotonic()
            if now >= deadline:
                stop = "wall"
                break
            cpu = _cpu_seconds(pid)
            if cpu is not None and cpu > limits.cpu_s:
                stop = "cpu"
                break
            watch = [*open_fds] if exit_code else [*open_fds, chan]
            ready, _, _ = select.select(watch, [], [], min(_POLL_S, deadline - now))
            for fd in ready:
                if fd is chan:
                    exit_code.append(json.loads(chan.recv(4096) or b'{"exit": -9}')["exit"])
                    continue
                chunk = os.read(fd, 65536)
                if not chunk:
                    open_fds.discard(fd)
                elif fd == out_fd:
                    output += chunk
                    if len(output) > limits.output_bytes:
                        stop = "output"
                else:
                    result += chunk
                    if header is None and b"\n" in result:
                        line, _, rest = bytes(result).partition(b"\n")
                        header, result = json.loads(line), bytearray(rest)
                    elif header is None and len(result) > _HEADER_MAX:
                        open_fds.discard(fd)  # not a header: the sandbox is misbehaving
                        result.clear()
                    if header is not None and budget is not None and len(result) > budget:
                        del result[budget:]
                        truncated = True
                        open_fds.discard(fd)  # read no further: the rest is never held
                    if fd not in open_fds:
                        fds.remove(fd)
                        os.close(fd)  # the child's next write fails instead of blocking
        text = bytes(output[: limits.output_bytes]).decode("utf-8", "replace")
        if stop is None and exit_code == [-signal.SIGXCPU]:
            stop = "cpu"
        if stop is not None:
            return ExecutionResult("limit", limit=stop, output=text)
        if header is None:
            return ExecutionResult("error", error="crashed", output=text)
        status = header.get("status")
        if status != "ok":
            return ExecutionResult(
                status, limit=header.get("limit"), error=header.get("error"), output=text
            )
        if truncated:
            value = bytes(result).decode("utf-8", "ignore")  # drops a character cut in half
            return ExecutionResult("ok", value=value, truncated=True, output=text)
        return ExecutionResult("ok", value=json.loads(bytes(result) or b"null"), output=text)


class OpenEgressExecutor(ForkingExecutor):
    """Mutant: the sandbox's network is left on; a program reaches any address, not only the
    broker (a container started on the default bridge network instead of the broker-only one)."""

    _egress = "open"


class LeakyEnvExecutor(ForkingExecutor):
    """Mutant: the sandbox inherits the caller's environment (``subprocess`` with ``env=None``,
    or a container started with ``--env-file`` of the runner's own)."""

    def _env(self, workdir):
        return {**os.environ, **super()._env(workdir)}


class NoTimeoutExecutor(ForkingExecutor):
    """Mutant: no wall-clock cap; a program that sleeps or blocks runs as long as it likes."""

    def _wall_s(self, limits):
        return 3600.0


class ReusedStateExecutor(ForkingExecutor):
    """Mutant: one scratch directory for every run, never cleaned (a warm pool that reuses a
    worker's directory instead of giving each run its own)."""

    def __init__(self) -> None:
        super().__init__()
        self._shared: str | None = None

    def _workdir(self):
        if self._shared is None:
            self._shared = super()._workdir()
        return self._shared

    def _release(self, workdir):
        pass  # kept for the next run; close() removes it


class UnboundedResultExecutor(ForkingExecutor):
    """Mutant: the whole value is read and returned, however long."""

    def _result_budget(self, limits):
        return None
