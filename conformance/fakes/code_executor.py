# SPDX-License-Identifier: Apache-2.0
"""Reference code executor: each program in a fresh fork of a warm Python process.  TEST-ONLY.

**THIS IS NOT AN ISOLATION BOUNDARY.  NEVER RUN MODEL-WRITTEN PROGRAMS WITH IT.**  ADR-0031
rejects in-process and plain-subprocess execution as a sandbox; this fake exists only so the
``codemode-executor`` suite has a subject whose checks observe something real in CI without
root, Docker or gVisor.  It has the shape decision 5 asks of the real one -- a long-lived
process that forks a fresh child per run -- and none of its hardening.  Per run
(``conformance/protocols/codemode_executor.py``, rules a-g):

* a fork of the zygote (``code_executor_child.py``: a ``python -I -S -B`` started once, with an
  empty environment, that never runs a program itself) in its own session, with an environment
  built from nothing (``HOME``, ``TMPDIR`` and a locale; not one variable of the caller's) and a
  fresh scratch directory as its working directory, removed when the run ends; the program
  reaches it as an unlinked file, so its size is bound only by ``MAX_PROGRAM_CHARS``;
* inside it a broker client that counts calls (``max_calls``) and turns each reply into a
  value, ``broker.Denied``, ``broker.Error`` or a sticky ``broker.Paused``; an address-space cap
  (a backstop well above the memory cap) and an audit hook that refuses connections to anything
  but the broker endpoint, name lookups, opening files outside the scratch directory (the
  standard library stays readable, for imports), new processes, signals to other processes and
  native code;
* from here: the wall clock, CPU seconds and resident memory (read from ``/proc`` every few
  milliseconds, with an ``RLIMIT_CPU`` backstop where there is no ``/proc``) and printed output
  are watched, and the run is killed at a cap (the process and its group, so a run stopped
  before it started its session dies too); output is cut on a character boundary and the value
  is read up to ``result_bytes`` and no further.

An audit hook does not see C code, and a program that sets out to escape it will.  The real
executor (the CM-7 spike chooses it, CM-8 builds it) is a hardened sandbox host that passes the same suite.
POSIX only (``fork``, ``SCM_RIGHTS``).
"""

from __future__ import annotations

import atexit
import contextlib
import json
import math
import os
import re
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
    DEFAULT_BROKER_BIND,
    ERROR_KINDS,
    MAX_PROGRAM_CHARS,
    MESSAGE_MAX,
    MESSAGE_UNSAFE,
    BrokerEndpoint,
    ExecutionError,
    ExecutionResult,
    Limits,
    PendingCall,
    ProgramTooLarge,
    UnsupportedLanguage,
)

CHILD = Path(__file__).with_name("code_executor_child.py")
_POLL_S = 0.005  # how often the CPU clock and the wall clock are looked at
_HEADER_MAX = 65536  # the child's header line (an error message at most 8000 chars); more is not
_UNSAFE = re.compile(MESSAGE_UNSAFE)
_REAP_S = 2.0  # how long a killed run's process may take to be reported gone


def cut_text(data: bytes, limit: int) -> str:
    """``data`` as text of at most ``limit`` UTF-8 bytes: invalid bytes become U+FFFD, and the
    text is cut on a character boundary after that (a replacement can be longer than the byte it
    replaces, so cutting the bytes first is not enough)."""
    text = data[:limit].decode("utf-8", "replace")
    raw = text.encode()
    return text if len(raw) <= limit else raw[:limit].decode("utf-8", "ignore")


def clean_message(text: str) -> str:
    """One line of at most MESSAGE_MAX characters, unsafe characters as spaces."""
    return _UNSAFE.sub(" ", text)[:MESSAGE_MAX]


def _resident_bytes(pid: int) -> int | None:
    """VmRSS of ``pid`` from ``/proc`` (None where there is none)."""
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        return None
    return None


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

    def spawn(self, cfg: dict, program: str) -> socket.socket:
        """Ask for one run; returns the run's channel (its pid and pipes, then its exit).  The
        program goes as an unlinked file, so its size is not bound by a socket message."""
        ours, theirs = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        try:
            with tempfile.TemporaryFile() as code:
                code.write(program.encode("utf-8"))
                code.flush()
                code.seek(0)
                with self._lock:
                    socket.send_fds(
                        self.ctl, [json.dumps(cfg).encode()], [theirs.fileno(), code.fileno()]
                    )
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
    broker_bind = DEFAULT_BROKER_BIND
    _egress = "broker-only"  # what the child's hook lets the program connect to
    _pause = "sticky"  # a pending reply pauses the run whatever the program catches

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

    def _max_calls(self, limits: Limits) -> int | None:
        """The broker client's call cap."""
        return limits.max_calls

    # ------------------------------------------------------------ contract
    def run(
        self, program: str, *, language: str, broker: BrokerEndpoint, limits: Limits
    ) -> ExecutionResult:
        if language not in self.languages:
            raise UnsupportedLanguage(
                f"this executor runs {sorted(self.languages)}, not {language!r}"
            )
        if len(program) > MAX_PROGRAM_CHARS:
            raise ProgramTooLarge(f"{len(program)} characters, over {MAX_PROGRAM_CHARS}")
        workdir = self._workdir()
        try:
            return self._run(program, broker, limits, workdir)
        finally:
            self._release(workdir)

    def _run(
        self, program: str, broker: BrokerEndpoint, limits: Limits, workdir: str
    ) -> ExecutionResult:
        cfg = {
            "host": broker.host,
            "port": broker.port,
            "token": broker.token,
            "workdir": workdir,
            "env": self._env(workdir),
            # resident memory is accounted from here; the address-space cap is a backstop
            "memory_backstop": 2 * limits.memory_bytes + (512 << 20),
            "max_calls": self._max_calls(limits),
            "pause": self._pause,
            "cpu_backstop_s": math.ceil(limits.cpu_s) + 1,
            "wall_s": limits.wall_s,
            "egress": self._egress,
        }
        started = time.monotonic()
        chan = _Zygote.get().spawn(cfg, program)
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
                # the process itself as well as its group: the group exists only once the
                # process has called setsid(), which a run stopped early may not have done yet
                self._kill(pid)
                with contextlib.suppress(OSError):
                    chan.recv(4096)  # the supervisor's report: the process is gone
            chan.close()

    def _kill(self, pid: int) -> None:
        for kill in (os.killpg, os.kill):
            with contextlib.suppress(ProcessLookupError, PermissionError):
                kill(pid, signal.SIGKILL)

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
            rss = _resident_bytes(pid)
            if rss is not None and rss > limits.memory_bytes:
                stop = "memory"
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
        text = cut_text(bytes(output), limits.output_bytes)
        if stop is None and exit_code == [-signal.SIGXCPU]:
            stop = "cpu"
        if stop is not None:
            return ExecutionResult("limit", limit=stop, output=text)
        if header is None:
            error = ExecutionError("sandbox", f"the sandbox ended without a result ({exit_code})")
            return ExecutionResult("error", error=error, output=text)
        status = header.get("status")
        if status == "error":
            err = header.get("error") or {}
            kind = err.get("kind") if err.get("kind") in ERROR_KINDS else "sandbox"
            error = ExecutionError(kind, clean_message(str(err.get("message", ""))))
            return ExecutionResult("error", error=error, output=text)
        if status == "paused":
            pending = tuple(
                PendingCall(p["step"], p["action"], p["request_id"], p["request_digest"])
                for p in header.get("pending", ())
            )
            return ExecutionResult("paused", pending=pending, output=text)
        if status != "ok":
            return ExecutionResult(status, output=text)
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


class NoCallCapExecutor(ForkingExecutor):
    """Mutant: the broker client never counts calls; a loop calls the broker without end."""

    def _max_calls(self, limits):
        return None


class CatchablePauseExecutor(ForkingExecutor):
    """Mutant: a pending reply raises an ordinary exception, so ``except Exception`` swallows
    the pause and the program goes on as if the call had been refused."""

    _pause = "catchable"


class UnboundedResultExecutor(ForkingExecutor):
    """Mutant: the whole value is read and returned, however long."""

    def _result_budget(self, limits):
        return None
