# SPDX-License-Identifier: Apache-2.0
"""The process side of :class:`conformance.fakes.code_executor.ForkingExecutor` (test-only).

Run once as ``python -I -S -B code_executor_child.py FD`` with an empty environment: the
*zygote*, a warm process that never runs a program itself.  For each run it receives the
configuration, a channel and the program (an unlinked file) over the socket ``FD`` and forks a supervisor, which forks the run's
own process and reports its pid, its output and result pipes and, at the end, its exit status.
The run's process starts a new session, takes the run's environment and scratch directory, caps
its address space (a backstop: the parent accounts resident memory) and CPU, installs an audit hook that refuses what the contract forbids, runs
the program and writes the outcome to the result pipe: one JSON header line, then (status
``ok``) the value's JSON.  A fork of a process that has run nothing is the "fresh child per
run" of ADR-0031 decision 5, at a few milliseconds a run instead of an interpreter start.

THIS IS NOT AN ISOLATION BOUNDARY.  An audit hook is a tripwire for well-behaved Python: it does
not see what a C extension, a stray file descriptor or the interpreter's own internals do, and a
program written to escape it will.  It exists so the suite's checks can observe something real
(a refused connection, an unreadable file) without root, Docker or gVisor in CI.
"""

from __future__ import annotations

import builtins
import contextlib
import json
import os
import resource
import signal
import socket
import sys

# what the hook refuses outright: processes, native code, raising limits, binding sockets
_DENY = frozenset(
    {
        "os.system",
        "os.exec",
        "os.fork",
        "os.forkpty",
        "os.posix_spawn",
        "os.spawn",
        "os.symlink",
        "os.link",
        "pty.spawn",
        "subprocess.Popen",
        "resource.setrlimit",
        "resource.prlimit",
        "socket.bind",
        "socket.getaddrinfo",
        "socket.gethostbyname",
        "socket.gethostbyaddr",
        "socket.gethostname",
        "socket.sethostname",
        "socket.sendmsg",
        "sys.remote_exec",
    }
)
_WRITE = os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_TRUNC


class Denied(Exception):
    """The broker denied the call (``reason`` is the broker's, or ``call-cap-reached``)."""

    def __init__(self, action: str, reason: str) -> None:
        super().__init__(f"{action}: {reason}")
        self.action, self.reason = action, reason


class Error(Exception):
    """The broker answered with an error, or could not be reached (``broker-unreachable``)."""

    def __init__(self, action: str, reason: str) -> None:
        super().__init__(f"{action}: {reason}")
        self.action, self.reason = action, reason


class Paused(BaseException):
    """The call needs approval: the run is paused.  Not an ``Exception``, so ``except
    Exception`` does not swallow it; every later call raises it again."""


class _CatchablePaused(Exception):
    """The pause-catchable mutant's pause: an ordinary exception."""


class _Broker:
    Denied, Error = Denied, Error

    def __init__(self, cfg: dict, token: str) -> None:
        self._addr = (cfg["host"], cfg["port"])
        self._token = token
        self._timeout = float(cfg["wall_s"])
        self._max_calls = cfg.get("max_calls")  # None: the no-call-cap mutant
        self._sticky = cfg.get("pause") != "catchable"
        self._bare = cfg.get("wire") == "bare"  # the bare-wire mutant: op and target dropped
        self.Paused = Paused if self._sticky else _CatchablePaused
        self.sent = 0
        self.pending: dict | None = None

    def __repr__(self) -> str:
        return "<broker>"

    def call(self, action, args=None, *, target=None):
        return self._send("call", action, args, target)

    def submit(self, action, args=None, *, target=None):
        """Submit the action for approval: the broker stores the request and the run pauses."""
        return self._send("submit", action, args, target)

    def _send(self, op, action, args, target):
        if self.pending is not None and self._sticky:
            raise self.Paused(self.pending["action"])
        if self._max_calls is not None and self.sent >= self._max_calls:
            raise Denied(action, "call-cap-reached")  # refused here, never sent
        step = self.sent
        self.sent += 1
        msg = {"token": self._token, "action": action, "args": args or {}}
        if op != "call" and not self._bare:
            msg["op"] = op
        if target is not None and not self._bare:
            msg["target"] = target
        line = json.dumps(msg)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s.settimeout(self._timeout)
                s.connect(self._addr)
                s.sendall(line.encode() + b"\n")
                buf = b""
                while not buf.endswith(b"\n"):
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
            finally:
                s.close()
            reply = json.loads(buf)
        except (OSError, ValueError):
            raise Error(action, "broker-unreachable") from None
        if not isinstance(reply, dict):
            raise Error(action, "broker-unreachable")
        if reply.get("ok") is True:
            return reply.get("value")
        if reply.get("denied"):
            raise Denied(action, str(reply.get("reason", "")))
        if reply.get("pending"):
            self.pending = {
                "step": step,
                "action": action,
                "request_id": str(reply.get("request_id", "")),
                "request_digest": str(reply.get("request_digest", "")),
            }
            raise self.Paused(action)
        raise Error(action, str(reply.get("reason", "")))


def _hook(cfg: dict, roots: tuple[str, ...]):
    workdir = cfg["workdir"]
    broker = (cfg["host"], cfg["port"])
    open_egress = cfg.get("egress") == "open"

    def inside(path: str, base: str) -> bool:
        return path == base or path.startswith(base.rstrip(os.sep) + os.sep)

    def hook(event: str, args: tuple) -> None:
        if open_egress and event.startswith("socket."):
            return  # the open-egress mutant: a sandbox with the network left on
        if event in _DENY or event.startswith("ctypes."):
            raise PermissionError(f"sandbox: {event} refused")
        if event in ("socket.connect", "socket.sendto"):
            addr = args[-1]
            if not (isinstance(addr, tuple) and tuple(addr[:2]) == broker):
                raise PermissionError("sandbox: only the broker is reachable")
        elif event == "open":
            path, _mode, flags = args
            if isinstance(path, int):
                return
            p = os.path.normpath(os.path.join(workdir, os.fsdecode(path)))
            if inside(p, workdir):
                return
            if not (flags or 0) & _WRITE and any(inside(p, r) for r in roots):
                return  # the standard library, read-only, for imports
            raise PermissionError(f"sandbox: {p} is outside the sandbox")
        elif event in ("os.remove", "os.rename", "os.rmdir", "os.mkdir", "os.chmod"):
            p = os.path.normpath(os.path.join(workdir, os.fsdecode(args[0])))
            if not inside(p, workdir):
                raise PermissionError(f"sandbox: {p} is outside the sandbox")
        elif event in ("os.kill", "os.killpg", "signal.pthread_kill") and args[0] != os.getpid():
            raise PermissionError("sandbox: no signals to other processes")

    return hook


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view) :]


def _message(exc: BaseException) -> str:
    """The exception as one line of text, roughly bounded (the parent cleans and cuts it)."""
    return f"{type(exc).__name__}: {exc}"[:8000]


def _execute(source: str, glb: dict) -> dict:
    """Compile and run the program in ``glb``; the result header of how it ended."""
    try:
        code = compile(source, "<program>", "exec")
    except (SyntaxError, ValueError) as exc:
        return {"status": "error", "error": {"kind": "syntax", "message": _message(exc)}}
    try:
        exec(code, glb)
    except Denied:
        return {"status": "denied"}
    except Error as exc:
        return {"status": "error", "error": {"kind": "broker", "message": _message(exc)}}
    except SystemExit as exc:
        if exc.code not in (None, 0):
            msg = f"SystemExit: {exc.code}"
            return {"status": "error", "error": {"kind": "runtime", "message": msg}}
    except BaseException as exc:  # Paused included: the pending check decides
        return {"status": "error", "error": {"kind": "runtime", "message": _message(exc)}}
    return {"status": "ok"}


def _program(cfg: dict, out_w: int, res_w: int, code_fd: int) -> None:
    """The run's own process: a fresh fork of the zygote, its own session, then the program."""
    os.setsid()
    devnull = os.open(os.devnull, os.O_RDONLY)
    os.dup2(devnull, 0)
    os.dup2(out_w, 1)
    os.dup2(out_w, 2)
    os.close(devnull)
    os.close(out_w)
    with os.fdopen(code_fd, "rb") as f:  # the program, from an unlinked file the parent wrote
        size = int(f.readline())  # the prelude's length in bytes, then the prelude, the program
        prelude = f.read(size).decode("utf-8")
        source = f.read().decode("utf-8")
    os.chdir(cfg["workdir"])
    os.environ.clear()
    os.environ.update(cfg["env"])
    mem = int(cfg["memory_backstop"])
    resource.setrlimit(resource.RLIMIT_AS, (mem, mem))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    cpu = int(cfg["cpu_backstop_s"])
    resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu + 1))
    roots = tuple(os.path.normpath(p) for p in sys.path if p)
    broker = _Broker(cfg, cfg.pop("token"))
    sys.addaudithook(_hook(cfg, roots))

    body = b""
    glb = {"__name__": "__program__", "__builtins__": builtins, "broker": broker}
    try:  # the prelude first, in the program's namespace (rule h): a failure is the sandbox's
        exec(compile(prelude, "<prelude>", "exec"), glb)
    except BaseException as exc:
        error = {"kind": "sandbox", "message": "the prelude failed: " + _message(exc)}
        header = {"status": "error", "error": error}
        if cfg.get("prelude_failure") == "swallow":  # the prelude-failure-swallowed mutant
            header = _execute(source, glb)
    else:
        header = _execute(source, glb)
    if broker.pending is not None and broker._sticky:
        header = {"status": "paused", "pending": [broker.pending]}
    if header["status"] == "ok":
        try:
            value = glb.get("result")
            # the pinned serialization (protocols/codemode_executor.py VALUE_JSON)
            body = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
            body = body.encode()
        except (TypeError, ValueError, RecursionError, MemoryError) as exc:
            error = {"kind": "runtime", "message": "the value is not JSON: " + _message(exc)}
            header, body = {"status": "error", "error": error}, b""
    sys.stdout.flush()
    sys.stderr.flush()
    # a broken pipe: the parent stopped reading, the value being longer than it keeps
    with contextlib.suppress(BrokenPipeError):
        _write_all(res_w, json.dumps(header).encode() + b"\n" + body)


def _supervise(cfg: dict, chan: socket.socket, code_fd: int) -> None:
    """One run: fork its process, hand the parent its pid and pipes, report how it ended."""
    signal.signal(signal.SIGCHLD, signal.SIG_DFL)  # this process waits for its child itself
    out_r, out_w = os.pipe()
    res_r, res_w = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(out_r)
            os.close(res_r)
            chan.close()
            _program(cfg, out_w, res_w, code_fd)
        finally:
            os._exit(0)
    os.close(out_w)
    os.close(res_w)
    os.close(code_fd)
    socket.send_fds(chan, [json.dumps({"pid": pid}).encode()], [out_r, res_r])
    os.close(out_r)
    os.close(res_r)
    _, status = os.waitpid(pid, 0)
    with contextlib.suppress(OSError):
        chan.send(json.dumps({"exit": os.waitstatus_to_exitcode(status)}).encode())


def zygote(ctl_fd: int) -> None:
    """The warm process: started once with an empty environment, it runs nothing itself and
    forks a supervisor per request (a JSON run configuration plus the run's channel)."""
    signal.signal(signal.SIGCHLD, signal.SIG_IGN)  # supervisors are reaped by the kernel
    ctl = socket.socket(fileno=ctl_fd)
    while True:
        msg, fds, _flags, _addr = socket.recv_fds(ctl, 1 << 16, 2)
        if not msg:
            return  # the executor went away
        chan, code_fd = socket.socket(fileno=fds[0]), fds[1]
        if os.fork() == 0:
            try:
                ctl.close()
                _supervise(json.loads(msg), chan, code_fd)
            finally:
                os._exit(0)
        chan.close()
        os.close(code_fd)


if __name__ == "__main__":
    zygote(int(sys.argv[1]))
