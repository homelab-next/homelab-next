# SPDX-License-Identifier: Apache-2.0
"""The process side of :class:`conformance.fakes.code_executor.ForkingExecutor` (test-only).

Run once as ``python -I -S -B code_executor_child.py FD`` with an empty environment: the
*zygote*, a warm process that never runs a program itself.  For each run it receives the
configuration and a channel over the socket ``FD`` and forks a supervisor, which forks the run's
own process and reports its pid, its output and result pipes and, at the end, its exit status.
The run's process starts a new session, takes the run's environment and scratch directory, caps
its address space and CPU, installs an audit hook that refuses what the contract forbids, runs
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
    """The broker denied the call."""


class _Broker:
    Denied = Denied

    def __init__(self, host: str, port: int, token: str, timeout: float) -> None:
        self._addr = (host, port)
        self._token = token
        self._timeout = timeout

    def __repr__(self) -> str:
        return "<broker>"

    def call(self, action, args=None):
        line = json.dumps({"token": self._token, "action": action, "args": args or {}})
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
        reply = json.loads(buf or b"{}")
        if reply.get("ok") is True:
            return reply.get("value")
        if reply.get("denied"):
            raise Denied(action)
        raise RuntimeError("the broker returned no answer")


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


def _program(cfg: dict, out_w: int, res_w: int) -> None:
    """The run's own process: a fresh fork of the zygote, its own session, then the program."""
    os.setsid()
    devnull = os.open(os.devnull, os.O_RDONLY)
    os.dup2(devnull, 0)
    os.dup2(out_w, 1)
    os.dup2(out_w, 2)
    os.close(devnull)
    os.close(out_w)
    os.chdir(cfg["workdir"])
    os.environ.clear()
    os.environ.update(cfg["env"])
    mem = int(cfg["memory_bytes"])
    resource.setrlimit(resource.RLIMIT_AS, (mem, mem))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    cpu = int(cfg["cpu_backstop_s"])
    resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu + 1))
    roots = tuple(os.path.normpath(p) for p in sys.path if p)
    broker = _Broker(cfg["host"], cfg["port"], cfg.pop("token"), float(cfg["wall_s"]))
    sys.addaudithook(_hook(cfg, roots))

    header: dict = {"status": "ok"}
    body = b""
    glb = {"__name__": "__program__", "__builtins__": builtins, "broker": broker}
    try:
        code = compile(cfg["program"], "<program>", "exec")
    except (SyntaxError, ValueError):
        header = {"status": "error", "error": "syntax"}
    else:
        try:
            exec(code, glb)
        except MemoryError:
            header = {"status": "limit", "limit": "memory"}
        except Denied:
            header = {"status": "denied"}
        except SystemExit:
            pass
        except BaseException as exc:
            print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
            header = {"status": "error", "error": "exception"}
    if header["status"] == "ok":
        try:
            value = glb.get("result")
            body = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
            body = body.encode()
        except MemoryError:
            header = {"status": "limit", "limit": "memory"}
        except (TypeError, ValueError, RecursionError):
            header, body = {"status": "error", "error": "unserializable"}, b""
    sys.stdout.flush()
    sys.stderr.flush()
    # a broken pipe: the parent stopped reading, the value being longer than it keeps
    with contextlib.suppress(BrokenPipeError):
        _write_all(res_w, json.dumps(header).encode() + b"\n" + body)


def _supervise(cfg: dict, chan: socket.socket) -> None:
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
            _program(cfg, out_w, res_w)
        finally:
            os._exit(0)
    os.close(out_w)
    os.close(res_w)
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
        msg, fds, _flags, _addr = socket.recv_fds(ctl, 1 << 20, 1)
        if not msg:
            return  # the executor went away
        chan = socket.socket(fileno=fds[0])
        if os.fork() == 0:
            try:
                ctl.close()
                _supervise(json.loads(msg), chan)
            finally:
                os._exit(0)
        chan.close()


if __name__ == "__main__":
    zygote(int(sys.argv[1]))
