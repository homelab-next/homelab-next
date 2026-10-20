# SPDX-License-Identifier: Apache-2.0
"""Run a pinned handler file: digest-verified, argv only, scrubbed env, bounded time and output.

What :func:`run_handler` guarantees, in order:

1. **Pinned content.**  The handler file is read once (``O_NOFOLLOW``), its sha256 compared with
   the declared ``handler_digest``, and *that byte string* is what runs: it is written into the
   run's private directory and executed from there, so the file cannot be swapped between the
   check and the exec.  A mismatch refuses the run (``handler-digest-mismatch``).  A handler is
   therefore one self-contained file (a script with a shebang, or a binary).
2. **No shell.**  The command is ``[handler, *argv]`` with ``argv`` fixed by the handler document;
   nothing from the request is ever put on the command line.  The request's ``params`` (already
   validated against ``params_schema``) arrive as JSON on stdin.
3. **Scrubbed environment.**  Only ``PATH``, ``LANG``, ``HOME``/``TMPDIR`` (the run directory),
   ``HNX_BROKER_*`` (action, request id, actor, target) and the handler's declared secrets.  The
   broker's own environment is not inherited.
4. **Secrets by name.**  The handler document lists secret *names*; each is resolved at run time
   by the broker's resolver and handed to that one process as an environment variable.  Values
   never appear in a request, an approval, the audit trail or a result; any occurrence of one in
   the captured output is replaced by ``<redacted>``.
5. **Bounded.**  ``timeout_s`` is enforced (the whole process group is killed); stdout and stderr
   are each captured up to ``max_output_bytes`` and the rest discarded, into ``stdout`` /
   ``stderr`` files in the run directory.
"""

from __future__ import annotations

import contextlib
import errno
import hashlib
import json
import os
import signal
import subprocess
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

__all__ = [
    "DEFAULT_MAX_OUTPUT",
    "ExecError",
    "ExecResult",
    "env_secret_resolver",
    "file_digest",
    "run_handler",
]

DEFAULT_MAX_OUTPUT = 1024 * 1024
SAFE_PATH = "/usr/local/bin:/usr/bin:/bin"
#: names a handler's ``secrets`` may not take (the broker sets them)
RESERVED_ENV = frozenset({"PATH", "LANG", "HOME", "TMPDIR"})
SECRET_ENV_PREFIX = "HNX_BROKER_SECRET_"
_CHUNK = 65536


class ExecError(Exception):
    """A refused or failed handler run; ``reason`` is the audit reason."""

    def __init__(self, reason: str, message: str, outcome: str = "error") -> None:
        super().__init__(message)
        self.reason = reason
        self.outcome = outcome


@dataclass(frozen=True)
class ExecResult:
    exit_code: int
    stdout: bytes
    stderr: bytes
    stdout_truncated: bool
    stderr_truncated: bool
    timed_out: bool


def file_digest(path: str | os.PathLike[str]) -> str:
    """``sha256:<hex>`` of a file's bytes (the ``handler_digest`` a handler document pins)."""
    return "sha256:" + hashlib.sha256(Path(path).read_bytes()).hexdigest()


def env_secret_resolver(
    environ: Mapping[str, str] | None = None, prefix: str = SECRET_ENV_PREFIX
) -> Callable[[str], str]:
    """Resolve secret ``NAME`` from the *broker's* ``<prefix>NAME`` environment variable.

    The default resolver: the broker process holds the values, the agent never does, and a
    handler sees only the names its document declares.  A deployment with a secrets store passes
    its own resolver (``name -> value``) instead.
    """
    env = os.environ if environ is None else environ

    def resolve(name: str) -> str:
        value = env.get(prefix + name)
        if value is None:
            raise KeyError(name)
        return value

    return resolve


def _read_pinned(path: Path) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ExecError(
                "handler-path-escape", "the handler file is a symlink", "denied"
            ) from None
        raise ExecError("handler-missing", "the handler file cannot be read", "denied") from None
    with os.fdopen(fd, "rb") as fh:
        return fh.read()


class _Capture(threading.Thread):
    """Drain a pipe, keeping the first ``cap`` bytes and counting the rest."""

    def __init__(self, stream, cap: int) -> None:
        super().__init__(daemon=True)
        self.stream, self.cap = stream, cap
        self.kept = bytearray()
        self.total = 0

    def run(self) -> None:
        with contextlib.suppress(OSError, ValueError):
            while chunk := self.stream.read(_CHUNK):
                self.total += len(chunk)
                room = self.cap - len(self.kept)
                if room > 0:
                    self.kept += chunk[:room]


def _feed(stream, data: bytes) -> None:
    with contextlib.suppress(OSError, ValueError):
        stream.write(data)
    with contextlib.suppress(OSError, ValueError):
        stream.close()


def _redact(data: bytes, values: Sequence[str]) -> bytes:
    for v in sorted({v for v in values if v}, key=len, reverse=True):
        data = data.replace(v.encode("utf-8"), b"<redacted>")
    return data


def run_handler(
    path: str | os.PathLike[str],
    digest: str,
    *,
    params: Mapping[str, Any],
    run_dir: str | os.PathLike[str],
    timeout_s: float,
    argv: Sequence[str] = (),
    env: Mapping[str, str] | None = None,
    secrets: Sequence[str] = (),
    resolve_secret: Callable[[str], str] | None = None,
    max_output: int = DEFAULT_MAX_OUTPUT,
) -> ExecResult:
    """Run the handler at ``path`` once; see the module doc for every guarantee."""
    run = Path(run_dir)
    content = _read_pinned(Path(path))
    if "sha256:" + hashlib.sha256(content).hexdigest() != digest:
        raise ExecError(
            "handler-digest-mismatch", "the handler file does not match its pinned digest", "denied"
        )
    resolver = resolve_secret or env_secret_resolver()
    values: dict[str, str] = {}
    for name in secrets:
        try:
            values[name] = resolver(name)
        except Exception:
            raise ExecError("secret-unavailable", f"secret {name} could not be resolved") from None
    exe = run / ("handler" + Path(path).suffix)
    fd = os.open(exe, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o700)
    with os.fdopen(fd, "wb") as fh:
        fh.write(content)
    tmp = run / "tmp"
    tmp.mkdir(mode=0o700, exist_ok=True)
    child_env = {"PATH": SAFE_PATH, "LANG": "C.UTF-8", "HOME": str(run), "TMPDIR": str(tmp)}
    child_env.update(env or {})
    child_env.update(values)
    try:
        proc = subprocess.Popen(
            [str(exe), *argv],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=run,
            env=child_env,
            start_new_session=True,
            close_fds=True,
        )
    except OSError:
        raise ExecError("handler-spawn-failed", "the handler could not be started") from None
    out, err = _Capture(proc.stdout, max_output), _Capture(proc.stderr, max_output)
    out.start()
    err.start()
    feeder = threading.Thread(
        target=_feed, args=(proc.stdin, json.dumps(dict(params)).encode()), daemon=True
    )
    feeder.start()
    timed_out = False
    try:
        proc.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        timed_out = True
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(proc.pid, signal.SIGKILL)  # the handler and anything it left running
    proc.wait()
    for t in (feeder, out, err):
        t.join(timeout=5)
    stdout = _redact(bytes(out.kept), list(values.values()))
    stderr = _redact(bytes(err.kept), list(values.values()))
    (run / "stdout").write_bytes(stdout)
    (run / "stderr").write_bytes(stderr)
    return ExecResult(
        exit_code=proc.returncode,
        stdout=stdout,
        stderr=stderr,
        stdout_truncated=out.total > max_output,
        stderr_truncated=err.total > max_output,
        timed_out=timed_out,
    )
