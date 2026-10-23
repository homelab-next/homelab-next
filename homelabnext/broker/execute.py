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
   the captured output is replaced by ``<redacted>``, and when the output is cut at its cap, a
   tail that is the beginning of a secret is dropped too (the cut cannot leak a prefix).  The
   redaction also catches the encodings a handler most often prints a value in without meaning
   to (:func:`secret_forms`: JSON-escaped, with and without ``\\uXXXX`` escapes, percent-encoded
   and base64).  It is a backstop, not a licence: **a handler must never print a secret**, since
   any other transformation (a substring, a hash, a different encoding) is not recognised.
5. **Bounded.**  ``timeout_s`` is enforced; stdout and stderr are each captured up to
   ``max_output_bytes`` and the rest discarded, into ``stdout`` / ``stderr`` files in the run
   directory.  When the handler exits, or at the timeout, its whole process group is killed
   (anything it left running) *before* the handler is reaped: the unreaped leader keeps its
   process-group id in use, so the kill cannot reach an unrelated group that reused the number.
   A descendant that left the group (``setsid``) is out of reach; contain that with the service
   manager (a systemd unit's cgroup) where it matters.

The handler copy is written through a close-on-exec descriptor.  If another thread forks while
that descriptor is open, the child holds it until it execs and the handler's own exec fails with
``ETXTBSY``; the spawn is retried a few times before it counts as ``handler-spawn-failed``.
"""

from __future__ import annotations

import base64
import contextlib
import errno
import hashlib
import json
import os
import re
import select
import signal
import subprocess
import threading
import time
import urllib.parse
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
    "secret_forms",
]

DEFAULT_MAX_OUTPUT = 1024 * 1024
SAFE_PATH = "/usr/local/bin:/usr/bin:/bin"
#: names a handler's ``secrets`` may not take (the broker sets them)
RESERVED_ENV = frozenset({"PATH", "LANG", "HOME", "TMPDIR"})
SECRET_ENV_PREFIX = "HNX_BROKER_SECRET_"
_CHUNK = 65536
_SPAWN_ATTEMPTS = 5


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


#: the shortest base64 run kept as a form of a secret inside a longer stream (offsets 1 and 2):
#: shorter runs would match unrelated output by chance
MIN_B64_CORE = 8


def _b64_cores(raw: bytes) -> set[str]:
    """Base64 of ``raw`` at byte offsets 0, 1 and 2 of a longer stream, standard and URL-safe:
    only the characters every such stream shares (those not touched by a neighbouring byte)."""
    out: set[str] = set()
    n = len(raw)
    for k in range(3):
        enc = base64.b64encode(bytes(k) + raw).decode("ascii")
        core = enc[-(-8 * k // 6) : (8 * (k + n)) // 6]
        if k == 0:
            out.add(enc)  # the whole value, padding and all
        if len(core) >= MIN_B64_CORE or (k == 0 and core):
            out |= {core, core.translate(str.maketrans("+/", "-_"))}
    return out


def secret_forms(value: str) -> set[bytes]:
    """The byte strings a secret ``value`` is redacted in: itself (UTF-8) and its trivially
    derived encodings -- inside a JSON string (``json.dumps`` with and without ``ensure_ascii``,
    so ``\\"``, ``\\\\`` and ``\\uXXXX`` escapes, and with ``/`` escaped as ``\\/``),
    percent-encoded (``quote`` and ``quote_plus``, upper- and lower-case hex), hex (both cases)
    and base64 (standard and URL-safe, at each of the three byte offsets it can start at inside
    a longer encoded stream).  Line-wrapped base64 is matched by :func:`_redact`, best effort."""
    raw = value.encode("utf-8")
    texts = {value, raw.hex(), raw.hex().upper(), *_b64_cores(raw)}
    for ascii_only in (False, True):
        js = json.dumps(value, ensure_ascii=ascii_only)[1:-1]
        texts |= {js, js.replace("/", "\\/")}
    for q in (urllib.parse.quote(value, safe=""), urllib.parse.quote_plus(value, safe="")):
        texts |= {q, re.sub(r"%[0-9A-F]{2}", lambda m: m[0].lower(), q)}
    return {t.encode("utf-8") for t in texts if t}


def _wrapped(forms: set[bytes]) -> list[re.Pattern[bytes]]:
    """Base64 forms with a line break allowed between any two characters (``base64 -w 76``,
    PEM's 64 columns)."""
    out = []
    for f in sorted(forms, key=len, reverse=True):
        if len(f) >= 2 * MIN_B64_CORE and re.fullmatch(rb"[A-Za-z0-9+/=_-]+", f):
            out.append(
                re.compile(rb"(?:\r?\n)?".join(re.escape(f[i : i + 1]) for i in range(len(f))))
            )
    return out


def _redact(data: bytes, values: Sequence[str], *, truncated: bool = False) -> bytes:
    """Every secret in ``data``, in any of its :func:`secret_forms`, replaced by ``<redacted>``;
    for output cut at its cap (``truncated``), a tail that begins one is dropped as well."""
    forms = {f for v in values if v for f in secret_forms(v)}
    secrets_ = sorted(forms, key=len, reverse=True)
    for v in secrets_:
        data = data.replace(v, b"<redacted>")
    if b"\n" in data:
        for rx in _wrapped(forms):
            data = rx.sub(b"<redacted>", data)
    if truncated:  # a base64 core redacted at the cut leaves the cut's last few characters
        data = re.sub(rb"(<redacted>)[A-Za-z0-9+/_-]{1,3}\Z", rb"\1", data)
    changed = truncated
    while changed:
        changed = False
        for v in secrets_:
            for n in range(min(len(v) - 1, len(data)), 0, -1):
                if data.endswith(v[:n]):
                    data, changed = data[:-n], True
                    break
    return data


def _wait_unreaped(
    proc: subprocess.Popen, timeout_s: float, *, clock: Callable[[], float] = time.monotonic
) -> bool:
    """Wait until ``proc`` exits *without reaping it*; True when it exited within ``timeout_s``.

    A pidfd (Linux 5.3+) becomes readable at exit; elsewhere ``waitid(WNOWAIT)`` is polled.
    """
    pidfd = None
    with contextlib.suppress(AttributeError, OSError):
        pidfd = os.pidfd_open(proc.pid)
    if pidfd is not None:
        try:
            poller = select.poll()
            poller.register(pidfd, select.POLLIN)
            return bool(poller.poll(max(0, int(timeout_s * 1000))))
        finally:
            os.close(pidfd)
    deadline = clock() + timeout_s
    delay = 0.001
    while True:
        if os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None:
            return True
        remaining = deadline - clock()
        if remaining <= 0:
            return False
        time.sleep(min(delay, remaining))
        delay = min(delay * 2, 0.05)


def _spawn(cmd: list[str], **kw: Any) -> subprocess.Popen:
    for attempt in range(_SPAWN_ATTEMPTS):
        try:
            return subprocess.Popen(cmd, **kw)
        except OSError as exc:
            if exc.errno != errno.ETXTBSY or attempt == _SPAWN_ATTEMPTS - 1:
                raise
        time.sleep(0.01 * (attempt + 1))  # another thread's fork still holds the copy open
    raise AssertionError("unreachable")  # pragma: no cover


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
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    tmp = run / "tmp"
    try:  # the private copy: a full disk or a descriptor limit here is an error, not a crash
        fd = os.open(exe, flags, 0o700)
        with os.fdopen(fd, "wb") as fh:
            fh.write(content)
        tmp.mkdir(mode=0o700, exist_ok=True)
    except OSError:
        raise ExecError(
            "handler-io-error", "the handler's private copy cannot be written"
        ) from None
    child_env = {"PATH": SAFE_PATH, "LANG": "C.UTF-8", "HOME": str(run), "TMPDIR": str(tmp)}
    child_env.update(env or {})
    child_env.update(values)
    try:
        proc = _spawn(
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
    timed_out = not _wait_unreaped(proc, timeout_s)
    with contextlib.suppress(ProcessLookupError, PermissionError):
        # the handler and anything it left running; the leader is not reaped yet, so its
        # process-group id cannot have been reused
        os.killpg(proc.pid, signal.SIGKILL)
    proc.wait()
    for t in (feeder, out, err):
        t.join(timeout=5)
    secret_values = list(values.values())
    stdout = _redact(bytes(out.kept), secret_values, truncated=out.total > max_output)
    stderr = _redact(bytes(err.kept), secret_values, truncated=err.total > max_output)
    try:
        (run / "stdout").write_bytes(stdout)
        (run / "stderr").write_bytes(stderr)
    except OSError:
        raise ExecError("handler-io-error", "the handler ran; its output cannot be kept") from None
    return ExecResult(
        exit_code=proc.returncode,
        stdout=stdout,
        stderr=stderr,
        stdout_truncated=out.total > max_output,
        stderr_truncated=err.total > max_output,
        timed_out=timed_out,
    )
