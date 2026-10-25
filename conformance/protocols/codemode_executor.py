# SPDX-License-Identifier: Apache-2.0
"""Contract for ``codemode-executor``: the sandbox that runs one Code Mode program (ADR-0031).

``run`` executes one program in a fresh sandbox and returns an :class:`ExecutionResult`.  The
sandbox is what decision 5 of ADR-0031 describes: it holds nothing and reaches nothing but the
broker.  The result's vocabulary is that of ``schemas/codemode/execution_result`` (a draft that
lands with the schemas PR, #64; until then this module is the reference).  The rules, one or two
suite checks each:

a. *No network but the broker.*  The program can open a connection to the broker endpoint it was
   given, and to nothing else: no other address or port, over TCP or UDP, and no name lookup.
   A refused attempt is an ``OSError`` inside the program, never a connection.
b. *No credentials.*  The sandbox environment and the files the program can read hold no secret:
   nothing from the caller's environment and none of the caller's files.  The run's broker token
   is scoped to this one run and is not hidden from the program (its ``broker`` handle uses it),
   but it is never put in the sandbox environment.
c. *Limits are enforced.*  A program that exceeds a cap in :class:`Limits` (CPU seconds, memory,
   wall-clock seconds, bytes of printed output) is ended, and the result has status ``limit``
   with ``limit`` naming the cap (:data:`LIMITS`).  The run never ends ``ok`` past a cap.
   Memory is resident (committed) memory, not address space; an executor may enforce it with
   an address-space cap, but a program that raises ``MemoryError`` itself has a ``runtime``
   error, not a memory limit.  ``output`` is the program's printed output exceeding
   ``output_bytes``.  Broker calls are capped by ``max_calls``: the executor's broker client
   refuses a call past the cap without sending it, as a denial with reason
   ``call-cap-reached``, and the run goes on (``calls`` is in :data:`LIMITS` for a runner that
   ends a run on the cap; this contract does not).  The client-side cap is behaviour, not
   enforcement: the client runs inside the sandbox, within the program's reach.  Enforcing a
   capped token is the broker's (token claims, ADR-0031 decision 6), proved by the runner
   contract (CM-5b).
d. *Disposable.*  Every run starts from nothing: no file, environment variable or interpreter
   state that an earlier run wrote is visible to a later one.  A writable scratch directory
   (the working directory, ``TMPDIR`` and ``HOME``) exists for the run and goes with it.
e. *The result is bounded.*  The program's value is its JSON serialization, pinned as
   :data:`VALUE_JSON` (compact, UTF-8, non-ASCII kept: what ``JSON.stringify`` produces).  When
   that is longer than ``Limits.result_bytes``, the result carries ``truncated=True`` and, as
   ``value``, a prefix of the serialization (a ``str`` of at most ``result_bytes`` UTF-8 bytes,
   cut on a character boundary).  ``truncated`` is the value's own flag, implied by no status.
   An oversized value is never returned whole.
f. *Every outcome is a result.*  A program that does not compile, raises, exits non-zero or
   leaves a value that is not JSON ends with status ``error``; ``error.kind`` is one of
   :data:`ERROR_KINDS` and ``error.message`` is one line of at most :data:`MESSAGE_MAX`
   characters with no control character, line separator or bidirectional override.  ``run``
   itself raises only for the caller's own mistakes: a language not in ``languages``
   (:class:`UnsupportedLanguage`), a program longer than :data:`MAX_PROGRAM_CHARS`
   characters (:class:`ProgramTooLarge`) and one that is not encodable as UTF-8, such as one
   holding a lone surrogate (:class:`UnencodableProgram`), before anything runs.
g. *The broker's answers reach the program as the broker gave them.*  A denial raises
   ``broker.Denied`` carrying the broker's ``reason``; a program that lets it escape ends with
   status ``denied``.  An error reply raises ``broker.Error`` (catchable, with ``reason``); an
   unreachable broker raises it with reason ``broker-unreachable``; escaping, either ends the run
   with error kind ``broker``.  A pending reply (the call needs approval) pauses the whole run:
   it raises ``broker.Paused``, a ``BaseException`` that ``except Exception`` does not catch,
   every later call raises it again, and the run ends with status ``paused`` and the call in
   ``pending`` however the program handled it.  Resuming is the runner's (CM-5b).  Like the
   call cap, the client-side pause is behaviour, not enforcement: refusing calls on a paused
   token is the broker's, checked by the runner contract.

**The program's view (language ``python``).**  The program is module source.  It sees one name
of its own, ``broker``: ``broker.call(action, args=None, *, target=None)`` sends one request to
the broker and returns the reply's value, and ``broker.submit(action, args=None, *, target=None)``
submits one for approval (the reply is pending, so the run pauses; CM-5b).  Calls are
synchronous (no ``await``).  Its value is the module
global ``result`` when it ends (``None`` when unset).  Printed text (stdout and stderr together)
is returned as ``output``.  Language names are those of schemas/codemode: ``python`` and
``typescript``.

**The broker wire.**  The executor owns the transport between the sandbox and the broker: it
may connect from inside the sandbox to the endpoint, or relay over a unix socket or vsock.  At
the endpoint, one TCP connection per call carries one JSON line ``{"token": ..., "action": ...,
"args": {...}}`` (plus ``"op": "submit"`` for a submit and ``"target"`` when the call names one;
absent, the op is ``call``) and one JSON line back, one of :data:`REPLIES`: ``{"ok": true, "value": ...}``,
``{"ok": false, "denied": true, "reason": ...}``, ``{"ok": false, "pending": true,
"request_id": ..., "request_digest": ...}`` or ``{"ok": false, "error": true, "reason": ...}``.
The runner contract (CM-5b) owns what the broker does with a call.  The suite serves a
stand-in broker (and its decoys) at the address the executor declares as ``broker_bind``
(``(host, port)``; loopback and an ephemeral port by default), so a sandbox behind a static
firewall rule can reach it.

Programs are untrusted model output.  An executor is an isolation boundary only when its sandbox
is: the suite proves the properties above from inside a program, which is necessary, not
sufficient (escape attempts are the hardening suite's job, docs/codemode.md phase 2).
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

__all__ = [
    "ERROR_KINDS",
    "LIMITS",
    "MAX_PROGRAM_CHARS",
    "MESSAGE_MAX",
    "MESSAGE_UNSAFE",
    "REPLIES",
    "STATUSES",
    "VALUE_JSON",
    "BrokerEndpoint",
    "CodeExecutor",
    "ExecutionError",
    "ExecutionResult",
    "ExecutorError",
    "Limits",
    "PendingCall",
    "ProgramTooLarge",
    "UnencodableProgram",
    "UnsupportedLanguage",
]

#: ``ExecutionResult.status``
STATUSES = ("ok", "paused", "denied", "error", "limit")
#: the caps a ``limit`` result names (``calls`` only by a runner that ends a run on the cap)
LIMITS = ("cpu", "memory", "wall", "calls", "output")
#: ``ExecutionError.kind``: the program did not compile, failed at run time (raised, exited
#: non-zero, left a value that is not JSON), the sandbox failed, the token was refused, or the
#: broker answered with an error or could not be reached
ERROR_KINDS = ("syntax", "runtime", "sandbox", "token", "broker")
#: the reply kinds of the broker wire
REPLIES = ("ok", "denied", "pending", "error")
#: the longest program ``run`` accepts, in characters (schemas/codemode ``code`` maxLength)
MAX_PROGRAM_CHARS = 65536
#: the longest ``ExecutionError.message``, in characters
MESSAGE_MAX = 2000
#: characters an error message (or a pending call's text) never holds: controls (tab aside),
#: line and paragraph separators, bidirectional marks and overrides, zero-width characters, the
#: byte-order mark and lone surrogates (schemas/codemode's single-line pattern)
MESSAGE_UNSAFE = (
    r"[\u0000-\u0008\u000a-\u001f\u007f-\u009f\u061c\u200b-\u200f\u2028\u2029"
    r"\u202a-\u202e\u2066-\u2069\ufeff\ud800-\udfff]"
)
#: the value's serialization: ``json.dumps(value, **VALUE_JSON)``, encoded as UTF-8
VALUE_JSON = {"ensure_ascii": False, "separators": (",", ":"), "allow_nan": False}
#: where the harness serves the broker unless the executor declares ``broker_bind`` (not in
#: ``__all__``: a raw address has no place on the generated reference page)
DEFAULT_BROKER_BIND = ("127.0.0.1", 0)  # no-raw-endpoint: allow loopback, ephemeral port


class ExecutorError(Exception):
    pass


class UnsupportedLanguage(ExecutorError, ValueError):
    """The executor does not run programs in the requested language."""


class ProgramTooLarge(ExecutorError, ValueError):
    """The program is longer than :data:`MAX_PROGRAM_CHARS` characters."""


class UnencodableProgram(ExecutorError, ValueError):
    """The program is not encodable as UTF-8 (it holds a lone surrogate)."""


@dataclass(frozen=True)
class BrokerEndpoint:
    """Where the broker answers this run, and the run's token for it."""

    host: str  # an address literal: the sandbox resolves no names
    port: int
    token: str = field(repr=False)  # scoped to this run; never in the sandbox environment


@dataclass(frozen=True)
class Limits:
    """The caps of one run.  Every value is finite and greater than zero."""

    cpu_s: float = 2.0  # CPU seconds
    memory_bytes: int = 256 * 1024 * 1024  # resident (committed) memory
    wall_s: float = 5.0  # wall-clock seconds from start to end
    max_calls: int = 200  # broker calls; one past the cap is refused (call-cap-reached)
    output_bytes: int = 64 * 1024  # printed output, stdout and stderr together
    result_bytes: int = 64 * 1024  # the value's JSON serialization; longer is truncated

    def __post_init__(self) -> None:
        for name in (
            "cpu_s",
            "memory_bytes",
            "wall_s",
            "max_calls",
            "output_bytes",
            "result_bytes",
        ):
            v = getattr(self, name)
            if isinstance(v, bool) or not isinstance(v, int | float):
                raise ValueError(f"{name} must be a number, got {v!r}")
            if not math.isfinite(v) or v <= 0:
                raise ValueError(f"{name} must be finite and > 0, got {v!r}")


@dataclass(frozen=True)
class ExecutionError:
    kind: str  # one of ERROR_KINDS
    message: str = ""  # one line, at most MESSAGE_MAX characters; untrusted program text


@dataclass(frozen=True)
class PendingCall:
    """A call that needs approval: the run paused on it."""

    step: int  # the call's index among the calls this run sent, from 0
    action: str
    request_id: str
    request_digest: str  # the digest an approval binds to


@dataclass(frozen=True)
class ExecutionResult:
    status: str  # ok | paused | denied | error | limit
    value: Any = None  # the program's value; a str prefix of its JSON when truncated
    truncated: bool = False  # the value was cut at result_bytes
    limit: str | None = None  # which cap ended the run (status limit)
    error: ExecutionError | None = None  # status error
    output: str = ""  # printed output, at most Limits.output_bytes UTF-8 bytes
    pending: tuple[PendingCall, ...] = ()  # status paused: the call waiting for approval


@runtime_checkable
class CodeExecutor(Protocol):
    languages: frozenset[str]  # the program languages this executor runs
    broker_bind: tuple[str, int]  # where the harness serves the broker (DEFAULT_BROKER_BIND)

    def run(
        self, program: str, *, language: str, broker: BrokerEndpoint, limits: Limits
    ) -> ExecutionResult:
        """Runs ``program`` in a fresh sandbox to its end or a cap.  Raises UnsupportedLanguage
        for a language not in ``languages``, ProgramTooLarge for a program longer than
        MAX_PROGRAM_CHARS characters and UnencodableProgram for one that is not UTF-8 text,
        before anything runs."""
