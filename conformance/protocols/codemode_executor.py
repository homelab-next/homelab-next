# SPDX-License-Identifier: Apache-2.0
"""Contract for ``codemode-executor``: the sandbox that runs one Code Mode program (ADR-0031).

``run`` executes one program in a fresh sandbox and returns an :class:`ExecutionResult`.  The
sandbox is what decision 5 of ADR-0031 describes: it holds nothing and reaches nothing but the
broker.  The rules, one per suite check:

a. *No network but the broker.*  The program can open a connection to the broker endpoint it was
   given, and to nothing else: no other address or port, over TCP or UDP, and no name lookup.
   A refused attempt is an ``OSError`` inside the program, never a connection.
b. *No credentials.*  The sandbox environment and the files the program can read hold no secret:
   nothing from the caller's environment, none of the caller's files, and not the run's broker
   token either (the token reaches the program only through its ``broker`` handle).
c. *Limits are enforced.*  A program that exceeds a cap in :class:`Limits` (CPU seconds, memory,
   wall-clock seconds, bytes of printed output) is ended, and the result has status ``limit``
   with ``limit`` naming the cap (:data:`LIMITS`).  The run never ends ``ok`` past a cap.
d. *Disposable.*  Every run starts from nothing: no file, environment variable or interpreter
   state that an earlier run wrote is visible to a later one.  A writable scratch directory
   (the working directory, ``TMPDIR`` and ``HOME``) exists for the run and goes with it.
e. *The result is bounded.*  The program's value is its JSON serialization.  When that is longer
   than ``Limits.result_bytes``, the result carries ``truncated=True`` and, as ``value``, a
   prefix of the serialization (a ``str`` of at most ``result_bytes`` UTF-8 bytes, cut on a
   character boundary).  An oversized value is never returned whole.
f. *Every outcome is a result.*  A program that raises, does not compile, or leaves a value that
   is not JSON ends with status ``error`` and ``error`` naming the kind (:data:`ERROR_KINDS`);
   a broker call the broker denies raises ``broker.Denied`` inside the program, and a program
   that lets it escape ends with status ``denied``.  ``run`` itself raises only for the caller's
   own mistakes (:class:`UnsupportedLanguage`).

**The program's view (language ``python``).**  The program is module source.  It sees one name
of its own, ``broker``: ``broker.call(action, args=None)`` sends one request to the broker and
returns the reply's value, raising ``broker.Denied`` when the broker denies it.  Calls are
synchronous (no ``await``); a call that needs approval pauses the whole run, which is the
runner's (CM-5).  Language names are those of schemas/codemode: ``python`` and ``typescript``.  Its value is
the module global ``result`` when it ends (``None`` when unset).  Printed text (stdout and stderr
together) is returned as ``output``.

**The broker wire.**  One TCP connection to ``(endpoint.host, endpoint.port)`` per call; the
sandbox writes one JSON line ``{"token": ..., "action": ..., "args": {...}}`` and reads one JSON
line back: ``{"ok": true, "value": ...}``, or ``{"ok": false, "denied": true}``.  This is the
minimum the executor needs; the runner contract (CM-5) owns what the broker does with a call.
The suite serves a stand-in broker (and its decoys) on loopback; an executor whose sandbox runs
on another host names the harness address it can reach as the attribute ``broker_host``.

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
    "STATUSES",
    "BrokerEndpoint",
    "CodeExecutor",
    "ExecutionResult",
    "ExecutorError",
    "Limits",
    "UnsupportedLanguage",
]

#: ``ExecutionResult.status``: the shape of schemas/codemode/execution_result without ``paused``
#: (a pause is the runner's, CM-5: the executor runs a program to its end)
STATUSES = ("ok", "denied", "error", "limit")
#: the caps a ``limit`` result names
LIMITS = ("cpu", "memory", "wall", "output")
#: what an ``error`` result names: the program raised, did not compile, left a value that is
#: not JSON, or the sandbox died without saying why
ERROR_KINDS = ("exception", "syntax", "unserializable", "crashed")


class ExecutorError(Exception):
    pass


class UnsupportedLanguage(ExecutorError, ValueError):
    """The executor does not run programs in the requested language."""


@dataclass(frozen=True)
class BrokerEndpoint:
    """Where the sandbox reaches the broker, and the run's token for it."""

    host: str  # an address literal: the sandbox resolves no names
    port: int
    token: str = field(repr=False)  # the run's broker token; never in the sandbox environment


@dataclass(frozen=True)
class Limits:
    """The caps of one run.  Every value is finite and greater than zero."""

    cpu_s: float = 2.0  # CPU seconds
    memory_bytes: int = 256 * 1024 * 1024  # address space
    wall_s: float = 5.0  # wall-clock seconds from start to end
    output_bytes: int = 64 * 1024  # printed output, stdout and stderr together
    result_bytes: int = 64 * 1024  # the value's JSON serialization; longer is truncated

    def __post_init__(self) -> None:
        for name in ("cpu_s", "memory_bytes", "wall_s", "output_bytes", "result_bytes"):
            v = getattr(self, name)
            if isinstance(v, bool) or not isinstance(v, int | float):
                raise ValueError(f"{name} must be a number, got {v!r}")
            if not math.isfinite(v) or v <= 0:
                raise ValueError(f"{name} must be finite and > 0, got {v!r}")


@dataclass(frozen=True)
class ExecutionResult:
    status: str  # ok | denied | error | limit
    value: Any = None  # the program's value; a str prefix of its JSON when truncated
    truncated: bool = False
    limit: str | None = None  # which cap ended the run (status limit)
    error: str | None = None  # the error kind (status error)
    output: str = ""  # printed output, at most Limits.output_bytes


@runtime_checkable
class CodeExecutor(Protocol):
    languages: frozenset[str]  # the program languages this executor runs

    def run(
        self, program: str, *, language: str, broker: BrokerEndpoint, limits: Limits
    ) -> ExecutionResult:
        """Runs ``program`` in a fresh sandbox to its end or a cap.  Raises UnsupportedLanguage
        for a language not in ``languages``, before anything runs."""
