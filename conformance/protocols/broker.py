# SPDX-License-Identifier: Apache-2.0
"""Contract for ``broker``: allowlisted commands for named callers, with an audit trail.

Callers never get a shell; they get ``call(caller, command, args)``.  A command exists only if
registered with an argument schema; a caller may run only the commands its allowlist names
(per command: being allowed one command grants nothing else); arguments are validated *before*
the handler runs; every call - allowed, denied, invalid, failed - leaves one audit record;
arguments the schema marks ``secret`` never appear in any audit record, whatever the outcome, nor
in anything ``call`` raises.  Redaction follows the schema's ``secret`` flag, not the argument's
name.  A handler failure surfaces as ``BrokerError`` naming the command only: the handler's own
exception (message, cause, context) is not passed to the caller.

``ArgSpec`` checks *shape* (presence and type), not *content*.  A value that passed validation is
still untrusted caller input: a ``str`` argument can hold ``../``, ``;``, a newline or a flag.
The handler is the trust boundary - it must treat every argument as hostile (no shell, no string
building of commands or paths without its own allowlist or pattern).

Deferred requests: ``submit(caller, command, args)`` runs the same allowlist and argument checks
as ``call`` and returns a request id instead of running the handler.  A request is bound to the
caller that submitted it: only that caller may ``status`` (read), ``run`` or ``cancel`` it.  Any
other caller gets ``Denied`` with ``reason == "not-request-owner"`` - the same answer as for an id
that does not exist, so a foreign request's existence is not disclosed - the request is left
exactly as it was, and the attempt leaves an audit record (outcome ``denied``, the same reason, the
operation and the request id).  ``status`` returns the request's state (``pending``, ``done``,
``error``, ``cancelled``); ``run`` executes a pending request once; ``cancel`` stops a pending one.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

__all__ = [
    "ArgSpec",
    "AuditRecord",
    "Broker",
    "BrokerError",
    "Denied",
    "InvalidArguments",
    "RequestStatus",
]


class BrokerError(Exception):
    pass


class Denied(BrokerError):
    """``reason`` is a machine-readable cause, e.g. ``not-request-owner``."""

    def __init__(self, message: str = "", reason: str = "") -> None:
        super().__init__(message)
        self.reason = reason


class InvalidArguments(BrokerError):
    pass


@dataclass(frozen=True)
class ArgSpec:
    type: str  # "str" | "int" | "bool"
    required: bool = True
    secret: bool = False


@dataclass(frozen=True)
class AuditRecord:
    caller: str
    command: str
    outcome: str  # ok | denied | invalid | error
    args: Mapping[str, Any]  # secret arguments replaced by "<redacted>"
    operation: str = "call"  # call | submit | status | run | cancel
    request_id: str | None = None  # set for operations on a deferred request
    reason: str = ""  # why a denial was denied (e.g. not-request-owner); empty otherwise


@dataclass(frozen=True)
class RequestStatus:
    request_id: str
    caller: str  # the owner: the caller that submitted it
    command: str
    state: str  # pending | done | error | cancelled


@runtime_checkable
class Broker(Protocol):
    def register(
        self,
        command: str,
        handler: Callable[..., Any],
        args: Mapping[str, ArgSpec],
    ) -> None: ...

    def allow(self, caller: str, commands: Sequence[str]) -> None: ...

    def call(self, caller: str, command: str, args: Mapping[str, Any]) -> Any:
        """Raises Denied / InvalidArguments; a handler exception becomes BrokerError."""

    def submit(self, caller: str, command: str, args: Mapping[str, Any]) -> str:
        """Check like ``call`` but defer running; returns the new request's id."""

    def status(self, caller: str, request_id: str) -> RequestStatus:
        """The owner's view of its request; anyone else: Denied(reason="not-request-owner")."""

    def run(self, caller: str, request_id: str) -> Any:
        """Run the owner's pending request once; same errors as ``call`` plus ownership."""

    def cancel(self, caller: str, request_id: str) -> None:
        """Cancel the owner's pending request; anyone else: Denied, request unchanged."""

    def audit(self) -> Sequence[AuditRecord]: ...
