# SPDX-License-Identifier: Apache-2.0
"""Contract for ``broker``: allowlisted commands for named callers, with an audit trail.

Callers never get a shell; they get ``call(caller, command, args)``.  A command exists only if
registered with an argument schema; a caller may run only what its allowlist names; arguments
are validated *before* the handler runs; every call - allowed, denied, failed - leaves one audit
record; arguments the schema marks ``secret`` never appear in the audit record or in results.
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
]


class BrokerError(Exception):
    pass


class Denied(BrokerError):
    pass


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

    def audit(self) -> Sequence[AuditRecord]: ...
