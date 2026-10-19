# SPDX-License-Identifier: Apache-2.0
"""In-memory allowlisted command broker with an audit trail."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any

from conformance.protocols.broker import ArgSpec, AuditRecord, BrokerError, Denied, InvalidArguments

_TYPES = {"str": str, "int": int, "bool": bool}


class FakeBroker:
    features = frozenset()

    def __init__(self) -> None:
        self._cmds: dict[str, tuple[Callable[..., Any], Mapping[str, ArgSpec]]] = {}
        self._allow: dict[str, set[str]] = {}
        self._audit: list[AuditRecord] = []

    def register(self, command, handler, args):
        self._cmds[command] = (handler, dict(args))

    def allow(self, caller, commands):
        self._allow.setdefault(caller, set()).update(commands)

    def _redact(self, spec: Mapping[str, ArgSpec], args: Mapping[str, Any]) -> dict[str, Any]:
        return {
            k: ("<redacted>" if spec.get(k, ArgSpec("str")).secret else v) for k, v in args.items()
        }

    def _log(self, caller, command, outcome, spec, args) -> None:
        self._audit.append(AuditRecord(caller, command, outcome, self._redact(spec, args)))

    def call(self, caller, command, args):
        entry = self._cmds.get(command)
        spec = entry[1] if entry else {}
        if entry is None or command not in self._allow.get(caller, set()):
            self._log(caller, command, "denied", spec, args)
            raise Denied(f"{caller!r} may not run {command!r}")
        handler = entry[0]
        problems = []
        for name, a in spec.items():
            if name not in args:
                if a.required:
                    problems.append(f"missing {name}")
            elif (isinstance(args[name], bool) and a.type != "bool") or not isinstance(
                args[name], _TYPES[a.type]
            ):
                problems.append(f"{name}: wrong type")
        problems += [f"unexpected {k}" for k in args if k not in spec]
        if problems:
            self._log(caller, command, "invalid", spec, args)
            raise InvalidArguments("; ".join(problems))
        try:
            result = self._run_handler(command, handler, args)
        except BrokerError:
            self._log(caller, command, "error", spec, args)
            raise
        self._log(caller, command, "ok", spec, args)
        return result

    @staticmethod
    def _run_handler(command, handler, args):
        failed = False
        try:
            result = handler(**dict(args))
        except Exception:
            failed = True
        if failed:  # raised outside the handler's except block: no __context__ to leak through
            raise BrokerError(f"{command} failed")
        return result

    def audit(self) -> Sequence[AuditRecord]:
        return list(self._audit)


class LoggingBroker(FakeBroker):
    """Defect: the audit trail records secret arguments in the clear."""

    def _redact(self, spec, args):
        return dict(args)


class CallerOnlyBroker(FakeBroker):
    """Defect: the allowlist is checked per caller, not per command."""

    def call(self, caller, command, args):
        if command in self._cmds and caller in self._allow:
            self._allow[caller].add(command)
        return super().call(caller, command, args)


class KeyNameRedactingBroker(FakeBroker):
    """Defect: redaction guesses from the argument's name instead of the schema's flag."""

    def _redact(self, spec, args):
        hints = ("secret", "token", "password", "key")
        return {k: ("<redacted>" if any(h in k for h in hints) else v) for k, v in args.items()}


class OkOnlyRedactingBroker(FakeBroker):
    """Defect: secrets are redacted on successful calls only; denied/invalid/error log them."""

    def _log(self, caller, command, outcome, spec, args):
        rec = self._redact(spec, args) if outcome == "ok" else dict(args)
        self._audit.append(AuditRecord(caller, command, outcome, rec))


class ChattyErrorBroker(FakeBroker):
    """Defect: a handler failure is passed through with the handler's own message and cause."""

    @staticmethod
    def _run_handler(command, handler, args):
        try:
            return handler(**dict(args))
        except Exception as exc:
            raise BrokerError(f"{command} failed: {exc}") from exc
