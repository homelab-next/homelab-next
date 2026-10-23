# SPDX-License-Identifier: Apache-2.0
"""In-memory allowlisted command broker with an audit trail."""

from __future__ import annotations

import itertools
import re
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from conformance.protocols.broker import (
    ArgSpec,
    AuditRecord,
    BrokerError,
    Denied,
    InvalidArguments,
    RequestStatus,
    arg_problems,
)

NOT_OWNER = "not-request-owner"


class FakeBroker:
    features = frozenset()

    def __init__(self) -> None:
        self._cmds: dict[str, tuple[Callable[..., Any], Mapping[str, ArgSpec]]] = {}
        self._allow: dict[str, set[str]] = {}
        self._audit: list[AuditRecord] = []
        self._reqs: dict[str, dict[str, Any]] = {}
        self._seq = itertools.count(1)

    def register(self, command, handler, args):
        self._cmds[command] = (handler, dict(args))

    def allow(self, caller, commands):
        self._allow.setdefault(caller, set()).update(commands)

    def _redact(self, spec: Mapping[str, ArgSpec], args: Mapping[str, Any]) -> dict[str, Any]:
        # redact by default: only a value the schema names, and does not mark secret, is shown
        # (a misspelt argument, or any argument of an unknown command, may well be a secret)
        return {
            k: (v if k in spec and not spec[k].secret else "<redacted>") for k, v in args.items()
        }

    def _log(self, caller, command, outcome, spec, args, **extra) -> None:
        self._audit.append(AuditRecord(caller, command, outcome, self._redact(spec, args), **extra))

    def _admit(self, caller, command, args, **extra):
        """The allowlist and argument checks shared by ``call`` and ``submit``."""
        entry = self._cmds.get(command)
        spec = entry[1] if entry else {}
        if entry is None or command not in self._allow.get(caller, set()):
            self._log(caller, command, "denied", spec, args, **extra)
            raise Denied(f"{caller!r} may not run {command!r}", reason="not-allowed")
        problems = arg_problems(spec, args)
        if problems:
            self._log(caller, command, "invalid", spec, args, **extra)
            raise InvalidArguments("; ".join(problems))
        return entry

    def _execute(self, caller, command, handler, spec, args, **extra):
        try:
            result = self._run_handler(command, handler, args)
        except BrokerError:
            self._log(caller, command, "error", spec, args, **extra)
            raise
        self._log(caller, command, "ok", spec, args, **extra)
        return result

    def call(self, caller, command, args):
        args = dict(args)  # checked and run as one snapshot
        handler, spec = self._admit(caller, command, args)
        return self._execute(caller, command, handler, spec, args)

    # ---- deferred requests: bound to the caller that submitted them
    def submit(self, caller, command, args):
        args = dict(args)  # the copy that is checked is the copy that runs
        _, spec = self._admit(caller, command, args, operation="submit")
        rid = f"req-{next(self._seq)}"
        self._reqs[rid] = {"caller": caller, "command": command, "args": args}
        self._reqs[rid]["state"] = "pending"
        self._log(caller, command, "ok", spec, args, operation="submit", request_id=rid)
        return rid

    def _owns(self, caller, req) -> bool:
        return req["caller"] == caller

    def _deny_foreign(self, caller, request_id, operation, req) -> None:
        cmd = req["command"] if req else ""
        self._audit.append(AuditRecord(caller, cmd, "denied", {}, operation, request_id, NOT_OWNER))

    def _owned(self, caller, request_id, operation):
        """The request, if ``caller`` owns it; otherwise audit and refuse (unknown ids alike)."""
        req = self._reqs.get(request_id)
        if req is None or not self._owns(caller, req):
            self._deny_foreign(caller, request_id, operation, req)
            raise Denied(f"no request {request_id!r} for {caller!r}", reason=NOT_OWNER)
        return req

    def _spec(self, command):
        entry = self._cmds.get(command)
        return entry[1] if entry else {}

    def status(self, caller, request_id):
        req = self._owned(caller, request_id, "status")
        extra = {"operation": "status", "request_id": request_id}
        self._log(caller, req["command"], "ok", self._spec(req["command"]), {}, **extra)
        return RequestStatus(request_id, req["caller"], req["command"], req["state"])

    def run(self, caller, request_id):
        req = self._owned(caller, request_id, "run")
        cmd, args, extra = (
            req["command"],
            req["args"],
            {"operation": "run", "request_id": request_id},
        )
        if req["state"] != "pending":
            self._log(caller, cmd, "invalid", self._spec(cmd), args, **extra)
            raise BrokerError(f"request {request_id!r} is {req['state']}, not pending")
        handler, spec = self._cmds[cmd]
        req["state"] = "error"  # stays so if the handler fails: a request runs at most once
        result = self._execute(caller, cmd, handler, spec, args, **extra)
        req["state"] = "done"
        return result

    def cancel(self, caller, request_id):
        req = self._owned(caller, request_id, "cancel")
        cmd, extra = req["command"], {"operation": "cancel", "request_id": request_id}
        if req["state"] != "pending":
            self._log(caller, cmd, "invalid", self._spec(cmd), {}, **extra)
            raise BrokerError(f"request {request_id!r} is {req['state']}, not pending")
        req["state"] = "cancelled"
        self._log(caller, cmd, "ok", self._spec(cmd), {}, **extra)

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

    def _log(self, caller, command, outcome, spec, args, **extra):
        rec = self._redact(spec, args) if outcome == "ok" else dict(args)
        self._audit.append(AuditRecord(caller, command, outcome, rec, **extra))


class ChattyErrorBroker(FakeBroker):
    """Defect: a handler failure is passed through with the handler's own message and cause."""

    @staticmethod
    def _run_handler(command, handler, args):
        try:
            return handler(**dict(args))
        except Exception as exc:
            raise BrokerError(f"{command} failed: {exc}") from exc


class SharedRequestsBroker(FakeBroker):
    """Defect: deferred requests are not bound to their caller; anyone may read, run or cancel."""

    def _owns(self, caller, req):
        return True


class SilentForeignAccessBroker(FakeBroker):
    """Defect: a refused read/run/cancel of someone else's request leaves no audit record."""

    def _deny_foreign(self, caller, request_id, operation, req):
        return None


class SubmitSkipsAllowlistBroker(FakeBroker):
    """Defect: ``submit`` checks the arguments but not the allowlist, so a caller allowed
    nothing can submit any registered command and then run it as the request's owner."""

    def _admit(self, caller, command, args, **extra):
        entry = self._cmds.get(command)
        if extra.get("operation") == "submit" and entry is not None:
            problems = arg_problems(entry[1], args)
            if problems:
                self._log(caller, command, "invalid", entry[1], args, **extra)
                raise InvalidArguments("; ".join(problems))
            return entry
        return super()._admit(caller, command, args, **extra)


class SubmitSkipsArgsBroker(FakeBroker):
    """Defect: ``submit`` checks the allowlist but not the arguments, so the handler later runs
    with missing, unexpected or mistyped arguments."""

    def _admit(self, caller, command, args, **extra):
        entry = self._cmds.get(command)
        if (
            extra.get("operation") == "submit"
            and entry is not None
            and command in self._allow.get(caller, set())
        ):
            return entry
        return super()._admit(caller, command, args, **extra)


class DeferredClearAuditBroker(FakeBroker):
    """Defect: ``call`` is redacted, but the audit records of ``submit`` and ``run`` carry the
    secret arguments in the clear."""

    def _log(self, caller, command, outcome, spec, args, **extra):
        if extra.get("operation") in ("submit", "run"):
            self._audit.append(AuditRecord(caller, command, outcome, dict(args), **extra))
            return
        super()._log(caller, command, outcome, spec, args, **extra)


class RunAuditedTwiceBroker(FakeBroker):
    """Defect: running a request leaves a ``started`` record and then its outcome, two records
    for one operation."""

    def _execute(self, caller, command, handler, spec, args, **extra):
        if extra.get("operation") == "run":
            self._log(caller, command, "started", spec, args, **extra)
        return super()._execute(caller, command, handler, spec, args, **extra)


class SubmitKeepsCallerArgsBroker(FakeBroker):
    """Defect: ``submit`` checks the arguments and then keeps the caller's own mapping, so what
    ``run`` hands the handler is whatever that mapping holds by then - never validated."""

    def submit(self, caller, command, args):
        rid = super().submit(caller, command, args)
        self._reqs[rid]["args"] = args
        return rid


class RefusedSubmitUnauditedBroker(FakeBroker):
    """Defect: a denied or invalid ``submit`` leaves no audit record (``call`` still does), so a
    stranger can probe the allowlist through ``submit`` unseen."""

    def _log(self, caller, command, outcome, spec, args, **extra):
        if extra.get("operation") == "submit" and outcome in ("denied", "invalid"):
            return
        super()._log(caller, command, outcome, spec, args, **extra)


class UnauditedSubmitBroker(FakeBroker):
    """Defect: no ``submit`` is audited at all; only the later ``run`` leaves a record."""

    def _log(self, caller, command, outcome, spec, args, **extra):
        if extra.get("operation") == "submit":
            return
        super()._log(caller, command, outcome, spec, args, **extra)


class KnownSecretsOnlyBroker(FakeBroker):
    """Defect: redaction is by known key only, so the value of a misspelt secret argument, or of
    any argument of an unregistered command, is audited in the clear."""

    def _redact(self, spec, args):
        return {
            k: ("<redacted>" if spec.get(k, ArgSpec("str")).secret else v) for k, v in args.items()
        }


class RunChattyErrorBroker(FakeBroker):
    """Defect: ``call`` contains a handler failure, but ``run`` passes the handler's own message
    and cause through to the caller."""

    def _execute(self, caller, command, handler, spec, args, **extra):
        if extra.get("operation") != "run":
            return super()._execute(caller, command, handler, spec, args, **extra)
        try:
            result = handler(**dict(args))
        except Exception as exc:
            self._log(caller, command, "error", spec, args, **extra)
            raise BrokerError(f"{command} failed: {exc}") from exc
        self._log(caller, command, "ok", spec, args, **extra)
        return result


class GuessingRedactionBroker(FakeBroker):
    """Defect: an argument the schema does not name is redacted only when its name looks secret
    (``pass``, ``token``, ``key`` ...), the common logging-filter idiom: redaction by guess."""

    _LOOKS = re.compile(r"(?i)pass|word|secret|token|key|cred|pwd")

    def _redact(self, spec, args):
        return {
            k: (
                ("<redacted>" if spec[k].secret else v)
                if k in spec
                else ("<redacted>" if self._LOOKS.search(k) else v)
            )
            for k, v in args.items()
        }


class EchoingRefusalBroker(FakeBroker):
    """Defect: the audit trail is redacted, but ``InvalidArguments`` names each unexpected
    argument with its value (``unexpected lable='...'``), as validation libraries' messages do."""

    def _admit(self, caller, command, args, **extra):
        entry = self._cmds.get(command)
        if entry is not None and command in self._allow.get(caller, set()):
            spec = entry[1]
            problems = arg_problems(spec, args)
            if problems:
                self._log(caller, command, "invalid", spec, args, **extra)
                shown = [p for p in problems if not p.startswith("unexpected")]
                shown += [f"unexpected {k}={args[k]!r}" for k in args if k not in spec]
                raise InvalidArguments("; ".join(shown))
        return super()._admit(caller, command, args, **extra)
