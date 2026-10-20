# SPDX-License-Identifier: Apache-2.0
"""The reference broker service: named actions for agents, decided by the manifest, run by pinned
handlers, every outcome audited to disk.

It implements the ``broker`` capability contract (``conformance.protocols.broker``) on top of
:func:`homelabnext.broker.decide` and a manifest (``schemas/broker/manifest`` 1.3).  An action is
one of three kinds:

* a **lane** write (``handler: builtin/lane``, ``lane: <name>``): ``memory.write``,
  ``finding.write``, ``proposal.file`` and the like, see :mod:`homelabnext.broker.lanes`;
* an **exec** handler: a file pinned by a handler document (``handler_docs``), run by
  :mod:`homelabnext.broker.execute`;
* an **in-process** command registered with ``register()`` (the contract's own API; how an
  embedding program exposes a Python function): tier ``write``, never needs approval, its
  arguments checked by ``ArgSpec``.  ``allow()`` grants such commands to a caller.

Default deny throughout: :func:`homelabnext.broker.decide` judges every call against the manifest
(action listed, caller granted, tier within the grant, handler declared, approval when required).
``call`` runs an allowed action now; ``submit`` stores a request and returns its id; an action
that needs approval can only be submitted.  Its request waits ``pending`` until an approver
listed in the manifest approves or denies it (:meth:`BrokerService.approve` /
:meth:`BrokerService.deny`, bound to the request digest), a ``decision.requested`` event is
emitted (carrying a ``link`` to the hub's Approvals page when ``approvals_url`` is set), and ``run`` then executes it once, consuming the approval durably.

State lives in one directory (:class:`homelabnext.broker.state.StateDir`): one file per request,
claim, result, approval, consumed approval and audit record, each created exclusively, so any
number of processes share it without locks and an approval is single use across all of them.
Every outcome - ok, denied, invalid, error, shadow - leaves one audit record that validates
against ``schemas/broker/audit``.  Arguments an ``ArgSpec`` marks ``secret`` are redacted in the
audit trail and never written to disk.

The service itself takes the caller as a string: an embedding program names it.  Stage 2a
(ADR-0017) authenticates it instead: :mod:`homelabnext.broker.server` serves this service on a
Unix socket and takes the caller from the peer's credentials, mapped through the manifest's
``callers`` (1.3); approvals arrive from the manifest's ``approval_relays``.  While a socket
request is being served, :data:`TRANSPORT_PEER` names the peer and every audit record carries it
as ``via``.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import tempfile
import urllib.parse
from collections.abc import Callable, Mapping, Sequence
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
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
from homelabnext.agent.schemas import schema_errors

from . import (
    DEFAULT_APPROVAL_TTL_S,
    check_manifest_handlers,
    decide,
    decide_access,
    request_digest,
    validation,
)
from . import execute as _exec
from . import lanes as _lanes
from .state import FileApprovalStore, StateDir, is_id, new_id

__all__ = [
    "NOT_OWNER",
    "TRANSPORT_PEER",
    "BrokerService",
    "ManifestError",
    "load_manifest",
    "make",
    "validate_manifest",
]

NOT_OWNER = "not-request-owner"
CALLABLE_HANDLER = "builtin/callable"
EMPTY_MANIFEST = {
    "manifest_id": "in-process",
    "default": "deny",
    "mode": "enforce",
    "actions": [],
    "grants": [],
}
APPROVAL_TITLE = "Broker approval needed"
APPROVAL_CLEARED = "Broker approval settled"
_SUMMARY_BYTES = 1024
_SVC_RE = re.compile(r"^svc:[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
#: the authenticated transport peer (``uid:<n>``) of the request being served on this thread, set
#: by :mod:`homelabnext.broker.server`; every audit record written meanwhile carries it as ``via``
TRANSPORT_PEER: ContextVar[str | None] = ContextVar("hnx_broker_transport_peer", default=None)


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _stamp(t: datetime) -> str:
    return t.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class ManifestError(ValueError):
    """The manifest, a handler document or a lane is not usable; ``problems`` lists each."""

    def __init__(self, problems: Sequence[str]) -> None:
        self.problems = list(problems)
        super().__init__("broker manifest invalid:\n  - " + "\n  - ".join(self.problems))


class _Refused(Exception):
    """Internal: a refusal to audit and turn into the contract's exception."""

    def __init__(self, outcome: str, reason: str, message: str) -> None:
        super().__init__(message)
        self.outcome, self.reason = outcome, reason


def _reasoned(message: str, reason: str) -> BrokerError:
    err = BrokerError(message)
    err.reason = reason  # type: ignore[attr-defined]
    return err


def _contract_error(exc: _Refused) -> BrokerError:
    if exc.outcome == "denied":
        return Denied(str(exc), reason=exc.reason)
    err: BrokerError = (
        InvalidArguments(str(exc)) if exc.outcome == "invalid" else BrokerError(str(exc))
    )
    err.reason = exc.reason  # type: ignore[attr-defined]
    return err


# ---------------------------------------------------------------- manifest loading and validation
def _read_doc(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".json":
        return json.loads(text)
    import yaml

    return yaml.safe_load(text)


def _inside(base: Path, rel: str) -> Path | None:
    """``base/rel`` when it resolves inside ``base`` (symlinks followed), else None."""
    p = (base / rel).resolve()
    return p if p.is_relative_to(base.resolve()) else None


def validate_manifest(
    manifest: Mapping[str, Any], base_dir: str | os.PathLike[str]
) -> tuple[list[dict[str, Any]], list[str]]:
    """(handler documents, problems) for ``manifest`` whose relative paths start at ``base_dir``.

    Checks: the manifest schema; each handler document's schema, path containment and that its
    handler file exists and matches ``handler_digest``; manifest/handler consistency
    (:func:`homelabnext.broker.check_manifest_handlers`, lane actions excluded); every lane action
    names a declared lane with ``handler: builtin/lane`` at tier ``write``; lane configuration.
    """
    base = Path(base_dir)
    problems = [f"manifest: {e}" for e in schema_errors("broker", "manifest", manifest)]
    if problems:
        return [], problems
    docs: list[dict[str, Any]] = []
    for rel in manifest.get("handler_docs", []):
        p = _inside(base, rel)
        if p is None or not p.is_file():
            problems.append(f"handler_docs: {rel} is missing or outside {base}")
            continue
        doc = _read_doc(p)
        errs = schema_errors("broker", "handler", doc)
        if errs:
            problems += [f"{rel}: {e}" for e in errs]
            continue
        docs.append(doc)
        for name in doc.get("secrets", []):
            if name in _exec.RESERVED_ENV or name.startswith("HNX_BROKER_"):
                problems.append(f"{rel}: secret name {name} is reserved")
        problems += [
            f"{rel}: params_schema {e}" for e in validation.schema_problems(doc["params_schema"])
        ]
        target = _inside(base, doc["handler"])
        if target is None or not target.is_file():
            problems.append(f"{rel}: handler {doc['handler']} is missing or outside {base}")
        elif _exec.file_digest(target) != doc["handler_digest"]:
            problems.append(
                f"{rel}: handler_digest does not match {doc['handler']} "
                f"(now {_exec.file_digest(target)})"
            )
    lanes = {}
    for ld in manifest.get("lanes", []):
        if ld["name"] in lanes:
            problems.append(f"lanes: {ld['name']} declared twice")
        lane = _lanes.Lane.from_doc(ld)
        lanes[lane.name] = lane
        problems += lane.problems()
    exec_actions = []
    for a in manifest["actions"]:
        if "lane" in a or a["handler"] == _lanes.LANE_HANDLER:
            if a.get("lane") not in lanes:
                problems.append(f"{a['action']}: lane {a.get('lane')!r} is not declared")
            if a["handler"] != _lanes.LANE_HANDLER:
                problems.append(f"{a['action']}: a lane action's handler is {_lanes.LANE_HANDLER}")
            if a["tier"] != "write":
                problems.append(f"{a['action']}: a lane action is tier write, not {a['tier']}")
        elif a["handler"].startswith("builtin/"):
            problems.append(f"{a['action']}: {a['handler']} is not a built-in handler")
        else:
            exec_actions.append(a)
    problems += check_manifest_handlers({"actions": exec_actions}, docs)
    problems += _peer_problems(manifest)
    return docs, problems


def _peer_problems(manifest: Mapping[str, Any]) -> list[str]:
    """Each transport peer (uid or user) is listed once, as a caller *or* a relay: one peer, one
    identity, so an agent's process can never also be the relay that approves for a human."""
    seen: dict[str, str] = {}
    out = []
    for where in ("callers", "approval_relays"):
        for entry in manifest.get(where, []):
            key = f"uid {entry['uid']}" if "uid" in entry else f"user {entry['user']}"
            if key in seen:
                out.append(f"{where}: {key} is already listed in {seen[key]}")
            seen.setdefault(key, where)
    return out


def load_manifest(path: str | os.PathLike[str]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Read and validate a manifest file; raises :class:`ManifestError` listing every problem."""
    p = Path(path)
    manifest = _read_doc(p)
    if not isinstance(manifest, dict):
        raise ManifestError([f"{p}: not a mapping"])
    docs, problems = validate_manifest(manifest, p.parent)
    if problems:
        raise ManifestError(problems)
    return manifest, docs


# ---------------------------------------------------------------- the service
@dataclass(frozen=True)
class _Action:
    name: str
    kind: str  # callable | exec | lane
    handler: Any = None  # callable, handler document, or Lane
    spec: Mapping[str, ArgSpec] | None = None


class BrokerService:
    """See the module doc.  One instance per process; any number may share ``state_dir``."""

    features = frozenset()

    def __init__(
        self,
        state_dir: str | os.PathLike[str],
        manifest: Mapping[str, Any] | None = None,
        *,
        base_dir: str | os.PathLike[str] | None = None,
        data_root: str | os.PathLike[str] | None = None,
        handler_docs: Sequence[Mapping[str, Any]] = (),
        bus: Any = None,
        notifier: Any = None,
        resolve_secret: Callable[[str], str] | None = None,
        clock: Callable[[], datetime] = _utcnow,
        source: str = "svc:broker",
        approvals_url: str | None = None,
    ) -> None:
        self.state = StateDir(state_dir)
        self.approvals_url = check_approvals_url(approvals_url)
        self.approvals = FileApprovalStore(self.state.root / "consumed")
        self.manifest = copy.deepcopy(dict(manifest or EMPTY_MANIFEST))
        self.base_dir = Path(base_dir) if base_dir is not None else Path.cwd()
        self.data_root = Path(data_root) if data_root is not None else self.state.root / "lanes"
        self.bus = bus
        self.notifier = notifier
        self.resolve_secret = resolve_secret or _exec.env_secret_resolver()
        self.clock = clock
        self.source = source
        self._docs = {d["action"]: dict(d) for d in handler_docs}
        self._lanes = {
            ld["name"]: _lanes.Lane.from_doc(ld) for ld in self.manifest.get("lanes", [])
        }
        self._callables: dict[str, tuple[Callable[..., Any], dict[str, ArgSpec]]] = {}
        self._allow: dict[str, set[str]] = {}
        self._secret_args: dict[str, dict[str, Any]] = {}
        if notifier is not None:
            notifier.register_pair(APPROVAL_TITLE, APPROVAL_CLEARED)

    @classmethod
    def from_manifest(
        cls,
        manifest_path: str | os.PathLike[str],
        state_dir: str | os.PathLike[str],
        **kwargs: Any,
    ) -> BrokerService:
        """A service over a validated manifest file; relative paths start at its directory."""
        manifest, docs = load_manifest(manifest_path)
        kwargs.setdefault("base_dir", Path(manifest_path).parent)
        return cls(state_dir, manifest, handler_docs=docs, **kwargs)

    # ---------------------------------------------------------------- the contract: setup
    def register(self, command, handler, args):
        if any(a["action"] == command for a in self.manifest["actions"]):
            raise ValueError(f"{command!r} is a manifest action; it cannot be re-registered")
        self._callables[command] = (handler, dict(args))

    def allow(self, caller, commands):
        self._allow.setdefault(caller, set()).update(commands)

    # ---------------------------------------------------------------- decisions
    def _view(self) -> dict[str, Any]:
        """The manifest plus the in-process commands and their grants, as decide() sees them."""
        view = dict(self.manifest)
        view["actions"] = [
            *self.manifest["actions"],
            *(
                {
                    "action": c,
                    "tier": "write",
                    "handler": CALLABLE_HANDLER,
                    "requires_approval": False,
                }
                for c in self._callables
            ),
        ]
        view["grants"] = [
            *self.manifest["grants"],
            *(
                {"profile": caller, "actions": sorted(cmds), "max_tier": "write"}
                for caller, cmds in self._allow.items()
            ),
        ]
        return view

    def _action(self, name: str) -> _Action | None:
        if name in self._callables:
            handler, spec = self._callables[name]
            return _Action(name, "callable", handler, spec)
        entry = next((a for a in self.manifest["actions"] if a["action"] == name), None)
        if entry is None:
            return None
        if entry.get("lane"):
            return _Action(name, "lane", self._lanes.get(entry["lane"]))
        return _Action(name, "exec", self._docs.get(name))

    def _now(self) -> datetime:
        return self.clock()

    # ---------------------------------------------------------------- audit
    def _summarize(self, args: Mapping[str, Any], spec: Mapping[str, ArgSpec] | None):
        out: dict[str, Any] = {}
        for k, v in args.items():
            if spec is not None and spec.get(k, ArgSpec("str")).secret:
                out[k] = "<redacted>"
                continue
            raw = json.dumps(v, sort_keys=True, ensure_ascii=False, default=repr)
            if len(raw.encode("utf-8")) > _SUMMARY_BYTES:
                out[k] = {"bytes": len(raw.encode()), "digest": _digest_text(raw)}
            else:
                out[k] = json.loads(raw)
        return out

    def _audit(
        self,
        caller: Any,
        action: str,
        operation: str,
        outcome: str,
        *,
        reason: str = "",
        args: Mapping[str, Any] | None = None,
        spec: Mapping[str, ArgSpec] | None = None,
        **extra: Any,
    ) -> None:
        t = self._now()
        rec: dict[str, Any] = {
            "audit_id": new_id("aud"),
            "at": t.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "caller": caller if isinstance(caller, str) else repr(caller),
            "action": str(action),
            "operation": operation,
            "outcome": outcome,
            "reason": reason if outcome not in ("ok",) else "",
            "args": self._summarize(args or {}, spec),
            "manifest_id": self.manifest.get("manifest_id", "in-process"),
        }
        rec.update({k: v for k, v in extra.items() if v is not None})
        via = TRANSPORT_PEER.get()
        if via is not None:
            rec["via"] = via
        problems = validation.named_errors("broker/audit", rec)
        if problems:  # a bug in the broker, never the caller's input: fail loudly
            raise BrokerError(f"audit record invalid: {problems[0]}")
        self.state.append_audit(rec, t.astimezone(UTC).strftime("%Y%m%dT%H%M%S%fZ"))

    def audit_refusal(
        self,
        caller: str,
        operation: str,
        outcome: str,
        reason: str,
        *,
        action: str = "",
        request_id: str | None = None,
    ) -> None:
        """Audit a refusal made before the service saw the request (the socket transport's:
        an unknown peer, an actor named in the body, a malformed or oversized request)."""
        self._audit(caller, action[:128], operation, outcome, reason=reason, request_id=request_id)

    def audit(self) -> Sequence[AuditRecord]:
        return [
            AuditRecord(
                caller=r["caller"],
                command=r["action"],
                outcome=r["outcome"],
                args=r.get("args", {}),
                operation=r["operation"],
                request_id=r.get("request_id"),
                reason=r.get("reason", ""),
            )
            for r in self.state.audit_records()
        ]

    def audit_documents(self, **match: Any) -> list[dict[str, Any]]:
        """Raw audit records whose fields equal every ``match`` value (None = any)."""
        want = {k: v for k, v in match.items() if v is not None}
        return [
            r for r in self.state.audit_records() if all(r.get(k) == v for k, v in want.items())
        ]

    # ---------------------------------------------------------------- argument checks
    def _check_args(self, act: _Action, caller: str, args: Any, now: str) -> None:
        if not isinstance(args, Mapping):
            raise _Refused("invalid", "invalid-params", "arguments must be an object")
        if act.kind == "callable":
            problems = arg_problems(act.spec, args)
            if problems:
                raise _Refused("invalid", "invalid-params", "; ".join(problems))
        elif act.kind == "lane":
            if act.handler is None:
                raise _Refused("denied", "handler-missing", f"{act.name}: lane not declared")
            try:
                _lanes.check_params(act.handler, caller, args, now)
            except _lanes.LaneError as exc:
                raise _Refused(exc.outcome, exc.reason, str(exc)) from None
        else:
            if act.handler is None:
                raise _Refused("denied", "handler-missing", f"{act.name}: no handler document")
            problems = validation.inline_errors(act.handler["params_schema"], dict(args))
            if problems:
                raise _Refused("invalid", "invalid-params", f"params: {problems[0]}")

    # ---------------------------------------------------------------- admission
    def _admit(self, caller: Any, action: Any, args: Any, operation: str, target: str | None):
        """(action, request, decision) or raise after auditing: the checks call and submit share."""
        now = self._now()
        rid = new_id("req")
        act = self._action(action) if isinstance(action, str) else None
        spec = act.spec if act else None
        request: dict[str, Any] = {
            "request_id": rid,
            "action": str(action),
            "actor": caller if isinstance(caller, str) else repr(caller),
            "params": dict(args) if isinstance(args, Mapping) else {},
            "created": _stamp(now),
        }
        if target is not None:
            request["target"] = target
        request["digest"] = request_digest(request)
        decision = decide(self._view(), request, None, now=_stamp(now), store=self.approvals)
        audit = {"request_id": rid, "request_digest": request["digest"]}
        log_args = args if isinstance(args, Mapping) else {}
        if decision["verdict"] == "deny":
            self._audit(
                caller,
                action,
                operation,
                "denied",
                reason=decision["reason"],
                args=log_args,
                spec=spec,
                **audit,
            )
            raise Denied(f"{caller!r} may not run {action!r}", reason=decision["reason"])
        try:
            if target is not None and not (isinstance(target, str) and _SVC_RE.match(target)):
                raise _Refused("invalid", "invalid-target", "target must be a svc: id")
            self._check_args(act, caller, args, _stamp(now))
        except _Refused as exc:
            self._audit(
                caller,
                action,
                operation,
                exc.outcome,
                reason=exc.reason,
                args=log_args,
                spec=spec,
                **audit,
            )
            raise _contract_error(exc) from None
        return act, request, decision

    # ---------------------------------------------------------------- execution
    def _execute(self, act: _Action, request: Mapping[str, Any], args: Mapping[str, Any]) -> Any:
        """Run one admitted action; raises :class:`_Refused` on a refusal or failure."""
        if act.kind == "callable":
            failed = False
            try:
                result = act.handler(**dict(args))
            except Exception:
                failed = True
            if failed:  # raised outside the except block: no __context__ leaks the handler's error
                raise _Refused("error", "handler-failed", f"{act.name} failed")
            return result
        if act.kind == "lane":
            try:
                written = _lanes.write(
                    act.handler, self.data_root, request["actor"], args, request["created"]
                )
            except _lanes.LaneError as exc:
                raise _Refused(exc.outcome, exc.reason, str(exc)) from None
            except OSError:
                raise _Refused("error", "lane-io-error", f"{act.name}: the write failed") from None
            if (
                act.handler.kind == "records-inbox"
                and args["note"].get("type", "proposal") == "proposal"
            ):
                self._proposal_created(request, args["note"], written["path"])
            return written
        return self._run_exec(act, request, args)

    def _proposal_created(self, request: Mapping[str, Any], note: Mapping[str, Any], path: str):
        data = {
            "proposal_id": Path(path).stem,
            "note": path,
            "requesting_agent": request["actor"],
            "risk": note["risk"],
            "summary": str(note.get("title", ""))[:300],
        }
        if note.get("affects"):
            data["affects"] = list(note["affects"])
        self._emit(
            "homelabnext.proposal.created", data, request["request_id"], key=f"proposal:{path}"
        )

    def _run_exec(self, act: _Action, request: Mapping[str, Any], args: Mapping[str, Any]):
        from homelabnext.runs import run_dir

        doc = act.handler
        path = _inside(self.base_dir, doc["handler"])
        if path is None:
            raise _Refused("denied", "handler-path-escape", f"{act.name}: handler outside the base")
        rd = run_dir(request["request_id"], self.state.root, env={})
        env = {
            "HNX_BROKER_ACTION": act.name,
            "HNX_BROKER_REQUEST_ID": request["request_id"],
            "HNX_BROKER_ACTOR": request["actor"],
        }
        if request.get("target"):
            env["HNX_BROKER_TARGET"] = request["target"]
        try:
            res = _exec.run_handler(
                path,
                doc["handler_digest"],
                params=args,
                run_dir=rd,
                timeout_s=doc["timeout_s"],
                argv=doc.get("argv", ()),
                env=env,
                secrets=doc.get("secrets", ()),
                resolve_secret=self.resolve_secret,
                max_output=doc.get("max_output_bytes", _exec.DEFAULT_MAX_OUTPUT),
            )
        except _exec.ExecError as exc:
            raise _Refused(exc.outcome, exc.reason, f"{act.name}: {exc}") from None
        if res.timed_out:
            raise _Refused("error", "handler-timeout", f"{act.name} exceeded {doc['timeout_s']}s")
        if res.exit_code != 0:
            raise _Refused("error", "handler-failed", f"{act.name} failed (exit {res.exit_code})")
        text = res.stdout.decode("utf-8", errors="replace")
        try:
            output: Any = json.loads(text) if text.strip() and not res.stdout_truncated else text
        except ValueError:
            output = text
        return {
            "exit_code": res.exit_code,
            "output": output,
            "truncated": res.stdout_truncated or res.stderr_truncated,
            "stderr_bytes": len(res.stderr),
        }

    def _run_audited(self, caller, act, request, args, operation) -> Any:
        extra = {"request_id": request["request_id"], "request_digest": request["digest"]}
        try:
            result = self._execute(act, request, args)
        except _Refused as exc:
            self._audit(
                caller,
                act.name,
                operation,
                exc.outcome,
                reason=exc.reason,
                args=args,
                spec=act.spec,
                **extra,
            )
            raise _contract_error(exc) from None
        summary = None
        if act.kind != "callable" and isinstance(result, Mapping):
            summary = {
                k: result[k] for k in ("path", "bytes", "digest", "exit_code") if k in result
            }
        self._audit(
            caller, act.name, operation, "ok", args=args, spec=act.spec, result=summary, **extra
        )
        return result

    def _shadow(self, caller, act, request, decision, operation):
        self._audit(
            caller,
            request["action"],
            operation,
            "shadow",
            reason=decision["reason"],
            args=request["params"],
            spec=act.spec if act else None,
            request_id=request["request_id"],
            request_digest=request["digest"],
        )
        return {"shadow": True, "decision": decision}

    # ---------------------------------------------------------------- the contract: calls
    def call(self, caller, command, args, *, target: str | None = None):
        act, request, decision = self._admit(caller, command, args, "call", target)
        if not decision["enforced"]:
            return self._shadow(caller, act, request, decision, "call")
        if decision["verdict"] == "needs-approval":
            self._audit(
                caller,
                command,
                "call",
                "denied",
                reason="approval-required",
                args=args,
                spec=act.spec,
                request_id=request["request_id"],
                request_digest=request["digest"],
            )
            raise Denied(f"{command!r} needs approval: submit it", reason="approval-required")
        return self._run_audited(caller, act, request, args, "call")

    def submit(self, caller, command, args, *, target: str | None = None):
        act, request, decision = self._admit(caller, command, args, "submit", target)
        rid = request["request_id"]
        stored = dict(request)
        secret = {}
        if act.kind == "callable":
            secret = {k: v for k, v in args.items() if act.spec.get(k, ArgSpec("str")).secret}
            stored["params"] = {k: ("<redacted>" if k in secret else v) for k, v in args.items()}
        record = {
            "request": stored,
            "kind": act.kind,
            "verdict": decision["verdict"],
            "decision_reason": decision["reason"],
        }
        self.state.put_request(rid, record)
        if secret:
            self._secret_args[rid] = secret
        self._audit(
            caller,
            command,
            "submit",
            "ok",
            args=args,
            spec=act.spec,
            request_id=rid,
            request_digest=request["digest"],
            decision_reason=decision["reason"],
        )
        if decision["verdict"] == "needs-approval":
            self._approval_requested(request)
        return rid

    def _owned(self, caller, request_id, operation):
        """The stored record when ``caller`` owns ``request_id``; otherwise audit and refuse.

        An unknown id and someone else's id get the same answer, so a foreign request's existence
        is not disclosed."""
        rec = self.state.get_request(request_id) if is_id(request_id) else None
        if rec is not None:
            op = "cancel" if operation == "cancel" else "read"
            access = decide_access(
                self.manifest, rec["request"], caller, op, now=_stamp(self._now())
            )
            if access["verdict"] == "allow":
                return rec
        action = rec["request"]["action"] if rec else ""
        self._audit(
            caller, action, operation, "denied", reason=NOT_OWNER, request_id=str(request_id)[:128]
        )
        raise Denied(f"no request {request_id!r} for {caller!r}", reason=NOT_OWNER)

    def status(self, caller, request_id):
        rec = self._owned(caller, request_id, "status")
        req = rec["request"]
        self._audit(caller, req["action"], "status", "ok", request_id=request_id)
        return RequestStatus(
            request_id, req["actor"], req["action"], self.state.state_of(request_id)
        )

    def detail(self, caller, request_id) -> dict[str, Any]:
        """The owner's full view: request, state, approvals and result (``hnx broker status``)."""
        st = self.status(caller, request_id)
        rec = self.state.get_request(request_id)
        return {
            "request": rec["request"],
            "state": st.state,
            "verdict": rec["verdict"],
            "approvals": self.state.approvals(request_id),
            "result": self.state.get_result(request_id),
        }

    def run(self, caller, request_id):
        rec = self._owned(caller, request_id, "run")
        req = rec["request"]
        extra = {"request_id": request_id, "request_digest": req["digest"]}
        state = self.state.state_of(request_id)
        if state != "pending":
            self._audit(caller, req["action"], "run", "invalid", reason="not-pending", **extra)
            raise _reasoned(f"request {request_id!r} is {state}, not pending", "not-pending")
        act = self._action(req["action"])
        args = {**req["params"], **self._secret_args.get(request_id, {})}
        approvals = [a for a in self.state.approvals(request_id) if a["decision"] == "approved"]
        approval = approvals[-1] if approvals else None
        now = _stamp(self._now())
        view = self._view()
        decision = decide(view, req, approval, now=now, store=self.approvals)
        if not decision["enforced"]:
            return self._shadow(caller, act, req, decision, "run")
        if decision["verdict"] != "allow":
            reason = decision["reason"]
            self._audit(
                caller,
                req["action"],
                "run",
                "denied",
                reason=reason,
                args=req["params"],
                spec=act.spec if act else None,
                approval_id=decision.get("approval_id"),
                **extra,
            )
            raise Denied(f"request {request_id!r} may not run: {reason}", reason=reason)
        try:
            held = self._secret_args.get(request_id, {})
            if (
                act
                and act.kind == "callable"
                and any(
                    act.spec.get(k, ArgSpec("str")).secret and k not in held for k in req["params"]
                )
            ):
                raise _Refused("error", "secret-args-lost", "a secret argument is not held here")
            self._check_args(act, req["actor"], args, req["created"])
        except _Refused as exc:
            self._audit(
                caller,
                req["action"],
                "run",
                exc.outcome,
                reason=exc.reason,
                args=req["params"],
                spec=act.spec,
                **extra,
            )
            raise _contract_error(exc) from None
        claimed = self.state.claim(
            request_id, {"op": "run", "by": caller, "at": now, "pid": os.getpid()}
        )
        if not claimed:
            self._audit(caller, req["action"], "run", "invalid", reason="not-pending", **extra)
            raise _reasoned(f"request {request_id!r} is no longer pending", "not-pending")
        try:
            result = self._run_audited(caller, act, req, args, "run")
        except BrokerError as exc:
            self.state.put_result(
                request_id, {"state": "error", "at": now, "reason": getattr(exc, "reason", "")}
            )
            raise
        finally:
            self._secret_args.pop(request_id, None)
        done = {"state": "done", "at": _stamp(self._now())}
        if act.kind != "callable" and isinstance(result, Mapping):
            done["result"] = json.loads(json.dumps(result, default=repr))
        self.state.put_result(request_id, done)
        return result

    def cancel(self, caller, request_id):
        rec = self._owned(caller, request_id, "cancel")
        req = rec["request"]
        extra = {"request_id": request_id, "request_digest": req["digest"]}
        claimed = self.state.claim(
            request_id, {"op": "cancel", "by": caller, "at": _stamp(self._now())}
        )
        if not claimed:
            state = self.state.state_of(request_id)
            self._audit(caller, req["action"], "cancel", "invalid", reason="not-pending", **extra)
            raise _reasoned(f"request {request_id!r} is {state}, not pending", "not-pending")
        self._secret_args.pop(request_id, None)
        self._audit(caller, req["action"], "cancel", "ok", **extra)
        if rec["verdict"] == "needs-approval":
            self._notify_settled(request_id, "cancelled by its owner")

    # ---------------------------------------------------------------- approvals
    def pending(self) -> list[dict[str, Any]]:
        """Requests waiting for an approver: needs-approval, still pending, not yet approved."""
        out = []
        for rid in self.state.request_ids():
            rec = self.state.get_request(rid)
            if (
                not rec
                or rec["verdict"] != "needs-approval"
                or self.state.state_of(rid) != "pending"
            ):
                continue
            approved = [a for a in self.state.approvals(rid) if a["decision"] == "approved"]
            req = rec["request"]
            out.append(
                {
                    "request_id": rid,
                    "action": req["action"],
                    "actor": req["actor"],
                    "target": req.get("target"),
                    "params": req["params"],
                    "created": req["created"],
                    "digest": req["digest"],
                    "approved": bool(approved),
                }
            )
        return out

    def pending_for(self, caller: str) -> list[dict[str, Any]]:
        """``caller``'s own requests still ``pending`` (awaiting approval, or approved and not yet
        run, or allowed and not yet run): what an agent may still run or cancel."""
        out = []
        for rid in self.state.request_ids():
            rec = self.state.get_request(rid)
            if (
                not rec
                or rec["request"]["actor"] != caller
                or self.state.state_of(rid) != "pending"
            ):
                continue
            req = rec["request"]
            approved = [a for a in self.state.approvals(rid) if a["decision"] == "approved"]
            out.append(
                {
                    "request_id": rid,
                    "action": req["action"],
                    "target": req.get("target"),
                    "created": req["created"],
                    "awaiting_approval": rec["verdict"] == "needs-approval" and not approved,
                    "approved": bool(approved),
                }
            )
        return out

    def actions_for(self, caller: str) -> list[dict[str, Any]]:
        """What ``caller`` may ask for: every action a grant of its names that :func:`decide`
        would admit (``allow`` or ``needs-approval``), with its tier, kind and parameters.
        Derived by asking ``decide`` itself (shadow mode, nothing consumed), so it cannot
        disagree with what a call would get."""
        view = self._view()
        names = sorted({a for g in view["grants"] if g["profile"] == caller for a in g["actions"]})
        out = []
        for name in names:
            probe = {"request_id": "req-probe", "action": name, "actor": caller, "params": {}}
            verdict = decide(dict(view, mode="shadow"), probe, None, store=self.approvals)
            if verdict["verdict"] not in ("allow", "needs-approval"):
                continue
            entry = next(a for a in view["actions"] if a["action"] == name)
            act = self._action(name)
            row: dict[str, Any] = {
                "action": name,
                "tier": entry["tier"],
                "kind": act.kind,
                "needs_approval": verdict["verdict"] == "needs-approval",
            }
            if act.kind == "lane" and act.handler is not None:
                row["lane"] = act.handler.name
                row["params"] = _lane_params(act.handler)
            elif act.kind == "exec" and act.handler is not None:
                row["params_schema"] = act.handler["params_schema"]
                row["description"] = act.handler.get("description", "")
            out.append(row)
        return out

    def approve(self, request_id, approver: str, *, note: str | None = None) -> dict[str, Any]:
        """File an approval of ``request_id`` by ``approver`` (``issuer:subject``)."""
        return self._decide_request(request_id, approver, "approved", note)

    def deny(self, request_id, approver: str, *, note: str | None = None) -> dict[str, Any]:
        """File a denial: the request becomes ``denied`` and can never run."""
        return self._decide_request(request_id, approver, "denied", note)

    def _decide_request(self, request_id, approver, decision, note):
        op = "approve" if decision == "approved" else "deny"
        who = approver if isinstance(approver, str) else repr(approver)
        rec = self.state.get_request(request_id) if is_id(request_id) else None
        if rec is None:
            self._audit(
                who, "", op, "denied", reason="unknown-request", request_id=str(request_id)[:128]
            )
            raise Denied(f"no request {request_id!r}", reason="unknown-request")
        req = rec["request"]
        extra = {"request_id": request_id, "request_digest": req["digest"]}
        state = self.state.state_of(request_id)
        if rec["verdict"] != "needs-approval" or state != "pending":
            self._audit(who, req["action"], op, "invalid", reason="not-awaiting-approval", **extra)
            raise _reasoned(
                f"request {request_id!r} is not awaiting approval ({state})",
                "not-awaiting-approval",
            )
        issuer, sep, subject = who.partition(":")
        now = self._now()
        ttl = self.manifest.get("approval_ttl_s") or DEFAULT_APPROVAL_TTL_S
        doc: dict[str, Any] = {
            "approval_id": new_id("appr"),
            "request_id": request_id,
            "request_digest": req["digest"],
            "decision": decision,
            "approver": {"issuer": issuer, "subject": subject},
            "approved_at": _stamp(now),
            "expires_at": _stamp(now + timedelta(seconds=ttl)),
        }
        if note:
            doc["note"] = note
        problems = (
            schema_errors("broker", "approval", doc) if sep else ["approver is issuer:subject"]
        )
        if problems:
            self._audit(who, req["action"], op, "invalid", reason="approval-invalid", **extra)
            raise InvalidArguments(f"approval: {problems[0]}")
        # the approver's identity is judged by decide() itself (allowlist, self, agent): the same
        # rules for a denial as for an approval, so a stranger cannot deny someone's request either
        probe = decide(
            dict(self._view(), mode="shadow"),
            req,
            {**doc, "decision": "approved"},
            now=doc["approved_at"],
            store=self.approvals,
        )
        if probe["reason"] != "approved":
            self._audit(who, req["action"], op, "denied", reason=probe["reason"], **extra)
            raise Denied(f"{who!r} may not {op} {request_id!r}", reason=probe["reason"])
        if decision == "denied" and not self.state.claim(
            request_id, {"op": "deny", "by": who, "at": doc["approved_at"]}
        ):
            self._audit(who, req["action"], op, "invalid", reason="not-awaiting-approval", **extra)
            raise _reasoned(f"request {request_id!r} is no longer pending", "not-pending")
        self.state.put_approval(doc)
        self._audit(who, req["action"], op, "ok", approval_id=doc["approval_id"], **extra)
        self._emit(
            "homelabnext.decision.returned",
            {
                "decision_id": request_id,
                "verdict": "accept" if decision == "approved" else "reject",
                "confidence": 1.0,
                "tier_used": "human",
            },
            request_id,
            key=f"returned:{doc['approval_id']}",
        )
        self._notify_settled(request_id, f"{decision} by {who}")
        return doc

    # ---------------------------------------------------------------- events and notify
    def _emit(self, event_type: str, data: Mapping[str, Any], rid: str, *, key: str) -> None:
        from homelabnext.events.envelope import build_event, canonical_body

        ev = build_event(
            event_type, self.source, data, dedupe_key=key, subject=rid, time=_stamp(self._now())
        )
        if self.bus is None:
            self.state.put_outbox(ev)
        else:
            self.bus.publish(event_type, canonical_body(ev), msg_id=ev["id"])

    def approval_link(self, rid: str) -> str | None:
        """The hub Approvals page for one request, when ``approvals_url`` is configured."""
        if not self.approvals_url:
            return None
        return f"{self.approvals_url}?{urllib.parse.urlencode({'request': rid})}"

    def _approval_requested(self, request: Mapping[str, Any]) -> None:
        rid = request["request_id"]
        link = self.approval_link(rid)
        data = {
            "decision_id": rid,
            "spec": "broker-approval",
            "subject": f"requests/{rid}.json",
            "action": request["action"],
            "actor": request["actor"],
            "request_digest": request["digest"],
        }
        if link:
            data["link"] = link
        self._emit("homelabnext.decision.requested", data, rid, key=f"requested:{rid}")
        if self.notifier is not None:
            from homelabnext.notify.core import Message

            body = f"{request['actor']} asks to run {request['action']} ({rid})"
            msg = Message(
                key=f"broker-approval-{rid}",
                title=APPROVAL_TITLE,
                body=body + (f"\nReview: {link}" if link else ""),
                level="warn",
                click=link,
            )
            self._notify(msg.key, "awaiting-approval", msg)

    def _notify_settled(self, rid: str, how: str) -> None:
        if self.notifier is None:
            return
        from homelabnext.notify.core import Message

        key = f"broker-approval-{rid}"
        self._notify(key, "ok", Message(key=key, title=APPROVAL_CLEARED, body=f"{rid} {how}"))

    def _notify(self, key, state, msg) -> None:
        # a notification is a courtesy: the event and the pending list already carry the request,
        # so a failed send never fails the broker operation that triggered it
        try:
            self.notifier.report(key, state, msg)
        except Exception:
            self._audit(
                "svc:broker", "", "notify", "error", reason="notify-failed", request_id=key[16:]
            )


def check_approvals_url(url: str | None) -> str | None:
    """``url`` when it is an absolute http(s) URL of a page (no credentials, query or fragment),
    else :class:`ValueError`; None and "" pass as None (no link)."""
    if not url:
        return None
    parts = urllib.parse.urlsplit(url)
    if (
        parts.scheme not in ("http", "https")
        or not parts.hostname
        or parts.username
        or parts.password
        or parts.query
        or parts.fragment
        or any(c.isspace() for c in url)
    ):
        raise ValueError(f"approvals URL {url!r} is not an http(s) page URL")
    return url


def _lane_params(lane: _lanes.Lane) -> dict[str, str]:
    """A caller's description of a lane action's params (``actions_for``)."""
    if lane.kind == "records-inbox":
        return {
            "note": "records note frontmatter: title, risk, rollback, ...; requesting_agent is "
            f"bound to the caller; type one of {', '.join(lane.note_types)}",
            "body": "optional Markdown body",
            "slug": "optional file name slug",
        }
    return {
        "name": f"file name matching {lane.filename_pattern}",
        "content": f"{lane.format}, at most {lane.max_bytes} bytes"
        + ("" if lane.overwrite else "; an existing file is never replaced"),
    }


def _digest_text(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def make(**config: Any) -> BrokerService:
    """Conformance factory: a fresh service over a private temporary state directory.

    ``config`` may name ``manifest`` (a file path) and ``data_root``; the target file
    ``conformance/targets/broker-reference.yml`` passes none, so the suite drives the in-process
    command API on an empty, default-deny manifest.
    """
    tmp = tempfile.TemporaryDirectory(prefix="hnx-broker-")
    root = Path(tmp.name)
    if config.get("manifest"):
        svc = BrokerService.from_manifest(
            config["manifest"], root / "state", data_root=config.get("data_root", root / "data")
        )
    else:
        svc = BrokerService(root / "state", data_root=root / "data")
    svc._tmpdir = tmp  # the directory lives as long as the service
    return svc
