# SPDX-License-Identifier: Apache-2.0
"""The reference broker service: named actions for agents, decided by the manifest, run by pinned
handlers, every outcome audited to disk.

It implements the ``broker`` capability contract (``conformance.protocols.broker``) on top of
:func:`homelabnext.broker.decide` and a manifest (``schemas/broker/manifest`` 1.4).  An action is
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
against ``schemas/broker/audit``.  An action that executes (a ``call``, or an approved ``run``)
first writes a ``started`` record (audit 1.2), and the broker refuses to execute it
(``audit-unavailable``) when that record cannot be written: the trail never lacks an action that
ran.  If the outcome record cannot be written afterwards (``audit-incomplete``), the ``started``
record is the evidence; a run then ends ``error`` (or reads ``interrupted`` when not even its
result can be written, :mod:`homelabnext.broker.state`).  The contract view (:meth:`audit`)
lists outcomes only, one per operation.  Arguments an ``ArgSpec`` marks ``secret`` are redacted in the
audit trail and never written to disk; in the request (and so in its digest, which is persisted,
audited and sent with events) each is replaced by ``hmac-sha256:<hex>``, a hash keyed with the
state directory's ``digest.key``, so a low-entropy secret cannot be recovered from the digest by
guessing, while the digest still changes with the value.

The service itself takes the caller as a string: an embedding program names it.  Stage 2a
(ADR-0017) authenticates it instead: :mod:`homelabnext.broker.server` serves this service on a
Unix socket and takes the caller from the peer's credentials, mapped through the manifest's
``callers`` (1.3); approvals arrive from the manifest's ``approval_relays``.  While a socket
request is being served, :data:`TRANSPORT_PEER` names the peer and every audit record carries it
as ``via``.

**Quotas on accepted work** (manifest 1.5 ``quotas``): an actor may have at most
``pending_per_actor`` requests pending at once (default :data:`DEFAULT_PENDING_PER_ACTOR`; a
``submit`` past it is refused ``too-many-pending`` and audited), and its approval requests page
the approver only while the actor has **no open page**, and at most once per ``notify_window_s``
(default :data:`DEFAULT_NOTIFY_WINDOW_S`).  A page is open from the moment the notifier reports it
sent (never before) until its request settles; it is for the actor's oldest request awaiting
approval and names every one of them (a request filed while a page is open is named on the next
page, and is on the Approvals page and in its ``decision.requested`` event at once).  What is
due is derived from state (:meth:`BrokerService.poll_pages`): every actor with a request
awaiting approval and no open page is paged as soon as its floor allows -- checked when the
service starts, by a timer on the monotonic clock, and on every submit, settle and pending
listing -- and a page whose send failed or whose budget was spent is retried after
:data:`PAGE_RETRY_S`.  So no waiting request is left without a page, whether it arrived after a
cancelled decoy, after a denial, after a failed send, before a restart, or after its approval
expired unused.  An approval or a denial closes the page with a settled
message saying how many still wait; a cancel by the owner closes it quietly, so a submit/cancel
loop pages at most once per floor.  Every message about an actor draws on that actor's own
notifier budget (``scope``), so one agent cannot spend the pages of every other.  The open page
is read from the notifier's own state (shared by every process using its store); the floor is
kept in this process (a restart may page once early), and a settled request's page is dropped
from the notifier's store.  A lane's directory has its own file and byte quota
(:mod:`homelabnext.broker.lanes`).
"""

from __future__ import annotations

import contextlib
import copy
import hashlib
import heapq
import hmac
import json
import logging
import os
import re
import tempfile
import threading
import time
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
    approver_kind,
    check_manifest_handlers,
    decide,
    decide_access,
    request_digest,
    validation,
)
from . import execute as _exec
from . import lanes as _lanes
from .relay import BROKER_SOURCE
from .state import (
    DECISION_KINDS,
    FileApprovalStore,
    StateDir,
    StateError,
    is_id,
    new_id,
    process_identity,
)

__all__ = [
    "DEFAULT_NOTIFY_WINDOW_S",
    "DEFAULT_PENDING_PER_ACTOR",
    "NOT_OWNER",
    "TRANSPORT_PEER",
    "BrokerService",
    "ManifestError",
    "load_manifest",
    "make",
    "validate_manifest",
]

NOT_OWNER = "not-request-owner"
TOO_MANY_PENDING = "too-many-pending"
#: an action was not run because its ``started`` record could not be written
AUDIT_UNAVAILABLE = "audit-unavailable"
#: an action ran and its outcome record could not be written (its ``started`` record stands)
AUDIT_INCOMPLETE = "audit-incomplete"
#: what writing an audit record can raise when the trail cannot take it
_AUDIT_FAILURES = (OSError, StateError, BrokerError)
log = logging.getLogger("homelabnext.broker.service")
#: manifest ``quotas`` defaults: requests one actor may have pending at once, and the least time
#: between two of its approval pages (s)
DEFAULT_PENDING_PER_ACTOR = 20
DEFAULT_NOTIFY_WINDOW_S = 300.0
#: request ids an approval page names before it says "and N more"
_PAGE_IDS = 10
#: how long after a page that could not be sent (a failed send, a spent budget) it is tried again
PAGE_RETRY_S = 60.0
#: the least time between two log lines about failed notifications (s)
NOTIFY_WARN_EVERY_S = 300.0
CALLABLE_HANDLER = "builtin/callable"
EMPTY_MANIFEST = {
    "manifest_id": "in-process",
    "default": "deny",
    "mode": "enforce",
    "actions": [],
    "grants": [],
}
APPROVAL_TITLE = "Broker approval needed"
#: decide()'s reason for a request's latest approval -> the approval_state pending() reports
_APPROVAL_STATES = {
    "approved": "valid",
    "approval-expired": "expired",
    "approval-replayed": "consumed",
    "approval-denied": "denied",
}
APPROVAL_CLEARED = "Broker approval settled"
#: the operator's notice that an agent's writes into a lane are being refused for its quota
LANE_QUOTA_TITLE = "Broker lane quota reached"
LANE_QUOTA_CLEARED = "Broker lane quota cleared"
#: the least time between two lane-quota notices for one actor and lane (s)
LANE_NOTICE_INTERVAL_S = 900.0
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


def _parse_errors() -> tuple[type[BaseException], ...]:
    """What reading a JSON or YAML document can raise on a bad file."""
    import yaml

    return (OSError, UnicodeDecodeError, ValueError, yaml.YAMLError)


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
        try:
            doc = _read_doc(p)
        except _parse_errors() as exc:
            problems.append(f"{rel}: cannot be read ({type(exc).__name__})")
            continue
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
    problems += _overlapping_lanes(list(lanes.values()))
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


def _overlapping_lanes(lanes: Sequence[_lanes.Lane]) -> list[str]:
    """Two lanes whose roots are the same directory, or one inside the other, are refused: each
    would keep its own quota, share and write rate over the same files (an actor writing through
    both would get two of each), and one lane's actor directories could collide with the
    other's (a profile slug ``inbox``)."""
    out = []
    for i, a in enumerate(lanes):
        for b in lanes[i + 1 :]:
            pa, pb = a.root.split("/"), b.root.split("/")
            n = min(len(pa), len(pb))
            if pa[:n] == pb[:n]:
                out.append(f"lanes: {a.name} ({a.root}) and {b.name} ({b.root}) overlap")
    return out


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
    try:
        manifest = _read_doc(p)
    except _parse_errors() as exc:
        raise ManifestError([f"{p}: cannot be read ({type(exc).__name__})"]) from None
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
    """See the module doc.  One instance per process.  Any number may share ``state_dir`` for
    the exactly-once guarantees (claims, approvals); the pending quota and the open-page state
    are per process, and the lane quotas' ``flock`` is per host: deploy one broker process, on
    one host, per data root and state directory (``docs/broker.md``)."""

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
        source: str = BROKER_SOURCE,
        approvals_url: str | None = None,
        page_timers: bool = True,
        monotonic: Callable[[], float] | None = None,
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
        quotas = self.manifest.get("quotas") or {}
        self.pending_per_actor = int(quotas.get("pending_per_actor", DEFAULT_PENDING_PER_ACTOR))
        self._submit_lock = threading.Lock()  # the pending count and the new request, as one
        self.notify_window_s = float(quotas.get("notify_window_s", DEFAULT_NOTIFY_WINDOW_S))
        self.page_timers = page_timers
        self._paged: dict[str, str] = {}  # actor -> the request its open page is for
        self._paging: set[str] = set()  # actors a page is being sent for right now
        # scheduling runs on a monotonic clock (an injected wall clock drives it in tests): a
        # wall-clock step can neither fire a page early nor strand one with no timer
        if monotonic is None:
            monotonic = time.monotonic if clock is _utcnow else (lambda: self.clock().timestamp())
        self._mono = monotonic
        self._last_page: dict[str, float] = {}  # actor -> when its last page went out
        self._retry_at: dict[str, float] = {}  # actor -> when a failed page may be tried again
        self._wakeups: list[float] = []  # a heap of times a page check is due
        self._timer: tuple[float, threading.Timer] | None = None
        self._paged_lock = threading.Lock()
        self._scoped = _takes_scope(notifier)
        self._lane_full: set[str] = set()  # lane-quota keys this process reported
        self._lane_notice_at: dict[str, datetime] = {}  # lane-quota key -> its last notice
        self._lane_logged: set[str] = set()  # lane-quota keys logged (no notifier)
        self._lane_red: dict[str, tuple[str, str]] = {}  # lane-quota key -> (lane, actor)
        self._notify_warned = float("-inf")  # when a failed send was last logged
        if notifier is not None:
            notifier.register_pair(APPROVAL_TITLE, APPROVAL_CLEARED)
            notifier.register_pair(LANE_QUOTA_TITLE, LANE_QUOTA_CLEARED)
            try:  # what is due is derived from state: a restart loses no page
                self.poll_pages()
            except Exception:
                log.exception("approval pages could not be polled at start")

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
        # what a caller supplied (its name, an action name, a request id) is cut to the schema's
        # bounds here, so no input can make the record of its own refusal unwritable
        who = (caller if isinstance(caller, str) else repr(caller))[:256] or "<none>"
        rec: dict[str, Any] = {
            "audit_id": new_id("aud"),
            "at": t.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "caller": who,
            "action": str(action)[:128],
            "operation": operation,
            "outcome": outcome,
            "reason": reason if outcome not in ("ok",) else "",
            "args": self._summarize(args or {}, spec),
            "manifest_id": self.manifest.get("manifest_id", "in-process"),
        }
        rec.update({k: v for k, v in extra.items() if v is not None})
        if isinstance(rec.get("request_id"), str):
            rec["request_id"] = rec["request_id"][:128]
        via = TRANSPORT_PEER.get()
        if via is not None:
            rec["via"] = via
        stamp = t.astimezone(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        problems = validation.named_errors("broker/audit", rec)
        if problems:
            # a bug in the broker, never the caller's input: still leave a record of the
            # outcome (a denial is never silently unrecorded), then fail loudly
            fallback = {
                k: rec[k]
                for k in ("audit_id", "at", "caller", "operation", "outcome", "via")
                if k in rec
            }
            fallback.update(
                action="",
                reason="" if outcome == "ok" else "audit-record-invalid",
                args={"audit_problem": problems[0][:200]},
            )
            if not validation.named_errors("broker/audit", fallback):
                self.state.append_audit(fallback, stamp)
            raise BrokerError(f"audit record invalid: {problems[0]}")
        self.state.append_audit(rec, stamp)

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
        self._audit(caller, action, operation, outcome, reason=reason, request_id=request_id)

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
            if r.get("outcome") != "started"  # an intent; its outcome is the operation's record
        ]

    def audit_documents(self, *, limit: int | None = None, **match: Any) -> list[dict[str, Any]]:
        """Raw audit records whose fields equal every ``match`` value (None = any), oldest first;
        with ``limit``, only the newest ``limit`` of them, read newest first (a tail reads the
        tail, not the whole trail).  A match on filed decisions (operation ``approve`` or
        ``deny``, outcome ``ok``: the hub's recent decisions and its "already decided" check)
        reads the ``decisions/`` index instead of the trail, so no volume of refusals an agent
        provokes makes it slow."""
        want = {k: v for k, v in match.items() if v is not None}

        def hit(r: Mapping[str, Any]) -> bool:
            return all(r.get(k) == v for k, v in want.items())

        indexed = (want.get("operation"), want.get("outcome")) in DECISION_KINDS
        source = self.state.decision_records if indexed else self.state.audit_records
        if limit is None:
            return [r for r in source() if hit(r)]
        out: list[dict[str, Any]] = []
        if limit > 0:
            for r in source(newest_first=True):
                if hit(r):
                    out.append(r)
                    if len(out) >= limit:
                        break
        return out[::-1]

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
                _lanes.check_params(act.handler, caller, args, now, key=self._name_key())
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
        params = dict(args) if isinstance(args, Mapping) else {}
        if spec is not None:  # secret arguments enter the request, and its digest, keyed
            params = {
                k: self._keyed(v) if spec.get(k, ArgSpec("str")).secret else v
                for k, v in params.items()
            }
        request: dict[str, Any] = {
            "request_id": rid,
            "action": str(action),
            "actor": caller if isinstance(caller, str) else repr(caller),
            "params": params,
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

    def _keyed(self, value: Any) -> str:
        """``hmac-sha256:<hex>`` of a secret argument, keyed with the broker-held key."""
        raw = json.dumps(value, sort_keys=True, ensure_ascii=False, default=repr).encode("utf-8")
        mac = hmac.new(self.state.digest_key(), raw, hashlib.sha256).hexdigest()
        return f"hmac-sha256:{mac}"

    def _name_key(self) -> bytes:
        """The key of a records-inbox name's tag, derived from the broker-held key."""
        return hmac.new(self.state.digest_key(), b"lane-name-tag", hashlib.sha256).digest()

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
                    act.handler,
                    self.data_root,
                    request["actor"],
                    args,
                    request["created"],
                    key=self._name_key(),
                    at=self._now().timestamp(),
                    ledger=self._ledger(),
                )
            except _lanes.LaneError as exc:
                if exc.reason == "lane-quota-exceeded":
                    self._lane_quota(act.handler, request, str(exc))
                raise _Refused(exc.outcome, exc.reason, str(exc)) from None
            except OSError:
                raise _Refused("error", "lane-io-error", f"{act.name}: the write failed") from None
            self._lane_quota(act.handler, request, None)
            if (
                act.handler.kind == "records-inbox"
                and args["note"].get("type", "proposal") == "proposal"
            ):
                try:  # the note is filed: its event is a courtesy that must not undo that
                    self._proposal_created(request, args["note"], written["path"])
                except Exception as exc:
                    log.error("%s: proposal.created not emitted (%s)", act.name, type(exc).__name__)
                    with contextlib.suppress(*_AUDIT_FAILURES):
                        self._audit(
                            BROKER_SOURCE, act.name, "notify", "error", reason="outbox-failed",
                            request_id=request["request_id"],
                        )  # fmt: skip
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
        try:
            rd = run_dir(request["request_id"], self.state.root, env={})
        except OSError:
            raise _Refused("error", "handler-io-error", f"{act.name}: no run directory") from None
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

    def _started(self, caller, act, request, args, operation) -> None:
        """Write the ``started`` record of an action about to execute, or refuse to execute it:
        an action never runs without a record of it (``audit-unavailable``)."""
        try:
            self._audit(
                caller,
                act.name,
                operation,
                "started",
                args=args,
                spec=act.spec,
                request_id=request["request_id"],
                request_digest=request["digest"],
            )
        except _AUDIT_FAILURES as exc:
            log.error("%s: not run, the audit trail cannot be written (%s)", act.name, exc)
            raise _reasoned(
                f"{act.name}: the audit trail cannot be written; nothing was run",
                AUDIT_UNAVAILABLE,
            ) from None

    def _outcome(self, caller, act, operation, outcome, **kw) -> None:
        """The outcome record of an action that executed; when it cannot be written, the action
        has still happened (its ``started`` record says so): ``audit-incomplete``."""
        try:
            self._audit(caller, act.name, operation, outcome, args=kw.pop("args"), **kw)
        except _AUDIT_FAILURES as exc:
            log.error("%s ran; its %s record cannot be written (%s)", act.name, outcome, exc)
            raise _reasoned(
                f"{act.name} ran but its outcome could not be audited", AUDIT_INCOMPLETE
            ) from None

    def _run_audited(self, caller, act, request, args, operation, *, started=False) -> Any:
        extra = {"request_id": request["request_id"], "request_digest": request["digest"]}
        if not started:
            self._started(caller, act, request, args, operation)
        try:
            try:
                result = self._execute(act, request, args)
            except OSError:  # an environment fault on the way (ENOSPC, EMFILE): still an outcome
                raise _Refused("error", "handler-io-error", f"{act.name}: an I/O error") from None
        except _Refused as exc:
            self._outcome(
                caller,
                act,
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
        self._outcome(
            caller, act, operation, "ok", args=args, spec=act.spec, result=summary, **extra
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
        secret = {}
        if act.kind == "callable":
            secret = {k: v for k, v in args.items() if act.spec.get(k, ArgSpec("str")).secret}
        record = {
            "request": request,
            "kind": act.kind,
            "verdict": decision["verdict"],
            "decision_reason": decision["reason"],
        }
        with self._submit_lock:
            if len(self._pending_of(request["actor"])) >= self.pending_per_actor:
                self._audit(
                    caller,
                    command,
                    "submit",
                    "denied",
                    reason=TOO_MANY_PENDING,
                    args=args,
                    spec=act.spec,
                    request_id=rid,
                    request_digest=request["digest"],
                )
                raise Denied(
                    f"{caller!r} has {self.pending_per_actor} requests pending: run, cancel or "
                    "wait for a decision on one first",
                    reason=TOO_MANY_PENDING,
                )
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

    def _pending_of(self, actor: str) -> list[dict[str, Any]]:
        """The stored records of ``actor``'s pending requests (the open index: O(open))."""
        out = []
        for rid in self.state.open_request_ids():
            rec = self.state.get_request(rid)
            if rec and rec["request"]["actor"] == actor:
                out.append(rec)
        return out

    def _awaiting(self, actor: str) -> list[dict[str, Any]]:
        """``actor``'s requests waiting for an approver (no valid approval yet), oldest first."""
        return [
            rec["request"]
            for rec in self._pending_of(actor)
            if rec["verdict"] == "needs-approval"
            and self.approval_state(rec["request"]["request_id"], rec["request"]) != "valid"
        ]

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
        """The owner's full view: request, state, approvals and result (``hnx broker status``).
        Each approval carries ``approver_kind``: ``human``, ``agent`` or None (no longer an
        allowlisted approver), judged now against the manifest -- the authoritative answer to
        "did a person approve this", where an event's ``tier_used`` is only advisory."""
        st = self.status(caller, request_id)
        rec = self.state.get_request(request_id)
        view = self._view()
        approvals = [
            {**a, "approver_kind": approver_kind(view, a.get("approver") or {})}
            for a in self.state.approvals(request_id)
        ]
        return {
            "request": rec["request"],
            "state": st.state,
            "verdict": rec["verdict"],
            "approvals": approvals,
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
        approval = self._latest_approval(request_id)
        now = _stamp(self._now())
        view = self._view()
        # decide without consuming: the approval is consumed only once this run holds the
        # request's claim, so a refusal on the way (arguments, a lost claim) never burns it
        enforce = view.get("mode", "enforce") == "enforce"
        decision = decide(
            dict(view, mode="shadow") if enforce else view,
            req,
            approval,
            now=now,
            store=self.approvals,
        )
        if not enforce:
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
        # the intent is on record before anything changes: when it cannot be written, the request
        # stays pending and its approval unused, to run once the trail can take it
        self._started(caller, act, req, args, "run")
        claimed = self.state.claim(
            request_id,
            {
                "op": "run",
                "by": caller,
                "at": now,
                "instance": self.state.instance_id(),
                **process_identity(),
            },
        )
        if not claimed:
            self._audit(caller, req["action"], "run", "invalid", reason="not-pending", **extra)
            raise _reasoned(f"request {request_id!r} is no longer pending", "not-pending")
        aid = decision.get("approval_id")
        if decision["reason"] == "approved" and not self.approvals.consume(aid):
            # only a run holding the claim consumes, so this means the approval was used
            # outside this request's run: refuse, and end the claimed request as an error
            self._secret_args.pop(request_id, None)
            self._finish(request_id, {"state": "error", "at": now, "reason": "approval-replayed"})
            self._audit(
                caller,
                req["action"],
                "run",
                "denied",
                reason="approval-replayed",
                approval_id=aid,
                **extra,
            )
            raise Denied(
                f"request {request_id!r}: approval already used", reason="approval-replayed"
            )
        try:
            result = self._run_audited(caller, act, req, args, "run", started=True)
        except Exception as exc:  # whatever ends the run, it ends: never "running" forever
            reason = getattr(exc, "reason", "") or "internal-error"
            self._finish(request_id, {"state": "error", "at": now, "reason": reason})
            raise
        finally:
            self._secret_args.pop(request_id, None)
        done = {"state": "done", "at": _stamp(self._now())}
        if act.kind != "callable" and isinstance(result, Mapping):
            done["result"] = json.loads(json.dumps(result, default=repr))
        self._finish(request_id, done)
        return result

    def _finish(self, request_id: str, doc: dict[str, Any]) -> None:
        """Record how a claimed run ended.  When the result cannot be written (a full disk), the
        request reads ``interrupted`` rather than ``running`` forever; the audit trail holds what
        happened."""
        try:
            self.state.put_result(request_id, doc)
        except (OSError, StateError) as exc:
            self.state.mark_unfinished(request_id)
            log.error("request %s: its result cannot be written (%s)", request_id, exc)

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
        if rec["verdict"] == "needs-approval":  # withdrawn by its owner: closed without a message
            self._notify_settled(request_id, "cancelled by its owner", req["actor"], quiet=True)

    # ---------------------------------------------------------------- approvals
    def _latest_approval(self, request_id: str) -> dict[str, Any] | None:
        approved = [a for a in self.state.approvals(request_id) if a["decision"] == "approved"]
        return approved[-1] if approved else None

    def approval_state(self, request_id: str, request: Mapping[str, Any]) -> str:
        """Where a request's latest approval stands, judged by :func:`decide` itself (shadow
        mode: nothing consumed): ``none`` (no approval filed), ``valid`` (it would let the
        request run now), ``expired`` (past its TTL: a fresh approval may be filed),
        ``consumed`` (already used), ``denied`` or ``invalid`` (it no longer matches the request
        or the manifest's approver rules)."""
        docs = self.state.approvals(request_id)
        if docs and docs[-1]["decision"] != "approved":
            return "denied"
        approval = self._latest_approval(request_id)
        if approval is None:
            return "none"
        probe = decide(
            dict(self._view(), mode="shadow"),
            request,
            approval,
            now=_stamp(self._now()),
            store=self.approvals,
        )
        return _APPROVAL_STATES.get(probe["reason"], "invalid")

    def _open_rows(self, keep: Callable[[Mapping[str, Any]], bool]) -> list[dict[str, Any]]:
        """One row per pending request whose stored record ``keep`` selects, oldest first.  Reads only the open-request index, so it costs O(open), not O(history)."""
        out = []
        for rid in self.state.open_request_ids():
            rec = self.state.get_request(rid)
            if not rec or not keep(rec):
                continue
            needs = rec["verdict"] == "needs-approval"
            state = self.approval_state(rid, rec["request"]) if needs else "not-required"
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
                    "approved": state == "valid",
                    "approval_state": state,
                    "awaiting_approval": needs and state != "valid",
                }
            )
        return out

    def pending(self) -> list[dict[str, Any]]:
        """Requests waiting for an approver: needs-approval and still pending.  ``approved`` is
        true while a valid, unconsumed approval is on file (it can run now); ``approval_state``
        says why not otherwise, and an ``expired`` one takes a fresh approval."""
        if self.notifier is not None:
            try:  # the hub lists this every few seconds: a deferred page is sent on time
                self.poll_pages()
            except Exception:
                log.exception("approval pages could not be polled")
        fields = (
            "request_id",
            "action",
            "actor",
            "target",
            "params",
            "created",
            "digest",
            "approved",
            "approval_state",
        )
        return [
            {k: r[k] for k in fields}
            for r in self._open_rows(lambda rec: rec["verdict"] == "needs-approval")
        ]

    def pending_for(self, caller: str) -> list[dict[str, Any]]:
        """``caller``'s own requests still ``pending`` (awaiting approval, or approved and not yet
        run, or allowed and not yet run): what an agent may still run or cancel."""
        fields = (
            "request_id",
            "action",
            "target",
            "created",
            "awaiting_approval",
            "approved",
            "approval_state",
        )
        return [
            {k: r[k] for k in fields}
            for r in self._open_rows(lambda rec: rec["request"]["actor"] == caller)
        ]

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
        # who decided: a person (``human``), or an approver of kind agent the manifest admits
        # (``allow_agent_approvers``): StackStorm's A03 acts on ``human`` only
        tier = "agent" if approver_kind(self._view(), doc["approver"]) == "agent" else "human"
        self._emit(
            "homelabnext.decision.returned",
            {
                "decision_id": request_id,
                "verdict": "accept" if decision == "approved" else "reject",
                "confidence": 1.0,
                "tier_used": tier,
            },
            request_id,
            key=f"returned:{doc['approval_id']}",
        )
        self._notify_settled(request_id, f"{decision} by {who}", req["actor"])
        if decision == "approved" and self.notifier is not None:
            # if it is not run before the approval expires, it waits again: page it then
            expires = datetime.fromisoformat(doc["expires_at"].replace("Z", "+00:00"))
            left = (expires - self._now()).total_seconds()
            self._wake_at(self._mono() + max(0.0, left) + 1.0)
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
            self.poll_pages()  # this actor's page among any other that is due

    @staticmethod
    def _page_key(rid: str) -> str:
        return f"broker-approval-{rid}"

    def _open_page(self, actor: str, waiting: Sequence[Mapping[str, Any]]) -> str | None:
        """The request of ``actor``'s that has an open page: one still awaiting approval whose
        page the notifier reports sent and not yet settled."""
        rids = [r["request_id"] for r in waiting]
        if self._paged.get(actor) in rids:
            return self._paged[actor]
        state_of = getattr(self.notifier, "state_of", None)
        if state_of is not None:
            return next((r for r in rids if state_of(self._page_key(r)) != "ok"), None)
        return None

    def _wake_at(self, when: float) -> None:
        """Make sure a page check runs at ``when`` (monotonic): it is kept in a heap, and one
        timer is armed for the earliest (best effort: :meth:`poll_pages` also runs at start and
        on every submit, settle and pending listing, and derives what is due from state)."""
        with self._paged_lock:
            heapq.heappush(self._wakeups, when)
        self._arm()

    def _arm(self) -> None:
        if not self.page_timers:
            return
        with self._paged_lock:
            now = self._mono()
            while self._wakeups and self._wakeups[0] <= now - 3600:
                heapq.heappop(self._wakeups)  # long past and never polled: nothing to arm
            future = [t for t in self._wakeups if t > now]
            if not future:
                return
            nxt = min(future)
            if self._timer is not None and self._timer[0] <= nxt and self._timer[1].is_alive():
                return
            if self._timer is not None:
                self._timer[1].cancel()
            timer = threading.Timer(nxt - now + 0.05, self._timer_fired)
            timer.daemon = True
            self._timer = (nxt, timer)
            timer.start()

    def _timer_fired(self) -> None:
        with self._paged_lock:
            self._timer = None
        try:
            self.poll_pages()
        except Exception:  # a timer thread: log it, the next poll tries again
            log.exception("approval pages could not be polled")

    def poll_pages(self) -> int:
        """Page every actor that has a request awaiting approval and no open page -- a page the
        floor deferred, a page whose send failed, a request whose approval expired unused, one
        filed before a restart -- each subject to the floor and the open-page gate, so this is
        idempotent.  Also retries a lane-quota "cleared" notice that was held back, and re-arms
        the timer for what is due next.  Returns how many actors were checked."""
        if self.notifier is None:
            return 0
        now = self._mono()
        with self._paged_lock:
            while self._wakeups and self._wakeups[0] <= now:
                heapq.heappop(self._wakeups)
        actors = []
        for rid in self.state.open_request_ids():
            rec = self.state.get_request(rid)
            if rec and rec["verdict"] == "needs-approval" and rec["request"]["actor"] not in actors:
                actors.append(rec["request"]["actor"])
        for actor in actors:
            try:
                self._page(actor)
            except Exception:  # one actor's failure never stops the rest
                log.exception("approval page for %s failed", actor)
        for lane_name, actor in list(self._lane_red.values()):
            lane = self._lanes.get(lane_name)
            if lane is not None:
                self._lane_quota(lane, {"actor": actor, "request_id": None}, None)
        self._arm()
        return len(actors)

    def _page(self, actor: str) -> None:
        """Page the approver about ``actor``'s oldest request awaiting approval, unless one of
        its requests already has an open page, or its last page is less than
        ``notify_window_s`` old, or its last attempt failed less than
        :data:`PAGE_RETRY_S` ago (then a check is scheduled for when that passes).  The actor
        counts as paged only once the notifier says the page went out."""
        waiting = self._awaiting(actor)
        if not waiting:
            return
        now = self._mono()
        later = None
        with self._paged_lock:
            if actor in self._paging or self._open_page(actor, waiting) is not None:
                return
            last = self._last_page.get(actor)
            retry = self._retry_at.get(actor)
            if retry is not None and retry > now:
                later = retry
            elif last is not None and now - last < self.notify_window_s:
                later = last + self.notify_window_s
            else:
                self._paging.add(actor)  # of racing requests, one pages
        if later is not None:
            self._wake_at(later)
            return
        request = waiting[0]
        rid = request["request_id"]
        key = self._page_key(rid)
        sent = False
        try:
            from homelabnext.notify.core import Message

            link = self.approval_link(rid)
            body = f"{actor} asks to run {request['action']} ({rid})"
            if len(waiting) > 1:
                ids = [r["request_id"] for r in waiting]
                named = ", ".join(ids[:_PAGE_IDS])
                if len(ids) > _PAGE_IDS:
                    named += f" and {len(ids) - _PAGE_IDS} more"
                body += f"; {len(ids)} requests await approval from {actor}: {named}"
            msg = Message(
                key=key,
                title=APPROVAL_TITLE,
                body=body + (f"\nReview: {link}" if link else ""),
                level="warn",
                click=link,
            )
            sent = self._notify(key, "awaiting-approval", msg, actor=actor)
        finally:
            with self._paged_lock:
                self._paging.discard(actor)
                if sent:
                    self._paged[actor] = rid
                    self._last_page[actor] = now
                    self._retry_at.pop(actor, None)
                else:  # a failed send, or the actor's budget spent: try again shortly
                    self._retry_at[actor] = now + PAGE_RETRY_S
        if not sent:
            self._wake_at(now + PAGE_RETRY_S)
            return
        if rid not in {r["request_id"] for r in self._awaiting(actor)}:
            # it settled while the page was in flight: its settling saw no page to close
            self._close_page(actor, rid, None)
            self._page(actor)

    def _close_page(self, actor: str, rid: str, body: str | None) -> bool:
        """Close ``rid``'s page if it has one: with a settled message, or quietly (``body``
        None: the owner withdrew it, which nobody needs paged about).  True when it had one."""
        key = self._page_key(rid)
        state_of = getattr(self.notifier, "state_of", None)
        with self._paged_lock:
            paged = self._paged.get(actor) == rid
            if paged:
                del self._paged[actor]
        if state_of is not None:
            paged = paged or state_of(key) != "ok"
        if not paged:
            return False
        if body is None:
            clear = getattr(self.notifier, "clear", None)
            if clear is not None:
                try:
                    clear(key)
                except Exception:
                    log.exception("approval page %s could not be cleared", key)
        else:
            from homelabnext.notify.core import Message

            msg = Message(key=key, title=APPROVAL_CLEARED, body=body)
            self._notify(key, "ok", msg, actor=actor)
        forget = getattr(self.notifier, "forget", None)
        if forget is not None:  # a settled request's page is done with: the store stays small
            with contextlib.suppress(Exception):
                forget(key)
        return True

    def _notify_settled(
        self, rid: str, how: str, actor: str | None = None, *, quiet: bool = False
    ) -> None:
        if self.notifier is None or actor is None:
            return
        waiting = self._awaiting(actor)
        body = f"{rid} {how}"
        if waiting:
            body += f"; {len(waiting)} more from {actor} await approval"
        self._close_page(actor, rid, None if quiet else body)
        self.poll_pages()  # the page moves to the oldest still waiting, after the floor

    def _lane_quota(self, lane: _lanes.Lane, request: Mapping[str, Any], refusal: str | None):
        """Tell the operator that ``lane`` refuses an actor's writes for its quota (the agent
        alone hears ``lane-quota-exceeded``, and a finding that is never written looks like a run
        that never happened), and that it has room again -- but only once the directory is back
        under :data:`homelabnext.broker.lanes.USAGE_WARN` of its quotas, not on the next small
        write that fits, and never two notices for one actor and lane within
        :data:`LANE_NOTICE_INTERVAL_S`.  State-diffed by the notifier, so a looping agent's
        thousandth refusal sends nothing, and its notices draw on its own budget."""
        actor = request["actor"]
        key = f"broker-lane-quota-{lane.name}-{re.sub(r'[^a-z0-9-]+', '-', actor.lower())}"
        if self.notifier is None:
            if refusal is not None and key not in self._lane_logged:
                self._lane_logged.add(key)  # no notifier: the log is the operator's signal
                log.warning("%s: lane %s refuses its writes: %s", actor, lane.name, refusal)
            return
        from homelabnext.notify.core import Message

        now = self._now()
        last = self._lane_notice_at.get(key)
        recent = last is not None and (now - last).total_seconds() < LANE_NOTICE_INTERVAL_S
        if refusal is None:
            state_of = getattr(self.notifier, "state_of", None)
            if key not in self._lane_full and (state_of is None or state_of(key) == "ok"):
                return  # nothing was reported: nothing to clear (the common case, one read)
            if recent:
                return
            try:
                used = _lanes.fill(
                    lane, self.data_root, actor, key=self._name_key(), ledger=self._ledger()
                )
            except (OSError, _lanes.LaneError):
                return
            if used >= _lanes.USAGE_WARN:
                return  # still nearly full: the next small write would only be refused again
            body = f"{actor} writes to lane {lane.name} again; it is {used:.0%} full of its quota"
            msg = Message(key=key, title=LANE_QUOTA_CLEARED, body=body)
            if self._notify(key, "ok", msg, request_id=request["request_id"], actor=actor):
                self._lane_full.discard(key)
                self._lane_red.pop(key, None)
                self._lane_notice_at[key] = now
            return
        if recent:
            return
        body = (
            f"{actor}'s writes to lane {lane.name} are refused lane-quota-exceeded: {refusal}. "
            "Raise the lane's quota in the manifest or clear the directory "
            "(hnx broker validate --data-root shows its usage)."
        )
        msg = Message(key=key, title=LANE_QUOTA_TITLE, body=body, level="warn")
        sent = self._notify(
            key, "lane-quota-exceeded", msg, request_id=request["request_id"], actor=actor
        )
        if sent:
            self._lane_full.add(key)
            self._lane_red[key] = (lane.name, actor)  # a held "cleared" is retried on each poll
            self._lane_notice_at[key] = now

    def _ledger(self) -> Path:
        return self.state.root / "lanes-ledger"

    def lane_usage(self) -> list[dict[str, Any]]:
        """Every lane directory's usage against its quotas, each actor's share of a shared lane
        included (:func:`homelabnext.broker.lanes.usage`, with the broker's own key and ledger)."""
        actors = tuple(sorted({g["profile"] for g in self._view()["grants"]}))
        return [
            row
            for lane in self._lanes.values()
            for row in _lanes.usage(
                lane, self.data_root, actors=actors, key=self._name_key(), ledger=self._ledger()
            )
        ]

    def _notify(
        self, key, state, msg, *, request_id: str | None = None, actor: str | None = None
    ) -> bool:
        """Whether the notifier sent ``msg``.  A notification is a courtesy: the event and the
        pending list already carry the request, so a failed send never fails the broker
        operation that triggered it.  A message about ``actor`` draws on that actor's own
        notifier budget (``scope``), so one agent cannot spend the pages of every other."""
        try:
            if actor is not None and self._scoped:
                scope = "actor-" + re.sub(r"[^a-z0-9-]+", "-", actor.lower())
                return bool(self.notifier.report(key, state, msg, scope=scope))
            return bool(self.notifier.report(key, state, msg))
        except Exception as exc:
            now = self._mono()
            if now - self._notify_warned >= NOTIFY_WARN_EVERY_S:  # logged, never a log flood
                self._notify_warned = now
                log.warning("a notification could not be sent: %s", type(exc).__name__)
            rid = request_id or (
                key.removeprefix("broker-approval-") if key.startswith("broker-approval-") else None
            )
            with contextlib.suppress(*_AUDIT_FAILURES):
                self._audit(
                    BROKER_SOURCE, "", "notify", "error", reason="notify-failed", request_id=rid
                )
            return False


def _takes_scope(notifier: Any) -> bool:
    """Whether ``notifier.report`` takes a ``scope`` (a per-actor budget)."""
    import inspect

    try:
        return "scope" in inspect.signature(notifier.report).parameters
    except (AttributeError, TypeError, ValueError):
        return False


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
