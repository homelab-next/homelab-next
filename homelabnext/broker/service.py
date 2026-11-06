# SPDX-License-Identifier: Apache-2.0
"""The reference broker service: named actions for agents, decided by the manifest, run by pinned
handlers, every outcome audited to disk.

It implements the ``broker`` capability contract (``conformance.protocols.broker``) on top of
:func:`homelabnext.broker.decide` and a manifest (``schemas/broker/manifest`` 1.9).  An action is
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
claim, result, approval, consumed approval and audit record, each created exclusively, so claims
and approvals are exactly-once across any number of processes without a lock.  Deploy one broker
process, on one host, per state directory all the same (:class:`BrokerService`): the pending quota
and page state are per process, and the lane, token and outbox ``flock`` locks are per host.
Every outcome - ok, denied, invalid, error, shadow - leaves one audit record that validates
against ``schemas/broker/audit``.  An action that executes (a ``call``, or an approved ``run``)
first writes a ``started`` record (audit 1.2), and the broker refuses to execute it
(``audit-unavailable``) when that record cannot be written: the trail never lacks an action that
ran.  If the outcome record cannot be written afterwards (``audit-incomplete``), the ``started``
record is the evidence; a run then ends ``error`` (or reads ``interrupted`` when not even its
result can be written, :mod:`homelabnext.broker.state`).  The contract view (:meth:`audit`)
lists outcomes only, one per operation.  Arguments an ``ArgSpec`` marks ``secret`` are redacted in the
audit trail and never written to disk (so is the value of an argument the ``ArgSpec`` does not name,
or of any argument of an unknown command: redaction is the default); in the request (and so in its digest, which is persisted,
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

**Code Mode capability tokens** (ADR-0031 decisions 2, 6 and 7; CM-5a; the contract's feature
``codemode-tokens``; ``docs/broker.md``).  ``codemode.execute`` is an action like any other (a
manifest exec action whose handler is the runner's client, or in process
:meth:`BrokerService.register_runner`); its params must be a
``schemas/codemode/execution_request``.  While its handler runs, the request is *in flight*,
bound to the runner it belongs to, and that runner (manifest 1.7 ``codemode.runners``) may
:meth:`~BrokerService.issue_token` for it, once: the claims' request id, actor, execution id and
code digest come from the request, never from the runner, and every listed action must be one
:func:`decide` admits for that actor (the token narrows, never widens), never ``codemode.*``,
within the call cap - per execution, so a resume carries what is left of it - and living at most
the run's wall budget plus ``codemode.ttl_margin_s``.  Execution ids are scoped per actor.  The
sandbox presents the secret (:meth:`~BrokerService.token_call`, :meth:`~BrokerService.token_submit`,
:meth:`~BrokerService.token_run`); the broker keeps only its digest
(:mod:`homelabnext.broker.tokens`), and checks, in order: known (``token-invalid``), the sandbox
(``token-sandbox-mismatch``, both ways), expiry, spent, paused, the action, and the count, which
every call past those checks takes before :func:`decide` runs, under one lock with the check.  The
call then runs as the token's actor on the ordinary path, and its answer, or a refusal raised once
its request exists, names that request (``request_id``, ``request_digest``).  A call that needs
approval, and every submit, stores its request and pauses the token in that same locked step
(audit ``token-pause``).  :meth:`spend_token` ends a token with an outcome (``finished`` or
``paused``; audit ``token-spend``), as does the end of its ``codemode.execute``; only a paused
execution resumes, and :meth:`token_run` then runs the request it paused on.  A sweep at start
ends a run whose broker is gone as ``crashed`` and drops ended executions past
``codemode.retention_days``.

**Where each part lives.**  :class:`BrokerService` is one facade built from one module per
privilege boundary, so each can be reviewed on its own: this module keeps setup, the decision
view, the audit trail, argument checks, admission and execution, and manifest loading;
:mod:`~homelabnext.broker.requests` the request lifecycle (``call``, ``submit``, ``run``,
``cancel``, what a caller may see); :mod:`~homelabnext.broker.approvals` the approver's verdicts
and the pending listings; :mod:`~homelabnext.broker.paging` approval pages, lane-quota notices and
the notifier; :mod:`~homelabnext.broker.codemode_tokens` Code Mode tokens.  What they share
(refusal reasons, defaults, :data:`TRANSPORT_PEER`) is :mod:`~homelabnext.broker.common`, and every
name of it is importable from here.
"""

from __future__ import annotations

import contextlib
import copy
import hashlib
import hmac
import json
import os
import tempfile
import threading
import time
from collections import deque
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from conformance.protocols.broker import (
    CODEMODE_EXECUTE,
    ArgSpec,
    AuditRecord,
    BrokerError,
    Denied,
    arg_problems,
)
from homelabnext.agent.schemas import schema_errors
from homelabnext.generators.safe import CONTROL_RE

from . import (
    check_manifest_handlers,
    decide,
    normalize_identity,
    request_digest,
    validation,
)
from . import execute as _exec
from . import lanes as _lanes
from .approvals import _ApprovalsMixin, check_approvals_url
from .codemode_tokens import _CodemodeTokensMixin
from .common import (
    _APPROVAL_STATES as _APPROVAL_STATES,
)
from .common import (
    _AUDIT_FAILURES as _AUDIT_FAILURES,
)
from .common import (
    _PAGE_IDS as _PAGE_IDS,
)
from .common import (
    _SUMMARY_BYTES as _SUMMARY_BYTES,
)
from .common import (
    _SVC_RE as _SVC_RE,
)
from .common import (
    _TOKEN as _TOKEN,
)
from .common import (
    APPROVAL_CLEARED as APPROVAL_CLEARED,
)
from .common import (
    APPROVAL_TITLE as APPROVAL_TITLE,
)
from .common import (
    AUDIT_INCOMPLETE as AUDIT_INCOMPLETE,
)
from .common import (
    AUDIT_UNAVAILABLE as AUDIT_UNAVAILABLE,
)
from .common import (
    CALL_RATE_EXCEEDED as CALL_RATE_EXCEEDED,
)
from .common import (
    CALL_RATE_WINDOW_S as CALL_RATE_WINDOW_S,
)
from .common import (
    CALLABLE_HANDLER as CALLABLE_HANDLER,
)
from .common import (
    COALESCE_WINDOW_S as COALESCE_WINDOW_S,
)
from .common import (
    DEFAULT_AUDIT_RETENTION_DAYS as DEFAULT_AUDIT_RETENTION_DAYS,
)
from .common import (
    DEFAULT_CALLS_PER_MINUTE as DEFAULT_CALLS_PER_MINUTE,
)
from .common import (
    DEFAULT_CODEMODE_MAX_CALLS as DEFAULT_CODEMODE_MAX_CALLS,
)
from .common import (
    DEFAULT_CODEMODE_WALL_S as DEFAULT_CODEMODE_WALL_S,
)
from .common import (
    DEFAULT_LIVE_TOKENS_PER_ACTOR as DEFAULT_LIVE_TOKENS_PER_ACTOR,
)
from .common import (
    DEFAULT_NOTIFY_WINDOW_S as DEFAULT_NOTIFY_WINDOW_S,
)
from .common import (
    DEFAULT_PENDING_PER_ACTOR as DEFAULT_PENDING_PER_ACTOR,
)
from .common import (
    DEFAULT_RUNS_RETENTION_DAYS as DEFAULT_RUNS_RETENTION_DAYS,
)
from .common import (
    DEFAULT_TOKEN_RETENTION_DAYS as DEFAULT_TOKEN_RETENTION_DAYS,
)
from .common import (
    DEFAULT_TOKEN_TTL_MARGIN_S as DEFAULT_TOKEN_TTL_MARGIN_S,
)
from .common import (
    EMPTY_MANIFEST as EMPTY_MANIFEST,
)
from .common import (
    LANE_NOTICE_INTERVAL_S as LANE_NOTICE_INTERVAL_S,
)
from .common import (
    LANE_QUOTA_CLEARED as LANE_QUOTA_CLEARED,
)
from .common import (
    LANE_QUOTA_TITLE as LANE_QUOTA_TITLE,
)
from .common import (
    NOT_A_RUNNER as NOT_A_RUNNER,
)
from .common import (
    NOT_OWNER as NOT_OWNER,
)
from .common import (
    NOTIFY_WARN_EVERY_S as NOTIFY_WARN_EVERY_S,
)
from .common import (
    PAGE_RETRY_S as PAGE_RETRY_S,
)
from .common import (
    REQUEST_DENIED as REQUEST_DENIED,
)
from .common import (
    RETENTION_PRUNE_INTERVAL_S as RETENTION_PRUNE_INTERVAL_S,
)
from .common import (
    RUNNER_HANDLER as RUNNER_HANDLER,
)
from .common import (
    SPEND_OUTCOMES as SPEND_OUTCOMES,
)
from .common import (
    TOKEN_SWEEP_INTERVAL_S as TOKEN_SWEEP_INTERVAL_S,
)
from .common import (
    TOO_MANY_PENDING as TOO_MANY_PENDING,
)
from .common import (
    TRANSPORT_PEER as TRANSPORT_PEER,
)
from .common import (
    UNKNOWN_TOKEN_CALLER as UNKNOWN_TOKEN_CALLER,
)
from .common import (
    ManifestError as ManifestError,
)
from .common import (
    _Action as _Action,
)
from .common import (
    _carry as _carry,
)
from .common import (
    _contract_error as _contract_error,
)
from .common import (
    _hidden as _hidden,
)
from .common import (
    _reasoned as _reasoned,
)
from .common import (
    _reasoned_invalid as _reasoned_invalid,
)
from .common import (
    _Refused as _Refused,
)
from .common import (
    _stamp as _stamp,
)
from .common import (
    _utcnow as _utcnow,
)
from .common import (
    log as log,
)
from .paging import _PagingMixin, _takes_scope
from .relay import BROKER_SOURCE
from .requests import _RequestsMixin
from .state import (
    AUDIT_STAMP,
    DECISION_KINDS,
    FileApprovalStore,
    StateDir,
    StateError,
    new_id,
)
from .tokens import TokenStore

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


#: the operator's memory tools (ADR-0037 decision 12): never broker actions, never answered to a
#: profile.  The whole ``memory.*`` namespace is refused (:func:`memory_admin_action`) except the
#: free-form notes lane's ``memory.write``, which is not one of them.
MEMORY_ADMIN_ACTIONS = frozenset(
    {"memory.retract", "memory.lift", "memory.purge", "memory.dependents", "memory.restamp"}
)
_MEMORY_LANE_ACTIONS = frozenset({"memory.write"})


def memory_admin_action(name: Any) -> bool:
    """True when ``name`` is in the operator's ``memory.*`` namespace (every ``memory.`` name but
    the notes lane's ``memory.write``)."""
    return isinstance(name, str) and name.startswith("memory.") and name not in _MEMORY_LANE_ACTIONS


def _imports_memory_admin(path: Path) -> bool:
    """True when a handler file names the operator's memory admin (a handler runs as the
    broker's user, which may never reach it).  Defence in depth only: the boundary is the uid
    (the broker's user is refused as an operator), not this text match."""
    try:
        return b"memory_admin" in path.read_bytes()
    except OSError:
        return False


def validate_manifest(
    manifest: Mapping[str, Any], base_dir: str | os.PathLike[str]
) -> tuple[list[dict[str, Any]], list[str]]:
    """(handler documents, problems) for ``manifest`` whose relative paths start at ``base_dir``.

    Checks: the manifest schema; each handler document's schema, path containment and that its
    handler file exists and matches ``handler_digest``; manifest/handler consistency
    (:func:`homelabnext.broker.check_manifest_handlers`, lane actions excluded); every lane action
    names a declared lane with ``handler: builtin/lane`` at tier ``write``; lane configuration;
    no action is in the operator's ``memory.*`` namespace (:func:`memory_admin_action`) and no
    handler names ``homelabnext.memory_admin``.
    """
    base = Path(base_dir)
    problems = [f"manifest: {e}" for e in schema_errors("broker", "manifest", manifest)]
    if problems:
        return [], problems
    problems += _control_problems("manifest", _manifest_names(manifest))
    problems += [
        f"actions: {a['action']} is an operator memory tool, never a broker action (ADR-0037 "
        "decision 12: MemoryAdmin is run by an operator through hnx agent memory)"
        for a in manifest.get("actions", [])
        if memory_admin_action(a.get("action"))
    ]
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
        errs += _control_problems(
            "handler", [("action", doc.get("action")), ("handler", doc.get("handler"))]
        )
        if memory_admin_action(doc.get("action")):
            errs.append(f"action {doc['action']} is an operator memory tool, never a broker action")
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
        if "result_schema" in doc:
            problems += [
                f"{rel}: result_schema {e}"
                for e in validation.schema_problems(doc["result_schema"])
            ]
        target = _inside(base, doc["handler"])
        if target is None or not target.is_file():
            problems.append(f"{rel}: handler {doc['handler']} is missing or outside {base}")
        elif _imports_memory_admin(target):
            problems.append(
                f"{rel}: handler {doc['handler']} names homelabnext.memory_admin; a broker handler "
                "never reaches the operator's memory tools (ADR-0037 decision 12)"
            )
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
    problems += _codemode_runner_problems(manifest)
    return docs, problems


def _codemode_runner_problems(manifest: Mapping[str, Any]) -> list[str]:
    """``codemode.execute``'s runner is named exactly: the action's ``runner`` is a listed
    runner, and with more than one listed the action names one (a run never belongs to whichever
    runner asks first)."""
    runners = [r["service"] for r in (manifest.get("codemode") or {}).get("runners", [])]
    out = []
    for a in manifest["actions"]:
        if a.get("runner") and a["action"] != CODEMODE_EXECUTE:
            out.append(f"{a['action']}: only {CODEMODE_EXECUTE} names a runner")
        elif a["action"] == CODEMODE_EXECUTE:
            if a.get("runner") and a["runner"] not in runners:
                out.append(f"{a['action']}: runner {a['runner']} is not in codemode.runners")
            elif not a.get("runner") and len(runners) > 1:
                out.append(f"{a['action']}: codemode.runners lists several; name its runner")
    return out


def _manifest_names(manifest: Mapping[str, Any]) -> list[tuple[str, Any]]:
    """(where, value) of every name the manifest matches on: ids, actions, profiles, peers."""
    out: list[tuple[str, Any]] = [("manifest_id", manifest.get("manifest_id"))]
    fields = {
        "actions": ("action", "handler", "lane"),
        "grants": ("profile",),
        "lanes": ("name", "root"),
        "approvers": ("issuer", "subject"),
        "callers": ("user", "profile"),
        "approval_relays": ("user", "issuer"),
        "operators": ("user",),
    }
    for key, names in fields.items():
        for i, entry in enumerate(manifest.get(key, [])):
            out += [(f"{key}[{i}].{n}", entry.get(n)) for n in names]
    for i, grant in enumerate(manifest.get("grants", [])):
        out += [(f"grants[{i}].actions", a) for a in grant["actions"]]
    cm = manifest.get("codemode") or {}
    for key, names in (("runners", ("user", "service")), ("sandboxes", ("user", "sandbox_id"))):
        for i, entry in enumerate(cm.get(key, [])):
            out += [(f"codemode.{key}[{i}].{n}", entry.get(n)) for n in names]
    return out


def _control_problems(what: str, names: Sequence[tuple[str, Any]]) -> list[str]:
    """A name holding a control character: a schema pattern without the ``(?!\\n)`` guard (an
    action name; the ``ids/`` ids and slugs carry it) matches before a trailing newline, so
    ``service.status\\n`` passes the schema; it is refused here (the value is not repeated)."""
    return [
        f"{what}: {where} holds a control character"
        for where, value in names
        if isinstance(value, str) and CONTROL_RE.search(value)
    ]


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
    """Each transport peer (uid or user) is listed once, as a caller, a relay, an operator, a Code
    Mode runner *or* a sandbox: one peer, one identity, so an agent's process can never also be the
    relay that approves for a human, the operator that lists the agents, nor the runner that issues
    its own tokens or a sandbox holding them."""
    seen: dict[str, str] = {}
    out = []
    cm = manifest.get("codemode") or {}
    for where, entries in (
        ("callers", manifest.get("callers", [])),
        ("approval_relays", manifest.get("approval_relays", [])),
        ("operators", manifest.get("operators", [])),
        ("codemode.runners", cm.get("runners", [])),
        ("codemode.sandboxes", cm.get("sandboxes", [])),
    ):
        for entry in entries:
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
class BrokerService(_RequestsMixin, _ApprovalsMixin, _PagingMixin, _CodemodeTokensMixin):
    """See the module doc.  One instance per process.  Any number may share ``state_dir`` for
    the exactly-once guarantees (claims, approvals); the pending quota and the open-page state
    are per process, and the lane quotas' ``flock`` is per host: deploy one broker process, on
    one host, per data root and state directory (``docs/broker.md``)."""

    features = frozenset({"codemode-tokens"})

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
        self.tokens = TokenStore(self.state.root)
        cm = self.manifest.get("codemode") or {}
        self.codemode_max_calls = int(cm.get("max_calls", DEFAULT_CODEMODE_MAX_CALLS))
        self.token_ttl_margin_s = int(cm.get("ttl_margin_s", DEFAULT_TOKEN_TTL_MARGIN_S))
        self.codemode_wall_s = int(cm.get("default_wall_s", DEFAULT_CODEMODE_WALL_S))
        self.live_tokens_per_actor = int(
            cm.get("max_live_tokens_per_actor", DEFAULT_LIVE_TOKENS_PER_ACTOR)
        )
        self.token_retention_days = float(cm.get("retention_days", DEFAULT_TOKEN_RETENTION_DAYS))
        #: sandbox ids a manifest sandbox entry is dedicated to: only that peer may present them
        self._dedicated_sandboxes = {
            e["sandbox_id"] for e in cm.get("sandboxes", []) if e.get("sandbox_id")
        }
        #: runner identity -> its in-process codemode.execute handler (None: a manifest runner)
        self._runners: dict[str, Callable[[Mapping[str, Any]], Any] | None] = {
            r["service"]: None for r in cm.get("runners", [])
        }
        self._tokens_swept = datetime.min.replace(tzinfo=UTC)
        #: (kind, transport peer) -> [window start (monotonic), refusals held back in it]
        self._coalescing: dict[tuple[str, str], list[float]] = {}
        self._coalesce_lock = threading.Lock()
        quotas = self.manifest.get("quotas") or {}
        self.pending_per_actor = int(quotas.get("pending_per_actor", DEFAULT_PENDING_PER_ACTOR))
        self._submit_lock = threading.Lock()  # the pending count and the new request, as one
        self.notify_window_s = float(quotas.get("notify_window_s", DEFAULT_NOTIFY_WINDOW_S))
        self.calls_per_minute = int(quotas.get("calls_per_minute", DEFAULT_CALLS_PER_MINUTE))
        self._calls: dict[str, deque[float]] = {}  # actor -> when its admitted operations were
        self._calls_lock = threading.Lock()
        retention = self.manifest.get("retention") or {}
        self.runs_retention_days = float(retention.get("runs_days", DEFAULT_RUNS_RETENTION_DAYS))
        audit_days = retention.get("audit_days", DEFAULT_AUDIT_RETENTION_DAYS)
        self.audit_retention_days = None if audit_days is None else float(audit_days)
        self._retention_pruned = float("-inf")
        self._prune_lock = threading.Lock()  # one prune at a time, its pacing checked under it
        self._prune_thread: threading.Thread | None = None  # the background prune, once started
        self.page_timers = page_timers
        self._paged: dict[str, str] = {}  # actor -> the request its open page is for
        self._paging: set[str] = set()  # actors a page is being sent for right now
        # scheduling runs on a monotonic clock (an injected wall clock drives it in tests): a
        # wall-clock step can neither fire a page early nor strand one with no timer
        self._mono = (
            monotonic
            if monotonic is not None
            else (time.monotonic if clock is _utcnow else self._clock_seconds)
        )
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
        self.prune_retention(force=True)
        try:  # a crash's leftovers are settled before anything is issued
            self.sweep_tokens(force=True)
        except OSError:
            log.exception("codemode tokens could not be swept at start")
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
        if command == CODEMODE_EXECUTE:
            raise ValueError(f"{command} is the runner's: register it with register_runner")
        self._callables[command] = (handler, dict(args))

    def register_runner(self, runner, handler):
        """In process: ``handler`` runs ``codemode.execute`` (it gets ``{request_id, actor,
        params}``) and ``runner`` may issue and spend its tokens.  The latest runner registered
        runs it; an earlier one stays a runner, holding the runs and tokens it already has.  A
        manifest that declares ``codemode.execute`` itself (an exec handler) lists its runners in
        ``codemode.runners`` and, with several, names the action's in its ``runner``."""
        if any(a["action"] == CODEMODE_EXECUTE for a in self.manifest["actions"]):
            raise ValueError(f"{CODEMODE_EXECUTE} is a manifest action; its runner is its handler")
        if not (isinstance(runner, str) and runner) or not callable(handler):
            raise ValueError("a runner is a non-empty identity and a callable")
        self._runners[runner] = handler

    def allow(self, caller, commands):
        self._allow.setdefault(caller, set()).update(commands)

    # ---------------------------------------------------------------- decisions
    def _view(self) -> dict[str, Any]:
        """The manifest plus the in-process commands and their grants, as decide() sees them.

        An exec action needs approval when its manifest entry *or* its handler document says so
        (:func:`~homelabnext.broker.check_manifest_handlers` refuses the two disagreeing; this
        keeps a service built from unvalidated documents fail closed too)."""
        view = dict(self.manifest)
        view["actions"] = [
            *(
                dict(a, requires_approval=True)
                if not a["requires_approval"]
                and (self._docs.get(a["action"]) or {}).get("requires_approval") is True
                else a
                for a in self.manifest["actions"]
            ),
            *(
                {
                    "action": c,
                    "tier": "write",
                    "handler": CALLABLE_HANDLER,
                    "requires_approval": False,
                }
                for c in [*self._callables, *([CODEMODE_EXECUTE] if self._runner() else [])]
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

    def _runner(self) -> Callable[[Mapping[str, Any]], Any] | None:
        """The in-process handler of ``codemode.execute``, if one is registered."""
        handlers = [h for h in self._runners.values() if h is not None]
        return handlers[-1] if handlers else None  # the latest registered

    def _action(self, name: str) -> _Action | None:
        if name == CODEMODE_EXECUTE and self._runner() is not None:
            return _Action(name, "runner", self._runner())
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

    def _clock_seconds(self) -> float:
        """Scheduling time from an injected clock (tests drive both with one clock)."""
        return self.clock().timestamp()

    # ---------------------------------------------------------------- audit
    def _summarize(self, args: Mapping[str, Any], spec: Mapping[str, ArgSpec] | None):
        """The audit view of ``args``.  Under an argument schema (an in-process command, or ``{}``
        for a command nobody registered) redaction is the default: only an argument the schema
        names and does not mark secret is shown, so a misspelt secret argument, or any argument of
        an unknown command, is recorded by name only.  ``None`` (a manifest action, whose params
        its own schema validates) shows every argument."""
        out: dict[str, Any] = {}
        for k, v in args.items():
            if spec is not None and _hidden(spec, k):
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
        tok = _TOKEN.get()
        if tok is not None and "token_id" not in rec:  # a call made with a token names it
            rec["token_id"], rec["execution_id"] = tok["token_id"], tok["execution_id"]
        if isinstance(rec.get("request_id"), str):
            rec["request_id"] = rec["request_id"][:128]
        via = TRANSPORT_PEER.get()
        if via is not None:
            rec["via"] = via
        stamp = t.astimezone(UTC).strftime(AUDIT_STAMP)
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
        coalesce: bool = False,
    ) -> None:
        """Audit a refusal made before the service saw the request (the socket transport's:
        an unknown peer, an actor named in the body, a malformed or oversized request).  With
        ``coalesce`` (a sandbox's: no bearer, a malformed body, a token in the body, an unknown
        operation) the records are coalesced per peer like unknown secrets (:meth:`_coalesce`,
        kind ``sandbox-refused``)."""
        args = None
        if coalesce:
            held = self._coalesce("sandbox-refused")
            if held is None:
                return
            args = {"coalesced": held} if held else None
        self._audit(
            caller, action, operation, outcome, reason=reason, request_id=request_id, args=args
        )

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
                token_id=r.get("token_id"),
                execution_id=r.get("execution_id"),
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
        if act.name == CODEMODE_EXECUTE:  # whoever runs it, its params are an execution request
            problems = validation.named_errors("codemode/execution_request", dict(args))
            if problems:
                raise _Refused("invalid", "invalid-params", f"params: {problems[0]}")
            if act.kind == "runner":
                return
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
        self._prune_soon()
        now = self._now()
        rid = new_id("req")
        act = self._action(action) if isinstance(action, str) else None
        spec = act.spec if act else {}  # an unknown command: every argument value is redacted
        params = dict(args) if isinstance(args, Mapping) else {}
        if spec is not None:  # hidden arguments enter the request, and its digest, keyed: the
            # same redact-by-default rule as the audit view, so a misspelt secret argument (or any
            # argument of an unknown command) is not an unkeyed hash a wordlist can reverse
            params = {k: self._keyed(v) if _hidden(spec, k) else v for k, v in params.items()}
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
            err = Denied(f"{caller!r} may not run {action!r}", reason=decision["reason"])
            raise _carry(err, request)
        try:
            # fullmatch: ``$`` would let a trailing newline through ("svc:dns\n")
            if target is not None and not (isinstance(target, str) and _SVC_RE.fullmatch(target)):
                raise _Refused("invalid", "invalid-target", "target must be a svc: id")
            self._check_args(act, caller, args, _stamp(now))
            doc = getattr(act, "handler", None) if act is not None else None
            if target is None and isinstance(doc, Mapping) and doc.get("target") == "required":
                # handler 1.3: the handler reads its target; without one it reports on nothing
                raise _Refused("invalid", "target-required", f"{action}: names no target")
            if not self._take_call(request["actor"]):
                raise _Refused(
                    "denied",
                    CALL_RATE_EXCEEDED,
                    f"{request['actor']} made {self.calls_per_minute} calls in the last "
                    f"{CALL_RATE_WINDOW_S:g} s: try again later",
                )
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
            raise _carry(_contract_error(exc), request) from None
        return act, request, decision

    def _take_call(self, actor: str) -> bool:
        """Count one admitted operation of ``actor`` (manifest 1.9 ``quotas.calls_per_minute``,
        a sliding window on the monotonic clock); False, counting nothing, when it is over.
        Keyed on the normalized identity, as ownership is compared, so one actor's spellings of
        itself share one bucket."""
        now = self._mono()
        with self._calls_lock:
            seen = self._calls.setdefault(normalize_identity(actor), deque())
            while seen and seen[0] <= now - CALL_RATE_WINDOW_S:
                seen.popleft()
            if len(seen) >= self.calls_per_minute:
                return False
            seen.append(now)
            return True

    # ---------------------------------------------------------------- retention
    def _prune_soon(self) -> None:
        """Start :meth:`prune_retention` on a background thread when one is due.  An operation
        starts it but never waits for it: a prune scans the whole trail, and a token operation
        holds the token store's lock meanwhile.  Cheap when none is due."""
        if self._mono() - self._retention_pruned < RETENTION_PRUNE_INTERVAL_S:
            return
        with self._calls_lock:
            if self._prune_thread is not None and self._prune_thread.is_alive():
                return
            self._prune_thread = threading.Thread(
                target=self._prune_quietly, name="broker-retention", daemon=True
            )
            self._prune_thread.start()

    def _prune_quietly(self) -> None:
        try:
            self.prune_retention()
        except Exception:  # a background thread: the next due prune tries again
            log.exception("broker state could not be pruned")

    def prune_retention(self, *, force: bool = False) -> dict[str, int]:
        """Remove finished state past its retention (manifest 1.9 ``retention``): run
        directories after ``runs_days``, audit records after ``audit_days``, never those of a
        request still pending or running.  At start, then at most once per
        :data:`RETENTION_PRUNE_INTERVAL_S` (on a background thread the next operation starts);
        one prune at a time.  A failure is logged, never raised: pruning must not refuse work."""
        with self._prune_lock:
            mono = self._mono()
            if not force and mono - self._retention_pruned < RETENTION_PRUNE_INTERVAL_S:
                return {"runs": 0, "audit": 0}
            self._retention_pruned = mono
            return self._prune_now()

    def _prune_now(self) -> dict[str, int]:
        none = {"runs": 0, "audit": 0}
        try:
            removed = self.state.prune_retained(
                self._now().timestamp(),
                runs_days=self.runs_retention_days,
                audit_days=self.audit_retention_days,
            )
        except (OSError, StateError):
            log.exception("broker state could not be pruned")
            return none
        if any(removed.values()):
            log.info(
                "retention: removed %d run directories and %d audit records",
                removed["runs"],
                removed["audit"],
            )
        return removed

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
        if act.kind in ("callable", "runner"):
            failed = False
            try:
                if act.kind == "runner":
                    result = act.handler(
                        {
                            "request_id": request["request_id"],
                            "actor": request["actor"],
                            "params": copy.deepcopy(dict(args)),
                        }
                    )
                else:
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
                if act.name == CODEMODE_EXECUTE:
                    result = self._execute_run(act, request, args)
                else:
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
            raise _carry(_contract_error(exc), request) from None
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
    clock = _SettableClock()  # the clock-control hook: tick() moves what expiry is judged by
    if config.get("manifest"):
        svc = BrokerService.from_manifest(
            config["manifest"],
            root / "state",
            data_root=config.get("data_root", root / "data"),
            clock=clock,
            monotonic=time.monotonic,  # hermetic: allow conformance factory: a live service on the real clock
        )
    else:
        svc = BrokerService(
            root / "state",
            data_root=root / "data",
            clock=clock,
            monotonic=time.monotonic,  # hermetic: allow conformance factory: a live service on the real clock
        )
    svc._tmpdir = tmp  # the directory lives as long as the service
    svc.tick = clock.tick
    svc.decide_request = svc._decide_for_test  # the approval-control hook
    svc.features = BrokerService.features | {"clock-control", "approval-control"}
    return svc


class _SettableClock:
    """The real UTC clock plus an offset :meth:`tick` adds to (the conformance factory's)."""

    def __init__(self) -> None:
        self.offset = timedelta(0)

    def __call__(self) -> datetime:
        return _utcnow() + self.offset  # hermetic: allow conformance factory: real UTC plus tick()

    def tick(self, seconds: float) -> None:
        self.offset += timedelta(seconds=seconds)
