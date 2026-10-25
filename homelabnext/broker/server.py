# SPDX-License-Identifier: Apache-2.0
"""The broker's local transport: a Unix-domain socket whose caller is the *peer*, not the body.

``hnx broker serve`` (ADR-0017, stage 2a).  Identity is authenticated by the kernel: the server
reads the connecting process's credentials (``SO_PEERCRED``; Linux only, see below) and maps its
uid through the manifest (``schemas/broker/manifest`` 1.7):

* ``callers: [{uid | user, profile}]`` - an agent's process; it acts as exactly that profile;
* ``approval_relays: [{uid | user, issuer}]`` - a process that authenticated a human (the hub
  behind the SSO front door, stage 2b) and files approvals and denials for that human, for its
  one issuer.  The manifest's approver rules (allowlist, no self-approval, no agent approver)
  still apply to the human it names;
* ``codemode.runners: [{uid | user, service}]`` (1.7) - the Code Mode runner: it asks for a
  capability token for a ``codemode.execute`` whose handler is running, and spends it;
* ``codemode.sandboxes: [{uid | user, sandbox_id?}]`` (1.7) - a sandbox: it may only present a
  token, and the token's actor is the one it acts as.  With ``sandbox_id`` the peer is that one
  sandbox, and only its tokens are accepted from it; a peer without one is a pool, and a token
  bound to a dedicated sandbox is refused from it (both ``token-sandbox-mismatch``).  A refusal
  after a token was admitted is not counted against the peer's refusal limit (the token's cap
  bounds it); one before is counted per presented token, so a program on a shared pool uid limits
  only itself, and a request with no known token counts against the uid's ceiling,
  :data:`UNKNOWN_TOKEN_FACTOR` times the limit.  The runner is exempt from the limit, like a
  relay.

A peer in neither list is refused (``unknown-caller``) before its request is read, and audited;
the server answers at once and closes without waiting for, or parsing, anything it sent.
A peer is listed once (``hnx broker validate`` refuses a peer listed in two of these roles).

Protocol: one request per connection.  The client sends one JSON object, terminated by a newline
or by closing its write side, of at most ``max_request_bytes`` (default 1 MiB); the server
answers one JSON object and a newline, then closes.  Reading the request is bounded by
``timeout_s`` (default 10 s) for the whole request, not per read, so a sender trickling bytes
cannot hold a connection open; running the action is not (a handler has its own timeout).

Request: ``{"v": 1, "op": OP, ...}``; ``v`` is optional, any other value is refused.

========================  ======  ===========================================================
op                        peer    fields
========================  ======  ===========================================================
``actions``               caller  -
``call`` / ``submit``     caller  ``action``, ``params`` (object, default ``{}``), ``target``
``status`` / ``run`` /    caller  ``request_id``
``cancel``
``pending-for-me``        caller  -
``approve`` / ``deny``    relay   ``request_id``, ``approver: {issuer, subject}``, ``note``
``pending``               relay   -
``audit``                 relay   ``action``, ``caller``, ``outcome``, ``operation``,
                                  ``request_id`` (filters), ``tail`` (default 50, max 500)
``token-issue``           runner  ``request_id``, ``sandbox_id``, ``actions``, ``max_calls``,
                                  ``ttl_s``: ``{secret, claims}``
``token-spend``           runner  ``token_id``, ``outcome`` (``finished`` | ``paused``)
``token-status``          runner  ``token_id``
``token-call`` /          sandbox ``action``, ``params``, ``target``: ``{result |
``token-submit``                  state: pending, request_id, request_digest, target?}``
``token-run``             sandbox ``request_id`` (a request an earlier token of the
                                  execution paused on): ``{result, request_id, request_digest}``
========================  ======  ===========================================================

A sandbox's request carries its token as a **bearer line**: the token (``hnxcmt_...``) alone on
the first line, the JSON body on the next.  The token is never a body field (``token`` is refused
``request-invalid`` like any field an operation does not take), so nothing the server parses,
audits or names in a log line ever held it.

The body never names the actor: a top-level ``actor``, ``caller`` (outside ``audit``), ``as``,
``who``, ``profile``, ``identity``, ``uid`` or ``user`` is refused (``actor-in-body``), and so is
any other field the operation does not take (``request-invalid``).

Response: ``{"ok": true, "result": ...}`` or ``{"ok": false, "error": REASON, "kind": KIND,
"message": TEXT}`` where ``kind`` is ``Denied``, ``InvalidArguments`` or ``BrokerError`` (the
broker contract's exception, which :class:`homelabnext.broker.client.BrokerClient` raises again).

Every request is audited by the service as usual, with ``via: uid:<n>``; a refusal made here,
before the service sees the request, is audited with operation ``connect`` when no operation
could be attributed.  Concurrency: one thread per connection, at most ``max_connections`` at once
for callers and unknown peers, plus ``relay_connections`` (default 4) kept for approval relays,
so agents holding every slot cannot keep the hub from approving or denying (more are answered
``busy``); the state directory already makes runs, cancels, denials and approval consumption
exactly-once across threads and processes.

Refusals are rate limited per peer (:class:`RefusalLimiter`): a caller or an unknown peer that
collects more than ``refusal_limit.max`` refusals (every answer that is not ``ok``, whatever its
kind: default deny, a malformed request, ``unknown-caller``, ``not-pending``, a failed handler,
...; only the broker's own faults, :data:`NOT_REFUSALS` -- its audit trail, its secret store, a
handler it could not start or that timed out, a disk error -- are not counted) within
``refusal_limit.window_s`` seconds (manifest 1.4; default :data:`DEFAULT_REFUSAL_LIMIT` per
:data:`DEFAULT_REFUSAL_WINDOW_S` s) is answered ``rate-limited`` for the rest of that window
without its request being looked at.  The
limit is audited once per peer and window (operation ``connect``, reason ``rate-limited``), not
once per request, so an agent probing the broker can fill neither the audit trail nor the disk;
how many requests the window suppressed is logged when it ends.  Approval relays are exempt (a
person's refused decisions must never lock the hub out), as they are from the connection cap.

Platforms: peer credentials are read with ``SO_PEERCRED``, which Linux provides.  macOS and the
BSDs have ``getpeereid``/``LOCAL_PEERCRED`` instead, which Python does not expose portably; the
server refuses to start there rather than fall back to an unauthenticated mode.
"""

from __future__ import annotations

import contextlib
import grp
import json
import logging
import os
import pwd
import socket
import socketserver
import stat
import struct
import threading
import time
from collections.abc import Callable, Hashable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from conformance.protocols.broker import BrokerError, Denied, InvalidArguments

from .service import TRANSPORT_PEER, BrokerService, ManifestError

__all__ = [
    "CALLER_OPS",
    "DEFAULT_MAX_REQUEST_BYTES",
    "DEFAULT_TIMEOUT_S",
    "FORBIDDEN_FIELDS",
    "PROTOCOL_VERSION",
    "RELAY_OPS",
    "RUNNER_OPS",
    "SANDBOX_OPS",
    "BrokerServer",
    "Identity",
    "PeerMap",
    "RefusalLimiter",
    "handle_request",
    "peer_credentials",
    "supported",
]

PROTOCOL_VERSION = 1
DEFAULT_MAX_REQUEST_BYTES = 1 << 20
DEFAULT_TIMEOUT_S = 10.0
DEFAULT_MAX_CONNECTIONS = 32
DEFAULT_RELAY_CONNECTIONS = 4
#: the socket's listen backlog
LISTEN_BACKLOG = 128
MAX_AUDIT_TAIL = 500
DEFAULT_REFUSAL_LIMIT = 60
DEFAULT_REFUSAL_WINDOW_S = 60.0
RATE_LIMITED = "rate-limited"
#: how much higher a sandbox uid's ceiling for requests with no known token is than the limit
UNKNOWN_TOKEN_FACTOR = 10
#: a request whose first line starts so is a sandbox's: that line is its token (the bearer line)
BEARER_PREFIX = b"hnxcmt_"
MAX_BEARER_BYTES = 256
#: failures of the broker itself (its trail, its secret store, its host), never counted as the
#: peer's refusals: an outage of any of them must not rate-limit a healthy agent
NOT_REFUSALS = frozenset(
    {
        "internal-error",
        "busy",
        "audit-unavailable",
        "audit-incomplete",
        "secret-unavailable",
        "handler-spawn-failed",
        "handler-timeout",
        "handler-io-error",
        "lane-io-error",
    }
)
#: what an agent's process may ask, and the fields each operation takes (beyond ``v``, ``op``)
CALLER_OPS: dict[str, frozenset[str]] = {
    "actions": frozenset(),
    "call": frozenset({"action", "params", "target"}),
    "submit": frozenset({"action", "params", "target"}),
    "status": frozenset({"request_id"}),
    "run": frozenset({"request_id"}),
    "cancel": frozenset({"request_id"}),
    "pending-for-me": frozenset(),
}
#: what an approval relay may ask
RELAY_OPS: dict[str, frozenset[str]] = {
    "approve": frozenset({"request_id", "approver", "note"}),
    "deny": frozenset({"request_id", "approver", "note"}),
    "pending": frozenset(),
    "audit": frozenset({"action", "caller", "outcome", "operation", "request_id", "tail"}),
}
#: what a Code Mode runner may ask (manifest 1.7 ``codemode.runners``)
RUNNER_OPS: dict[str, frozenset[str]] = {
    "token-issue": frozenset({"request_id", "sandbox_id", "actions", "max_calls", "ttl_s"}),
    "token-spend": frozenset({"token_id", "outcome"}),
    "token-status": frozenset({"token_id"}),
}
#: what a sandbox may ask: only calls made with a token (manifest 1.7 ``codemode.sandboxes``)
SANDBOX_OPS: dict[str, frozenset[str]] = {
    "token-call": frozenset({"action", "params", "target"}),
    "token-submit": frozenset({"action", "params", "target"}),
    "token-run": frozenset({"request_id"}),
}
_TABLES = {"caller": CALLER_OPS, "relay": RELAY_OPS, "runner": RUNNER_OPS, "sandbox": SANDBOX_OPS}
#: every operation name, mapped to itself: what a log line may name (see :func:`_refuse`)
_OP_NAMES = {name: str(name) for table in _TABLES.values() for name in table}
#: top-level fields that would name the actor: the transport says who is calling, never the body
FORBIDDEN_FIELDS = frozenset(
    {"actor", "caller", "as", "who", "profile", "identity", "uid", "user", "approver_uid"}
)
#: operations the audit schema knows; anything else is audited as ``connect``
_AUDIT_OPS = frozenset(
    {"call", "submit", "status", "run", "cancel", "approve", "deny", "token-issue", "token-spend"}
)
#: a transport refusal of a token op is audited as the operation it carries
_AUDITED_AS = {"token-call": "call", "token-submit": "submit", "token-run": "run"}
_MAX_NOTE = 2000
_MAX_NAME = 64

log = logging.getLogger("homelabnext.broker.server")


def supported() -> bool:
    """True when this platform can authenticate a socket peer (``SO_PEERCRED``)."""
    return hasattr(socket, "SO_PEERCRED")


def peer_credentials(conn: socket.socket) -> tuple[int, int, int]:
    """``(pid, uid, gid)`` of the process at the other end of ``conn`` (Linux)."""
    raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    return struct.unpack("3i", raw)


# ---------------------------------------------------------------- identity
@dataclass(frozen=True)
class Identity:
    """Who a peer is: a ``caller`` acting as ``profile``, a ``relay`` for ``issuer``, a Code Mode
    ``runner`` known as ``service``, or a ``sandbox`` (``sandbox_id`` when it is one sandbox)."""

    role: str
    uid: int
    profile: str | None = None
    issuer: str | None = None
    service: str | None = None
    sandbox_id: str | None = None


class PeerMap:
    """The manifest's ``callers``, ``approval_relays`` and ``codemode`` runners and sandboxes by
    uid; user names resolved once."""

    def __init__(
        self,
        manifest: Mapping[str, Any],
        *,
        user_uid: Callable[[str], int] | None = None,
    ) -> None:
        lookup = user_uid or (lambda name: pwd.getpwnam(name).pw_uid)
        self._by_uid: dict[int, Identity] = {}
        problems: list[str] = []
        cm = manifest.get("codemode") or {}
        for where, role, entries in (
            ("callers", "caller", manifest.get("callers", [])),
            ("approval_relays", "relay", manifest.get("approval_relays", [])),
            ("codemode.runners", "runner", cm.get("runners", [])),
            ("codemode.sandboxes", "sandbox", cm.get("sandboxes", [])),
        ):
            for entry in entries:
                if "uid" in entry:
                    uid = int(entry["uid"])
                else:
                    try:
                        uid = lookup(entry["user"])
                    except KeyError:
                        problems.append(f"{where}: no such user {entry['user']!r}")
                        continue
                if uid in self._by_uid:
                    problems.append(f"{where}: uid {uid} is listed twice")
                    continue
                self._by_uid[uid] = Identity(
                    role,
                    uid,
                    profile=entry.get("profile"),
                    issuer=entry.get("issuer"),
                    service=entry.get("service"),
                    sandbox_id=entry.get("sandbox_id"),
                )
        if problems:
            raise ManifestError(problems)

    def lookup(self, uid: int) -> Identity | None:
        return self._by_uid.get(uid)

    def __len__(self) -> int:
        return len(self._by_uid)


# ---------------------------------------------------------------- refusal rate limit
class RefusalLimiter:
    """Per-peer count of refusals in a fixed window (see the module doc).  Thread-safe."""

    def __init__(
        self,
        max_refusals: int = DEFAULT_REFUSAL_LIMIT,
        window_s: float = DEFAULT_REFUSAL_WINDOW_S,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_refusals < 1 or window_s <= 0:
            raise ValueError("refusal limit: max is at least 1 and window_s is positive")
        self.max_refusals = max_refusals
        self.window_s = window_s
        self.clock = clock
        self._lock = threading.Lock()
        #: key (a uid; a sandbox's (uid, token digest)) -> [window start, refusals, suppressed]
        self._peers: dict[Hashable, list[float]] = {}
        self._unknown: RefusalLimiter | None = None

    @property
    def unknown_tokens(self) -> RefusalLimiter:
        """The per-uid ceiling for a sandbox's requests that present no known token (garbage,
        a wrong secret, a malformed request): :data:`UNKNOWN_TOKEN_FACTOR` times this limit, in
        the same window, so one program's garbage cannot lock its pool out at the normal limit,
        and a flood of it still ends."""
        if self._unknown is None:
            self._unknown = RefusalLimiter(
                self.max_refusals * UNKNOWN_TOKEN_FACTOR, self.window_s, clock=self.clock
            )
        return self._unknown

    @classmethod
    def from_manifest(cls, manifest: Mapping[str, Any], **kw: Any) -> RefusalLimiter:
        cfg = manifest.get("refusal_limit") or {}
        return cls(
            int(cfg.get("max", DEFAULT_REFUSAL_LIMIT)),
            float(cfg.get("window_s", DEFAULT_REFUSAL_WINDOW_S)),
            **kw,
        )

    def _current(self, uid: Hashable, now: float) -> list[float] | None:
        st = self._peers.get(uid)
        if st is not None and now - st[0] >= self.window_s:
            if st[2]:
                log.warning(
                    "%s: %d request(s) answered rate-limited in the last window",
                    _key_name(uid),
                    int(st[2]),
                )
            del self._peers[uid]
            st = None
        return st

    def check(self, uid: Hashable) -> tuple[bool, bool]:
        """(limited, first): whether ``uid`` is over its limit now, and whether this is the first
        request of the window to be refused for it (the one that is audited)."""
        with self._lock:
            st = self._current(uid, self.clock())
            if st is None or st[1] < self.max_refusals:
                return False, False
            st[2] += 1
            return True, st[2] == 1

    def refused(self, uid: Hashable) -> None:
        """Count one refusal for ``uid``."""
        with self._lock:
            now = self.clock()
            st = self._current(uid, now)
            if st is None:
                st = self._peers[uid] = [now, 0, 0]
            st[1] += 1


def _key_name(key: Hashable) -> str:
    """A limiter key for a log line: its uid only (a sandbox's key also names a token)."""
    uid = key[0] if isinstance(key, tuple) else key
    return f"uid {uid}" + (" (one token)" if isinstance(key, tuple) else "")


def _sandbox_key(
    svc: BrokerService, uid: int, bearer: str | None, limiter: RefusalLimiter
) -> tuple[Hashable, RefusalLimiter]:
    """Where a sandbox's refusals count: per presented token, so a program on a shared pool uid
    limits only itself; a request with no known token counts against the uid's much higher
    ceiling (:attr:`RefusalLimiter.unknown_tokens`)."""
    tok = svc.tokens.by_secret(bearer) if bearer is not None else None
    if tok is not None:  # keyed by the token's id: nothing of the secret is kept here
        return (uid, tok["claims"]["token_id"]), limiter
    return uid, limiter.unknown_tokens


# ---------------------------------------------------------------- the protocol
def _error(reason: str, message: str, kind: str = "Denied") -> dict[str, Any]:
    return {"ok": False, "error": reason, "kind": kind, "message": message}


def _from_exception(exc: BrokerError) -> dict[str, Any]:
    kind = (
        "Denied"
        if isinstance(exc, Denied)
        else "InvalidArguments"
        if isinstance(exc, InvalidArguments)
        else "BrokerError"
    )
    reason = getattr(exc, "reason", "") or type(exc).__name__
    out = _error(reason, str(exc), kind)
    for field in ("request_id", "request_digest"):  # a refusal of a request that was built
        if isinstance(getattr(exc, field, None), str):
            out[field] = getattr(exc, field)
    if getattr(exc, "admitted", False):
        out["_admitted"] = True  # internal: popped before the answer is sent
    return out


def _jsonable(value: Any) -> Any:
    return json.loads(json.dumps(value, default=repr))


def _refuse(
    svc: BrokerService,
    who: Identity | None,
    uid: int,
    op: Any,
    outcome: str,
    reason: str,
    message: str,
    body: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Audit a transport refusal and build its response."""
    body = body or {}
    caller = who.profile if who is not None and who.role == "caller" else f"uid:{uid}"
    if who is not None and who.role == "runner":
        caller = str(who.service)
    action = body.get("action") if isinstance(body.get("action"), str) else ""
    rid = body.get("request_id")
    op = _AUDITED_AS.get(op, op) if isinstance(op, str) else op
    svc.audit_refusal(
        caller,
        op if op in _AUDIT_OPS else "connect",
        outcome,
        reason,
        action=action,
        request_id=rid[:128] if isinstance(rid, str) and rid else None,
    )
    # the operation as one of the protocol's own names, never the text the peer sent: a body can
    # carry a token's secret beside its op, so nothing read from it is logged
    log.warning("refused uid %d op %s: %s", uid, _OP_NAMES.get(op, "unknown"), reason)
    return _error(reason, message, "Denied" if outcome == "denied" else "InvalidArguments")


def _name(value: Any) -> str | None:
    if isinstance(value, str) and 0 < len(value) <= _MAX_NAME and value.isprintable():
        return value
    return None


def handle_request(
    svc: BrokerService,
    peers: PeerMap,
    uid: int,
    raw: bytes | None,
    *,
    problem: str = "",
    limiter: RefusalLimiter | None = None,
    bearer: str | None = None,
) -> dict[str, Any]:
    """The response to one request from the peer ``uid``.

    ``bearer`` is the request's bearer line (a Code Mode token, sent ahead of the body by a
    sandbox), kept apart from ``raw`` from the socket on.  ``raw`` is the request's bytes, or None
    with ``problem`` set (``request-too-large``,
    ``request-timeout``) when the transport could not read it.  ``limiter`` rate-limits the
    peer's refusals (none: unlimited).  Pure apart from the service and the limiter: the socket
    server and the tests call it alike.
    """
    token = TRANSPORT_PEER.set(f"uid:{uid}")
    try:
        who = peers.lookup(uid)
        # relays (a person's decisions) and the Code Mode runner (it acts for every agent: one
        # program's refusals must not lock the others out) are exempt
        limited = limiter if who is None or who.role not in ("relay", "runner") else None
        key: Hashable = uid
        if limited is not None and who is not None and who.role == "sandbox":
            key, limited = _sandbox_key(svc, uid, bearer, limited)
        if limited is not None:
            over, first = limited.check(key)
            if over:
                message = "too many refused requests from this peer; try again later"
                if first:  # coalesced: one audit record per peer and window
                    return _refuse(svc, who, uid, None, "denied", RATE_LIMITED, message)
                return _error(RATE_LIMITED, message)
        if who is None:
            response = _refuse(
                svc, None, uid, None, "denied", "unknown-caller", "this peer is not a broker caller"
            )
        else:
            response = _handle(svc, who, raw, problem, bearer)
        # a sandbox's call refused after its token was admitted is bounded by the token's cap
        # (and is another program's business on a shared pool uid): only refusals before
        # admission, an unknown token above all, count against the peer
        admitted = bool(response.pop("_admitted", False))
        # every refusal counts, whatever its class: not-pending is a plain BrokerError, and an
        # agent looping run on a finished request must not write one audit record per try
        if (
            limited is not None
            and not response.get("ok")
            and response.get("error") not in NOT_REFUSALS
            and not admitted
        ):
            limited.refused(key)
        return response
    finally:
        TRANSPORT_PEER.reset(token)


def _handle(
    svc: BrokerService, who: Identity, raw: bytes | None, problem: str, bearer: str | None = None
) -> dict[str, Any]:
    uid = who.uid
    if raw is None:
        return _refuse(svc, who, uid, None, "invalid", problem, problem.replace("-", " "))
    try:
        body = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        body = None
    if not isinstance(body, dict) or not isinstance(body.get("op"), str):
        return _refuse(
            svc,
            who,
            uid,
            None,
            "invalid",
            "request-malformed",
            "a request is a JSON object with op",
        )
    op = body["op"]
    if body.get("v", PROTOCOL_VERSION) != PROTOCOL_VERSION:
        return _refuse(
            svc, who, uid, op, "invalid", "unsupported-version", "protocol version 1", body
        )
    named = sorted(FORBIDDEN_FIELDS & set(body) - ({"caller"} if op == "audit" else set()))
    if named:
        return _refuse(
            svc,
            who,
            uid,
            op,
            "denied",
            "actor-in-body",
            "the caller is the authenticated peer; the request may not name it",
            body,
        )
    table = _TABLES[who.role]
    if not any(op in t for t in _TABLES.values()):
        return _refuse(svc, who, uid, op, "invalid", "unknown-operation", "no such operation")
    if op not in table:
        reason = (
            "not-an-approval-relay"
            if op in RELAY_OPS
            else "not-a-codemode-runner"
            if op in RUNNER_OPS
            else "not-a-sandbox"
            if op in SANDBOX_OPS
            else "not-a-caller"
        )
        return _refuse(svc, who, uid, op, "denied", reason, f"this peer may not {op}", body)
    extra = set(body) - table[op] - {"v", "op"}
    if extra:
        return _refuse(
            svc, who, uid, op, "invalid", "request-invalid", f"{op} takes {sorted(table[op])}", body
        )
    try:
        if bearer is not None and who.role != "sandbox":
            raise _BadField("only a sandbox sends a bearer line")
        if who.role == "caller":
            result = _caller_op(svc, who, op, body)
        elif who.role == "relay":
            result = _relay_op(svc, who, op, body)
        elif who.role == "runner":
            result = _runner_op(svc, who, op, body)
        else:
            result = _sandbox_op(svc, who, op, body, bearer)
    except BrokerError as exc:
        return _from_exception(exc)
    except _BadField as exc:
        return _refuse(svc, who, uid, op, "invalid", "request-invalid", str(exc), body)
    except _IssuerMismatch:
        return _refuse(
            svc,
            who,
            uid,
            op,
            "denied",
            "relay-issuer-mismatch",
            "this relay carries approvers of another issuer",
            body,
        )
    return {"ok": True, "result": _jsonable(result)}


class _BadField(Exception):
    pass


class _IssuerMismatch(Exception):
    pass


def _rid(body: Mapping[str, Any]) -> str:
    rid = body.get("request_id")
    if not isinstance(rid, str) or not rid:
        raise _BadField("request_id is a non-empty string")
    return rid


def _caller_op(svc: BrokerService, who: Identity, op: str, body: Mapping[str, Any]) -> Any:
    caller = str(who.profile)
    if op == "actions":
        return {"caller": caller, "actions": svc.actions_for(caller)}
    if op == "pending-for-me":
        return {"requests": svc.pending_for(caller)}
    if op in ("call", "submit"):
        action, params = body.get("action"), body.get("params", {})
        if not isinstance(action, str) or not action:
            raise _BadField("action is a non-empty string")
        target = body.get("target")
        if op == "call":
            return {"result": svc.call(caller, action, params, target=target)}
        rid = svc.submit(caller, action, params, target=target)
        waiting = svc.state.get_request(rid)["verdict"] == "needs-approval"
        return {"request_id": rid, "state": "pending", "awaiting_approval": waiting}
    rid = _rid(body)
    if op == "status":
        return svc.detail(caller, rid)
    if op == "run":
        return {"request_id": rid, "result": svc.run(caller, rid)}
    svc.cancel(caller, rid)
    return {"request_id": rid, "state": "cancelled"}


def _runner_op(svc: BrokerService, who: Identity, op: str, body: Mapping[str, Any]) -> Any:
    runner = str(who.service)
    if op == "token-issue":
        token = svc.issue_token(
            runner,
            _rid(body),
            sandbox_id=body.get("sandbox_id"),
            actions=body.get("actions"),
            max_calls=body.get("max_calls"),
            ttl_s=body.get("ttl_s"),
        )
        # the answer is built from the two apart: the claims are a fresh copy, the secret is
        # added last and appears in nothing else (no log, no audit record, no error)
        claims = json.loads(json.dumps(dict(token.claims)))
        return {"claims": claims, "secret": token.secret}
    tid = body.get("token_id")
    if not isinstance(tid, str) or not tid:
        raise _BadField("token_id is a non-empty string")
    if op == "token-status":
        return svc.token_status(runner, tid)
    outcome = body.get("outcome", "finished")
    if not isinstance(outcome, str):
        raise _BadField("outcome is finished or paused")
    svc.spend_token(runner, tid, outcome)
    return {"token_id": tid, "state": "spent", "outcome": outcome}


def _sandbox_op(
    svc: BrokerService, who: Identity, op: str, body: Mapping[str, Any], bearer: str | None
) -> Any:
    """A sandbox's call with a token.  The token is the request's bearer frame, never a body
    field: nothing parsed out of the body (which is audited and named in logs) ever held it."""
    if bearer is None:
        raise _BadField("a token operation is sent with its token as the bearer line")
    sandbox = who.sandbox_id or ""  # the peer's sandbox: one dedicated sandbox, or "" for a pool
    if op == "token-run":
        return svc.token_run(bearer, _rid(body), sandbox_id=sandbox)
    action, params = body.get("action"), body.get("params", {})
    if not isinstance(action, str) or not action:
        raise _BadField("action is a non-empty string")
    kw = {"target": body.get("target"), "sandbox_id": sandbox}
    if op == "token-call":
        return svc.token_call(bearer, action, params, **kw)
    return svc.token_submit(bearer, action, params, **kw)


def _relay_op(svc: BrokerService, who: Identity, op: str, body: Mapping[str, Any]) -> Any:
    if op == "pending":
        return {"requests": svc.pending()}
    if op == "audit":
        match = {}
        for k in ("action", "caller", "outcome", "operation", "request_id"):
            v = body.get(k)
            if v is not None and not isinstance(v, str):
                raise _BadField(f"{k} is a string")
            match[k] = v
        tail = body.get("tail", 50)
        if not isinstance(tail, int) or isinstance(tail, bool) or not 0 <= tail <= MAX_AUDIT_TAIL:
            raise _BadField(f"tail is an integer from 0 to {MAX_AUDIT_TAIL}")
        return {"records": svc.audit_documents(limit=tail, **match)}
    rid = _rid(body)
    approver = body.get("approver")
    if not isinstance(approver, Mapping) or set(approver) != {"issuer", "subject"}:
        raise _BadField("approver is {issuer, subject}: the human this relay authenticated")
    issuer, subject = _name(approver["issuer"]), _name(approver["subject"])
    if issuer is None or subject is None or ":" in issuer:
        raise _BadField("approver issuer and subject are short printable strings")
    if issuer != who.issuer:  # exact, like the approver allowlist the issuer qualifies
        raise _IssuerMismatch
    note = body.get("note")
    if note is not None and not (isinstance(note, str) and len(note) <= _MAX_NOTE):
        raise _BadField(f"note is a string of at most {_MAX_NOTE} characters")
    fn = svc.approve if op == "approve" else svc.deny
    return fn(rid, f"{issuer}:{subject}", note=note)


# ---------------------------------------------------------------- the socket server
def _read_request(
    conn: socket.socket,
    limit: int,
    timeout_s: float,
    *,
    clock: Callable[[], float] = time.monotonic,
) -> tuple[bytes | None, str, str | None]:
    """(request bytes, "", bearer) or (None, problem, None): one line or everything up to EOF, at
    most ``limit`` bytes, all of it within ``timeout_s``.  A first line that starts with
    :data:`BEARER_PREFIX` is a sandbox's bearer line (its token, at most :data:`MAX_BEARER_BYTES`)
    and the request is the line after it: the token is never part of the JSON body."""
    buf = b""
    deadline = clock() + timeout_s
    eof = False
    try:
        while True:
            lines = buf.count(b"\n")
            bearer_first = buf.startswith(BEARER_PREFIX)
            if lines >= (2 if bearer_first else 1) or eof:
                break
            if len(buf) > limit + MAX_BEARER_BYTES + 1:
                return None, "request-too-large", None
            remaining = deadline - clock()
            if remaining <= 0:
                return None, "request-timeout", None
            conn.settimeout(remaining)
            chunk = conn.recv(65536)
            eof = not chunk
            buf += chunk
    except TimeoutError:
        return None, "request-timeout", None
    bearer = None
    if buf.startswith(BEARER_PREFIX):
        line, _, buf = buf.partition(b"\n")
        if len(line) > MAX_BEARER_BYTES:
            return None, "request-too-large", None
        bearer = line.rstrip(b"\r").decode("ascii", "replace")
    raw = buf.split(b"\n", 1)[0]
    if len(raw) > limit:
        return None, "request-too-large", None
    return raw, "", bearer


def _discard(
    conn: socket.socket,
    limit: int,
    timeout_s: float,
    *,
    clock: Callable[[], float] = time.monotonic,
) -> None:
    """Drop what a known peer sent and was not read (a refused or oversized request), up to
    ``limit`` bytes and for at most ``timeout_s``, so closing does not reset the connection
    before it reads the answer."""
    seen = 0
    deadline = clock() + timeout_s
    while seen <= limit:
        remaining = deadline - clock()
        if remaining <= 0:
            return
        conn.settimeout(remaining)
        chunk = conn.recv(65536)
        if not chunk:
            return
        seen += len(chunk)


class _Handler(socketserver.BaseRequestHandler):
    server: _UnixServer

    def handle(self) -> None:
        srv = self.server.broker
        conn: socket.socket = self.request
        try:
            _pid, uid, _gid = srv.credentials(conn)
        except OSError:
            return  # the peer is gone; nothing to answer
        conn.settimeout(srv.timeout_s)
        if srv.peers.lookup(uid) is None:  # refuse before reading a byte from a stranger
            response = handle_request(srv.service, srv.peers, uid, b"", limiter=srv.limiter)
            with contextlib.suppress(OSError):
                conn.sendall(json.dumps(response, sort_keys=True).encode("utf-8") + b"\n")
                conn.shutdown(socket.SHUT_WR)
                # never wait for a stranger: drop only what already arrived, unparsed, so the
                # close does not reset the connection before the peer reads its answer
                conn.setblocking(False)
                conn.recv(srv.max_request_bytes)
            return
        else:
            raw, problem, bearer = _read_request(conn, srv.max_request_bytes, srv.timeout_s)
            try:
                response = handle_request(
                    srv.service,
                    srv.peers,
                    uid,
                    raw,
                    problem=problem,
                    limiter=srv.limiter,
                    bearer=bearer,
                )
            except Exception:  # a broker bug: the service audited what it could; say so
                log.exception("broker request from uid %d failed", uid)
                response = _error("internal-error", "the broker failed; see its log", "BrokerError")
        conn.settimeout(srv.timeout_s)
        with contextlib.suppress(OSError):
            conn.sendall(json.dumps(response, sort_keys=True).encode("utf-8") + b"\n")
            conn.shutdown(socket.SHUT_WR)
            _discard(conn, srv.max_request_bytes, srv.timeout_s)


class _UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = False
    request_queue_size = LISTEN_BACKLOG  # socketserver's default of 5 refuses a burst of agents

    def __init__(self, broker: BrokerServer) -> None:
        self.broker = broker  # before the base binds: server_bind reads the mode and group
        super().__init__(str(broker.path), _Handler)

    def server_bind(self) -> None:
        old = os.umask(0o177)  # the socket is born 0600; chmod widens it to the configured mode
        try:
            super().server_bind()
        finally:
            os.umask(old)
        b = self.broker
        if b.gid is not None:
            os.chown(self.server_address, -1, b.gid)
        os.chmod(self.server_address, b.mode)

    def _pool(self, request) -> threading.BoundedSemaphore:
        """The connection slots this peer draws from: the relays' own, or everyone else's."""
        try:
            _pid, uid, _gid = self.broker.credentials(request)
        except OSError:
            return self.broker.slots
        who = self.broker.peers.lookup(uid)
        return (
            self.broker.relay_slots
            if who is not None and who.role == "relay"
            else self.broker.slots
        )

    def process_request(self, request, client_address) -> None:
        pool = self._pool(request)
        if not pool.acquire(blocking=False):
            # answered on the accepting thread, so nothing here may block: a non-blocking
            # drain of what already arrived keeps the close from resetting the connection
            with contextlib.suppress(OSError):
                busy = _error("busy", "too many connections", "BrokerError")
                request.sendall(json.dumps(busy).encode() + b"\n")
                request.shutdown(socket.SHUT_WR)
                request.setblocking(False)
                request.recv(self.broker.max_request_bytes)
            self.shutdown_request(request)
            return
        # the handler ignores the address (a Unix peer has none); it carries the slot's pool
        super().process_request(request, (client_address, pool))

    def process_request_thread(self, request, client_address) -> None:
        address, pool = client_address
        try:
            super().process_request_thread(request, address)
        finally:
            pool.release()


class BrokerServer:
    """:class:`BrokerService` on a Unix socket at ``socket_path``.

    ``mode`` is the socket file's mode (default ``0o600``, the service user only; ``0o660`` with
    ``group`` lets that group's processes connect); it may grant nothing to others.  The parent
    directory is created ``0750`` (``0700`` without a group) when missing; when it exists it must
    be owned by the broker's user (or root), not writable by its group and not reachable by
    others, so no other account can swap the socket.  A stale socket file at ``socket_path`` is
    replaced; any other file is refused.
    """

    def __init__(
        self,
        service: BrokerService,
        socket_path: str | os.PathLike[str],
        *,
        mode: int = 0o600,
        group: str | int | None = None,
        max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        max_connections: int = DEFAULT_MAX_CONNECTIONS,
        relay_connections: int = DEFAULT_RELAY_CONNECTIONS,
        peers: PeerMap | None = None,
        limiter: RefusalLimiter | None = None,
    ) -> None:
        if not supported():
            raise BrokerError(
                "peer credentials (SO_PEERCRED) are not available on this platform; the broker "
                "socket needs them to authenticate callers"
            )
        if mode & 0o007 or mode & 0o600 != 0o600 or mode & ~0o777:
            raise ValueError(f"socket mode {mode:o}: owner rw, nothing for others")
        if max_request_bytes < 1 or timeout_s <= 0 or max_connections < 1 or relay_connections < 1:
            raise ValueError(
                "max_request_bytes, timeout_s, max_connections and relay_connections are positive"
            )
        self.service = service
        self.path = Path(socket_path)
        self.mode = mode
        self.gid = (
            None
            if group is None
            else group
            if isinstance(group, int)
            else grp.getgrnam(group).gr_gid
        )
        self.max_request_bytes = max_request_bytes
        self.timeout_s = timeout_s
        self.slots = threading.BoundedSemaphore(max_connections)
        self.relay_slots = threading.BoundedSemaphore(relay_connections)
        self.peers = peers if peers is not None else PeerMap(service.manifest)
        self.limiter = (
            limiter if limiter is not None else RefusalLimiter.from_manifest(service.manifest)
        )
        self.credentials = peer_credentials
        self._server: _UnixServer | None = None
        self._thread: threading.Thread | None = None

    def _prepare(self) -> None:
        parent = self.path.parent
        if not parent.exists():
            parent.mkdir(mode=0o750 if self.gid is not None else 0o700, parents=True)
            if self.gid is not None:
                os.chown(parent, -1, self.gid)
        st = parent.lstat()
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise BrokerError(f"{parent} is not a real directory")
        if st.st_uid not in (os.geteuid(), 0):
            raise BrokerError(
                f"{parent} is owned by uid {st.st_uid}; the socket's directory must be owned by "
                "the broker's user or root"
            )
        if st.st_mode & 0o027:
            raise BrokerError(
                f"{parent} is mode {stat.S_IMODE(st.st_mode):o}; the socket's directory must be "
                "0700 or 0750 (not group-writable, nothing for others)"
            )
        try:
            existing = self.path.lstat()
        except FileNotFoundError:
            return
        if not stat.S_ISSOCK(existing.st_mode):
            raise BrokerError(f"{self.path} exists and is not a socket; refusing to replace it")
        self.path.unlink()

    def bind(self) -> None:
        """Create and bind the socket (listening); :meth:`serve_forever` or :meth:`start` next."""
        self._prepare()
        self._server = _UnixServer(self)
        log.info("broker listening on %s (%d peers mapped)", self.path, len(self.peers))

    def serve_forever(self) -> None:
        if self._server is None:
            self.bind()
        assert self._server is not None
        self._server.serve_forever(poll_interval=0.2)

    def start(self) -> BrokerServer:
        """Bind and serve on a background thread (embedding and tests)."""
        self.bind()
        self._thread = threading.Thread(target=self.serve_forever, daemon=True)
        self._thread.start()
        return self

    def close(self) -> None:
        if self._server is not None:
            if self._thread is not None:
                self._server.shutdown()
                self._thread.join(timeout=5)
            self._server.server_close()
            self._server = None
            with contextlib.suppress(FileNotFoundError):
                self.path.unlink()

    def __enter__(self) -> BrokerServer:
        return self.start()

    def __exit__(self, *exc: Any) -> None:
        self.close()
