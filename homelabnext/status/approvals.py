# SPDX-License-Identifier: Apache-2.0
"""The hub's Approvals page: people approve broker requests through the front door (ADR-0017,
stage 2b).

``GET /approvals`` lists the broker requests awaiting an approver (action, actor, target, params,
created, digest, age) and the recent decisions; ``POST /approvals/decide`` approves or denies one.
The hub is the broker's **approval relay** (``approval_relays`` in the broker manifest): it speaks
to the broker socket with :class:`homelabnext.broker.client.BrokerClient`, as its own system user,
and names the human it authenticated.  The broker still judges that human (approver allowlist, no
self-approval, no agent approver).

Who may do what -- the private tier's front door (:func:`.agents.auth.authorize`: trusted proxy
address, shared front-door secret header, the forward-auth identity header), then a group:

=========================  ==================================================================
see the queue (``GET``)    the **viewer group** (the private tier's) *or* the approver group:
                           pending params are as sensitive as the private tier's details
approve / deny (``POST``)  the **approver group** only, distinct from the viewer group
=========================  ==================================================================

The approver sent to the broker is ``issuer`` = the configured SSO issuer and ``subject`` = the
forward-auth username **unchanged** -- **never anything from the form body**, which may carry
only ``request_id``, ``digest``, ``decision``, ``token`` and ``note``.  The broker matches its
approver allowlist exactly, and an IdP's usernames are case-sensitive (Authentik's are: ``Bob``
and ``bob`` can be two accounts), so the hub never folds one into another: a username that is not
already a canonical approver subject (:data:`SUBJECT_RE`, the approval schema's: lower-case, a
letter first, then letters, digits, ``.``, ``_`` or ``-``) cannot decide (``403``) and the page
says why.

This is the hub's only state-changing endpoint, so a decision passes, in order (first failure
answers): the front door and the approver group (``403``); a same-origin ``Origin`` (or, without
one, ``Referer``) -- scheme, host and port equal to the configured ``public_origin``, or, without
one, host and port equal to the request's ``Host`` (:func:`same_origin`) -- and no cross-site
``Sec-Fetch-Site`` (``403``);
``application/x-www-form-urlencoded`` (``415``) with a ``Content-Length`` (``411``) of at most
8 KiB (``413``) holding exactly the fields above, each well-formed (``400``); the CSRF token
(``403``): an HMAC over the issue time, the request id, the digest shown and the approver, valid
for :data:`TOKEN_TTL_S`, under the key ``approvals.csrf_key`` names in the secret store (so a token
survives a restart and verifies on every hub instance with that key; without it, a key drawn when
the hub starts, and a startup warning); then the broker's **current** digest
for that request must equal the one the form carries -- the human approves exactly what they saw
(``409``).  A re-submit of a decision the same approver already made answers ``200`` "already
decided" and files nothing; a request no longer awaiting approval is ``409``; a broker refusal is
``403`` with its reason; an unreachable broker ``502``.  Every attempt, refused or not, is one line
in the hub's access log (``view: approve | deny | decide``, ``request``, ``outcome``, ``reason``).

Rendering is escaped text only and the page has no script; its CSP is the hub's, except that
``form-action`` is ``'self'`` so the decision forms can post back to the hub, and its
``Referrer-Policy`` is ``same-origin`` (the hub's ``no-referrer`` would make a browser send
``Origin: null`` with the form, which the same-origin check refuses).  A request shows its form
again when its approval expired (``approval_state``, else ``approved``: :func:`approval_valid`).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import time
import urllib.parse
from collections.abc import Callable, Mapping
from datetime import datetime
from typing import Any

from homelabnext._http import content_length
from homelabnext.broker.state import is_id

from .agents.auth import AccessLog, Decision, authorize
from .agents.config import ApprovalsSettings, FrontDoor
from .render import _e, nav_html, shell_html
from .serve import host_header_name, style_hash

Response = tuple[int, str, bytes, dict[str, str]]
HTML = "text/html; charset=utf-8"
PAGE = "/approvals"
DECIDE = "/approvals/decide"
TOKEN_TTL_S = 1800
MAX_FORM_BYTES = 8192
MAX_NOTE = 2000
RECENT = 20
FORM_FIELDS = frozenset({"request_id", "digest", "decision", "token", "note"})
_REQUIRED = FORM_FIELDS - {"note"}
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
#: an approver subject as ``schemas/broker/approval`` takes it, and as the allowlist names it
SUBJECT_RE = re.compile(r"[a-z][a-z0-9._-]{0,63}")  # fullmatch: "$" would take a "\n"
_TOKEN_RE = re.compile(r"^[0-9]{1,12}\.[0-9a-f]{64}$")
_DECISIONS = {"approve": "approved", "deny": "denied"}
#: the hub's CSP with forms allowed to post back to the hub (and nowhere else)
CSP = (
    f"default-src 'none'; style-src {style_hash()}; img-src 'self' data:; "
    "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
)
#: ``Referrer-Policy: same-origin`` on these pages (the hub's is ``no-referrer``): under
#: ``no-referrer`` a browser sends ``Origin: null`` and no ``Referer`` with the form's ``POST``,
#: which the same-origin check rightly refuses; ``same-origin`` sends the real Origin to this host
#: and still nothing to any other
_PAGE_HEADERS = {"Content-Security-Policy": CSP, "Referrer-Policy": "same-origin"}


def _text(code: int, message: str) -> Response:
    return code, "text/plain; charset=utf-8", (message + "\n").encode("utf-8"), {}


def _age(created: str, now: float) -> str:
    try:
        then = datetime.fromisoformat(str(created).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return ""
    s = max(0, int(now - then))
    if s < 120:
        return f"{s}s"
    if s < 7200:
        return f"{s // 60}m"
    if s < 172800:
        return f"{s // 3600}h"
    return f"{s // 86400}d"


def _reason(exc: Exception) -> str:
    return str(getattr(exc, "reason", "") or type(exc).__name__)


def approval_valid(row: Mapping[str, Any]) -> bool:
    """True when a pending row has a still-valid, unconsumed approval: ``approval_state`` when
    the broker reports it (``none | valid | expired | consumed``), else its ``approved`` flag."""
    state = row.get("approval_state")
    if state is not None:
        return state == "valid"
    return bool(row.get("approved"))


_DEFAULT_PORTS = {"http": 80, "https": 443}


def origin_tuple(value: str | None) -> tuple[str, str, int] | None:
    """(scheme, host, port) of an http(s) origin or URL, the port made explicit; None for
    ``null``, other schemes and garbage."""
    try:
        parts = urllib.parse.urlsplit((value or "").strip())
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS or not parts.hostname:
        return None
    return scheme, parts.hostname.rstrip(".").lower(), port or _DEFAULT_PORTS[scheme]


def _host_port(value: str | None) -> tuple[str, int | None] | None:
    name = host_header_name(value)
    if name is None:
        return None
    try:
        return name.lower(), urllib.parse.urlsplit(f"//{value.strip()}").port  # type: ignore[union-attr]
    except ValueError:
        return None


def same_origin(headers: Any, public_origin: str | None = None) -> tuple[bool, str]:
    """True when a state-changing request comes from a page of this hub: its ``Origin`` (or,
    when absent, its ``Referer``) is ``public_origin`` -- scheme, host and port, compared
    exactly -- or, when no public origin is configured, names the ``Host`` it was sent to, host
    and port (a ``Host`` without a port matches the origin scheme's default port; the scheme
    itself cannot be checked behind a TLS-terminating proxy, which is why ``public_origin`` is
    the better setting).  ``Sec-Fetch-Site``, when sent, must be ``same-origin``.  No header at
    all is refused (fail closed); so is another port or scheme on the same hostname, which is
    another origin."""
    site = headers.get("Sec-Fetch-Site")
    if site is not None and site.strip().lower() != "same-origin":
        return False, "cross-site request"
    origin = headers.get("Origin")
    if origin is None:
        origin = headers.get("Referer")
        if origin is None:
            return False, "no Origin or Referer"
    got = origin_tuple(origin)
    if got is None:
        return False, "foreign Origin"
    if public_origin is not None:
        return (True, "") if got == origin_tuple(public_origin) else (False, "foreign Origin")
    host = _host_port(headers.get("Host"))
    if host is None or host[0] != got[1] or (host[1] or _DEFAULT_PORTS[got[0]]) != got[2]:
        return False, "foreign Origin"
    return True, ""


class ApprovalsSite:
    """``/approvals`` over one broker relay client (``BrokerClient`` or anything with its
    ``pending``, ``audit``, ``approve`` and ``deny`` methods)."""

    def __init__(
        self,
        client: Any,
        settings: ApprovalsSettings,
        front_door: FrontDoor,
        *,
        clock: Callable[[], float] = time.time,
        key: bytes | None = None,
    ) -> None:
        self.client = client
        self.settings = settings
        self.front_door = front_door
        self.clock = clock
        self.access_log = AccessLog(front_door.access_log, clock=clock)
        #: True when the token key came from the secret store (``approvals.csrf_key``): tokens
        #: then survive a restart and verify on every hub instance given the same key
        self.persistent_key = key is not None or settings.csrf_key is not None
        self._key = key if key is not None else (settings.csrf_key or os.urandom(32))

    @classmethod
    def from_settings(
        cls, settings: ApprovalsSettings, front_door: FrontDoor, **kw: Any
    ) -> ApprovalsSite:
        from homelabnext.broker.client import BrokerClient

        return cls(
            BrokerClient(settings.socket, timeout_s=settings.timeout_s), settings, front_door, **kw
        )

    # ---------------------------------------------------------------- who
    def _viewer(self, client: str | None, headers: Any) -> Decision:
        d = authorize(self.front_door, client, headers)
        if d.allowed:
            return d
        a = self._approver(client, headers)
        return a if a.allowed else d

    def _approver(self, client: str | None, headers: Any) -> Decision:
        return authorize(self.front_door, client, headers, group=self.settings.approver_group)

    def subject(self, user: str) -> str | None:
        """The approver subject for the front door's ``user``: the username unchanged when it is
        canonical, else None (never folded: two spellings may be two accounts)."""
        return user if SUBJECT_RE.fullmatch(user) else None

    # ---------------------------------------------------------------- the CSRF token
    def token(self, request_id: str, digest: str, user: str, *, at: float | None = None) -> str:
        issued = int(self.clock() if at is None else at)
        return f"{issued}.{self._mac(issued, request_id, digest, user)}"

    def _mac(self, issued: int, request_id: str, digest: str, user: str) -> str:
        msg = "\n".join((str(issued), request_id, digest, self.settings.issuer, user))
        return hmac.new(self._key, msg.encode("utf-8"), hashlib.sha256).hexdigest()

    def token_ok(self, token: str, request_id: str, digest: str, user: str) -> bool:
        if not _TOKEN_RE.match(token):
            return False
        issued_s, mac = token.split(".")
        issued = int(issued_s)
        now = self.clock()
        if issued > now + 60 or now - issued > TOKEN_TTL_S:
            return False
        return hmac.compare_digest(mac, self._mac(issued, request_id, digest, user))

    # ---------------------------------------------------------------- routes
    def handle(
        self, route: str, query: str, doc: Mapping[str, Any], client: str | None, headers: Any
    ) -> Response | None:
        """The ``GET`` response for an approvals route, or None when ``route`` is not one."""
        if route == DECIDE:
            return 405, "text/plain; charset=utf-8", b"POST only\n", {"Allow": "POST"}
        if route != PAGE:
            return None
        d = self._viewer(client, headers)
        if not d.allowed:
            return _text(403, "forbidden: approvals")
        q = urllib.parse.parse_qs(query)
        only = q.get("request", [None])[0]
        only = only if is_id(only) else None
        self.access_log.append(d.user or "", "approvals", request=only)
        can_decide = self._approver(client, headers).allowed
        private = authorize(self.front_door, client, headers).allowed
        return self._page(doc, d, private, can_decide, only)

    def _page(
        self, doc, d: Decision, private: bool, can_decide: bool, only: str | None
    ) -> Response:
        user = d.user or ""
        try:
            pending = self.client.pending()
            recent = self._recent()
        except Exception as exc:  # the broker is down or refused the relay: say so, show nothing
            main = (
                "<h2>Approvals</h2>"
                f'<p class="fail">The broker did not answer ({_e(_reason(exc))}).</p>'
            )
            return self._shell(doc, private, main, code=502)
        rows = [r for r in pending if only is None or r.get("request_id") == only]
        now = self.clock()
        subject = self.subject(user)
        if subject is None:
            can_decide = False
        role = "approver" if can_decide else "viewer (read only)"
        filed = (
            f"decisions are filed as <code>{_e(f'{self.settings.issuer}:{subject}')}</code>"
            if subject is not None
            else "this username is not a canonical approver subject (lower-case), so it cannot "
            "decide"
        )
        parts = [
            "<h2>Approvals</h2>",
            f'<p class="muted">signed in as <code>{_e(user)}</code> &middot; {_e(role)} &middot; '
            f"{filed}</p>",
        ]
        if only:
            parts.append(
                f'<p>Showing request <code>{_e(only)}</code> &middot; <a href="{PAGE}">all</a></p>'
            )
        if not rows:
            parts.append('<p class="muted">nothing awaits an approver</p>')
        for r in rows:
            parts.append(self._request_block(r, user, now, can_decide))
        parts.append("<h3>Recent decisions</h3>")
        parts.append(self._recent_table(recent))
        return self._shell(doc, private, "".join(parts))

    def _request_block(self, r: Mapping[str, Any], user: str, now: float, can_decide: bool) -> str:
        rid, digest = str(r.get("request_id", "")), str(r.get("digest", ""))
        params = json.dumps(r.get("params", {}), indent=2, sort_keys=True, ensure_ascii=False)
        facts = "".join(
            f"<dt>{_e(k)}</dt><dd>{v}</dd>"
            for k, v in (
                ("action", f"<code>{_e(r.get('action'))}</code>"),
                ("actor", f"<code>{_e(r.get('actor'))}</code>"),
                ("target", _e(r.get("target") or "")),
                ("created", _e(r.get("created"))),
                ("age", _e(_age(str(r.get("created", "")), now))),
                ("digest", f"<code>{_e(digest)}</code>"),
            )
        )
        valid = approval_valid(r)
        state = " (approved, not yet run)" if valid else ""
        out = [
            f'<div class="pane" id="{_e(rid)}"><h3>Request <code>{_e(rid)}</code>{_e(state)}</h3>',
            f"<dl>{facts}</dl><h4>params</h4><pre>{_e(params)}</pre>",
        ]
        if can_decide and not valid:
            hidden = "".join(
                f'<input type="hidden" name="{k}" value="{_e(v)}">'
                for k, v in (
                    ("request_id", rid),
                    ("digest", digest),
                    ("token", self.token(rid, digest, user)),
                )
            )
            out.append(
                f'<form method="post" action="{DECIDE}">{hidden}'
                f'<label>note <input type="text" name="note" maxlength="{MAX_NOTE}"></label> '
                '<button type="submit" name="decision" value="approve">Approve</button> '
                '<button type="submit" name="decision" value="deny">Deny</button></form>'
            )
        out.append("</div>")
        return "".join(out)

    def _recent(self) -> list[Mapping[str, Any]]:
        # two bounded reads (``tail``): the hub never pulls more than RECENT rows of each; the
        # broker answers both from its decisions index, not by walking its whole audit trail
        rows = [
            *self.client.audit(operation="approve", outcome="ok", tail=RECENT),
            *self.client.audit(operation="deny", outcome="ok", tail=RECENT),
        ]
        return sorted(rows, key=lambda r: str(r.get("at", "")), reverse=True)[:RECENT]

    @staticmethod
    def _recent_table(rows) -> str:
        if not rows:
            return '<p class="muted">no decisions yet</p>'
        body = "".join(
            "<tr>"
            + "".join(
                f"<td>{_e(r.get(k) or '')}</td>"
                for k in ("at", "operation", "caller", "action", "request_id")
            )
            + "</tr>"
            for r in rows
        )
        head = "".join(f"<th>{h}</th>" for h in ("When", "Decision", "By", "Action", "Request"))
        return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"

    def _shell(self, doc, private: bool, main: str, *, code: int = 200) -> Response:
        """``private``: the request may see the private menu group (the viewer group)."""
        html = shell_html(doc, "Approvals", main, nav=nav_html(doc, live=True, private=private))
        return code, HTML, html.encode("utf-8"), dict(_PAGE_HEADERS)

    # ---------------------------------------------------------------- the decision
    def refuse(self, client: str | None, headers: Any, code: int, reason: str) -> Response:
        """A decision refused before the form is read (the server's host guard), logged."""
        user = self._approver(client, headers).user or ""
        self.access_log.append(user, "decide", outcome="refused", reason=reason)
        return _text(code, f"forbidden: {reason}")

    def decide(
        self,
        doc: Mapping[str, Any],
        client: str | None,
        headers: Any,
        read_body: Callable[[int], bytes],
    ) -> Response:
        """``POST /approvals/decide`` (see the module doc).  ``read_body(n)`` reads ``n`` bytes."""
        d = self._approver(client, headers)
        user = d.user or ""
        log = {"request": None, "decision": None}

        def refuse(code: int, view: str, reason: str) -> Response:
            self.access_log.append(user, view, outcome="refused", reason=reason, **log)
            return _text(code, f"refused: {reason}")

        if not d.allowed:
            return refuse(403, "decide", "not an approver through the front door")
        subject = self.subject(user)
        if subject is None:
            return refuse(403, "decide", "username is not a canonical approver subject")
        ok, why = same_origin(headers, self.settings.public_origin)
        if not ok:
            return refuse(403, "decide", why)
        ctype = (headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if ctype != "application/x-www-form-urlencoded":
            return refuse(415, "decide", "not a form")
        length = content_length(headers.get("Content-Length"))
        if length is None:  # absent, or not ASCII digits: refused (and logged), never parsed
            return refuse(411, "decide", "no Content-Length")
        if length > MAX_FORM_BYTES:
            return refuse(413, "decide", "form too large")
        try:
            raw = read_body(length).decode("utf-8")
            form = urllib.parse.parse_qs(raw, keep_blank_values=True, strict_parsing=bool(raw))
        except (UnicodeDecodeError, ValueError):
            return refuse(400, "decide", "malformed form")
        if any(len(v) != 1 for v in form.values()) or not set(form) <= FORM_FIELDS:
            return refuse(400, "decide", "unexpected or repeated form fields")
        f = {k: v[0] for k, v in form.items()}
        if not set(f) >= _REQUIRED:
            return refuse(400, "decide", "missing form fields")
        rid, digest, op, note = f["request_id"], f["digest"], f["decision"], f.get("note") or None
        if not is_id(rid):
            return refuse(400, "decide", "malformed request_id")
        log["request"] = rid
        if op not in _DECISIONS:
            return refuse(400, "decide", "decision is approve or deny")
        log["decision"] = op
        if not _DIGEST_RE.match(digest):
            return refuse(400, op, "malformed digest")
        if note is not None and len(note) > MAX_NOTE:
            return refuse(400, op, "note too long")
        if not self.token_ok(f["token"], rid, digest, user):
            return refuse(403, op, "bad or expired form token")

        private = authorize(self.front_door, client, headers).allowed
        try:
            pending = {r.get("request_id"): r for r in self.client.pending()}
            row = pending.get(rid)
            if row is None or (approval_valid(row) and op == "approve"):
                # "already" only while the decision still stands: a denial removes the request,
                # a valid approval keeps it pending; an approval that ran (the request is gone)
                # or expired (the request is pending without one) is not "already approved"
                standing = op == "deny" if row is None else True
                if standing and self._already(rid, op, subject):
                    self.access_log.append(user, op, outcome="unchanged", reason="already", **log)
                    return self._result(
                        doc, private, f"Request {rid} was already {_DECISIONS[op]}."
                    )
                return refuse(409, op, "not awaiting approval")
            if row.get("digest") != digest:
                return refuse(409, op, "digest mismatch: the request is not what was shown")
            fn = self.client.approve if op == "approve" else self.client.deny
            fn(rid, self.settings.issuer, subject, note=note)
        except Exception as exc:
            reason = _reason(exc)
            code = 502 if reason == "transport-error" else 403
            return refuse(code, op, f"broker: {reason}")
        self.access_log.append(user, op, outcome="ok", **log)
        return self._result(doc, private, f"Request {rid} {_DECISIONS[op]}.")

    def _already(self, rid: str, op: str, subject: str) -> bool:
        who = f"{self.settings.issuer}:{subject}"
        rows = self.client.audit(request_id=rid, operation=op, outcome="ok", tail=50)
        return any(r.get("caller") == who for r in rows)

    def _result(self, doc, private: bool, message: str) -> Response:
        main = (
            f'<h2>Approvals</h2><p>{_e(message)}</p><p><a href="{PAGE}">Back to approvals</a></p>'
        )
        return self._shell(doc, private, main)
