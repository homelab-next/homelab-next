# SPDX-License-Identifier: Apache-2.0
"""The hub's Approvals page (ADR-0017 stage 2b): the front door and the approver group, the write
safety of the hub's one POST (same origin, CSRF token, the digest the person saw, idempotent
re-submits, every attempt logged), escaped rendering, the config, the Caddy site, and a round trip
through a real ``hnx broker serve`` socket."""

from __future__ import annotations

import dataclasses
import json
import os
import shutil
import subprocess
import sys
import threading
import time
import urllib.parse
from pathlib import Path

import pytest
import yaml
from agent_helpers import AUTHORIZED, FAKE_SECRET, HOSTILE, front_door, request
from status_helpers import ROOT, T0, VIEWS

from homelabnext.status import build_status, load_views
from homelabnext.status.agents import AgentsConfigError, load_config
from homelabnext.status.agents.config import ApprovalsSettings
from homelabnext.status.approvals import TOKEN_TTL_S, ApprovalsSite, same_origin
from homelabnext.status.model import iso
from homelabnext.status.serve import LOOPBACK, make_server

DIGEST = "sha256:" + "ab" * 32
OTHER_DIGEST = "sha256:" + "cd" * 32
RID = "req-0a1b2c3d4e5f6a7b"
APPROVER = {**AUTHORIZED, "X-Authentik-Groups": "staff|hub-approvers"}
VIEWER = dict(AUTHORIZED)  # in the viewer group, not the approver group
DOC_ADDR = ".".join(["192", "0", "2", "10"])
KEY = b"fake-csrf-key-0123456789abcdef!!"


class FakeBroker:
    """The relay half of ``BrokerClient``: pending rows, audit rows, and what it was asked."""

    def __init__(self):
        self.rows = [
            {
                "request_id": RID,
                "action": "service.restart",
                "actor": "profile:triage",
                "target": "svc:queue",
                "params": {"grace_s": 30, "why": HOSTILE},
                "created": iso(T0 - 300),
                "digest": DIGEST,
                "approved": False,
            }
        ]
        self.audit_rows: list[dict] = []
        self.calls: list[tuple] = []
        self.down = False

    def _check(self):
        if self.down:
            err = RuntimeError("no socket")
            err.reason = "transport-error"
            raise err

    def pending(self):
        self._check()
        return [dict(r) for r in self.rows]

    def audit(self, *, tail=50, **match):
        self._check()
        rows = [r for r in self.audit_rows if all(r.get(k) == v for k, v in match.items() if v)]
        return rows[-tail:]

    def _decide(self, op, rid, issuer, subject, note=None):
        self._check()
        self.calls.append((op, rid, issuer, subject, note))
        who = f"{issuer}:{subject}"
        self.audit_rows.append(
            {"at": iso(T0), "operation": op, "outcome": "ok", "caller": who,
             "action": "service.restart", "request_id": rid}
        )  # fmt: skip
        for r in self.rows:
            if r["request_id"] == rid:
                r["approved"] = op == "approve"
        if op == "deny":
            self.rows = [r for r in self.rows if r["request_id"] != rid]
        return {"decision": "approved" if op == "approve" else "denied"}

    def approve(self, rid, issuer, subject, *, note=None):
        return self._decide("approve", rid, issuer, subject, note)

    def deny(self, rid, issuer, subject, *, note=None):
        return self._decide("deny", rid, issuer, subject, note)


SETTINGS = ApprovalsSettings(
    socket=Path("/run/x.sock"), issuer="sso", approver_group="hub-approvers"
)


def _doc(registry, approvals=False):
    snap = {"now": iso(T0), "observations": [], "sources": []}
    return build_status(snap, load_views(VIEWS), registry, [], approvals=approvals)


@pytest.fixture
def broker():
    return FakeBroker()


@pytest.fixture
def served(tmp_path, clock, registry, broker):
    """``start(trusted=LOOPBACK, approvals=True, settings=SETTINGS, key=KEY) -> (base, site)``
    (``key=None``: the key the settings give, as ``hnx status serve`` builds it)."""
    servers = []

    def start(trusted=LOOPBACK, approvals=True, settings=SETTINGS, key=KEY):
        fd = front_door(tmp_path, trusted)
        site = ApprovalsSite(broker, settings, fd, clock=clock, key=key)
        srv = make_server(
            lambda: _doc(registry, approvals=approvals), approvals=site if approvals else None
        )
        threading.Thread(target=srv.serve_forever, args=(0.05,), daemon=True).start()
        servers.append(srv)
        host, port = srv.server_address[:2]
        return f"http://{host}:{port}", site

    yield start
    for srv in servers:
        srv.shutdown()
        srv.server_close()


def _form(site, *, rid=RID, digest=DIGEST, decision="approve", user="operator", **extra):
    fields = {"request_id": rid, "digest": digest, "decision": decision}
    fields["token"] = extra.pop("token", None) or site.token(rid, digest, user)
    fields.update(extra)
    return urllib.parse.urlencode(fields).encode()


def _post(
    base, body, headers=APPROVER, *, origin="same", ctype="application/x-www-form-urlencoded"
):
    h = {**headers, "Content-Type": ctype}
    if origin == "same":
        h["Origin"] = base
    elif origin is not None:
        h["Origin"] = origin
    return request(base, "/approvals/decide", method="POST", headers=h, body=body)


def _log(tmp_path):
    path = tmp_path / "access.jsonl"
    return [json.loads(x) for x in path.read_text().splitlines()] if path.exists() else []


# ---------------------------------------------------------------- the page
def test_the_page_lists_pending_escaped_with_its_csp_and_no_script(served, broker):
    broker.audit_rows.append(
        {"at": iso(T0 - 60), "operation": "deny", "outcome": "ok", "caller": "sso:operator",
         "action": HOSTILE, "request_id": "req-older"}
    )  # fmt: skip
    base, _ = served()
    status, headers, body = request(base, "/approvals", headers=APPROVER)
    html = body.decode()
    assert status == 200
    csp = headers["Content-Security-Policy"]
    assert "default-src 'none'" in csp and "form-action 'self'" in csp and "script" not in csp
    assert "frame-ancestors 'none'" in csp
    assert "<script" not in html and HOSTILE not in html  # escaped, never interpreted
    assert "&lt;script&gt;" in html
    for text in (RID, "service.restart", "profile:triage", "svc:queue", DIGEST, "5m", "req-older"):
        assert text in html
    assert 'action="/approvals/decide"' in html and 'name="token"' in html
    assert "decisions are filed as <code>sso:operator</code>" in html


def test_a_viewer_sees_the_queue_without_forms(served, tmp_path):
    base, _ = served()
    status, _, body = request(base, "/approvals", headers=VIEWER)
    assert status == 200 and RID in body.decode() and "<form" not in body.decode()
    assert _log(tmp_path)[-1]["view"] == "approvals"


def test_request_filter_and_an_unreachable_broker(served, broker):
    base, _ = served()
    status, _, body = request(base, f"/approvals?request={RID}", headers=VIEWER)
    assert status == 200 and "Showing request" in body.decode()
    broker.down = True
    status, _, body = request(base, "/approvals", headers=VIEWER)
    assert status == 502 and "transport-error" in body.decode() and RID not in body.decode()


# ---------------------------------------------------------------- the auth matrix
@pytest.mark.parametrize(
    "trusted, headers, get_status, post_status",
    [
        (DOC_ADDR, APPROVER, 403, 403),  # not from the trusted proxy
        (LOOPBACK, {**APPROVER, "X-Hnx-Front-Door": "fake-wrong-secret"}, 403, 403),
        (LOOPBACK, {k: v for k, v in APPROVER.items() if k != "X-Authentik-Username"}, 403, 403),
        (LOOPBACK, {**APPROVER, "X-Authentik-Groups": "staff"}, 403, 403),  # neither group
        (LOOPBACK, VIEWER, 200, 403),  # viewer, not approver: reads, never decides
        (LOOPBACK, {**APPROVER, "X-Authentik-Groups": "hub-approvers"}, 200, 200),  # approver only
        (LOOPBACK, APPROVER, 200, 200),
    ],
)
def test_auth_matrix(served, broker, tmp_path, trusted, headers, get_status, post_status):
    base, site = served(trusted)
    assert request(base, "/approvals", headers=headers)[0] == get_status
    status, _, _ = _post(base, _form(site), headers)
    assert status == post_status
    assert bool(broker.calls) is (post_status == 200)
    assert _log(tmp_path)[-1]["outcome"] == ("ok" if post_status == 200 else "refused")


# ---------------------------------------------------------------- CSRF and the form
@pytest.mark.parametrize(
    "origin, extra, reason",
    [
        (None, {}, "no Origin or Referer"),
        ("https://evil.example", {}, "host not allowed"),  # the hub's own Origin guard
        ("null", {}, "host not allowed"),
        (None, {"Referer": "https://evil.example/x"}, "foreign Origin"),
        ("same", {"Sec-Fetch-Site": "cross-site"}, "cross-site request"),
    ],
)
def test_cross_origin_posts_are_refused(served, broker, tmp_path, origin, extra, reason):
    base, site = served()
    status, _, body = _post(base, _form(site), {**APPROVER, **extra}, origin=origin)
    assert status == 403 and reason in body.decode() and broker.calls == []
    assert _log(tmp_path)[-1]["reason"] == reason


def test_another_port_on_the_same_host_is_another_origin(served, broker, tmp_path):
    """The check compared hostnames only, so a page on another port of the hub's host (another
    service, another origin) could post a decision."""
    base, site = served()
    port = int(base.rsplit(":", 1)[1])
    other = f"http://{LOOPBACK}:{port + 1 if port < 65535 else port - 1}"
    for headers, origin in (
        (APPROVER, other),
        ({**APPROVER, "Referer": other + "/approvals"}, None),
    ):
        status, _, body = _post(base, _form(site), headers, origin=origin)
        assert status == 403 and "foreign Origin" in body.decode(), (origin, headers)
    assert broker.calls == [] and _log(tmp_path)[-1]["reason"] == "foreign Origin"


def test_a_configured_public_origin_is_compared_in_full(served, broker):
    """With ``public_origin`` the scheme counts too: behind a TLS-terminating edge, an ``http``
    page on the hub's name is not the ``https`` page the person uses."""
    base, site = served()
    hostport = base.removeprefix("http://")
    public = f"https://{hostport}"  # what browsers see through the edge
    site.settings = dataclasses.replace(SETTINGS, public_origin=public)
    for origin in (base, f"{public}0", f"https://{LOOPBACK}"):
        status, _, body = _post(base, _form(site), origin=origin)
        assert status == 403 and "foreign Origin" in body.decode(), origin
    assert broker.calls == []
    assert _post(base, _form(site), origin=public)[0] == 200
    assert broker.calls == [("approve", RID, "sso", "operator", None)]


HUB = "hub.lab.example"


@pytest.mark.parametrize(
    "host, origin, public, ok",
    [
        ("", "https://", None, True),
        ("", "http://", None, True),  # no public origin: the scheme cannot be checked
        (":8443", "https://:8443", None, True),
        ("", "https://:8443", None, False),  # another port is another origin
        (":8443", "https://", None, False),
        ("", "https://", "https://", True),
        ("", "https://:443", "https://", True),  # the default port, spelled out
        ("", "http://", "https://", False),  # with a public origin, the scheme counts
        ("", "https://:444", "https://", False),
        ("", "https://:99999", None, False),  # not a port
    ],
)
def test_same_origin_compares_scheme_host_and_port(host, origin, public, ok):
    def url(spec):  # "https://:8443" -> the hub's name with that scheme and port
        scheme, _, port = spec.partition("//")
        return f"{scheme}//{HUB}{port}"

    headers = {"Host": HUB + host, "Origin": url(origin)}
    assert same_origin(headers, url(public) if public else None)[0] is ok
    referer = {"Host": HUB + host, "Referer": url(origin) + "/approvals?x"}
    assert same_origin(referer, url(public) if public else None)[0] is ok


def test_a_same_origin_referer_is_enough_without_origin(served, broker):
    base, site = served()
    headers = {**APPROVER, "Referer": base + "/approvals", "Sec-Fetch-Site": "same-origin"}
    assert _post(base, _form(site), headers, origin=None)[0] == 200
    assert broker.calls == [("approve", RID, "sso", "operator", None)]


@pytest.mark.parametrize(
    "token_for, reason",
    [
        ({"token": "1.fake0deadbeef"}, "bad or expired"),
        ({"token": "fake"}, "bad or expired"),
        ({"rid": "req-other"}, "bad or expired"),  # a token minted for another request
        ({"user": "someone-else"}, "bad or expired"),  # ... or another approver
        ({"digest": OTHER_DIGEST}, "bad or expired"),  # ... or another digest
    ],
)
def test_a_bad_token_is_refused(served, broker, token_for, reason):
    base, site = served()
    if "token" in token_for:
        token = token_for["token"]
    else:
        args = {"rid": RID, "digest": DIGEST, "user": "operator", **token_for}
        token = site.token(args["rid"], args["digest"], args["user"])
    status, _, body = _post(base, _form(site, token=token))
    assert status == 403 and reason in body.decode() and broker.calls == []


def test_an_expired_token_is_refused(served, broker, clock):
    base, site = served()
    body = _form(site)
    clock.advance(TOKEN_TTL_S + 1)
    assert _post(base, body)[0] == 403 and broker.calls == []


@pytest.mark.parametrize(
    "body, ctype, code",
    [
        (None, "application/json", 415),
        ("subject=evil", None, 400),  # the approver can never come from the form
        ("issuer=other", None, 400),
        ("decision=maybe", None, 400),
        ("request_id=..%2Fx", None, 400),
        ("note=" + "x" * 2001, None, 400),
    ],
)
def test_malformed_forms_are_refused(served, broker, body, ctype, code):
    base, site = served()
    base_form = _form(site).decode()
    if body and body.split("=")[0] in ("decision", "request_id"):
        key = body.split("=")[0]
        parts = [p for p in base_form.split("&") if not p.startswith(key + "=")]
        data = "&".join([*parts, body])
    else:
        data = base_form + ("&" + body if body else "")
    status, _, _ = _post(base, data.encode(), ctype=ctype or "application/x-www-form-urlencoded")
    assert status == code and broker.calls == []


def test_a_large_body_is_refused_unread(served, broker):
    base, _ = served()
    assert _post(base, b"note=" + b"x" * 9000)[0] == 413 and broker.calls == []


# ---------------------------------------------------------------- the digest and idempotency
def test_the_digest_shown_must_be_the_brokers_current_one(served, broker, tmp_path):
    base, site = served()
    status, _, body = _post(base, _form(site, digest=OTHER_DIGEST))
    assert status == 409 and "digest mismatch" in body.decode() and broker.calls == []
    assert _log(tmp_path)[-1]["reason"].startswith("digest mismatch")


def test_approve_files_the_front_door_identity_and_re_submits_are_idempotent(
    served, broker, tmp_path
):
    base, site = served()
    headers = {**APPROVER, "X-Authentik-Username": "operator.one"}
    form = _form(site, user="operator.one", note="ok to restart")
    status, _, body = _post(base, form, headers)
    assert status == 200 and "approved" in body.decode()
    # the username unchanged: never folded to operator-one, which may be another account
    assert broker.calls == [("approve", RID, "sso", "operator.one", "ok to restart")]
    status, _, body = _post(base, form, headers)  # the same form again
    assert status == 200 and "already approved" in body.decode()
    assert len(broker.calls) == 1, "a re-submit files nothing"
    log = _log(tmp_path)
    assert [e["outcome"] for e in log] == ["ok", "unchanged"]
    assert all(e["request"] == RID and e["view"] == "approve" for e in log)


@pytest.mark.parametrize("user", ["Operator", "OPERATOR", "operator+ops"])
def test_a_non_canonical_username_is_not_folded_and_cannot_decide(served, broker, tmp_path, user):
    """The IdP's usernames are case-sensitive: ``Operator`` is not ``operator``, so the hub never
    lower-cases one into the other's allowlist entry; it refuses to decide for it."""
    base, site = served()
    headers = {**APPROVER, "X-Authentik-Username": user}
    status, _, body = _post(base, _form(site, user=user), headers)
    assert status == 403 and "canonical" in body.decode() and broker.calls == []
    assert _log(tmp_path)[-1]["reason"] == "username is not a canonical approver subject"
    status, _, page = request(base, "/approvals", headers=headers)
    html = page.decode()
    assert status == 200 and "not a canonical approver subject" in html and "<form" not in html


def test_deny_then_resubmit_and_a_request_no_longer_pending(served, broker):
    base, site = served()
    assert _post(base, _form(site, decision="deny"))[0] == 200
    assert _post(base, _form(site, decision="deny"))[0] == 200  # idempotent
    assert [c[0] for c in broker.calls] == ["deny"]
    status, _, body = _post(base, _form(site, decision="approve"))  # denied: cannot approve
    assert status == 409 and "not awaiting approval" in body.decode()


def test_a_broker_refusal_is_reported_with_its_reason(served, broker):
    def refuse(*a, **k):
        from conformance.protocols.broker import Denied

        raise Denied("no", reason="approval-self-approved")

    broker.approve = refuse
    base, site = served()
    status, _, body = _post(base, _form(site))
    assert status == 403 and "approval-self-approved" in body.decode()


# ---------------------------------------------------------------- what a browser sends
#: Referrer-Policy values under which a browser's same-origin form POST carries the page's real
#: Origin (Fetch, "serializing a request origin": only no-referrer turns it into "null")
REAL_ORIGIN_POLICIES = {
    "same-origin", "strict-origin", "strict-origin-when-cross-origin", "origin",
    "origin-when-cross-origin", "no-referrer-when-downgrade", "unsafe-url",
}  # fmt: skip


def _browser_post(base, site, page_headers):
    """The POST a browser makes from a form on a page served with ``page_headers``: Origin (and
    Referer) follow that page's Referrer-Policy, as the Fetch standard serializes them."""
    policy = page_headers["Referrer-Policy"]
    if policy == "no-referrer":
        return _post(base, _form(site), origin="null")  # and no Referer at all
    headers = {**APPROVER, "Referer": base + "/approvals", "Sec-Fetch-Site": "same-origin"}
    return _post(base, _form(site), headers, origin="same")


def test_a_browser_form_post_from_the_page_carries_its_real_origin(served, broker):
    base, site = served()
    _, headers, _ = request(base, "/approvals", headers=APPROVER)
    assert headers["Referrer-Policy"] in REAL_ORIGIN_POLICIES
    status, _, body = _browser_post(base, site, headers)
    assert status == 200, body
    assert broker.calls == [("approve", RID, "sso", "operator", None)]
    # a literal null Origin (an opaque or no-referrer document) is still refused
    assert _post(base, _form(site), origin="null")[0] == 403
    # the rest of the hub keeps sending no referrer
    assert request(base, "/status.json")[1]["Referrer-Policy"] == "no-referrer"


# ---------------------------------------------------------------- the approval's real state
def test_an_expired_approval_shows_the_form_again_and_re_approves(served, broker):
    broker.rows[0].update(approved=True, approval_state="expired")
    broker.audit_rows.append(
        {"at": iso(T0 - 7200), "operation": "approve", "outcome": "ok", "caller": "sso:operator",
         "action": "service.restart", "request_id": RID}
    )  # fmt: skip
    base, site = served()
    _, _, body = request(base, "/approvals", headers=APPROVER)
    assert "<form" in body.decode() and "not yet run" not in body.decode()
    status, _, body = _post(base, _form(site))
    assert status == 200 and "already" not in body.decode()
    assert broker.calls == [("approve", RID, "sso", "operator", None)]  # filed again


@pytest.mark.parametrize("state", ["valid", None])  # None: a broker without approval_state
def test_a_still_valid_approval_is_already_approved(served, broker, state):
    base, site = served()
    assert _post(base, _form(site))[0] == 200
    if state:
        broker.rows[0]["approval_state"] = state
    _, _, body = request(base, "/approvals", headers=APPROVER)
    assert "<form" not in body.decode() and "approved, not yet run" in body.decode()
    status, _, body = _post(base, _form(site))
    assert status == 200 and "already approved" in body.decode() and len(broker.calls) == 1


def test_a_consumed_approval_is_not_awaiting_approval(served, broker):
    base, site = served()
    assert _post(base, _form(site))[0] == 200
    broker.rows = []  # the approved request ran: no longer pending
    status, _, body = _post(base, _form(site))
    assert status == 409 and "not awaiting approval" in body.decode()


# ---------------------------------------------------------------- one document per request
def test_each_request_builds_the_document_at_most_once(registry):
    calls = []

    def document():
        calls.append(1)
        return _doc(registry)

    class Passing:  # a page site that serves none of the routes asked for
        def handle(self, *a):
            return None

    p = Passing()
    srv = make_server(document, agents=p, strategy=p, baselines=p, approvals=p)
    threading.Thread(target=srv.serve_forever, args=(0.05,), daemon=True).start()
    try:
        host, port = srv.server_address[:2]
        for path in ("/agents", "/no-such-page"):
            calls.clear()
            assert request(f"http://{host}:{port}", path)[0] == 404
            assert len(calls) <= 1, path
    finally:
        srv.shutdown()
        srv.server_close()


# ---------------------------------------------------------------- the rest stays read-only
def test_the_hub_is_read_only_everywhere_else(served):
    base, site = served()
    assert _post(base, _form(site))[0] == 200
    for path in ("/", "/approvals", "/status.json", "/approvals/decide?x=1/../"):
        h = {**APPROVER, "Origin": base, "Content-Type": "application/x-www-form-urlencoded"}
        if path.startswith("/approvals/decide"):
            continue
        assert request(base, path, method="POST", headers=h, body=b"")[0] == 405
    assert request(base, "/approvals/decide", headers=APPROVER)[0] == 405
    assert request(base, "/approvals", method="PUT", headers=APPROVER)[0] == 405
    off, _ = served(approvals=False)
    assert _post(off, _form(site))[0] == 405
    assert request(off, "/approvals", headers=APPROVER)[0] == 404


# ---------------------------------------------------------------- config and the edge
CSRF_REF = "secret:status/approvals-csrf-secret"
CSRF_KEY = "fake-shared-csrf-key-0123456789abcdef"


def _cfg(tmp_path, registry, secret=FAKE_SECRET, csrf=CSRF_KEY, **approvals):
    """The example agents.yml (no ingest) with ``approvals`` overrides; ``csrf``: the value the
    secret store holds for ``approvals.csrf_key`` (None: not set); ``csrf_key=None`` drops the
    setting itself."""
    doc = yaml.safe_load((ROOT / "examples" / "status" / "agents.yml").read_text())
    doc.pop("ingest")
    if approvals.pop("drop_private", False):
        doc.pop("private")
    doc["approvals"].update(approvals)
    doc["approvals"] = {k: v for k, v in doc["approvals"].items() if v is not None}
    path = tmp_path / "agents.yml"
    path.write_text(yaml.safe_dump(doc))
    return load_config(path, registry, lambda ref: csrf if ref == CSRF_REF else secret)


def test_config(tmp_path, registry):
    cfg = _cfg(tmp_path, registry)
    assert cfg.approvals == ApprovalsSettings(
        socket=Path("/run/hnx-broker/broker.sock"),
        issuer="sso",
        approver_group="hub-approvers",
        csrf_key=CSRF_KEY.encode(),
        public_origin="https://status.lab.example",
    )
    assert CSRF_KEY not in repr(cfg.approvals) and cfg.warnings == []
    loose = _cfg(tmp_path, registry, public_origin=None)
    assert loose.approvals.public_origin is None
    assert any("public_origin is not set" in w for w in loose.warnings)
    with pytest.raises(AgentsConfigError, match="public_origin"):
        _cfg(tmp_path, registry, public_origin="https://status.lab.example/approvals")
    with pytest.raises(AgentsConfigError, match="needs private"):
        _cfg(tmp_path, registry, drop_private=True)
    with pytest.raises(AgentsConfigError, match="must differ"):
        _cfg(tmp_path, registry, approver_group="hub-private-viewers")
    with pytest.raises(AgentsConfigError, match="socket"):
        _cfg(tmp_path, registry, socket="relative/broker.sock")
    off = _cfg(tmp_path, registry, secret=None)  # no front-door secret: no private tier
    assert off.approvals is None and any("approvals page disabled" in w for w in off.warnings)


# ---------------------------------------------------------------- the persistent CSRF key
def _settings(tmp_path, registry, **kw):
    return _cfg(tmp_path, registry, **kw).approvals


def _two_sites(settings, broker, tmp_path, clock, other=None):
    """Two hub instances (two processes' worth of ApprovalsSite) over the same broker."""
    fd = front_door(tmp_path)
    a = ApprovalsSite(broker, settings, fd, clock=clock)
    b = ApprovalsSite(broker, other or settings, fd, clock=clock)
    return a, b


def test_a_token_from_one_instance_verifies_on_another_with_the_same_key(
    served, broker, tmp_path, clock, registry
):
    settings = _settings(tmp_path, registry, public_origin=None)  # the test server's own origin
    a, b = _two_sites(settings, broker, tmp_path, clock)
    assert a.persistent_key and b.persistent_key
    token = a.token(RID, DIGEST, "operator")
    assert b.token_ok(token, RID, DIGEST, "operator")
    # the token still binds the request, the digest and the approver on the second instance
    assert not b.token_ok(token, "req-other", DIGEST, "operator")
    assert not b.token_ok(token, RID, OTHER_DIGEST, "operator")
    assert not b.token_ok(token, RID, DIGEST, "someone-else")
    clock.advance(TOKEN_TTL_S + 1)  # ... and its issue time
    assert not b.token_ok(token, RID, DIGEST, "operator")
    # end to end: a form rendered by instance a is accepted by a restarted hub (instance b)
    clock.t = T0
    base, _ = served(settings=settings, key=None)
    assert _post(base, _form(a))[0] == 200
    assert broker.calls == [("approve", RID, "sso", "operator", None)]


def test_a_token_is_refused_by_an_instance_with_another_key(broker, tmp_path, clock, registry):
    settings = _settings(tmp_path, registry)
    other = _settings(tmp_path, registry, csrf="fake-another-csrf-key-0123456789abcdef")
    a, b = _two_sites(settings, broker, tmp_path, clock, other)
    assert not b.token_ok(a.token(RID, DIGEST, "operator"), RID, DIGEST, "operator")


@pytest.mark.parametrize("value", ["fake-short-key", "f" * 31])
def test_a_short_csrf_key_is_refused_at_config_load(tmp_path, registry, value):
    with pytest.raises(AgentsConfigError, match="csrf_key: the key is shorter than 32") as exc:
        _cfg(tmp_path, registry, csrf=value)
    assert value not in str(exc.value)  # the message names the setting, never the value


def test_the_csrf_key_is_its_own_secret(tmp_path, registry):
    front = registry.services["status-hub"].front_door["secret"]
    with pytest.raises(AgentsConfigError, match="not the front door's"):
        _cfg(tmp_path, registry, csrf_key=front)


@pytest.mark.parametrize(
    "kw, warning",
    [
        ({"csrf_key": None}, "approvals.csrf_key is not set"),  # the setting is absent
        ({"csrf": None}, "approvals.csrf_key names a secret that is not set"),  # unresolved
    ],
)
def test_without_a_csrf_key_a_per_process_key_still_works_within_the_process(
    served, broker, tmp_path, clock, registry, kw, warning
):
    cfg = _cfg(tmp_path, registry, public_origin=None, **kw)
    assert cfg.approvals is not None and cfg.approvals.csrf_key is None
    assert any(w.startswith(warning) and "per-process key" in w for w in cfg.warnings)
    assert not any(FAKE_SECRET in w or CSRF_KEY in w for w in cfg.warnings)
    a, b = _two_sites(cfg.approvals, broker, tmp_path, clock)
    assert not a.persistent_key
    token = a.token(RID, DIGEST, "operator")
    assert a.token_ok(token, RID, DIGEST, "operator")  # within one process: as before
    assert not b.token_ok(token, RID, DIGEST, "operator")  # a restart (new key) refuses it
    base, site = served(settings=cfg.approvals, key=None)
    assert _post(base, _form(site))[0] == 200


# ---------------------------------------------------------------- the menu entry
def test_the_menu_lists_approvals_only_when_configured_and_only_privately(served, registry):
    from homelabnext.status.render import nav_html

    on, off = _doc(registry, approvals=True), _doc(registry)
    entry = next(m for m in on["menu"] if m["id"] == "approvals")
    assert entry == {
        "id": "approvals", "title": "Approvals", "kind": "page", "panel": "approvals",
        "href": "/approvals", "available": True, "group": "private",
    }  # fmt: skip
    assert not next(m for m in off["menu"] if m["id"] == "approvals")["available"]
    link = 'href="/approvals"'
    assert link in nav_html(on, live=True, private=True)
    assert link not in nav_html(on, live=True, private=False)  # the public view: never linked
    assert link not in nav_html(on, private=True)  # the static page: never linked
    assert ">Approvals<" not in nav_html(off, live=True, private=True)  # not configured: absent
    base, _ = served()
    _, _, page = request(base, "/approvals", headers=VIEWER)
    assert link in page.decode()  # the page's own menu, for a private viewer
    _, _, body = request(base, "/status.json")
    assert all(m["id"] != "approvals" for m in json.loads(body)["menu"])  # not in the contract


def test_the_approvals_entry_must_sit_in_the_private_group(registry, specs):
    from homelabnext.status.views import views_problems

    doc = yaml.safe_load(VIEWS.read_text())
    assert views_problems(doc, registry, specs) == []
    next(v for v in doc["menu"] if v["id"] == "approvals").pop("group")
    assert any("private" in p for p in views_problems(doc, registry, specs))


def test_the_generated_caddy_site_covers_the_approvals_path(registry):
    from homelabnext.generators.builtin import caddy

    site = caddy(registry)["caddy/sites.caddy"].split("status.lab.example {", 1)[1]
    site = site.split("\n}", 1)[0]
    # one site-wide handler: forward auth and the front-door header apply to every path and
    # method, /approvals and POST /approvals/decide included; no matcher narrows it
    assert "import hnx_forward_auth" in site and "header_up X-Hnx-Front-Door" in site
    for narrowing in ("handle", "route", "@", "path ", "method "):
        assert narrowing not in site


# ---------------------------------------------------------------- a real broker socket
def _supported() -> bool:
    from homelabnext.broker.server import supported

    return supported()


@pytest.mark.skipif(
    not _supported(), reason="SO_PEERCRED: the broker socket authenticates peers on Linux only"
)
def test_round_trip_through_a_real_broker_socket(tmp_path, clock, registry):
    from homelabnext.broker.service import BrokerService

    src = ROOT / "examples" / "broker"
    dst = tmp_path / "broker"
    shutil.copytree(src, dst)
    doc = yaml.safe_load((src / "manifest.yml").read_text())
    doc.update(dev_identity=False, approval_relays=[{"uid": os.getuid(), "issuer": "sso"}])
    (dst / "manifest.yml").write_text(yaml.safe_dump(doc))
    state = tmp_path / "state"
    # an agent's request, filed in process (an embedding program names its caller)
    svc = BrokerService.from_manifest(dst / "manifest.yml", state)
    rid = svc.submit("profile:triage", "service.restart", {"grace_s": 5}, target="svc:queue")
    sock = tmp_path / "run" / "b.sock"
    proc = subprocess.Popen(
        [sys.executable, "-m", "homelabnext.cli", "broker", "serve", "--manifest",
         str(dst / "manifest.yml"), "--state", str(state), "--socket", str(sock)],
        cwd=ROOT, env={**os.environ, "PYTHONPATH": str(ROOT)}, stderr=subprocess.PIPE,
    )  # fmt: skip
    try:
        for _ in range(100):
            if sock.exists():
                break
            time.sleep(0.1)
        settings = ApprovalsSettings(socket=sock, issuer="sso", approver_group="hub-approvers")
        site = ApprovalsSite.from_settings(settings, front_door(tmp_path), clock=clock)
        srv = make_server(lambda: _doc(registry), approvals=site)
        threading.Thread(target=srv.serve_forever, args=(0.05,), daemon=True).start()
        base = "http://{}:{}".format(*srv.server_address[:2])
        try:
            who = {**APPROVER, "X-Authentik-Username": "operator-one"}
            status, _, body = request(base, "/approvals", headers=who)
            pending = svc.pending()[0]
            assert status == 200 and rid in body.decode() and pending["digest"] in body.decode()
            form = _form(site, rid=rid, digest=pending["digest"], user="operator-one")
            status, _, body = _post(base, form, who)
            assert status == 200, body
            [appr] = svc.state.approvals(rid)
            assert appr["approver"] == {"issuer": "sso", "subject": "operator-one"}
            [rec] = svc.audit_documents(operation="approve", request_id=rid)
            assert rec["outcome"] == "ok" and rec["via"] == f"uid:{os.getuid()}"
            status, _, body = _post(base, form, who)  # the re-submit: already approved
            assert status == 200 and "already approved" in body.decode()
            assert len(svc.state.approvals(rid)) == 1
            status, _, body = request(base, "/approvals", headers=who)
            assert "sso:operator-one" in body.decode()  # in the recent decisions
        finally:
            srv.shutdown()
            srv.server_close()
    finally:
        proc.terminate()
        assert proc.wait(timeout=10) == 0


def test_an_approver_subject_with_a_trailing_newline_is_not_canonical(broker, tmp_path, clock):
    """``^...$`` matches before a final newline: ``operator\\n`` passed as canonical."""
    site = ApprovalsSite(broker, SETTINGS, front_door(tmp_path), clock=clock)
    assert site.subject("operator") == "operator"
    assert site.subject("operator\n") is None and site.subject("operator\r\n") is None
