# SPDX-License-Identifier: Apache-2.0
"""``edge`` (extended): routing, forward-auth enforcement and header hygiene of a reverse proxy."""

from __future__ import annotations

from conformance.fakes.edge_proxy import FakeEdgeProxy, SpoofableEdgeProxy
from conformance.protocols.edge import IDENTITY_HEADER, Request, Response
from homelabnext.conform.core import Mutant, Suite

from ._util import ip

SUITE = Suite(
    "edge",
    "reverse proxy: host/prefix routing, forward-auth, identity header hygiene, 502 on failure",
    "conformance.protocols.edge:EdgeProxy",
    tier="extended",
)

HOST = "app.lab.example"


class _Up:
    def __init__(self, name):
        self.name, self.seen = name, []

    def __call__(self, req: Request) -> Response:
        self.seen.append(req)
        return Response(200, self.name)


def _proxy(p, **routes):
    ups = {}
    for name in ("app", "admin", "boom"):
        ups[name] = _Up(name)
        p.add_upstream(name, ups[name])

    def explode(req):
        raise RuntimeError("upstream down")

    p.add_upstream("boom", explode)
    p.set_authenticator(lambda h: "alice" if h.get("authorization") == "Bearer good" else None)
    return ups


@SUITE.check("known-host-routes-to-upstream", "a configured host reaches its upstream")
def _(p):
    ups = _proxy(p)
    p.add_route(HOST, "app")
    r = p.handle(Request(HOST, "/x"))
    assert (r.status, r.body) == (200, "app") and len(ups["app"].seen) == 1


@SUITE.check("unknown-host-is-404", "an unconfigured host never reaches any upstream")
def _(p):
    ups = _proxy(p)
    p.add_route(HOST, "app")
    assert p.handle(Request("other.lab.example", "/")).status == 404
    assert ups["app"].seen == []


@SUITE.check(
    "host-match-ignores-case-and-port", "Host matching is case-insensitive and ignores the port"
)
def _(p):
    _proxy(p)
    p.add_route(HOST, "app")
    assert p.handle(Request("APP.Lab.Example:8443", "/")).status == 200


@SUITE.check("longest-prefix-wins", "the most specific path prefix selects the upstream")
def _(p):
    _proxy(p)
    p.add_route(HOST, "app", prefix="/")
    p.add_route(HOST, "admin", prefix="/admin")
    assert p.handle(Request(HOST, "/admin/users")).body == "admin"
    assert p.handle(Request(HOST, "/adminx")).body == "app", "prefix matched across a path segment"


@SUITE.check(
    "auth-required-blocks-anonymous",
    "a protected route returns 401 and never contacts the upstream",
)
def _(p):
    ups = _proxy(p)
    p.add_route(HOST, "admin", prefix="/admin", auth=True)
    assert p.handle(Request(HOST, "/admin")).status == 401
    assert ups["admin"].seen == [], "an unauthenticated request reached the upstream"


@SUITE.check(
    "auth-sets-identity-header", "an authenticated request carries the user the proxy resolved"
)
def _(p):
    ups = _proxy(p)
    p.add_route(HOST, "admin", prefix="/admin", auth=True)
    r = p.handle(Request(HOST, "/admin", headers={"authorization": "Bearer good"}))
    assert r.status == 200
    assert ups["admin"].seen[0].headers.get(IDENTITY_HEADER) == "alice"


@SUITE.check(
    "spoofed-identity-header-stripped",
    "a client-supplied identity header never reaches the upstream",
)
def _(p):
    ups = _proxy(p)
    p.add_route(HOST, "app", prefix="/")
    p.handle(Request(HOST, "/", headers={IDENTITY_HEADER: "root"}))
    assert IDENTITY_HEADER not in ups["app"].seen[0].headers, "client-chosen identity was forwarded"
    p.add_route(HOST, "admin", prefix="/admin", auth=True)
    p.handle(
        Request(HOST, "/admin", headers={IDENTITY_HEADER: "root", "authorization": "Bearer good"})
    )
    assert ups["admin"].seen[0].headers.get(IDENTITY_HEADER) == "alice", "spoofed value won"


@SUITE.check("path-is-normalised-before-routing", "dot segments cannot dodge a protected prefix")
def _(p):
    ups = _proxy(p)
    p.add_route(HOST, "app", prefix="/")
    p.add_route(HOST, "admin", prefix="/admin", auth=True)
    for sneaky in ("/public/../admin", "/./admin", "//admin"):
        r = p.handle(Request(HOST, sneaky))
        assert r.status in (401, 404), f"{sneaky!r} -> {r.status}"
    assert ups["admin"].seen == []


@SUITE.check("upstream-failure-is-502", "an upstream that raises yields 502, not an exception")
def _(p):
    _proxy(p)
    p.add_route(HOST, "boom")
    assert p.handle(Request(HOST, "/")).status == 502


@SUITE.check(
    "forwarded-for-appended", "the client address is appended to X-Forwarded-For", severity="should"
)
def _(p):
    ups = _proxy(p)
    p.add_route(HOST, "app")
    p.handle(Request(HOST, "/", headers={"x-forwarded-for": ip(9, 1)}, client=ip(7, 2)))
    assert ups["app"].seen[0].headers["x-forwarded-for"] == f"{ip(9, 1)}, {ip(7, 2)}"


@SUITE.check(
    "hop-by-hop-headers-dropped",
    "Connection/Upgrade style headers are not forwarded",
    severity="should",
)
def _(p):
    ups = _proxy(p)
    p.add_route(HOST, "app")
    p.handle(
        Request(HOST, "/", headers={"connection": "keep-alive", "upgrade": "h2c", "x-ok": "1"})
    )
    h = ups["app"].seen[0].headers
    assert "connection" not in h and "upgrade" not in h and h.get("x-ok") == "1"


def make_fake():
    return FakeEdgeProxy()


MUTANTS = {
    "identity-header-spoofable": Mutant(
        SpoofableEdgeProxy,
        "spoofed-identity-header-stripped",
        "client-sent X-Auth-User is forwarded untouched",
    ),
}
