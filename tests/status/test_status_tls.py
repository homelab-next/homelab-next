# SPDX-License-Identifier: Apache-2.0
"""The hub's mTLS listener (Stage 5, H1; ``homelabnext.status.tls``): real TLS handshakes against
``make_server`` with certificates minted in the test's own temporary directory (never committed),
the client-name pin, the explicit plain-HTTP opt-in, the identity headers dropped from any request
that is not a trusted proxy over a verified certificate, and the hooks' probe."""

from __future__ import annotations

import hashlib
import http.client
import json
import socket
import ssl
import subprocess
import threading
from pathlib import Path

import pytest
import yaml
from agent_helpers import AUTHORIZED, FAKE_SECRET, front_door
from status_helpers import ROOT, VIEWS

from homelabnext.status.serve import (
    LOOPBACK,
    is_identity_header,
    make_server,
    strip_identity,
)
from homelabnext.status.tls import (
    TLSConfigError,
    TLSSettings,
    client_name_ok,
    peer_names,
    probe,
)

pytestmark = pytest.mark.requires_tool("openssl")

EDGE = "edge.example.internal"
OTHER = "other.example.internal"
HEALTH = "hub-health.example.internal"
HUB_SOURCE = "127.0.0.1"  # no-raw-endpoint: allow loopback, the hub's own address here: the health certificate's source
ELSE_SOURCE = "127.0.0.2"  # no-raw-endpoint: allow loopback, another host on the same wire (the edge's, in the lab)
DOC_A = "192.0.2.9"  # no-raw-endpoint: allow a documentation address, bound in the parsing tests
DOC_B = "192.0.2.10"  # no-raw-endpoint: allow a documentation address
DOC_C = "192.0.2.8"  # no-raw-endpoint: allow a documentation address
HUB_HOST = "status.lab.example"
DOC = {"schema_version": 1, "generated_at": "2026-11-13T00:00:00Z", "sources": [], "menu": []}
#: not loopback (the example registry's edge address, never connected to): a front door that
#: trusts only it never trusts the test's own connections
ELSEWHERE = yaml.safe_load((ROOT / "examples/services.yml").read_text())["hosts"]["edge-core"][
    "address"
]


def _openssl(*args: str, cwd: Path) -> None:
    subprocess.run(["openssl", *args], check=True, capture_output=True, timeout=60, cwd=cwd)


def _ca(d: Path, name: str) -> tuple[Path, Path]:
    key, crt = d / f"{name}.key", d / f"{name}.crt"
    _openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
             "-days", "2", "-keyout", str(key), "-out", str(crt), "-subj", f"/CN={name}",
             "-addext", "basicConstraints=critical,CA:TRUE",
             "-addext", "keyUsage=critical,keyCertSign,cRLSign", cwd=d)  # fmt: skip
    return crt, key


def _leaf(d: Path, name: str, ca: tuple[Path, Path], *, san: str, eku: str) -> tuple[Path, Path]:
    key, csr, crt, ext = (d / f"{name}.{x}" for x in ("key", "csr", "crt", "ext"))
    ext.write_text(f"subjectAltName={san}\nextendedKeyUsage={eku}\nbasicConstraints=CA:FALSE\n")
    _openssl("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
             "-keyout", str(key), "-out", str(csr), "-subj", f"/CN={name}", cwd=d)  # fmt: skip
    _openssl("x509", "-req", "-in", str(csr), "-CA", str(ca[0]), "-CAkey", str(ca[1]),
             "-set_serial", str(int(hashlib.sha256(name.encode()).hexdigest()[:12], 16)), "-days", "2", "-out", str(crt),
             "-extfile", str(ext), cwd=d)  # fmt: skip
    return crt, key


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    """A lab CA (the hub's server certificate, the edge's and another client's), and a foreign CA
    with a client certificate of the edge's own name."""
    d = tmp_path_factory.mktemp("pki")
    try:
        ca = _ca(d, "lab-ca")
        rogue = _ca(d, "rogue-ca")
    except (OSError, subprocess.SubprocessError) as exc:  # pragma: no cover - the marker checks
        pytest.fail(f"openssl could not mint the test CA: {exc}")
    return {
        "ca": ca[0],
        "server": _leaf(d, "server", ca, san=f"DNS:localhost,IP:{LOOPBACK}", eku="serverAuth"),
        "edge": _leaf(d, "edge", ca, san=f"DNS:{EDGE}", eku="clientAuth"),
        "other": _leaf(d, "other", ca, san=f"DNS:{OTHER}", eku="clientAuth"),
        "health": _leaf(d, "health", ca, san=f"DNS:{HEALTH}", eku="clientAuth"),
        "server_only": _leaf(d, "srvonly", ca, san=f"DNS:{EDGE}", eku="serverAuth"),
        "rogue": _leaf(d, "rogue", rogue, san=f"DNS:{EDGE}", eku="clientAuth"),
    }


def _settings(pki, names=()) -> TLSSettings:
    crt, key = pki["server"]
    return TLSSettings(crt, key, pki["ca"], frozenset(names))


@pytest.fixture
def serve():
    servers = []

    def start(document=lambda: DOC, **kw):
        kw.setdefault("allowed_hosts", [HUB_HOST])
        srv = make_server(document, host=LOOPBACK, port=0, **kw)
        threading.Thread(target=srv.serve_forever, args=(0.05,), daemon=True).start()
        servers.append(srv)
        return srv.server_address[1]

    yield start
    for srv in servers:
        srv.shutdown()
        srv.server_close()


def _client_ctx(pki, cert: str | None) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=str(pki["ca"]))
    if cert:
        ctx.load_cert_chain(*(str(p) for p in pki[cert]))
    return ctx


def _get(port: int, pki, cert: str | None, path="/status.json", headers=None, source=None):
    """(status, body) over TLS, or raises the TLS/socket error the hub's refusal produced;
    ``source``: the address to connect from (another loopback address stands in for another host)."""
    conn = http.client.HTTPSConnection(
        "localhost", port, context=_client_ctx(pki, cert), timeout=10,
        source_address=(source, 0) if source else None,
    )  # fmt: skip
    try:
        conn.request("GET", path, headers={"Host": HUB_HOST, **(headers or {})})
        r = conn.getresponse()
        return r.status, r.read()
    finally:
        conn.close()


REFUSED = (ssl.SSLError, ConnectionError, http.client.RemoteDisconnected, OSError)


# ---------------------------------------------------------------- the handshake
def test_a_peer_with_the_edge_certificate_is_served(serve, pki):
    port = serve(tls=_settings(pki))
    status, body = _get(port, pki, "edge")
    assert status == 200 and json.loads(body)["generated_at"] == DOC["generated_at"]


@pytest.mark.parametrize("cert", [None, "rogue", "server_only"])
def test_a_peer_without_a_client_certificate_from_the_ca_is_refused_in_the_handshake(
    serve, pki, cert
):
    """No certificate, one from another CA (even naming the edge), or the CA's certificate whose
    key usage is server-only: the connection never carries HTTP."""
    port = serve(tls=_settings(pki))
    with pytest.raises(REFUSED):
        _get(port, pki, cert)


def test_plain_http_on_the_tls_port_gets_no_http_answer(serve, pki):
    port = serve(tls=_settings(pki))
    with socket.create_connection((LOOPBACK, port), timeout=10) as s:
        s.sendall(f"GET /status.json HTTP/1.1\r\nHost: {HUB_HOST}\r\n\r\n".encode())
        try:
            data = s.recv(4096)
        except OSError:
            data = b""
    assert not data.startswith(b"HTTP/")


def test_the_pin_admits_only_the_edges_name(serve, pki):
    port = serve(tls=_settings(pki, [EDGE]))
    assert _get(port, pki, "edge")[0] == 200
    with pytest.raises(REFUSED):
        _get(port, pki, "other")  # signed by the CA, but not the edge


def _bound(pki) -> TLSSettings:
    """The pin as the role writes it: the edge's name (any source), the hooks' own bound to the hub."""
    crt, key = pki["server"]
    return TLSSettings.from_args(
        str(crt), str(key), str(pki["ca"]), [EDGE, f"{HEALTH}@{HUB_SOURCE}"]
    )


def test_the_hooks_certificate_is_accepted_only_from_the_hubs_own_address(serve, pki):
    """Finding G of the first real deploy: the health certificate got 200 from the edge's address
    too, because the pin judged the name alone. Bound to the hub's address it is refused in the
    handshake from any other source, and the edge's certificate, unbound, is unaffected."""
    port = serve(tls=_bound(pki))
    assert _get(port, pki, "health", source=HUB_SOURCE)[0] == 200
    with pytest.raises(REFUSED):
        _get(port, pki, "health", source=ELSE_SOURCE)
    assert _get(port, pki, "edge", source=ELSE_SOURCE)[0] == 200
    assert _get(port, pki, "edge", source=HUB_SOURCE)[0] == 200


def test_a_name_bound_to_addresses_fails_closed_without_a_source_and_in_the_cli_form():
    cert = {"subjectAltName": (("DNS", HEALTH),)}
    s = TLSSettings.from_args("a.crt", "a.key", "ca.crt", [f"{HEALTH}@{DOC_A},2001:db8::1", EDGE])
    assert s.client_sources == {HEALTH: frozenset({DOC_A, "2001:db8::1"})}
    assert s.name_allowed(cert, DOC_A) and s.name_allowed(cert, "2001:db8:0::1")
    assert not s.name_allowed(cert, DOC_B) and not s.name_allowed(cert, None)
    assert not s.name_allowed(cert, "not-an-address")
    assert s.name_allowed({"subjectAltName": (("DNS", EDGE),)}, None)  # unbound: any source
    for bad in (f"{HEALTH}@", f"{HEALTH}@edge.example.internal", f"{HEALTH}@{DOC_A},x"):
        with pytest.raises(TLSConfigError, match="IP addresses"):
            TLSSettings.from_args("a.crt", "a.key", "ca.crt", [bad])
    with pytest.raises(TLSConfigError, match="both bound and unbound"):
        TLSSettings.from_args("a.crt", "a.key", "ca.crt", [HEALTH, f"{HEALTH}@{DOC_A}"])
    with pytest.raises(TLSConfigError, match="two address sets"):
        TLSSettings.from_args(
            "a.crt", "a.key", "ca.crt", [f"{HEALTH}@{DOC_A}", f"{HEALTH}@{DOC_C}"]
        )


def test_a_stalled_peer_does_not_stop_the_hub_accepting(serve, pki):
    """The handshake runs on the connection's thread: one peer that connects and sends nothing
    does not hold the accept loop."""
    port = serve(tls=_settings(pki))
    with socket.create_connection((LOOPBACK, port), timeout=10):
        assert _get(port, pki, "edge")[0] == 200


# ---------------------------------------------------------------- the opt-in and the settings
def test_off_loopback_plain_http_needs_the_explicit_opt_in(pki):
    with pytest.raises(ValueError, match="plain HTTP"):
        make_server(dict, host=ELSEWHERE, allow_remote=True, allowed_hosts=[HUB_HOST])
    with pytest.raises(ValueError, match="exclusive"):
        make_server(dict, tls=_settings(pki), plain_http=True)


def test_tls_settings_go_together_and_pin_only_names():
    assert TLSSettings.from_args(None, None, None) is None
    with pytest.raises(TLSConfigError, match="go together"):
        TLSSettings.from_args("a.crt", None, "ca.crt")
    with pytest.raises(TLSConfigError, match="needs"):
        TLSSettings.from_args(None, None, None, [EDGE])
    with pytest.raises(TLSConfigError, match="wildcard"):
        TLSSettings.from_args("a.crt", "a.key", "ca.crt", ["*.example.internal"])
    assert TLSSettings.from_args(
        "a.crt", "a.key", "ca.crt", ["Edge.Example.Internal."]
    ).client_names == {EDGE}
    assert client_name_ok(EDGE) and not client_name_ok("*.x") and not client_name_ok("a b")


def test_a_bad_certificate_fails_the_start_not_the_first_connection(tmp_path, pki):
    with pytest.raises(TLSConfigError, match="server certificate"):
        make_server(dict, tls=TLSSettings(tmp_path / "no.crt", tmp_path / "no.key", pki["ca"]))
    crt, key = pki["server"]
    with pytest.raises(TLSConfigError, match="client CA"):
        make_server(dict, tls=TLSSettings(crt, key, tmp_path / "no-ca.crt"))


def test_peer_names_prefer_the_sans_over_the_cn():
    cn = ((("commonName", "cn.example"),),)
    assert peer_names({"subject": cn, "subjectAltName": (("DNS", "A.x."),)}) == {"a.x"}
    assert peer_names({"subject": cn}) == {"cn.example"}
    # IP SANs only: the CN is not read (it names nothing the pin can trust)
    assert peer_names({"subject": cn, "subjectAltName": (("IP Address", ELSEWHERE),)}) == set()
    assert peer_names(None) == frozenset()


def test_the_cli_refuses_a_partial_tls_set_and_a_remote_plain_bind(capsys):
    from homelabnext.status.cli import main

    base = ["serve", "--registry", str(ROOT / "examples/services.yml"), "--port", "0"]
    assert main([*base, "--tls-cert", "a.crt"]) == 2
    assert "go together" in capsys.readouterr().err
    rc = main([*base, "--bind", ELSEWHERE, "--allow-remote", "--allowed-host", HUB_HOST])
    assert rc == 2 and "plain HTTP" in capsys.readouterr().err


# ---------------------------------------------------------------- who is the edge
class _Recorder:
    """An Approvals-page stand-in that records what the hub hands it: the client address and
    the headers left on the request."""

    def __init__(self, fd):
        self.front_door = fd
        self.seen: list[tuple[str | None, dict[str, str]]] = []

    def handle(self, route, query, doc, client, headers):
        if route != "/approvals":
            return None
        self.seen.append((client, {k.lower(): v for k, v in headers.items()}))
        return 200, "text/plain; charset=utf-8", b"ok\n"


FORGED = {
    **AUTHORIZED,
    "X-Forwarded-User": "mallory",
    "X-Forwarded-Preferred-Username": "mallory",
    "X-Auth-Request-User": "mallory",
    "X_Auth_Request_Email": "mallory@example.internal",
}


def test_a_forged_identity_from_an_untrusted_peer_is_stripped(serve, pki, tmp_path):
    """A verified certificate whose source is not a trusted proxy: every identity header,
    X-Forwarded-User included, is gone before any site sees the request."""
    rec = _Recorder(front_door(tmp_path, trusted=ELSEWHERE))
    port = serve(tls=_settings(pki), approvals=rec)
    assert _get(port, pki, "edge", "/approvals", FORGED)[0] == 200
    ((client, headers),) = rec.seen
    assert client == LOOPBACK
    assert not [h for h in headers if is_identity_header(h)], headers
    assert headers["x-hnx-front-door"] == FAKE_SECRET  # not an identity header: judged after


def test_a_trusted_proxy_over_a_verified_certificate_keeps_the_identity(serve, pki, tmp_path):
    rec = _Recorder(front_door(tmp_path))  # trusts loopback
    port = serve(tls=_settings(pki, [EDGE]), approvals=rec)
    assert _get(port, pki, "edge", "/approvals", AUTHORIZED)[0] == 200
    ((client, headers),) = rec.seen
    assert client == LOOPBACK
    assert headers["x-auth-request-preferred-username"] == "operator"


def test_a_forged_x_forwarded_user_never_reaches_the_private_tier(
    serve, pki, tmp_path, clock, registry
):
    """End to end with the real agent pages: from an untrusted source the right front-door secret
    and a forged identity are 403, and the access log names nobody; X-Forwarded-User is never an
    identity, even from the trusted edge."""
    from homelabnext.status import build_status, load_views
    from homelabnext.status.agents.pages import AgentSite
    from homelabnext.status.agents.store import ActivityStore

    def start(fd, names=()):
        site = AgentSite(ActivityStore(tmp_path / f"{id(fd)}.db", clock=clock), front_door=fd,
                         clock=clock)  # fmt: skip
        snap = {"now": "2026-09-21T13:33:20Z", "observations": [], "sources": []}
        return serve(
            lambda: build_status(snap, load_views(VIEWS), registry, [], agents=site.summary()),
            tls=_settings(pki, names),
            agents=site,
        )

    untrusted = front_door(tmp_path, trusted=ELSEWHERE)
    port = start(untrusted)
    assert _get(port, pki, "edge", "/private/sessions", FORGED)[0] == 403
    assert not untrusted.access_log.exists() or "mallory" not in untrusted.access_log.read_text()

    trusted = front_door(tmp_path / "t")
    port = start(trusted, [EDGE])
    assert _get(port, pki, "edge", "/private/sessions", AUTHORIZED)[0] == 200
    only_forwarded = {
        k: v for k, v in FORGED.items() if not k.lower().startswith(("x-auth", "x_auth"))
    }
    assert _get(port, pki, "edge", "/private/sessions", only_forwarded)[0] == 403


def test_strip_identity_takes_every_spelling(tmp_path):
    import email.message

    m = email.message.Message()
    for k, v in {
        **FORGED,
        "X-Hnx-Front-Door": "x",
        "Remote-User": "m",
        "x-auth-request-groups": "g",
    }.items():
        m[k] = v
    m["X-Forwarded-User"] = "second copy"
    strip_identity(m)
    assert sorted(m.keys()) == ["X-Hnx-Front-Door"]


# ---------------------------------------------------------------- the hooks' probe
def _probe(pki, port, cert=None, *, server="server", name="localhost"):
    kw = {}
    if cert:
        kw = {"client_cert": str(pki[cert][0]), "client_key": str(pki[cert][1])}
    return probe(LOOPBACK, port, host_header=HUB_HOST, server_cert=str(pki[server][0]),
                 server_name=name, **kw)  # fmt: skip


def test_probe_passes_a_refusal_and_fails_an_answer(serve, pki):
    port = serve(tls=_settings(pki))
    r = _probe(pki, port)
    assert r.ok and r.outcome == "refused", r
    r = _probe(pki, port, "edge")
    assert r.ok and r.outcome == "answered", r
    plain = serve(plain_http=True)  # loopback plain HTTP: not a TLS listener
    r = _probe(pki, plain)
    assert not r.ok and r.outcome == "not-tls", r


def test_probe_trusts_exactly_the_hubs_certificate_by_its_name(serve, pki):
    """Another certificate (even from the same CA), or a name the hub's does not hold, fails
    before anything is sent."""
    port = serve(tls=_settings(pki))
    r = _probe(pki, port, server="edge")
    assert not r.ok and r.outcome == "server-cert", r
    r = _probe(pki, port, name="status-hub.svc.example.internal")
    assert not r.ok and r.outcome == "server-cert", r


def test_probe_fails_a_hooks_certificate_outside_the_pin(serve, pki):
    port = serve(tls=_settings(pki, [EDGE]))
    r = _probe(pki, port, "other")
    assert not r.ok and r.outcome == "closed", r


def test_probe_tls_command_exit_codes(serve, pki, capsys):
    from homelabnext.status.cli import main

    port = serve(tls=_settings(pki))
    base = ["probe-tls", "--address", LOOPBACK, "--port", str(port), "--host-header", HUB_HOST,
            "--server-cert", str(pki["server"][0]), "--server-name", "localhost"]  # fmt: skip
    assert main(base) == 0
    assert "refused" in capsys.readouterr().out
    edge = [str(p) for p in pki["edge"]]
    assert main([*base, "--client-cert", edge[0], "--client-key", edge[1]]) == 0
    assert main([*base[:-1], "status-hub.svc.example.internal"]) == 1
    assert main([*base, "--client-cert", edge[0]]) == 2


def test_a_cn_with_only_ip_sans_does_not_pass_the_pin(serve, pki, tmp_path):
    """The audit's case: a CA-signed certificate whose CN is the pinned name and whose only SAN
    is an address is closed by the pin."""
    ca = (pki["ca"], pki["ca"].with_suffix(".key"))
    crt, key = _leaf(tmp_path, EDGE, ca, san=f"IP:{LOOPBACK}", eku="clientAuth")
    port = serve(tls=_settings(pki, [EDGE]))
    pki = {**pki, "cn_only": (crt, key)}
    with pytest.raises(REFUSED):
        _get(port, pki, "cn_only")


def test_the_probe_pins_the_leaf_not_anything_in_the_file(serve, pki, tmp_path):
    """An extra certificate appended to the server certificate file (a CA, under the partial-chain
    flag a trust anchor too) does not let another server pass: the leaf's digest is compared."""
    port = serve(tls=_settings(pki))
    bundle = tmp_path / "edge-then-ca.pem"
    bundle.write_text(pki["edge"][0].read_text() + pki["ca"].read_text())
    r = probe(
        LOOPBACK, port, host_header=HUB_HOST, server_cert=str(bundle), server_name="localhost"
    )
    assert not r.ok and r.outcome == "server-cert", r


def test_refused_handshakes_are_counted_and_said(pki, capsys):
    srv = make_server(lambda: DOC, tls=_settings(pki), allowed_hosts=[HUB_HOST])
    done = threading.Event()
    real = srv._refusal

    def refusal(why):
        real(why)
        done.set()

    srv._refusal = refusal
    threading.Thread(target=srv.serve_forever, args=(0.05,), daemon=True).start()
    try:
        with pytest.raises(REFUSED):
            _get(srv.server_address[1], pki, None)
        assert done.wait(10)
    finally:
        srv.shutdown()
        srv.server_close()
    assert srv.tls_refused == 1
    assert "1 TLS connection(s) refused so far" in capsys.readouterr().err
