# SPDX-License-Identifier: Apache-2.0
"""Views, the status.json contract, the page and the console server: exceptions first (O-05),
the grid follows reality (O-02, with fakes), a blackholed source cannot stall the console (O-07),
render is deterministic, serve is loopback and GET only."""

from __future__ import annotations

import copy
import dataclasses
import json
import threading
import time
import urllib.error
import urllib.request

import pytest
import yaml
from status_helpers import ROOT, VIEWS, Clock, FakeHttp, endpoint, spec

from homelabnext.status import (
    CollectContext,
    Draft,
    Scheduler,
    SourceResult,
    ViewsError,
    build_status,
    load_views,
    views_problems,
)
from homelabnext.status.catalog import check as catalog_check
from homelabnext.status.catalog import render_catalog
from homelabnext.status.render import render_html, write
from homelabnext.status.serve import LOOPBACK, LOOPBACK_NAMES, make_server

PANEL_VIEWS = {
    "views_version": 1,
    "shell": {"title": "Test lab", "main": "overview"},
    "menu": [
        {"id": "overview", "title": "Overview", "panel": "exceptions"},
        {"id": "grid", "title": "Grid", "panel": "grid"},
        {"id": "only-b", "title": "Only B", "panel": "grid", "select": {"sources": ["b"]}},
        {"id": "sources", "title": "Sources", "panel": "sources"},
        {"id": "grafana", "title": "Grafana", "external": {"service": "dashboards"}},
        {"id": "agents", "title": "Agent console", "external": {"service": "agent-console", "optional": True}},
    ],
}  # fmt: skip


def _specs():
    return [spec("a", service="svc-a"), spec("b", service="svc-b", capability="notify")]


def _doc(hub, registry, specs, views=PANEL_VIEWS):
    return build_status(hub.snapshot(), views, registry, specs, capability_pages={"notify"})


def _healthy(hub):
    hub.record(SourceResult("a", (Draft("disk", "ok", "fine"), Draft("cpu", "ok", "fine"))))
    hub.record(SourceResult("b", (Draft("queue", "ok", "2 waiting", value=2, work=True),)))


def test_example_views_validate_against_the_example_registry(registry, specs):
    doc = load_views(VIEWS, registry, specs)
    assert doc["shell"]["main"] == "overview"
    assert any(v.get("external", {}).get("optional") for v in doc["menu"])


@pytest.mark.parametrize(
    "mutate, needle",
    [
        (lambda d: d["menu"].append(dict(d["menu"][0])), "duplicate view id 'overview'"),
        (lambda d: d["shell"].update(main="grafana"), "is not a panel view"),
        (lambda d: d["menu"][2]["select"].update(sources=["nope"]), "unknown status source 'nope'"),
        (lambda d: d["menu"][4]["external"].update(service="nope"), "'nope' is not registered"),
        (lambda d: d["menu"][4].update(external={"url": "https://x.example.invalid"}), "schema:"),
        (lambda d: d["shell"].update(act_via={"service": "nope"}), "shell.act_via"),
    ],
)
def test_views_cross_references_are_checked(registry, mutate, needle):
    d = copy.deepcopy(PANEL_VIEWS)
    mutate(d)
    problems = views_problems(d, registry, _specs())
    assert any(needle in p for p in problems), problems


def test_an_optional_external_entry_is_listed_unavailable(make_hub, registry):
    doc = _doc(make_hub(_specs()), registry, _specs())
    menu = {m["id"]: m for m in doc["menu"]}
    assert (
        menu["grafana"]["href"] == "https://dashboards.lab.example/"
        and menu["grafana"]["available"]
    )
    assert menu["agents"] == {
        "id": "agents", "title": "Agent console", "kind": "external", "service": "agent-console",
        "href": None, "available": False,
    }  # fmt: skip


def test_exceptions_first_shows_only_the_green_count_and_live_work_when_healthy(make_hub, registry):
    """O-05: with every source healthy, the console shows only the green count, live work and
    attention items (none)."""
    hub = make_hub(_specs())
    _healthy(hub)
    doc = _doc(hub, registry, _specs())
    overview = doc["views"]["overview"]
    assert overview["attention"] == [] and overview["ok"] == 3
    assert [r["item"] for r in overview["live"]] == ["queue"]
    page = render_html(doc)
    section = page.split('id="view-overview"', 1)[1].split("</section>", 1)[0]
    assert '<p class="green">3 ok</p>' in section
    assert "Live work" in section and "queue" in section
    assert "Needs attention" not in section and "<table" not in section and "disk" not in section


def test_exceptions_first_lists_the_failing_item(make_hub, registry, clock):
    hub = make_hub(_specs())
    _healthy(hub)
    hub.record(SourceResult("a", (Draft("disk", "fail", "97% full"), Draft("cpu", "ok", "fine"))))
    doc = _doc(hub, registry, _specs())
    att = doc["views"]["overview"]["attention"]
    assert [(r["item"], r["state"]) for r in att] == [("disk", "fail")]
    section = render_html(doc).split('id="view-overview"', 1)[1].split("</section>", 1)[0]
    assert "Needs attention" in section and "97% full" in section and "cpu" not in section


def test_a_source_never_read_is_an_attention_item_not_silence(make_hub, registry):
    hub = make_hub(_specs())
    hub.record(SourceResult("a", (Draft("disk", "ok", "fine"),)))
    att = _doc(hub, registry, _specs())["views"]["overview"]["attention"]
    assert [(r["source"], r["item"], r["state"]) for r in att] == [("b", "_source", "unknown")]


def test_grid_tile_turns_red_when_the_monitored_service_stops(make_hub, registry, clock):
    """O-02 with fakes: the poll after the service stops turns its tile red."""
    s = [spec("svc-a-health", service="svc-a", on_error="fail", mapping={"state": "status"})]
    hub = make_hub(s)
    http = FakeHttp()
    http.routes["http://svc-a.status.invalid/health"] = (200, {"status": "ok"})
    ctx = CollectContext(clock=clock, http=http, endpoint=endpoint)
    sch = Scheduler()
    for r in sch.run(s, ctx):
        hub.record(r)
    views = {**PANEL_VIEWS, "menu": PANEL_VIEWS["menu"][:2]}
    tile = _doc(hub, registry, s, views)["views"]["grid"]["modules"][0]
    assert (tile["module"], tile["state"]) == ("svc-a", "ok")
    http.down.add("svc-a.status.invalid")  # the service stops
    clock.advance(s[0].interval_s)
    for r in sch.run(s, ctx):
        hub.record(r)
    tile = _doc(hub, registry, s, views)["views"]["grid"]["modules"][0]
    assert tile["state"] == "fail" and "connection refused" in tile["items"][0]["summary"]
    assert 'class="tile fail"' in render_html(_doc(hub, registry, s, views))


def test_grid_selection_and_module_links(make_hub, registry):
    hub = make_hub(_specs())
    _healthy(hub)
    doc = _doc(hub, registry, _specs())
    assert [m["module"] for m in doc["views"]["only-b"]["modules"]] == ["svc-b"]
    links = {m["module"]: m["links"] for m in doc["modules"]}
    assert links["svc-b"]["contract"] == "docs/capabilities/notify.md"
    assert "contract" not in links["svc-a"] and links["svc-a"]["service"] == "svc:svc-a"


def test_render_is_deterministic_self_contained_and_escaped(make_hub, registry, tmp_path):
    hub = make_hub(_specs())
    _healthy(hub)
    hub.record(SourceResult("a", (Draft("x", "fail", "<script>alert(1)</script>"),)))
    doc = _doc(hub, registry, _specs())
    doc["title"] = "Test <lab>"  # build_status takes the title as validated; render escapes anyway
    a = write(tmp_path / "a", doc)
    b = write(tmp_path / "b", json.loads(json.dumps(doc)))
    assert [p.read_bytes() for p in a] == [p.read_bytes() for p in b]
    page = a[0].read_text()
    assert "<script" not in page and "&lt;script&gt;" in page
    assert "Test &lt;lab&gt;" in page
    assert "http://" not in page and "cdn" not in page.lower()
    assert json.loads(a[1].read_text())["schema"] == "homelabnext.status/1"


def test_status_json_contract_keys(make_hub, registry):
    hub = make_hub(_specs())
    _healthy(hub)
    doc = _doc(hub, registry, _specs())
    assert set(doc) == {
        "schema", "generated_at", "title", "main", "act_via", "summary", "menu", "views",
        "modules", "sources", "observations", "agents",
    }  # fmt: skip
    assert doc["summary"] == {"total": 3, "ok": 3, "warn": 0, "fail": 0, "unknown": 0, "stale": 0}
    assert set(doc["views"]) == {"overview", "grid", "only-b", "sources"}
    assert {s["id"] for s in doc["views"]["sources"]["sources"]} == {"a", "b"}


def _get(url, method="GET"):
    req = urllib.request.Request(url, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:  # loopback only
            return r.status, r.headers, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read()


@pytest.fixture
def served(make_hub, registry):
    hub = make_hub(_specs())
    _healthy(hub)
    srv = make_server(lambda: _doc(hub, registry, _specs()))
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    host, port = srv.server_address[:2]
    yield f"http://{host}:{port}", hub
    srv.shutdown()
    srv.server_close()


def test_serve_binds_loopback_and_answers_get_only(served):
    base, _ = served
    assert base.startswith("http://127.")
    code, headers, body = _get(base + "/")
    assert code == 200 and b'class="green">3 ok' in body
    assert "default-src 'none'" in headers["Content-Security-Policy"]
    code, _, body = _get(base + "/status.json")
    assert code == 200 and json.loads(body)["summary"]["ok"] == 3
    assert _get(base + "/status.json", "HEAD")[0] == 200
    assert _get(base + "/nope")[0] == 404
    for method in ("POST", "PUT", "DELETE", "PATCH"):
        code, headers, _ = _get(base + "/", method)
        assert code == 405 and headers["Allow"] == "GET, HEAD"


def test_serve_refuses_a_non_loopback_bind_unless_asked():
    with pytest.raises(ValueError, match="loopback-only"):
        make_server(dict, host="0.0.0.0")  # never bound: refused before the socket opens


def test_a_blackholed_source_cannot_stall_the_console(served, make_hub):
    """O-07: with one source hung, the page renders in < 2 s and that module reads stale."""
    base, hub = served
    release = threading.Event()

    class Blackhole:
        def collect(self, s, ctx):
            release.wait(30)
            return []

    clock: Clock = hub.clock
    sch = Scheduler({"poll-http-json": Blackhole()})
    try:
        clock.advance(181)  # the hung source has said nothing for longer than stale_after_s
        hung = [dataclasses.replace(_specs()[0], timeout_s=0.5)]
        bg = threading.Thread(
            target=lambda: [hub.record(r) for r in sch.run(hung, CollectContext())]
        )
        bg.start()
        t0 = time.monotonic()
        code, _, body = _get(base + "/status.json")
        assert time.monotonic() - t0 < 2.0 and code == 200
        mods = {m["module"]: m["state"] for m in json.loads(body)["modules"]}
        assert mods["svc-a"] == "stale"
        bg.join(10)
        srcs = {s["id"]: s for s in json.loads(_get(base + "/status.json")[2])["sources"]}
        assert srcs["a"]["state"] == "stale" and srcs["a"]["error"] == "timeout after 0.5s"
    finally:
        release.set()


def test_source_catalog_page_is_current_and_detects_drift(specs, tmp_path):
    assert catalog_check(ROOT / "docs/status/sources.md", specs) == []
    page = render_catalog(specs)
    for s in specs:
        assert f"### {s.id}\n\n{s.what}" in page
    stale = tmp_path / "sources.md"
    stale.write_text(page.replace(specs[0].what, "edited by hand"))
    assert catalog_check(stale, specs) and catalog_check(tmp_path / "missing.md", specs)


def test_load_views_reports_unreadable_and_invalid_files(tmp_path, registry):
    bad = tmp_path / "v.yml"
    bad.write_text(
        yaml.safe_dump({"views_version": 1, "shell": {"title": "x", "main": "a"}, "menu": []})
    )
    with pytest.raises(ViewsError, match="invalid views"):
        load_views(bad, registry)
    with pytest.raises(ViewsError, match="cannot read"):
        load_views(tmp_path / "missing.yml")


def _raw(base, path="/status.json", *, host="keep", origin=None, method="GET"):
    """A request with exactly the Host/Origin given (``host=None`` sends no Host at all)."""
    import http.client
    import urllib.parse

    u = urllib.parse.urlsplit(base)
    conn = http.client.HTTPConnection(u.hostname, u.port, timeout=5)
    conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
    if host == "keep":
        conn.putheader("Host", u.netloc)
    elif host is not None:
        conn.putheader("Host", host)
    if origin is not None:
        conn.putheader("Origin", origin)
    conn.endheaders()
    resp = conn.getresponse()
    out = resp.status, dict(resp.getheaders()), resp.read()
    conn.close()
    return out


@pytest.mark.parametrize(
    "host, origin",
    [
        ("attacker.example:8099", None),  # DNS rebinding: a hostname re-resolved to loopback
        (LOOPBACK + ".attacker.example", None),
        (None, None),  # no Host at all
        ("keep", "http://attacker.example"),  # loopback Host, forged Origin
        ("keep", "null"),
    ],
)
def test_serve_refuses_foreign_host_or_origin(served, host, origin):
    base, _ = served
    code, headers, body = _raw(base, host=host, origin=origin)
    assert code == 403 and b"status" not in body
    assert not any(k.lower().startswith("access-control-") for k in headers)
    assert _raw(base, host=host, origin=origin, method="POST")[0] == 403


@pytest.mark.parametrize(
    "host, origin",
    [
        ("keep", None),
        ("localhost", None),
        ("[::1]", "http://localhost"),
        ("keep", "http://" + LOOPBACK),
    ],
)
def test_serve_answers_loopback_hosts_with_hardening_headers(served, host, origin):
    base, _ = served
    code, headers, body = _raw(base, host=host, origin=origin)
    assert code == 200 and json.loads(body)["schema"] == "homelabnext.status/1"
    assert headers["X-Content-Type-Options"] == "nosniff" and headers["Cache-Control"] == "no-store"
    csp = headers["Content-Security-Policy"]
    assert "default-src 'none'" in csp and "frame-ancestors 'none'" in csp
    assert "unsafe-inline" not in csp and not any(
        k.lower().startswith("access-control-") for k in headers
    )


def test_csp_hash_admits_exactly_the_page_stylesheet(served):
    import base64
    import hashlib
    import re

    base, _ = served
    code, headers, body = _raw(base, path="/")
    css = re.search(rb"<style>(.*?)</style>", body, re.S).group(1)
    want = base64.b64encode(hashlib.sha256(css).digest()).decode()
    assert code == 200 and f"style-src 'sha256-{want}'" in headers["Content-Security-Policy"]
    assert b"<script" not in body and b"<img" not in body


def test_allow_remote_needs_explicit_allowed_hosts(make_hub, registry):
    with pytest.raises(ValueError, match="allowed_hosts"):
        make_server(dict, host="0.0.0.0", allow_remote=True)
    from homelabnext.status.serve import host_allowed

    allowed = LOOPBACK_NAMES | {"status.lab.example"}
    assert host_allowed("status.lab.example", "https://status.lab.example", allowed)
    assert not host_allowed("other.lab.example", None, allowed)
    assert not host_allowed("status.lab.example", "https://evil.example", allowed)


def test_cli_refuses_allow_remote_without_allowed_host(capsys):
    from homelabnext.status.cli import main

    rc = main(["serve", "--registry", str(ROOT / "examples/services.yml"), "--views", str(VIEWS),
               "--bind", "0.0.0.0", "--allow-remote", "--port", "0"])  # fmt: skip
    assert rc == 2 and "allowed_hosts" in capsys.readouterr().err
