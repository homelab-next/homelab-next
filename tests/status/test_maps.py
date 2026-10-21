# SPDX-License-Identifier: Apache-2.0
"""The generated maps (ADR-0018): the Markdown table reader, each map's view-model and page
(goldens over small synthetic models), escaping of hostile names, and the hub wiring (menu,
serve routes, static render)."""

from __future__ import annotations

import json
import os
import threading
import urllib.request
from pathlib import Path
from types import SimpleNamespace

import pytest
from status_helpers import REGISTRY, ROOT, VIEWS

from homelabnext.compute.model import ZoneFlow
from homelabnext.graph.model import Edge, Graph, Node
from homelabnext.registry.model import load
from homelabnext.status.cli import main
from homelabnext.status.maps import MapSite, architecture, dataflow, roadmap, topology
from homelabnext.status.maps.mdtables import parse_tables, split_row
from homelabnext.status.model import sources_from_registry
from homelabnext.status.views import build_status, load_views

GOLDEN = Path(__file__).parent / "golden" / "maps"
GUESTS = ROOT / "examples" / "minimal" / "guests"
SITE = ROOT / "examples" / "minimal" / "site.yml"
HOSTILE = '<script>alert("x")</script>'


def golden(name: str, text: str) -> None:
    """Compare with ``golden/maps/<name>``; ``HNX_UPDATE_GOLDEN=1`` rewrites it."""
    path = GOLDEN / name
    if os.environ.get("HNX_UPDATE_GOLDEN") == "1":
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    assert path.read_text(encoding="utf-8") == text, f"{name}: rerun with HNX_UPDATE_GOLDEN=1"


def as_json(vm) -> str:
    return json.dumps(vm, indent=1, sort_keys=True) + "\n"


def assert_safe(html: str) -> None:
    """Script-free and CSP-clean: no script, no inline style attribute, no event handler."""
    low = html.lower()
    assert "<script" not in low and " style=" not in low and "<img" not in low


# ------------------------------------------------------------------------- Markdown tables
def test_split_row_keeps_escaped_pipes_and_code_spans():
    assert split_row("| a | b \\| c | `x|y` |") == ["a", "b | c", "`x|y`"]
    assert split_row("| a | |") == ["a", ""]
    assert split_row("a | b") == ["a", "b"]


def test_parse_tables_tracks_headings_skips_fences_and_pads_rows():
    text = (
        "# Top\n## Phases PUBLIC-NOW\n\n| A | B |\n|---|:-:|\n| 1 | 2 | 3 |\n| 4 |\n\nprose\n"
        "```\n| not | a |\n|---|---|\n| table | x |\n```\n### Sub\n| C |\n|---|\n| 5 |\n"
    )
    t = parse_tables(text)
    assert [x.header for x in t] == [("A", "B"), ("C",)]
    assert t[0].headings == ("Top", "Phases PUBLIC-NOW") and t[0].line == 4
    assert t[0].rows == (("1", "2"), ("4", "")) and t[0].records()[1] == {"A": "4", "B": ""}
    assert t[1].headings == ("Top", "Phases PUBLIC-NOW", "Sub") and t[1].heading == "Sub"
    assert parse_tables("| A |\n| B |\n") == []  # no delimiter row: not a table


# ------------------------------------------------------------------------------ topology
def _guest(gid, kind, node, zone, ip, **extra):
    raw = {"id": gid, "kind": kind, "placement": {"node": node},
           "network": {"zone": zone, "ip": ip}, "capability": "cap:events", **extra}  # fmt: skip
    return SimpleNamespace(raw=raw)


SITE_DOC = {
    "site": {"id": "lab"},
    "zones": [
        {"id": "mgmt", "purpose": "management", "vlan_id": 10, "subnet": "192.0.2.0/26",
         "gateway": "192.0.2.1", "egress": {"internet": "deny"}},
        {"id": "data", "vlan_id": 20, "subnet": "192.0.2.64/26", "gateway": "192.0.2.65"},
    ],
    "firewall": {"default_action": "deny"},
}  # fmt: skip
GUEST_SET = [
    _guest("guest:hv-a", "host", "hv-a", "mgmt", "192.0.2.10", baseline={"names": ["server"]}),
    _guest("guest:db-1", "vm", "hv-a", "data", "192.0.2.70", baseline={"names": ["server", "db"]}),
    _guest("guest:app-1", "lxc", "hv-b", "data", "192.0.2.71",
           baseline={"exemption": {"reason": "lab"}}),
    _guest("guest:odd-1", "vm", "hv-b", "lab", "192.0.2.72"),
]  # fmt: skip
FLOWS = [ZoneFlow("mgmt", "data"), ZoneFlow("mgmt", "data", ("tcp",), (22, 443))]


def test_topology_view_model_and_page_match_their_goldens():
    vm = topology.build(SITE_DOC, GUEST_SET, FLOWS)
    assert [z["id"] for z in vm["zones"]] == ["mgmt", "data", "lab"]  # site order, then unknown
    assert vm["zones"][-1]["known"] is False
    assert [(n["id"], n["hypervisor"]) for n in vm["nodes"]] == [("hv-a", True), ("hv-b", False)]
    assert vm["flows"] == [{"from": "mgmt", "to": "data", "allowed": "any; tcp 22, 443"}]
    golden("topology.json", as_json(vm))
    html = topology.render(vm)
    assert_safe(html)
    assert 'role="img" aria-labelledby="topology-hosts-title topology-hosts-desc"' in html
    assert "<caption>Guests</caption>" in html and "not in the site model" in html
    golden("topology.html", html)


def test_topology_escapes_hostile_names_and_honours_the_default_action():
    site = {"zones": [{"id": HOSTILE, "purpose": HOSTILE}, {"id": "b"}],
            "firewall": {"default_action": "allow"}}  # fmt: skip
    vm = topology.build(site, [_guest("guest:x", HOSTILE, "n<1>", HOSTILE, "&")], [])
    html = topology.render(vm)
    assert_safe(html)
    assert "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;" in html and "n&lt;1&gt;" in html
    assert "no rule, the default action (allow)" in html and "every other pair: allow" in html


def test_topology_of_the_example_lab():
    vm = topology.load(GUESTS, SITE)
    assert {z["id"] for z in vm["zones"]} >= {"mgmt", "data", "compute", "edge", "sandbox"}
    assert [g["id"] for n in vm["nodes"] for g in n["guests"]] == ["guest:bus-core", "guest:hv-a"]
    flows = {(f["from"], f["to"]): f["allowed"] for f in vm["flows"]}
    assert flows[("mgmt", "compute")] == "tcp 22, 443" and ("edge", "data") not in flows


# ------------------------------------------------------------------------------ dataflow
PKG = {
    "__init__.py": "",
    "model.py": 'EVENT = "homelabnext.thing.made"\n__all__ = ["EVENT"]\n',
    "maker.py": "from .model import EVENT\n\ndef go(b):\n    return b(EVENT, {})\n",
    "eater.py": (
        '"""Reads homelabnext.thing.made events."""\nfrom pkg.model import EVENT as E\n\n'
        "def eat(body):\n    return decode_event(body, types=[E])\n"
    ),
    "help.py": 'HELP = "publish each summary as homelabnext.thing.made"\n',
    "direct.py": 'def f(x):\n    return x.emit("homelabnext.other.done")\n',
    "broken.py": "def (:\n",
}


def test_scan_code_finds_producers_and_consumers_through_imports(tmp_path):
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    for name, text in PKG.items():
        (pkg / name).write_text(text, encoding="utf-8")
    got = dataflow.scan_code(pkg, ["homelabnext.thing.made", "homelabnext.other.done", "x.y"])
    assert got == {
        "homelabnext.other.done": {"consumes": [], "produces": ["pkg.direct"]},
        "homelabnext.thing.made": {"consumes": ["pkg.eater"], "produces": ["pkg.maker"]},
    }  # the constant's definition, the docstring and the help text are not uses


DATAFLOW_INPUTS = {
    "event_types": ["homelabnext.alert.created", "homelabnext.task.queued"],
    "samples": {"homelabnext.alert.created": ["svc:siem"]},
    "code": {"homelabnext.task.queued": {"produces": ["homelabnext.q"], "consumes": []}},
    "packs": [{"name": "page-on-alert", "event": "homelabnext.alert.created",
               "actions": [("notify.page", "svc:notify")], "tables": ["table:owners"],
               "decides": ["page"]}],
    "services": [
        {"name": "bus", "capability": "events", "impl": "nats", "upstreams": [],
         "status_sources": []},
        {"name": "hub", "capability": "status-hub", "impl": "hnx", "upstreams": [],
         "status_sources": [{"id": "runs", "kind": "push-event", "target_service": None}]},
        {"name": "cat", "capability": "lake-catalog", "impl": "", "upstreams": ["s3"],
         "status_sources": [{"id": "health", "kind": "poll-http-json", "target_service": None}]},
        {"name": "query", "capability": "lake-query", "impl": "", "upstreams": ["cat"],
         "status_sources": []},
        {"name": "s3", "capability": "object-store", "impl": "minio", "upstreams": [],
         "status_sources": []},
    ],
    "tables": ["authentication"],
    "lanes": [{"name": "memory", "kind": "files", "actions": ["memory.write"]}],
    "broker_manifest": "examples/broker/manifest.yml",
}  # fmt: skip


def test_dataflow_view_model_and_page_match_their_goldens():
    vm = dataflow.build(DATAFLOW_INPUTS)
    edges = {
        (f["transport"], f["from"]["title"], f["label"], f["to"]["title"]) for f in vm["flows"]
    }
    assert ("bus", "siem", "homelabnext.alert.created", "page-on-alert") in edges
    assert ("bus", "q", "homelabnext.task.queued", "no consumer declared") in edges
    assert ("collect", "cat", "health", "hub") in edges and ("bus", "hub", "homelabnext.status"
            ".observed (runs)", "hub") in edges  # fmt: skip
    assert ("lake", "no writer declared", "authentication", "query") in edges
    assert ("lake", "no writer declared", "table:owners", "page-on-alert") in edges
    assert ("object-store", "cat", "objects", "no reader declared") in edges
    assert ("broker", "page-on-alert", "notify.page", "notify") in edges
    assert ("broker", "agent profiles", "memory.write", "lane memory") in edges
    golden("dataflow.json", as_json(vm))
    html = dataflow.render(vm)
    assert_safe(html)
    golden("dataflow.html", html)


def test_dataflow_escapes_hostile_names():
    inputs = {"event_types": [HOSTILE], "samples": {HOSTILE: [HOSTILE]},
              "packs": [{"name": HOSTILE, "event": HOSTILE, "actions": [(HOSTILE, HOSTILE)],
                         "tables": [], "decides": []}]}  # fmt: skip
    html = dataflow.render(dataflow.build(inputs))
    assert_safe(html)
    assert html.count("&lt;script&gt;") > 5


def test_dataflow_of_the_repository():
    vm = dataflow.build(dataflow.gather(ROOT, load(REGISTRY)))
    edges = {(f["transport"], f["from"]["id"], f["label"], f["to"]["id"]) for f in vm["flows"]}
    observed = "homelabnext.status.observed"
    assert ("bus", "pkg:homelabnext.status.hub", observed, "pkg:homelabnext.status.hub") in edges
    assert ("bus", "pkg:homelabnext.events.deploy", "homelabnext.deploy.changed", None) in edges
    assert any(t == "bus" and lbl == "homelabnext.alert.created" and c == "workflow:new-critical-alert"
               for t, _, lbl, c in edges)  # fmt: skip
    assert ("broker", "profile:*", "proposal.file", "lane:proposals") in edges
    assert ("collect", "svc:metrics", "invariants", "svc:status-hub") in edges


# -------------------------------------------------------------------------- architecture
def _graph() -> Graph:
    n = [
        Node("cap:events", "cap", attrs={"conformance": "core"}),
        Node("cap:dns", "cap", attrs={"conformance": "extended"}),
        Node("cap:metrics", "cap"),
        Node("cap:tool-only", "cap"),
        Node("adapter:pkg.real:make", "adapter", attrs={"real": True}),
        Node("adapter:pkg.fakes:FakeBus", "adapter", attrs={"real": False}),
        Node("svc:bus", "svc"),
        Node("svc:prom", "svc"),
    ]
    e = [
        Edge("adapter:pkg.real:make", "cap:events", "implements", "t"),
        Edge("adapter:pkg.real:make", "product:nats", "for", "t"),
        Edge("adapter:pkg.fakes:FakeBus", "cap:events", "implements", "t"),
        Edge("cap:events", "adapter:pkg.fakes:FakeBus", "faked_by", "t"),
        Edge("svc:bus", "cap:events", "provides", "r"),
        Edge("svc:bus", "product:nats", "runs", "r"),
        Edge("svc:prom", "cap:metrics", "provides", "r"),
        Edge("svc:prom", "product:prometheus", "runs", "r"),
    ]
    return Graph({x.id: x for x in n}, e)


CONTROL = {
    "broker": {"actions": ["memory.write"], "lanes": ["memory"], "source": "m.yml"},
    "decision": {"specs": ["page"], "safety": ["hostile-content"]},
    "workflows": {"packs": ["p"], "triggers": ["homelabnext.alert.created"], "decides": True,
                  "acts": False},
    "status-hub": {"service": "hub", "sources": ["a", "b"], "pushed": []},
    "bus": {"service": "bus", "impl": "nats"},
}  # fmt: skip


def test_architecture_view_model_and_page_match_their_goldens():
    vm = architecture.build(_graph(), CONTROL)
    rows = {c["id"]: c for c in vm["capabilities"]}
    assert set(rows) == {"events", "dns", "metrics"}  # a capability with nothing is not a row
    assert rows["events"] == {
        "id": "events", "conformance": "core", "fakes": ["pkg.fakes:FakeBus"],
        "adapters": ["pkg.real:make"], "products": ["nats"], "services": ["bus"],
    }  # fmt: skip
    assert rows["metrics"]["products"] == ["prometheus"] and rows["dns"]["services"] == []
    assert architecture.control_edges(CONTROL) == [
        ("agents", "broker", "named actions"),
        ("bus", "workflows", "trigger events"),
        ("workflows", "decision", "decide steps"),
    ]  # no action step, no pushed status source: no edge drawn for either
    golden("architecture.json", as_json(vm))
    html = architecture.render(vm)
    assert_safe(html)
    golden("architecture.html", html)


def test_architecture_escapes_hostile_names():
    g = Graph({}, [Edge(f"svc:{HOSTILE}", f"cap:{HOSTILE}", "provides", "r")])
    html = architecture.render(architecture.build(g, {"broker": {"actions": [HOSTILE]}}))
    assert_safe(html)
    assert "&lt;script&gt;" in html


def test_architecture_of_the_repository():
    vm = architecture.build(
        architecture.graph_for(ROOT), architecture.gather_control(ROOT, load(REGISTRY))
    )
    rows = {c["id"]: c for c in vm["capabilities"]}
    assert "homelabnext.conform.adapters.nats_jetstream:make" in rows["events"]["adapters"]
    assert rows["events"]["services"] == ["events"] and rows["events"]["conformance"] == "core"
    assert "proposal.file" in vm["control"]["broker"]["actions"]
    assert "critical-alert-page" in vm["control"]["decision"]["specs"]


# ------------------------------------------------------------------------------- roadmap
BUILD_ORDER = """# Build order
## PUBLIC-NOW phases
| Phase | Goal | Checklist |
|---|---|---|
| P0 | CI | F, Q-01 |
| P1 | Contracts | T-01-T-02, Z-99, Y |
### P1 in detail
| Step | Deliverable | Exit criterion |
|---|---|---|
| P1.1 | schemas | they validate |
## SERVER phases
| Phase | Goal | Checklist |
|---|---|---|
| S1 | Hardware | F |
"""
CHECKLIST = """# Checklist
## F - Foundation
| ID | Must be true | Observable / pass criterion | Tag |
|---|---|---|---|
| F-01 | Rebuildable | plan | SERVER |
| F-02 | No leaks | scan | PUBLIC-NOW |
## T - Transport
| ID | Must be true | Observable / pass criterion | Tag |
|---|---|---|---|
| T-01 | One bus | lag | SERVER |
| T-02 | Valid events | fixtures | PUBLIC-NOW |
| T-03 | Nothing dropped | dlq | SERVER |
## Q - Quality
| ID | Must be true | Observable / pass criterion | Tag |
|---|---|---|---|
| Q-01 | Tests run | ci | PUBLIC-NOW |
"""
RESULTS = {"last_run": "2026-10-20", "results": {"F-02": {"status": "pass"},
           "Q-01": {"status": "fail"}, "T-02": {"status": "error"}, "T-01": {"status": "bogus"}}}  # fmt: skip


def test_roadmap_view_model_and_page_match_their_goldens():
    vm = roadmap.build(BUILD_ORDER, CHECKLIST, RESULTS)
    by = {p["id"]: p for p in vm["phases"]}
    assert [c["id"] for c in by["P0"]["criteria"]] == ["F-02", "Q-01"]  # F filtered by the tag
    assert [c["id"] for c in by["S1"]["criteria"]] == ["F-01"]
    assert [c["id"] for c in by["P1"]["criteria"]] == ["T-01", "T-02"]  # a range: whatever tag
    assert by["P0"]["counts"] == {"total": 2, "pass": 1, "fail": 1, "error": 0, "skip": 0,
                                  "untested": 0}  # fmt: skip
    assert by["P1"]["steps"] == [{"id": "P1.1", "deliverable": "schemas", "exit": "they validate"}]
    assert [c["status"] for c in by["P1"]["criteria"]] == ["untested", "error"]  # bogus: untested
    assert vm["problems"] == ["P1: 'Z-99' names no checklist row", "P1: 'Y' names no checklist row"]
    assert [c["id"] for c in vm["unphased"]] == ["T-03"]
    golden("roadmap.json", as_json(vm))
    html = roadmap.render(vm)
    assert_safe(html)
    assert "invariants results of 2026-10-20" in html and "Unphased criteria" in html
    golden("roadmap.html", html)


def test_roadmap_without_results_reads_untested_and_escapes():
    hostile = CHECKLIST.replace("No leaks", '<img src=x onerror="y">')
    vm = roadmap.build(BUILD_ORDER, hostile)
    assert {c["status"] for p in vm["phases"] for c in p["criteria"]} == {"untested"}
    html = roadmap.render(vm)
    assert_safe(html)
    assert "&lt;img src=x" in html and "no invariants results given" in html


def test_roadmap_results_files(tmp_path):
    assert roadmap.load_results(None) == (None, None)
    bad = tmp_path / "r.json"
    bad.write_text("[]")
    assert "not an invariants results document" in roadmap.load_results(bad)[1]
    assert "cannot read" in roadmap.load_results(tmp_path / "none.json")[1]
    vm = roadmap.load(ROOT, tmp_path / "none.json")
    assert vm["problems"][0].startswith("cannot read the invariants results")


def test_every_checklist_row_belongs_to_a_build_phase():
    """docs/build-order.md names every docs/checklist.md row and only real ones (the check
    fails on the synthetic pair above: an unknown token and an unphased row)."""
    vm = roadmap.load(ROOT)
    assert vm["problems"] == [] and vm["unphased"] == []
    assert sum(p["counts"]["total"] for p in vm["phases"]) >= len(
        roadmap.checklist_rows((ROOT / "docs" / "checklist.md").read_text(encoding="utf-8"))
    )


# ------------------------------------------------------------------- the hub: menu, pages
def _doc(maps=()):
    reg = load(REGISTRY)
    views = load_views(VIEWS, reg, sources_from_registry(reg))
    snap = {"now": "2026-10-21T00:00:00Z", "observations": [], "sources": []}
    return build_status(snap, views, reg, [], maps=maps)


def test_the_maps_are_a_menu_group_available_only_when_configured():
    menu = {m["id"]: m for m in _doc({"roadmap"})["menu"]}
    for panel in ("topology", "dataflow", "architecture", "roadmap"):
        assert menu[panel]["group"] == "maps" and menu[panel]["href"] == f"/{panel}"
        assert menu[panel]["available"] is (panel == "roadmap")


def test_the_site_serves_only_its_configured_maps():
    site = MapSite(guests=GUESTS, guests_site=SITE)
    assert site.available() == {"topology"}
    assert site.handle("/roadmap", "", _doc()) is None and site.handle("/x", "", _doc()) is None
    code, ctype, body = site.handle("/topology", "", _doc({"topology"}))
    assert code == 200 and ctype.startswith("text/html")
    html = body.decode()
    assert "<h2>Topology</h2>" in html and "guest:bus-core" in html
    assert '<a href="/topology">Topology</a>' in html
    assert "unavailable" in site.body("roadmap")
    full = MapSite(root=ROOT, registry=load(REGISTRY), guests=GUESTS, guests_site=SITE)
    assert full.available() == {"topology", "dataflow", "architecture", "roadmap"}
    assert MapSite(root=ROOT).available() == {"roadmap"}


def test_an_unreadable_source_is_an_error_line_not_a_crash(tmp_path):
    (tmp_path / "site.yml").write_text("site_version: 1\nzones: nope\n")
    site = MapSite(root=tmp_path, guests=tmp_path, guests_site=tmp_path / "site.yml")
    assert "cannot build the map" in site.body("topology")
    assert "cannot build the map" in site.body("roadmap")  # no docs/ in this root


def test_serve_routes_the_maps():
    from homelabnext.status.serve import make_server

    site = MapSite(root=ROOT, registry=load(REGISTRY))
    srv = make_server(lambda: _doc(site.available()), maps=site)
    threading.Thread(target=srv.serve_forever, args=(0.05,), daemon=True).start()
    host, port = srv.server_address[:2]
    try:
        for route in ("/dataflow", "/architecture", "/roadmap"):
            with urllib.request.urlopen(
                f"http://{host}:{port}{route}", timeout=10
            ) as r:  # loopback
                html = r.read().decode()
                assert r.headers["Content-Security-Policy"].startswith("default-src 'none'")
            assert '<svg class="map"' in html and "cannot build" not in html
            assert_safe(html)
        with pytest.raises(urllib.error.HTTPError):
            urllib.request.urlopen(f"http://{host}:{port}/topology", timeout=10)  # loopback
    finally:
        srv.shutdown()
        srv.server_close()


def test_render_writes_the_maps_beside_the_page(tmp_path, capsys):
    results = tmp_path / "results.json"
    results.write_text(json.dumps(RESULTS))
    out = tmp_path / "site"
    args = ["render", "--out", str(out), "--registry", str(REGISTRY), "--views", str(VIEWS),
            "--state", str(tmp_path / "s.json"), "--now", "2026-10-21T00:00:00Z",
            "--guests", str(GUESTS), "--guests-site", str(SITE), "--maps", str(ROOT),
            "--invariants-results", str(results)]  # fmt: skip
    assert main(args) == 0
    names = sorted(p.name for p in out.iterdir())
    assert names == ["architecture.html", "dataflow.html", "index.html", "roadmap.html",
                     "status.json", "topology.html"]  # fmt: skip
    index = (out / "index.html").read_text()
    assert '<a href="topology.html">Topology</a>' in index
    page = (out / "roadmap.html").read_text()
    assert 'href="index.html#view-overview"' in page and "invariants results of 2026-10-20" in page
    assert_safe(page)


def test_map_options_are_checked(tmp_path, capsys):
    base = ["render", "--out", str(tmp_path / "o"), "--registry", str(REGISTRY),
            "--state", str(tmp_path / "s.json")]  # fmt: skip
    assert main([*base, "--guests", str(GUESTS)]) == 2
    assert main([*base, "--maps", str(tmp_path / "nope")]) == 2
    assert main([*base, "--invariants-results", str(tmp_path / "r.json")]) == 2
    err = capsys.readouterr().err
    assert "--guests needs --guests-site" in err and "not a directory" in err
    assert "--invariants-results needs --maps" in err
