# SPDX-License-Identifier: Apache-2.0
"""The generated maps (ADR-0018): the Markdown table reader, each map's view-model and page
(goldens over small synthetic models), escaping of hostile names, and the hub wiring (menu,
serve routes, static render)."""

from __future__ import annotations

import json
import os
import re
import threading
import urllib.request
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from homelabnext.compute.model import ZoneFlow
from homelabnext.graph.model import Edge, Graph, Node
from homelabnext.registry.model import load
from homelabnext.status.cli import main
from homelabnext.status.maps import MapSite, architecture, assets, dataflow, roadmap, topology
from homelabnext.status.maps.lab import host_flows
from homelabnext.status.maps.mdtables import parse_tables, split_row
from homelabnext.status.model import sources_from_registry
from homelabnext.status.views import build_status, load_views

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "examples" / "services.yml"
VIEWS = ROOT / "examples" / "status" / "views.yml"
GOLDEN = Path(__file__).parent / "golden" / "maps"
FIXTURES = Path(__file__).parent / "fixtures" / "maps"
GUESTS = ROOT / "examples" / "minimal" / "guests"
SITE = ROOT / "examples" / "minimal" / "site.yml"
LAB = ROOT / "examples" / "lab-topology"
HOSTILE = '<script>alert("x")</script>'
BOX_IP = "192.0.2.9"  # no-raw-endpoint: allow RFC 5737 documentation address


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


def assert_interactive_safe(html: str, *, scripts: int) -> None:
    """An interactive map: exactly ``scripts`` script elements (the data, and the page's own
    script), no inline style attribute, no event-handler attribute, no markup from data."""
    low = html.lower()
    assert low.count("<script") == scripts == low.count("</script>")
    assert " style=" not in low and "<img" not in low
    assert not re.search(r"<[a-z][^<>]*\son[a-z]+\s*=", low)  # an event-handler attribute


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


_TOPO = yaml.safe_load((FIXTURES / "topology.yml").read_text(encoding="utf-8"))
SITE_DOC = _TOPO["site"]
GUEST_SET = [SimpleNamespace(raw=g) for g in _TOPO["guests"]]
FLOWS = [
    ZoneFlow(f["src"], f["dst"], tuple(f.get("protocols", ())), tuple(f.get("ports", ())))
    for f in _TOPO["flows"]
]


LAB_FACTS, NODES, DATAFLOW_VM = _TOPO["lab"], _TOPO["nodes"], _TOPO["dataflow"]


def _topo(**kw):
    args = {"lab": LAB_FACTS, "nodes": NODES, "dataflow": DATAFLOW_VM, **kw}
    return topology.build(SITE_DOC, GUEST_SET, FLOWS, **args)


def _data(html: str) -> dict:
    m = re.search(r'<script type="application/json" id="topo-data">(.*?)</script>', html, re.S)
    assert m and "<" not in m.group(1) and ">" not in m.group(1) and "&" not in m.group(1)
    return json.loads(m.group(1))


def test_topology_view_model_and_page_match_their_goldens():
    vm = _topo()
    assert [z["id"] for z in vm["zones"]] == ["mgmt", "data", "lab"]  # site order, then unknown
    assert vm["zones"][-1]["known"] is False
    # the top cluster: internet, router, switches, then hypervisors and physical hosts
    # the edge chain from the site, then the switches not in it, the UPSes, the physical row
    assert [[c["node"] for c in row] for row in vm["top"]] == [
        ["internet"], ["edge:modem-1"], ["router:gw"], ["switch:sw-1"], ["ups:ups-1", "ups:ups-2"],
        ["guest:hv-a", "node:hv-b"]]  # fmt: skip
    assert vm["top"][5][0]["category"] == "hypervisor" and vm["top"][5][1]["category"] == "node"
    # power: own declarations, the site default, what each UPS feeds, a VM's inherited power
    top = {c["node"]: c for row in vm["top"] for c in row}
    assert [b["text"] for b in top["switch:sw-1"]["badges"]] == ["UPS: ups-1, ups-2"]
    assert top["node:hv-b"]["power"] == "ups-1" and top["internet"]["power"] is None
    assert vm["details"]["node:hv-b"]["power"] == ["UPS ups-1 (the site's power.default)"]
    assert vm["details"]["ups:ups-1"]["power"] == [
        "feeds modem-1", "feeds hv-b", "feeds gw", "feeds sw-1"]  # fmt: skip
    assert [b["text"] for b in top["ups:ups-2"]["badges"]] == ["feeds 2"]
    assert {(p["source"], p["dest"]) for p in vm["power"]} >= {
        ("ups:ups-2", "guest:hv-a"), ("ups:ups-1", "node:hv-b")}  # fmt: skip
    assert vm["details"]["guest:db-1"]["power"] == ["inherits hv-a: UPS ups-2"]
    assert vm["details"]["guest:app-1"]["power"] == ["inherits hv-b: UPS ups-1"]
    # lanes: the data lane has more than STACK_MIN guests in several groups, so it is stacked
    lanes = {ln["id"]: ln for ln in vm["lanes"]}
    assert [s["title"] for s in lanes["data"]["stacks"]] == ["lake", "orchestration", "scanner"]
    assert lanes["mgmt"]["stacks"] == [{"title": None, "cards": [], "cols": 1}]
    assert lanes["lab"]["known"] is False
    cards = {c["node"]: c for ln in vm["lanes"] for s in ln["stacks"] for c in s["cards"]}
    badges = {n: [b["text"] for b in c["badges"]] for n, c in cards.items()}
    assert badges["guest:db-1"] == ["2 services"] and cards["guest:db-1"]["vmid"] == 170
    assert badges["guest:cache-1"] == ["1 service", "planned"]
    assert badges["guest:old-1"] == ["1 service", "retired"]
    assert badges["guest:job-1"] == ["not IaC"]
    assert cards["guest:db-1"]["meta"] == [
        "vm \u00b7 terraform", "2 vCPU \u00b7 3 GB \u00b7 20 GB disk", "debian-12 (linux-6)",
        "cap:events", "on hv-a"]  # fmt: skip
    # flows: transport hops, upstreams, firewall allows and service exceptions; a planned end
    # makes a planned arrow, a retired end none at all
    assert vm["edges"] == [
        {"source": "guest:app-1", "dest": "guest:cache-1", "label": "calls cache",
         "state": "planned"},
        {"source": "guest:app-1", "dest": "guest:db-1",
         "label": "db.write, homelabnext.thing.made, allow app, calls db", "state": "live"},
        {"source": "guest:db-1", "dest": "guest:cache-1", "label": "homelabnext.thing.made",
         "state": "planned"},
        {"source": "internet", "dest": "guest:db-1", "label": "allow web", "state": "live"},
        {"source": "zone:mgmt", "dest": "guest:db-1", "label": "exception to svc:db",
         "state": "live"},
    ]  # fmt: skip
    assert not any("old-1" in e["source"] + e["dest"] for e in vm["edges"])
    d = vm["details"]["guest:db-1"]
    assert d["does"] == "Holds the tables." and d["yaml"].startswith("id: guest:db-1\nkind: vm\n")
    assert [s["name"] for s in d["services"]] == ["svc:db", "svc:events"]
    assert "IN <- any (the internet): allow web [tcp 443]" in [f["text"] for f in d["flows"]]
    assert vm["flows"] == [{"from": "mgmt", "to": "data", "allowed": "any; tcp 22, 443"}]
    golden("topology.json", as_json(vm))
    html = topology.render(vm)
    assert_interactive_safe(html, scripts=1)
    assert _data(html)["edges"] == vm["edges"] and _data(html)["power"] == vm["power"]
    assert 'id="power-toggle"' in html and 'data-power="ups-1, ups-2"' in html
    assert "<caption>Guests</caption>" in html and "not in the site model" in html
    assert 'data-node="guest:db-1"' in html and 'data-collapse="lane-1-content"' in html
    assert 'role="img" aria-labelledby="topology-flows-title topology-flows-desc"' in html
    golden("topology.html", html)


def test_topology_without_a_registry_or_flows_still_draws_the_lanes():
    vm = topology.build(SITE_DOC, GUEST_SET, FLOWS)
    assert [(e["source"], e["label"]) for e in vm["edges"]] == [
        ("guest:app-1", "allow app"), ("internet", "allow web")]  # fmt: skip
    assert vm["details"]["guest:db-1"]["services"] == []
    assert [[c["node"] for c in row] for row in vm["top"]][-1] == ["guest:hv-a", "node:hv-b"]


def test_topology_escapes_hostile_names_and_honours_the_default_action():
    site = {"zones": [{"id": HOSTILE, "purpose": HOSTILE}, {"id": "b"}],
            "firewall": {"default_action": "allow"}, "power": {"ups": [{"id": "u", "model": HOSTILE}]},
            "edge": [{"id": "isp", "kind": "modem", "model": HOSTILE, "power": {"ups": "u"}}]}  # fmt: skip
    box = _guest("guest:box", "host", "box", "b", BOX_IP,
                 power={"ups": "none", "reason": HOSTILE})  # fmt: skip
    hostile = _guest("guest:x", HOSTILE, "n<1>", HOSTILE, "&", display_name=HOSTILE,
                     description='</script><script>alert(1)</script><img src=x onerror="y">')  # fmt: skip
    lab = {"hosts": {}, "services": [{"name": "s", "capability": "c", "impl": HOSTILE,
           "host": "x", "protocol": "tcp", "port": 1, "description": HOSTILE, "upstreams": []}]}  # fmt: skip
    vm = topology.build(site, [hostile, box], [], lab=lab)
    html = topology.render(vm)
    assert_interactive_safe(html, scripts=1)
    assert 'data-power="no UPS: &lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;"' in html
    assert _data(html)["details"]["guest:box"]["power"] == [f"no UPS (declared): {HOSTILE}"]
    assert "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;" in html and "n&lt;1&gt;" in html
    assert "no rule, the default action (allow)" in html and "every other pair: allow" in html
    detail = _data(html)["details"]["guest:x"]  # the JSON round-trips to the hostile text
    assert (
        detail["does"].startswith("</script><script>")
        and detail["services"][0]["description"] == HOSTILE
    )


def test_topology_of_the_example_lab():
    vm = topology.load(GUESTS, SITE)
    assert {z["id"] for z in vm["zones"]} >= {"mgmt", "data", "compute", "edge", "sandbox"}
    assert [g["id"] for g in vm["guests"]] == ["guest:bus-core", "guest:hv-a", "guest:ops-core"]
    flows = {(f["from"], f["to"]): f["allowed"] for f in vm["flows"]}
    assert flows[("mgmt", "compute")] == "tcp 22, 443" and ("edge", "data") not in flows


def test_topology_of_the_lab_topology_example():
    reg = load(LAB / "services.yml")
    vm = topology.load(LAB / "guests", LAB / "site.yml", registry=reg)
    assert len(vm["guests"]) == 18 and [ln["id"] for ln in vm["lanes"]] == [
        "mgmt", "services", "data", "edge", "lab"]  # fmt: skip
    assert [c["node"] for c in vm["top"][-1]] == [
        "guest:hv-1", "guest:hv-2", "guest:bench-1", "guest:nas-1"]  # fmt: skip
    assert [[c["node"] for c in row] for row in vm["top"][:5]] == [
        ["internet"], ["edge:cable-modem"], ["router:harbor-gw"], ["switch:core-sw"],
        ["ups:ups-a", "ups:ups-b"]]  # fmt: skip
    bench = next(c for c in vm["top"][-1] if c["name"] == "bench-1")
    assert bench["power"].startswith("no UPS: A bench machine") and {"cls": "nopower",
           "text": "no UPS"} in bench["badges"]  # fmt: skip
    services = next(ln for ln in vm["lanes"] if ln["id"] == "services")
    assert len(services["stacks"]) >= 3 and services["grid"] == 3
    states = {g["name"]: g["status"] for g in vm["guests"]}
    assert states["query-1"] == "planned" and states["old-scan-1"] == "retired"
    assert {"live", "planned"} == {e["state"] for e in vm["edges"]} and len(vm["edges"]) > 15
    assert vm["details"]["guest:siem-1"]["services"][0]["name"] == "svc:detections"


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
    assert_interactive_safe(html, scripts=0)  # the page adds the shared script, not the body
    assert '<div class="flow-row state-gap" data-state="gap"' in html
    assert 'data-collapse="df-group-0"' in html and "<caption>Flows</caption>" in html
    golden("dataflow.html", html)


def test_the_dataflow_page_places_services_on_guests_and_grades_each_row():
    raws = [g.raw for g in GUEST_SET]
    idx = topology.index_for(SITE_DOC, raws, LAB_FACTS, NODES)
    extra = host_flows(SITE_DOC, idx)
    pm = dataflow.page(DATAFLOW_VM, idx=idx, extra=extra)
    assert [g["title"] for g in pm["groups"]] == ["Event bus", "Broker", "Service calls",
                                                  "Firewall allows"]  # fmt: skip
    bus = pm["groups"][0]
    assert bus["sub"] == "svc:events (nats) on db-1"
    first, second = bus["rows"]
    assert (
        first["from"]["on"].startswith("on app-1 \u00b7 192.0.2.") and first["state"] == "planned"
    )
    assert second["state"] == "gap" and second["from"]["on"] == "code"
    calls = {(r["from"]["title"], r["to"]["title"]): r["state"] for r in pm["groups"][2]["rows"]}
    assert calls[("app on app-1", "cache on cache-1")] == "planned"
    assert calls[("scan on old-1", "events on db-1")] == "retired"
    assert pm["counts"] == {"live": 5, "planned": 2, "retired": 1, "gap": 1, "sample": 0}
    html = dataflow.render(DATAFLOW_VM, idx=idx, extra=extra)
    assert 'data-state-filter="planned"' in html and "Firewall allows" in html


def test_dataflow_escapes_hostile_names():
    inputs = {"event_types": [HOSTILE], "samples": {HOSTILE: [HOSTILE]},
              "packs": [{"name": HOSTILE, "event": HOSTILE, "actions": [(HOSTILE, HOSTILE)],
                         "tables": [], "decides": []}]}  # fmt: skip
    html = dataflow.render(dataflow.build(inputs))
    assert_interactive_safe(html, scripts=0)
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
    code, ctype, body, headers = site.handle("/topology", "", _doc({"topology"}))
    assert code == 200 and ctype.startswith("text/html")
    assert "script-src 'self'" in headers["Content-Security-Policy"]
    html = body.decode()
    assert "<h2>Topology</h2>" in html and "guest:bus-core" in html
    assert '<a href="/topology">Topology</a>' in html
    assert "unavailable" in site.body("roadmap")
    full = MapSite(root=ROOT, registry=load(REGISTRY), guests=GUESTS, guests_site=SITE)
    assert full.available() >= {"topology", "dataflow", "architecture", "roadmap"}
    assert MapSite(root=ROOT).available() & {"topology", "dataflow", "architecture"} == set()


def test_an_unreadable_source_is_an_error_line_not_a_crash(tmp_path):
    (tmp_path / "site.yml").write_text("site_version: 1\nzones: nope\n")
    site = MapSite(root=tmp_path, guests=tmp_path, guests_site=tmp_path / "site.yml")
    assert "cannot build the map" in site.body("topology")
    assert "cannot build the map" in site.body("roadmap")  # no docs/ in this root


def _get(host, port, route):
    with urllib.request.urlopen(f"http://{host}:{port}{route}", timeout=10) as r:  # loopback
        return r.headers, r.read().decode()


def test_serve_routes_the_maps():
    from homelabnext.status.serve import make_server

    site = MapSite(root=ROOT, registry=load(REGISTRY))
    srv = make_server(lambda: _doc(site.available()), maps=site)
    threading.Thread(target=srv.serve_forever, args=(0.05,), daemon=True).start()
    host, port = srv.server_address[:2]
    try:
        for route in ("/architecture", "/roadmap"):
            headers, html = _get(host, port, route)
            assert headers["Content-Security-Policy"].startswith("default-src 'none'")
            assert "script-src" not in headers["Content-Security-Policy"]
            assert '<svg class="map"' in html and "cannot build" not in html
            assert_safe(html)
        # the interactive dataflow: its own CSP (scripts from the hub only), the shared script
        headers, html = _get(host, port, "/dataflow")
        csp = headers["Content-Security-Policy"]
        assert csp == assets.live_csp() and "script-src 'self';" in csp
        assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
        assert assets.sha256_source(assets.css()) in csp
        assert '<script src="/static/maps.js"></script>' in html and "cannot build" not in html
        assert_interactive_safe(html, scripts=1)
        headers, js = _get(host, port, assets.SCRIPT_ROUTE)
        assert headers["Content-Type"].startswith("text/javascript") and js == assets.js()
        assert headers["X-Content-Type-Options"] == "nosniff"
        with pytest.raises(urllib.error.HTTPError):
            urllib.request.urlopen(f"http://{host}:{port}/topology", timeout=10)  # loopback
    finally:
        srv.shutdown()
        srv.server_close()


def test_the_script_is_served_only_with_an_interactive_map():
    assert MapSite(root=ROOT).handle(assets.SCRIPT_ROUTE, "", _doc()) is None  # roadmap only
    site = MapSite(guests=GUESTS, guests_site=SITE)
    code, ctype, body = site.handle(assets.SCRIPT_ROUTE, "", _doc())
    assert code == 200 and ctype == assets.JS_TYPE and body.decode() == assets.js()


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
    assert names == ["architecture.html", "dataflow.html", "index.html", "links.html", "mcp-servers.html",
                     "roadmap.html", "roster.html", "schedule.html", "status.json",
                     "topology.html"]  # fmt: skip
    index = (out / "index.html").read_text()
    assert '<a href="topology.html">Topology</a>' in index
    page = (out / "roadmap.html").read_text()
    assert 'href="index.html#view-overview"' in page and "invariants results of 2026-10-20" in page
    assert_safe(page)
    for name in ("topology.html", "dataflow.html"):  # self-contained: inline, pinned by hash
        page = (out / name).read_text()
        assert_static_interactive(page)
        assert 'src="/static' not in page and "<link" not in page


def assert_static_interactive(page: str) -> None:
    """A written interactive map: its CSP meta pins exactly the inline script and styles."""
    import html as htmllib

    meta = re.search(r'<meta http-equiv="Content-Security-Policy" content="([^"]*)">', page)
    csp = htmllib.unescape(meta.group(1))
    scripts = re.findall(r"<script>(.*?)</script\s*>", page, re.S | re.I)
    styles = re.findall(r"<style>(.*?)</style>", page, re.S)
    assert scripts == [assets.js()] and len(styles) == 2
    assert f"script-src {assets.sha256_source(scripts[0])};" in csp
    for st in styles:
        assert assets.sha256_source(st) in csp
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp and "http" not in csp
    assert page.index("Content-Security-Policy") < page.index("<style>")
    assert_interactive_safe(page, scripts=1 + page.count('type="application/json"'))


def test_json_text_cannot_close_its_element_and_round_trips():
    data = {"a": '</script><script>alert("x")</script>', "b": "<!-- & -->", "c": "\u2028"}
    text = assets.json_text(data)
    assert not set("<>&") & set(text)
    assert json.loads(text) == data
    assert assets.json_script("x", data).count("</script>") == 1


def test_the_script_has_no_markup_or_eval_sinks():
    """CodeQL's DOM-XSS and code-injection queries, enforced here first: the script writes the
    page with textContent and attributes only."""
    js = assets.js()
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(",
                 "new Function", "setAttribute(\"style", "setAttribute('style", "CSS.escape"):  # fmt: skip
        assert sink not in js, sink
    assert "textContent" in js and "<script" not in js.lower() and "<!--" not in js  # inlined
    assert assets.css().count("@import") == 0 and "url(http" not in assets.css()


def test_map_options_are_checked(tmp_path, capsys):
    base = ["render", "--out", str(tmp_path / "o"), "--registry", str(REGISTRY),
            "--state", str(tmp_path / "s.json")]  # fmt: skip
    assert main([*base, "--guests", str(GUESTS)]) == 2
    assert main([*base, "--maps", str(tmp_path / "nope")]) == 2
    assert main([*base, "--invariants-results", str(tmp_path / "r.json")]) == 2
    assert main([*base, "--guests-registry", str(LAB / "services.yml")]) == 2
    bad = tmp_path / "bad.yml"
    bad.write_text("registry_version: 1\n")
    assert main([*base, "--guests", str(GUESTS), "--guests-site", str(SITE),
                 "--guests-registry", str(bad)]) == 2  # fmt: skip
    err = capsys.readouterr().err
    assert "--guests-registry needs --guests" in err and "--guests-registry " in err
    assert "--guests needs --guests-site" in err and "not a directory" in err
    assert "--invariants-results needs --maps" in err
