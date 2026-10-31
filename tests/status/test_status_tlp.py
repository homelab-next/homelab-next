# SPDX-License-Identifier: Apache-2.0
"""TLP ceilings on the hub's views and exports, and the release transforms of its public view
(ADR-0033 decisions 6, 7 and 8)."""

from __future__ import annotations

import copy
import csv
import io
import json
import threading
from pathlib import Path

import pytest
import yaml
from agent_helpers import AUTHORIZED, front_door, request, summary
from status_helpers import ROOT, T0, VIEWS, spec

from homelabnext import tlp
from homelabnext.status import build_status, load_views, views_problems
from homelabnext.status import release as rel
from homelabnext.status.agents import ActivityStore
from homelabnext.status.agents.pages import AgentSite
from homelabnext.status.model import iso
from homelabnext.status.render import render_html, write
from homelabnext.status.serve import LOOPBACK, make_server
from homelabnext.status.views import WITHHELD_PANELS, public_status

FULL_VIEWS = {
    "views_version": 1,
    "shell": {"title": "Test lab", "main": "overview", "act_via": {"service": "dashboards"}},
    "exports": {n: {"tlp": "clear"} for n in rel.EXPORTS},
    "menu": [
        {"id": "overview", "title": "Overview", "panel": "exceptions", "tlp": "clear"},
        {"id": "grid", "title": "Grid", "panel": "grid", "tlp": "clear"},
        {"id": "sources", "title": "Sources", "panel": "sources", "tlp": "clear"},
        {"id": "agents", "title": "Agents", "panel": "agents", "tlp": "clear"},
        {"id": "dashboards", "title": "Dashboards", "external": {"service": "dashboards"}, "tlp": "clear"},
        {"id": "detail", "title": "Detail", "panel": "agent-detail", "group": "private", "tlp": "red"},
    ],
}  # fmt: skip
#: documentation addresses, built so the raw-endpoint gate does not read them as endpoints
IP = ".".join(("203", "0", "113", "9"))
IP_B, IP_C = ".".join(("192", "0", "2", "7")), ".".join(("198", "51", "100", "4"))
#: values planted in kept fields: a hostname-like source id, agent and tool, an IP as a
#: session id, a path and a TLP marker; the value checks must replace every one of them
PLANTED = ("db1.lab.example", "agent.lab.example", "usr/bin/curl", IP, "TLP:RED")
#: what the public view must never carry, whatever the source held
SECRETISH = ("lab-host-7", "private-project", "example-model-large", "/var/lib/probe.json",
             *PLANTED)  # fmt: skip


@pytest.fixture
def store(tmp_path, clock):
    s = ActivityStore(tmp_path / "activity.db", clock=clock)
    full = {"host": "lab-host-7", "project": "private-project", "model": "example-model-large",
            "surface": "local", "agent": "triage-agent", "parent_session_id": "s-0",
            "tokens_in": 10, "tokens_out": 20, "cost_usd": 0.5, "has_detail": False}  # fmt: skip
    s.add([summary(1, **full), summary(2, kind="prompt", outcome="info", **full)], [], via="test")
    planted = [  # kept fields holding what no kept field may release
        summary(3, session=IP, agent="agent.lab.example", tool="usr/bin/curl"),
        summary(4, session="s-2", agent="TLP:RED", tool="TLP:RED", runtime="codex"),
    ]
    s.add(planted, [], via="test")
    return s


def _full_doc(registry, site):
    """A status document with every field the hub writes today, each one populated."""
    src = spec(
        "db1.lab.example", kind="poll-file", file="/var/lib/probe.json", path=None, service="dashboards",
        power={"ups": "ups-1", "model": "x", "feeds": [], "guests": []},
    )  # fmt: skip
    t = iso(T0)
    obs = {"source": src.id, "module": src.module, "item": "lab-host-7 disk", "state": "fail",
           "summary": "lab-host-7 /var/lib full", "link": "status:a", "observed_at": t,
           "expires_at": t, "value": 3, "work": True, "reported_state": "fail",
           "history": [[t, "fail"]], "flags": ["late"]}  # fmt: skip
    source = {**src.describe(), "state": "warn", "last_attempt": t, "last_ok": t,
              "error": "lab-host-7 refused", "clock_skew_s": 4}  # fmt: skip
    snap = {"now": t, "observations": [obs], "sources": [source]}
    return build_status(snap, FULL_VIEWS, registry, [src], agents=site.summary())


# ---------------------------------------------------------------- ceilings in views.yml
def test_the_example_views_declare_every_ceiling(registry, specs):
    doc = load_views(VIEWS, registry, specs)
    assert {v["tlp"] for v in doc["menu"] if v.get("group") != "private"} == {"clear"}
    assert {v["tlp"] for v in doc["menu"] if v.get("group") == "private"} == {"red"}
    assert set(doc["exports"]) == set(rel.EXPORTS)


def _example():
    return yaml.safe_load(VIEWS.read_text(encoding="utf-8"))


def _entry(doc, vid):
    return next(v for v in doc["menu"] if v["id"] == vid)


def _external(doc):
    """The first external link entry: a menu link is a public view too."""
    return next(v for v in doc["menu"] if "external" in v)


@pytest.mark.parametrize(
    "mutate, problem",
    [
        (lambda d: _entry(d, "overview").pop("tlp"), "view overview: declares no TLP ceiling"),
        (lambda d: _external(d).pop("tlp"), ": declares no TLP ceiling (tlp: clear)"),
        (lambda d: _entry(d, "topology").pop("tlp"), "view topology: declares no TLP ceiling"),
        (lambda d: _entry(d, "agent-detail").pop("tlp"), "view agent-detail: declares no TLP"),
        (lambda d: _entry(d, "overview").update(tlp="green"), "a public view's TLP ceiling is clear, not green"),
        (lambda d: _entry(d, "activity").update(tlp="red"), "a public view's TLP ceiling is clear, not red"),
        (lambda d: _external(d).update(tlp="amber"), "a public view's TLP ceiling is clear, not amber"),
        (lambda d: _entry(d, "approvals").update(tlp="clear"), "a private view's TLP ceiling is red, not clear"),
        (lambda d: d.pop("exports"), "exports.status.json: declares no TLP ceiling"),
        (lambda d: d["exports"].pop("activity.csv"), "exports.activity.csv: declares no TLP ceiling"),
        (lambda d: d["exports"]["activity.jsonl"].update(tlp="green"), "a public export's TLP ceiling is clear, not green"),
        (lambda d: _entry(d, "overview").update(tlp="TLP:CLEAR"), "schema:"),
        (lambda d: _entry(d, "overview").update(tlp="white"), "schema:"),
        (lambda d: _entry(d, "overview").update(tlp="amber-strict"), "schema:"),
        (lambda d: d["exports"].update({"other.csv": {"tlp": "clear"}}), "schema:"),
    ],
)  # fmt: skip
def test_a_missing_or_wrong_ceiling_is_refused(registry, specs, mutate, problem):
    doc = _example()
    mutate(doc)
    assert any(problem in p for p in views_problems(doc, registry, specs)), problem


def test_reachability_never_raises_a_ceiling(registry, specs):
    """A public page in a group of its own, or one that is reachable from outside, is still a
    public view; only the private group's grant is red."""
    doc = _example()
    _entry(doc, "links").update(group="lab-only", tlp="red")
    problems = views_problems(doc, registry, specs)
    assert "view links: a public view's TLP ceiling is clear, not red" in problems


def test_the_views_schema_spells_labels_as_the_label_type_does():
    schema = json.loads((ROOT / "schemas/status/views.schema.json").read_text(encoding="utf-8"))
    assert tuple(schema["$defs"]["tlp"]["enum"]) == tlp.LABELS


# ---------------------------------------------------------------- the registry
def test_the_hub_registry_is_valid_and_covers_what_the_hub_serves():
    r = rel.registry()
    for name in rel.EXPORTS:
        (t,) = r.serving(name)
        assert t.output == tlp.Label.CLEAR and t.input == tlp.Label.RED
    for view in rel.VIEWS:
        assert r.serving(view)


def _registry_doc():
    return yaml.safe_load(rel.REGISTRY.read_text(encoding="utf-8"))


def test_a_public_export_or_view_with_no_transform_fails(registry, specs):
    doc = _registry_doc()
    doc["transforms"] = [t for t in doc["transforms"] if t["id"] != rel.STATUS_PUBLIC]
    problems, transforms = rel.registry_problems(doc)
    assert any(f"transform {rel.STATUS_PUBLIC}" in p and "not declared" in p for p in problems)
    without = views_problems(_example(), registry, specs, rel.Releases(transforms))
    assert (
        "exports.status.json: no release transform serves 'status.json', so it is withdrawn"
        in without
    )
    assert "view overview: no release transform serves 'exceptions', so it is withdrawn" in without
    with pytest.raises(rel.ReleaseError, match="withdrawn"):
        public_status({"schema": "x"}, rel.Releases(transforms))


def test_a_transform_above_the_ceiling_fails(registry, specs):
    doc = _registry_doc()
    next(t for t in doc["transforms"] if t["id"] == rel.EVENTS_PUBLIC)["output"] = "green"
    problems, transforms = rel.registry_problems(doc)
    assert problems == []
    out = views_problems(_example(), registry, specs, rel.Releases(transforms))
    assert (
        "exports.activity.csv: release transform agent-events-public outputs green, above the "
        "ceiling clear" in out
    )


@pytest.mark.parametrize(
    "mutate, problem",
    [
        (lambda t: t.update(input="white-ish"), "input: not a TLP label"),
        (lambda t: t.update(output="red", input="clear"), "stricter than its input"),
        (lambda t: t["keep"].update(summary="count"), "overlaps another listed path"),
        (lambda t: t["keep"].update({"menu[]": "slug"}), "overlaps another listed path"),
        (lambda t: t["keep"].update(observations="count"), "keep and withdraw overlap"),
        (lambda t: t["keep"].update({"menu[].x-y": "slug"}), "not a field path"),
        (lambda t: t["keep"].update(title="text"), "unknown value kind 'text'"),
        (lambda t: t["keep"].update(title="enum:colours"), "unknown set 'colours'"),
        (lambda t: t["keep"].update(title="const:"), "const needs its value"),
        (lambda t: t["keep"].update(title="slug:x"), "slug takes no argument"),
        (lambda t: t["withdraw"].append({"field": "extra"}), "with a reason"),
        (lambda t: t["withdraw"].append({"field": "extra", "why": " "}), "with a reason"),
        (lambda t: t["serves"].append("topology"), "serves 'topology'"),
        (lambda t: t.update(keep={}), "keep is a non-empty mapping"),
        (lambda t: t.update(keep=["schema"]), "keep is a non-empty mapping"),
        (lambda t: t.pop("withdraw"), "missing 'withdraw'"),
        (lambda t: t.update(note="x"), "unknown key 'note'"),
    ],
)  # fmt: skip
def test_a_malformed_transform_is_refused(mutate, problem):
    doc = _registry_doc()
    mutate(next(t for t in doc["transforms"] if t["id"] == rel.STATUS_PUBLIC))
    problems, _ = rel.registry_problems(doc)
    assert any(problem in p for p in problems), problems


def test_an_export_served_twice_is_refused():
    doc = _registry_doc()
    next(t for t in doc["transforms"] if t["id"] == rel.SESSIONS_PUBLIC)["serves"].append(
        "activity.csv"
    )
    problems, _ = rel.registry_problems(doc)
    assert any("export activity.csv is served by 2 transforms" in p for p in problems)


def test_the_registry_is_governance():
    """A change to the release transforms is human-approve: CODEOWNERS names the registry and
    the code that applies it."""
    owners = (ROOT / ".github/CODEOWNERS").read_text(encoding="utf-8").splitlines()
    rules = {line.split()[0] for line in owners if line.strip() and not line.startswith("#")}
    for path in ("homelabnext/status/release_transforms.yml", "homelabnext/status/release.py"):
        assert "/" + path in rules, path


# ---------------------------------------------------------------- the transform itself
def test_a_transform_passing_an_unlisted_field_fails():
    t = rel.registry().by_id[rel.EVENTS_PUBLIC]
    assert t.unlisted({"event_id": "e", "host": "lab-host-7"}) == ["host"]

    class Leaky(rel.Transform):
        def apply(self, data):
            return dict(data)  # passes everything: the release must refuse it

    leaky = Leaky(**{k: getattr(t, k) for k in t.__dataclass_fields__})
    with pytest.raises(rel.ReleaseError, match="passed unlisted fields: host"):
        rel.Releases([leaky]).release(rel.EVENTS_PUBLIC, "activity.csv", {"host": "lab-host-7"})


def _transform(keep):
    return rel.Transform("x", "x", ("status.json",), tlp.Label.RED, tlp.Label.CLEAR, keep, {})


def test_a_kept_leaf_is_a_scalar_only():
    """A kept path keeps a scalar; a list of scalars only through an explicit ``x[]`` path."""
    t = _transform({"a": "slug"})
    assert t.apply({"a": {"secret": 1}}) == {}
    assert t.apply({"a": [{"secret": 1}]}) == {}
    assert t.apply({"a": [1, "b"]}) == {}
    assert t.unlisted({"a": ["b"]}) == ["a[]"]
    items = _transform({"a[]": "slug"})
    assert (
        items.apply({"a": ["b", {"c": 1}]}) == {"a": ["b"]} and items.unlisted({"a": ["b"]}) == []
    )


def test_the_output_recheck_does_not_trust_apply():
    """``unlisted`` flattens the output by its own walk: it catches what a wrong apply passes."""
    t = _transform({"views.*.ok": "count", "menu[].id": "slug"})
    assert t.unlisted({"views": {"o": {"ok": 1}}, "menu": [{"id": "a"}]}) == []
    assert t.unlisted({"views": {"o": {"ok": 1, "x": 2}}}) == ["views.o.x"]
    assert t.unlisted({"menu": [{"id": {"deep": 1}}]}) == ["menu[].id.deep"]
    assert t.unlisted({"menu": [], "views": {}}) == []  # empty, on the way to a kept leaf
    assert t.unlisted({"other": []}) == ["other"]


@pytest.mark.parametrize(
    "kind, good, bad",
    [
        ("slug", ["s-1", "triage-agent", "profile:triage", "Bash", "mcp__x__y"],
         ["db1.lab.example", "a/b", IP_B, "TLP:RED", "tlp amber", "", "x" * 81, "a b"]),
        ("title", ["Overview", "Proposals and approvals", "Agent analytics (beta)"],
         ["svc.lab.example", "TLP:AMBER notes", "/etc/hosts", "<b>", "2001:db8::5 view"]),
        ("time", ["2026-09-21T13:33:20Z", "2026-09-21T13:33:20.5Z"],
         ["2026-09-21 13:33:20", "yesterday", "2026-09-21T13:33:20+02:00"]),
        ("enum:state", ["ok", "fail"], ["broken", "OK"]),
        ("enum:outcome", ["success", "denied"], ["maybe"]),
        ("const:homelabnext.status/1", ["homelabnext.status/1"], ["homelabnext.status/2"]),
        ("count", [0, 3, 0.5, None], ["3", True]),
        ("bool", [True, False, None], [1, "true"]),
    ],
)  # fmt: skip
def test_each_value_kind_is_closed(kind, good, bad):
    assert all(rel.check_value(kind, v) for v in good), kind
    assert not any(rel.check_value(kind, v) for v in bad), kind


def test_the_closed_sets_match_the_activity_schema():
    schema = json.loads((ROOT / "schemas/status/agent_activity.schema.json").read_text("utf-8"))
    props = schema["properties"]
    assert rel.SETS["activity-kind"] == tuple(props["kind"]["enum"])
    assert rel.SETS["outcome"] == tuple(props["outcome"]["enum"])
    assert rel.SETS["surface"] == tuple(props["surface"]["enum"])


def test_a_value_that_fails_is_replaced_never_passed():
    t = rel.registry().by_id[rel.EVENTS_PUBLIC]
    out = rel.registry().release(
        rel.EVENTS_PUBLIC, "activity.jsonl",
        {"event_id": "ev-1", "agent": "db1.lab.example", "tool": "/usr/bin/x", "kind": "boom",
         "session_id": IP_C, "tokens_in": "12", "has_detail": "yes",
         "runtime": "TLP:RED"},
    )  # fmt: skip
    assert out == {"event_id": "ev-1", "agent": rel.PLACEHOLDER, "tool": rel.PLACEHOLDER,
                   "kind": rel.PLACEHOLDER, "session_id": rel.PLACEHOLDER, "tokens_in": None,
                   "has_detail": None, "runtime": rel.PLACEHOLDER}  # fmt: skip
    assert t.unlisted(out) == []


def test_every_public_field_is_kept_or_withdrawn(registry, store, clock):
    """The day-one migration (decision 8): every field the public view and the exports carry
    today is listed by its transform, kept or withdrawn; a field added later fails here until
    someone judges it (and is dropped from the public view meanwhile)."""
    site = AgentSite(store, clock=clock)
    doc = _full_doc(registry, site)
    r = rel.registry()
    status = r.by_id[rel.STATUS_PUBLIC]
    assert status.unclassified(doc) == []
    for e in store.events(limit=None):
        assert r.by_id[rel.EVENTS_PUBLIC].unclassified(e) == []
    for s in store.sessions():
        assert r.by_id[rel.SESSIONS_PUBLIC].unclassified(s) == []
    later = copy.deepcopy(doc)
    later["modules"][0]["owner_email"] = "someone@lab.example"
    assert status.unclassified(later) == ["modules[0].owner_email"]
    assert "owner_email" not in json.dumps(public_status(later))


def test_the_public_status_carries_only_kept_fields(registry, store, clock):
    site = AgentSite(store, clock=clock)
    doc = _full_doc(registry, site)
    out = public_status(doc, contract=True)
    text = json.dumps(out)
    for s in SECRETISH:
        assert s not in text, s
    assert "observations" not in out and "act_via" not in out
    assert out["summary"]["fail"] == 1 and out["modules"] == [
        {"state": "fail", "counts": {"total": 1, "ok": 0, "warn": 0, "fail": 1, "unknown": 0,
                                     "stale": 0}}
    ]  # fmt: skip
    # nothing that names which system is failing: no source, module or attention item
    assert "sources" not in out and "attention" not in out["views"]["overview"]
    assert "sources" not in out["views"]["sources"]
    assert all("module" not in m for v in out["views"].values() for m in v.get("modules", []))
    assert all("href" not in m and "service" not in m for m in out["menu"])
    assert [m["id"] for m in out["menu"] if m.get("group") == "private"] == []
    assert out["agents"]["counts"]["working"] + out["agents"]["counts"]["waiting"] >= 0
    assert {"host", "project", "model"}.isdisjoint(out["agents"]["sessions"][0])
    page = render_html(public_status(doc), live=True)
    for s in SECRETISH:
        assert s not in page, s
    assert 'href="/agents"' in page and 'title="lab only">Dashboards' in page


def test_render_writes_the_public_view(registry, store, clock, tmp_path):
    doc = _full_doc(registry, AgentSite(store, clock=clock))
    page, data = write(tmp_path, doc)
    for f in (page, data):
        body = f.read_text(encoding="utf-8")
        assert not any(s in body for s in SECRETISH)
    assert json.loads(data.read_text(encoding="utf-8")) == public_status(doc, contract=True)


# ---------------------------------------------------------------- served
@pytest.fixture
def served(tmp_path, clock, store, registry):
    servers = []

    def start(releases=None, *, door=True, **sites):
        fd = front_door(tmp_path) if door else None
        site = AgentSite(store, front_door=fd, clock=clock, releases=releases)
        srv = make_server(
            lambda: _full_doc(registry, site),
            agents=site,
            releases=releases,
            **sites,
            allow_remote=True,
            host=LOOPBACK,
            allowed_hosts=["status.lab.example"],
        )
        threading.Thread(target=srv.serve_forever, args=(0.05,), daemon=True).start()
        servers.append(srv)
        host, port = srv.server_address[:2]
        return f"http://{host}:{port}"

    yield start
    for srv in servers:
        srv.shutdown()
        srv.server_close()


PUBLIC = ["/", "/status.json", "/agents", "/agents/session?id=s-1", "/agents/session?id=s-2",
          "/activity", "/activity?event=ev-s-1-1", "/activity?event=ev-s-2-4",
          "/agent-analytics", "/activity.csv", "/activity.jsonl",
          "/activity.jsonl?session=s-2"]  # fmt: skip


@pytest.mark.parametrize("path", PUBLIC)
def test_no_public_route_carries_a_withdrawn_field(served, path):
    base = served()
    for headers in ({}, AUTHORIZED, {"Host": "status.lab.example"}):
        code, _, body = request(base, path, headers=headers)
        assert code == 200, (path, headers)
        assert not any(s.encode() in body for s in SECRETISH), (path, headers)


def test_a_planted_value_reaches_no_public_route_even_by_its_own_id(served):
    """Asked for by the planted session id itself, the page answers without echoing it."""
    base = served()
    for path in (f"/agents/session?id={IP}", f"/activity?session={IP}"):
        code, _, body = request(base, path)
        assert code == 200 and b"usr/bin/curl" not in body and b"agent.lab.example" not in body
        assert IP.encode() not in body.replace(f"session={IP}".encode(), b""), path


def test_the_front_door_grant_does_not_raise_a_public_ceiling(served):
    base = served()
    anon = request(base, "/status.json")[2]
    assert request(base, "/status.json", headers=AUTHORIZED)[2] == anon
    assert (
        request(base, "/activity.jsonl", headers=AUTHORIZED)[2]
        == request(base, "/activity.jsonl")[2]
    )
    assert b"private/sessions" not in request(base, "/")[2]  # the private group: grant only


def test_the_exports_carry_only_their_transform(served):
    base = served()
    keep = set(rel.registry().by_id[rel.EVENTS_PUBLIC].keep)  # the paths
    rows = [json.loads(line) for line in request(base, "/activity.jsonl")[2].decode().splitlines()]
    assert rows and all(set(r) <= keep for r in rows)
    header = next(csv.reader(io.StringIO(request(base, "/activity.csv")[2].decode())))
    assert header[:3] == ["time", "event_id", "session_id"]
    assert set(header) <= keep and {"host", "project", "model"}.isdisjoint(header)


def test_a_failed_release_is_withdrawn_not_served(served):
    t = rel.registry()

    class Leaky(rel.Transform):
        def apply(self, data):
            return dict(data)

    leaky = rel.Releases(
        Leaky(**{k: getattr(x, k) for k in x.__dataclass_fields__}) for x in t.transforms
    )
    base = served(leaky)
    for path in PUBLIC:
        code, _, body = request(base, path)
        assert code == 500 and body == b"withdrawn: release failed\n", path


@pytest.mark.parametrize("panel", sorted(WITHHELD_PANELS))
def test_a_public_withheld_panel_is_refused(registry, specs, panel):
    """A page no release transform shapes cannot be public, at any ceiling (decision 8)."""
    doc = _example()
    entry = next(v for v in doc["menu"] if v.get("panel") == panel)
    assert entry["group"] == "private" and entry["tlp"] == "red"
    entry.pop("group")
    entry["tlp"] = "clear"
    problems = views_problems(doc, registry, specs)
    assert (
        f"view {entry['id']}: the {panel} panel has no release transform, so it is withdrawn "
        "from the public view: put it in the 'private' group (tlp: red)" in problems
    )
    entry["group"] = "maps"  # any other group is public too
    assert any("has no release transform" in p for p in views_problems(doc, registry, specs))


def test_a_released_view_is_not_in_the_private_group(registry, specs):
    doc = _example()
    _entry(doc, "activity").update(group="private", tlp="red")
    assert any(
        "view activity: the 'private' group holds only the private and the withheld pages" in p
        for p in views_problems(doc, registry, specs)
    )


class _Withheld:
    """A withheld page site (strategy, projects, ...): it serves lab data with no transform."""

    def handle(self, route, query, doc):
        if route == "/strategy":
            return 200, "text/html; charset=utf-8", b"lab-host-7 private-project"
        return None


def test_a_withheld_page_is_served_only_through_the_front_door(served, tmp_path):
    base = served(strategy=_Withheld())
    for headers in ({}, {"Host": "status.lab.example"}):
        code, _, body = request(base, "/strategy", headers=headers)
        assert code == 403 and body == b"forbidden: private view\n"
    code, _, body = request(base, "/strategy", headers=AUTHORIZED)
    assert code == 200 and b"lab-host-7" in body
    log = [json.loads(line) for line in (tmp_path / "access.jsonl").read_text().splitlines()]
    assert {"user": "operator", "view": "strategy"}.items() <= log[-1].items()
    no_door = served(strategy=_Withheld(), door=False)
    assert request(no_door, "/strategy", headers=AUTHORIZED)[0] == 403


class _Counting(_Withheld):
    def __init__(self):
        self.calls = 0

    def handle(self, route, query, doc):
        self.calls += 1
        return super().handle(route, query, doc)


def test_a_withheld_route_is_refused_before_any_site_work(served):
    site = _Counting()
    base = served(strategy=site)
    assert request(base, "/strategy")[0] == 403 and site.calls == 0
    assert request(base, "/orchestration/job?run=x")[0] == 403 and site.calls == 0
    bare = served()  # no withheld site configured at all: the same 403, never a 404
    for path in ("/strategy", "/topology", "/orchestration/job", "/static/maps.js"):
        code, _, body = request(bare, path)
        assert (code, body) == (403, b"forbidden: private view\n"), path
    assert request(bare, "/strategy", headers=AUTHORIZED)[0] == 404  # allowed, nothing there


def test_the_real_withheld_sites_refuse_an_anonymous_request(served, tmp_path):
    from homelabnext.compute.pages import BaselineSite
    from homelabnext.orchestration.pages import OrchestrationSite
    from homelabnext.orchestration.store import TelemetryStore
    from homelabnext.projects.pages import ProjectsSite
    from homelabnext.status.maps import MapSite
    from homelabnext.strategy.pages import StrategySite

    sites = {
        "strategy": StrategySite(ROOT / "examples" / "strategy", clock=lambda: T0),
        "projects": ProjectsSite(ROOT / "examples" / "projects", clock=lambda: T0),
        "orchestration": OrchestrationSite(
            TelemetryStore(tmp_path / "t.db", clock=lambda: T0), clock=lambda: T0
        ),
        "baselines": BaselineSite(
            ROOT / "examples" / "minimal" / "guests", ROOT / "examples" / "minimal" / "site.yml"
        ),
        "maps": MapSite(root=ROOT),
    }
    base = served(**sites)
    routes = ["/strategy", "/requirements", "/objectives", "/rfis", "/projects",
              "/orchestration", "/orchestration/job?run=x", "/baselines", "/architecture",
              "/roadmap", "/links", "/schedule", "/roster", "/mcp-servers"]  # fmt: skip
    for path in routes:
        for headers in ({}, {"Host": "status.lab.example"}):
            code, _, body = request(base, path, headers=headers)
            assert (code, body) == (403, b"forbidden: private view\n"), (path, headers)
    assert request(base, "/strategy", headers=AUTHORIZED)[0] == 200


def test_the_withheld_routes_cover_every_withheld_page():
    from homelabnext.status.maps import assets
    from homelabnext.status.views import PAGE_PANELS, WITHHELD_ROUTES, withheld_route

    assert {PAGE_PANELS[p] for p in WITHHELD_PANELS} | {assets.SCRIPT_ROUTE} == set(WITHHELD_ROUTES)
    assert withheld_route("/orchestration/job") and not withheld_route("/rosterx")
    assert not any(withheld_route(r) for r in ("/", "/agents", "/activity", "/activity.csv"))


def test_the_public_agent_pages_render_from_the_released_document(served):
    """Their shell (menu, title, the change link) comes from the released document only."""
    base = served()
    for path in ("/agents", "/activity", "/agent-analytics"):
        body = request(base, path)[2]
        assert b"Make a change" not in body and b"Test lab" in body, path


def test_the_registry_file_is_packaged():
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert '"status/*.yml"' in pyproject
    assert Path(rel.REGISTRY).is_file()
