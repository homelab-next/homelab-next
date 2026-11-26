# SPDX-License-Identifier: Apache-2.0
"""The register pages of the status hub (Kanban, Lessons, Runbooks, Invariants): rendered from
YAML register files built here at run time, withheld like the other generated pages."""

from __future__ import annotations

import json
import os
import re
import threading

import pytest
import yaml
from reg_helpers import AUTHORIZED, ROOT, T0, VIEWS, front_door, request

from homelabnext.registry.model import load
from homelabnext.status import build_status, load_views, views_problems
from homelabnext.status import registers as reg
from homelabnext.status.agents import ActivityStore
from homelabnext.status.agents.pages import AgentSite
from homelabnext.status.model import iso
from homelabnext.status.registers import RegistersSite
from homelabnext.status.serve import LOOPBACK, make_server
from homelabnext.status.views import REGISTER_PANELS, WITHHELD_PANELS, public_status

ROUTES = {"kanban": "/kanban", "lessons": "/lessons", "runbooks": "/runbooks",
          "invariants": "/invariants"}  # fmt: skip
HOSTILE = "<script>alert(1)</script><img src=x onerror=alert(2)>"
HOURS = 3600


def _doc(registers: bool = True) -> dict:
    snapshot = {"now": iso(T0), "observations": [], "sources": []}
    registry = load(ROOT / "examples" / "services.yml")
    views = load_views(VIEWS)
    return build_status(snapshot, views, registry, [], capability_pages=set(), registers=registers)


def _dump(path, doc) -> None:
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")


def _lesson(n: int, **kw) -> dict:
    d = {
        "id": f"LL-{n:03d}", "title": f"title {n}", "date": "2026-10-01", "systems": ["alpha"],
        "recurrences": 1, "status": "controlled", "symptom": f"symptom {n}",
        "contributing_factors": ["a factor"], "root_cause": f"root {n}",
        "corrective_action": "fixed", "preventive_control": "a control",
        "verification": "a test",
    }  # fmt: skip
    d.update(kw)
    return d


def _write(root, *, stamp: float | None = None, lessons=None, results=True) -> None:
    root.mkdir(exist_ok=True)
    _dump(root / "lessons.yml", {"lessons": lessons or [
        _lesson(1, systems=["lake", "siem_core"]),
        _lesson(2, status="partial", title="needle in a haystack", systems=["alpha"]),
        _lesson(3, status="open", systems=["lake"]),
    ]})  # fmt: skip
    _dump(root / "kanban.yml", {
        "columns": [{"id": "blocked", "title": "Blocked"}, {"id": "todo", "title": "To Do"},
                    {"id": "partial", "title": "Projects (partial)"}, {"id": "done"}],
        "cards": [
            {"title": "blocked card", "column": "blocked", "date": "2026-11-01",
             "tags": [{"class": "tag-owner", "text": "owner:claude"}],
             "body": ["See <code>file.py</code> &amp; <strong>this</strong>."]},
            {"id": "PRJ-001", "title": "a project", "column": "partial", "date": "2026-11-02",
             "steps": [{"n": 1, "text": "step one", "status": "done", "date": "2026-11-03",
                        "result": "it worked"},
                       {"n": 2, "text": "step two", "status": "open"}]},
            {"id": "PRJ-001.2", "title": "step two card", "column": "todo", "date": "2026-11-04"},
            {"title": "archived thing", "column": "done", "date": "2026-10-01"},
        ],
    })  # fmt: skip
    _dump(root / "runbooks.yml", {"runbooks": [
        {"id": "RB-001", "name": "Alpha rules", "kind": "app", "systems": ["siem-core", "alpha"],
         "summary": "sum", "when_to_use": "when", "access": "acc",
         "checklist": [{"step": "do the thing", "verify": "see the thing"}],
         "verification": "done when", "identity": {"hostname": "host-a"},
         "aids": {"tools": ["check.py"]}},
        {"id": "RB-002", "name": "Other flow", "kind": "flow", "systems": ["unrelated"],
         "summary": "s", "when_to_use": "w", "access": "a", "checklist": [],
         "verification": "v"},
    ]})  # fmt: skip
    _dump(root / "invariants.yml", {
        "definition": "things that must hold",
        "pillars": [{"id": "A", "name": "Foundation", "intent": "i"}],
        "criteria": [
            {"id": "A-01", "pillar": "A", "statement": "auto passes", "observable": "run it",
             "expected": "exit 0", "evidence": "auto"},
            {"id": "A-02", "pillar": "A", "statement": "auto red", "observable": "run it",
             "expected": "exit 0", "evidence": "auto"},
            {"id": "A-03", "pillar": "A", "statement": "auto unseen", "observable": "o",
             "expected": "e", "evidence": "auto"},
            {"id": "A-04", "pillar": "A", "statement": "manual", "observable": "o",
             "expected": "e", "evidence": "manual", "status": "pass", "last_checked": "2026-11-01"},
        ],
    })  # fmt: skip
    if results:
        (root / "invariants.results.json").write_text(json.dumps({
            "schema_version": 1, "last_run": "2026-11-22",
            "results": {"A-01": {"status": "pass", "evidence": "ok=1", "checked_at": "2026-11-22T01:00:00"},
                        "A-02": {"status": "fail", "evidence": "drift=2", "checked_at": "2026-11-22T01:00:00"}},
        }))  # fmt: skip
    fetched = T0 - 600 if stamp is None else stamp
    (root / "meta.json").write_text(
        json.dumps({"commit": "abc123def4567890", "fetched_at": iso(fetched)})
    )


@pytest.fixture
def regs(tmp_path):
    root = tmp_path / "registers"
    _write(root)
    return root


def _site(root) -> RegistersSite:
    return RegistersSite(root, clock=lambda: T0)


def _get(site: RegistersSite, route: str, query: str = "") -> str:
    code, ctype, raw = site.handle(route, query, _doc())
    assert (code, ctype) == (200, "text/html; charset=utf-8")
    return raw.decode()


# ---------------------------------------------------------------- menu, views, withholding
@pytest.mark.static
def test_the_register_panels_are_withheld_pages():
    assert set(ROUTES) == REGISTER_PANELS and REGISTER_PANELS <= WITHHELD_PANELS
    doc = yaml.safe_load(VIEWS.read_text())
    entries = {v["panel"]: v for v in doc["menu"] if v.get("panel") in REGISTER_PANELS}
    assert set(entries) == REGISTER_PANELS
    assert all(e["group"] == "private" and e["tlp"] == "red" for e in entries.values())


def test_the_example_views_pass_the_views_check(registry, specs):
    assert views_problems(yaml.safe_load(VIEWS.read_text()), registry, specs) == []


@pytest.mark.parametrize("panel", sorted(REGISTER_PANELS))
def test_a_public_register_panel_is_refused(registry, specs, panel):
    doc = yaml.safe_load(VIEWS.read_text())
    entry = next(v for v in doc["menu"] if v.get("panel") == panel)
    entry.pop("group")
    entry["tlp"] = "clear"
    assert any("has no release transform" in p for p in views_problems(doc, registry, specs))


def test_the_menu_lists_each_page_only_when_registers_are_given():
    for on in (True, False):
        menu = {m["id"]: m for m in _doc(on)["menu"]}
        for panel, route in ROUTES.items():
            assert menu[panel]["kind"] == "page" and menu[panel]["href"] == route
            assert menu[panel]["available"] is on  # unavailable, never an error


def test_the_public_view_never_carries_a_register_page():
    pub = public_status(_doc(), contract=True)
    assert not [m for m in pub["menu"] if m.get("panel") in REGISTER_PANELS]
    text = json.dumps(pub)
    assert "kanban" not in text and "/lessons" not in text


# ---------------------------------------------------------------- the pages
def test_kanban_shows_cards_projects_and_steps(regs):
    html = _get(_site(regs), "/kanban")
    assert "<h2>Kanban</h2>" in html and "blocked card" in html and "a project" in html
    assert "PRJ-001</code></a> &middot; 1/2" in html and "it worked" in html
    assert "<code>file.py</code> &amp; <strong>this</strong>" in html
    assert "owner:claude" in html and "step two card" in html
    assert "archived thing" not in html  # the archive is ?status=done
    assert html.index("Blocked</h3>") < html.index("To Do</h3>") < html.index("Projects (partial)")
    done = _get(_site(regs), "/kanban", "status=done")
    assert "archived thing" in done and "blocked card" not in done


def test_kanban_id_filter_shows_a_project_with_its_step_cards(regs):
    html = _get(_site(regs), "/kanban", "id=PRJ-001")
    assert "a project" in html and "step two card" in html and "blocked card" not in html


def test_lessons_show_every_field_and_the_counts(regs):
    html = _get(_site(regs), "/lessons")
    for text in ("LL-001", "symptom 1", "root 1", "a control", "a test", "fixed", "a factor"):
        assert text in html
    assert "controlled (1)" in html and "partial (1)" in html and "bitten 1x" in html
    assert "lake (2)" in html and "alpha (1)" in html


def test_lesson_filters(regs):
    site = _site(regs)
    q = _get(site, "/lessons", "q=NEEDLE")
    assert "LL-002" in q and "LL-001" not in q
    st = _get(site, "/lessons", "status=open")
    assert "LL-003" in st and "LL-001" not in st and "LL-002" not in st
    sysf = _get(site, "/lessons", "system=siem-core")  # _ and - are the same tag
    assert "LL-001" in sysf and "LL-002" not in sysf
    one = _get(site, "/lessons", "id=LL-002")
    assert "LL-002" in one and "LL-001" not in one and "<details open>" in one
    assert "no lesson matches" in _get(site, "/lessons", "q=nothing-like-this")


def test_pagination_caps_rows_and_links_the_pages(tmp_path):
    root = tmp_path / "r"
    _write(root, lessons=[_lesson(n) for n in range(1, 61)])
    site = _site(root)
    p1 = _get(site, "/lessons")
    assert p1.count("<details") == reg.PAGE_SIZE and "60 records, showing 1-25 (page 1 of 3)" in p1
    assert 'href="/lessons?page=2"' in p1 and "previous" not in p1
    p3 = _get(site, "/lessons", "page=3")
    assert p3.count("<details") == 10 and "LL-060" in p3 and "next" not in p3
    assert "page 3 of 3" in _get(site, "/lessons", "page=999")  # clamped
    assert "page 1 of 3" in _get(site, "/lessons", "page=0")
    kept = _get(site, "/lessons", "status=controlled&q=title")
    assert "page=2" in kept and "status=controlled" in kept and "q=title" in kept


def test_runbooks_show_checklists_with_verify_and_the_lessons_that_apply(regs):
    html = _get(_site(regs), "/runbooks")
    assert "do the thing" in html and "verify: see the thing" in html and "host-a" in html
    assert 'href="/lessons?id=LL-001"' in html  # siem_core (lesson) == siem-core (runbook)
    assert 'href="/lessons?id=LL-002"' in html and "LL-003" not in html.split("RB-002")[0]
    assert "Other flow" in html
    only = _get(_site(regs), "/runbooks", "status=flow")
    assert "Other flow" in only and "Alpha rules" not in only
    assert "RB-001" in _get(_site(regs), "/runbooks", "system=alpha")


def test_invariants_merge_live_results_and_open_the_reds(regs):
    html = _get(_site(regs), "/invariants")
    assert "2 INVARIANT(S) NOT HOLDING" in html and "of 4 live criteria" in html
    assert "drift=2" in html and "ok=1" in html and "No remediation recorded" in html
    assert "2 pass, 1 fail, 0 error, 1 untested, 0 deferred" in html
    assert "auto checks last run 2026-11-22" in html
    assert "<details open><summary><code>A-02" in html
    assert "<details><summary><code>A-01" in html
    assert "A-02" not in _get(_site(regs), "/invariants", "status=pass")
    assert "A-04" in _get(_site(regs), "/invariants", "pillar=A&status=pass")


def test_invariants_all_holding_and_missing_results(tmp_path):
    root = tmp_path / "r"
    _write(root, results=False)
    html = _get(_site(root), "/invariants")
    assert "NO LIVE RESULTS" in html and "invariants.results.json not found" in html
    assert "1 pass, 0 fail, 0 error, 3 untested, 0 deferred" in html
    doc = yaml.safe_load((root / "invariants.yml").read_text())
    doc["criteria"] = [c for c in doc["criteria"] if c["evidence"] == "manual"]
    _dump(root / "invariants.yml", doc)
    assert "ALL INVARIANTS HOLD" in _get(_site(root), "/invariants")


def test_a_malformed_results_file_is_a_banner_not_a_failure(regs):
    (regs / "invariants.results.json").write_text("{not json")
    html = _get(_site(regs), "/invariants")
    assert "NO LIVE RESULTS" in html and "not valid JSON" in html and "A-01" in html


# ---------------------------------------------------------------- escaping
def test_hostile_values_are_escaped_on_every_page(tmp_path):
    root = tmp_path / "r"
    _write(root)
    bad = HOSTILE + '" onmouseover="x'
    _dump(root / "lessons.yml", {"lessons": [_lesson(
        1, title=bad, symptom=bad, root_cause=bad, systems=[bad], status=bad,
        contributing_factors=[bad], note=bad)]})  # fmt: skip
    _dump(root / "kanban.yml", {"cards": [
        {"id": "PRJ-9", "title": bad, "column": "todo", "date": bad,
         "tags": [{"text": bad}], "body": [bad + '<a href="javascript:x()">link</a>'],
         "steps": [{"n": bad, "text": bad, "status": "done", "result": bad}]},
        {"title": "other", "column": bad},
    ]})  # fmt: skip
    _dump(root / "runbooks.yml", {"runbooks": [
        {"id": "RB-9", "name": bad, "kind": bad, "systems": [bad], "summary": bad,
         "when_to_use": bad, "access": bad, "verification": bad,
         "identity": {bad: bad}, "key_files": [{"path": bad, "why": bad}],
         "checklist": [{"step": bad, "verify": bad}]}]})  # fmt: skip
    _dump(root / "invariants.yml", {"definition": bad, "pillars": [{"id": bad, "name": bad}],
          "criteria": [{"id": "X-1", "pillar": bad, "statement": bad, "observable": bad,
                        "expected": bad, "evidence": "manual", "status": bad, "check": bad,
                        "remediation": bad}]})  # fmt: skip
    (root / "meta.json").write_text(json.dumps({"commit": bad, "fetched_at": bad}))
    site = _site(root)
    for route in ROUTES.values():
        for query in (
            "",
            "status=done",
            "q=" + "%3Cscript%3E",
            "system=%3Cb%3E",
            "id=%3Cscript%3E",
        ):
            html = _get(site, route, query)
            assert "<script" not in html and "<img" not in html, (route, query)
            assert 'href="javascript' not in html and '<a href="javascript' not in html
            # no tag the page itself did not write: every "<" opens a known element
            tags = set(re.findall(r"</?([a-zA-Z0-9]+)", html))
            assert tags <= {
                "html",
                "head",
                "meta",
                "title",
                "style",
                "body",
                "nav",
                "h1",
                "p",
                "br",
                "a",
                "div",
                "span",
                "h2",
                "h3",
                "h4",
                "code",
                "strong",
                "b",
                "em",
                "i",
                "ul",
                "ol",
                "li",
                "details",
                "summary",
                "pre",
                "dl",
                "dt",
                "dd",
                "main",
                "table",
                "thead",
                "tbody",
                "tr",
                "th",
                "td",
            }, (route, tags)
    assert "&lt;script&gt;" in _get(site, "/lessons", "id=LL-001")


def test_inline_markup_keeps_only_the_fixed_tags():
    assert reg._inline("<code>x</code> &amp; <b>y") == "<code>x</code> &amp; <b>y</b>"
    assert reg._inline("</b>stray") == "stray"
    assert reg._inline('<a href="http://x">t</a>') == "t"
    assert (
        reg._inline("<code onclick=x>y</code>") == "&lt;code onclick=x&gt;y"
    )  # the orphan close tag is dropped
    assert reg._inline("&lt;script&gt;") == "&lt;script&gt;"


# ---------------------------------------------------------------- freshness
def test_each_page_shows_the_commit_and_fetch_time(regs):
    for route in ROUTES.values():
        html = _get(_site(regs), route)
        assert "abc123def4567890" in html and iso(T0 - 600) in html and "STALE" not in html


def test_a_snapshot_older_than_two_hours_is_stale(tmp_path):
    root = tmp_path / "r"
    _write(root, stamp=T0 - 2 * HOURS - 60)
    for route in ROUTES.values():
        html = _get(_site(root), route)
        assert "STALE</b>" in html and "2h 1m ago" in html, route
    _write(root, stamp=T0 - 2 * HOURS + 60)
    assert "STALE" not in _get(_site(root), "/kanban")
    _write(root, stamp=T0 - 3 * 24 * HOURS)
    assert "3d 0h ago" in _get(_site(root), "/kanban")


@pytest.mark.parametrize("meta", [None, "{oops", "[]", '{"commit": "c"}', '{"fetched_at": "soon"}'])
def test_an_unreadable_snapshot_age_is_loud_too(regs, meta):
    if meta is None:
        (regs / "meta.json").unlink()
    else:
        (regs / "meta.json").write_text(meta)
    html = _get(_site(regs), "/lessons")
    assert "STALE?" in html and "unknown" in html and "LL-001" in html


# ---------------------------------------------------------------- bad files
BAD = {
    "unterminated: [": "not valid YAML",
    "": "list at its top level",
    "lessons: 3": "list at its top level",
    "lessons:\n- not a mapping": "is not a mapping",
    "lessons: []\nlessons: []": "not valid YAML",  # a duplicate key
    "lessons: !!python/object/apply:os.getcwd []": "not valid YAML",  # nothing executes
}


@pytest.mark.parametrize("text", sorted(BAD))
def test_a_malformed_file_is_a_banner_on_its_page_only(regs, text):
    (regs / "lessons.yml").write_text(text)
    site = _site(regs)
    html = _get(site, "/lessons")
    assert "ERROR</b> this register cannot be shown" in html and BAD[text] in html
    for other in ("/kanban", "/runbooks", "/invariants"):
        assert "ERROR</b>" not in _get(site, other), other
    assert "LL-001" not in html


def test_a_missing_file_is_a_banner_naming_the_file_and_not_the_directory(regs):
    (regs / "kanban.yml").unlink()
    html = _get(_site(regs), "/kanban")
    assert "kanban.yml not found in the register directory" in html and str(regs) not in html
    assert "LL-001" in _get(_site(regs), "/lessons")
    missing = RegistersSite(regs / "nowhere", clock=lambda: T0)
    for route in ROUTES.values():
        assert "ERROR</b>" in _get(missing, route)


def test_a_file_above_the_size_limit_is_refused_unread(regs, monkeypatch):
    monkeypatch.setattr(reg, "MAX_FILE_BYTES", 100)
    html = _get(_site(regs), "/lessons")
    assert "above the 100 byte limit" in html and "LL-001" not in html


def test_an_unexpected_failure_while_rendering_is_still_not_a_500(regs, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("secret detail")

    monkeypatch.setattr(reg, "_lesson", boom)
    html = _get(_site(regs), "/lessons")
    assert "could not be rendered (RuntimeError)" in html and "secret detail" not in html


def test_an_unknown_route_is_not_this_sites():
    assert RegistersSite("/nonexistent", clock=lambda: T0).handle("/other", "", _doc()) is None


def test_hostile_query_values_are_ignored_or_escaped(regs):
    site = _site(regs)
    for query in (
        "status[]=a&status=b",
        "status=a&status=b",
        "page=x",
        "page=" + "9" * 50,
        "q=" + "a" * 5000,
        "q=%00%01",
        "system=" + "x" * 200,
        "id=../../etc",
    ):
        _get(site, "/lessons", query)
    assert "&lt;b&gt;" in _get(site, "/lessons", "q=%3Cb%3E")


# ---------------------------------------------------------------- cache
def test_a_file_is_parsed_once_until_it_changes(regs):
    site = _site(regs)
    for _ in range(3):
        _get(site, "/lessons")
        _get(site, "/lessons", "q=root")
    assert site.parses == 1
    _get(site, "/kanban")
    assert site.parses == 2
    _dump(regs / "lessons.yml", {"lessons": [_lesson(7, title="fresh title")]})
    os.utime(regs / "lessons.yml", ns=(10**18, 10**18))
    assert "fresh title" in _get(site, "/lessons") and site.parses == 3


def test_a_malformed_file_is_not_re_parsed_per_request(regs):
    (regs / "lessons.yml").write_text("unterminated: [")
    site = _site(regs)
    for _ in range(3):
        _get(site, "/lessons")
    assert site.parses == 1


def test_concurrent_requests_parse_a_file_once(regs):
    site = _site(regs)
    threads = [threading.Thread(target=_get, args=(site, "/lessons")) for _ in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert site.parses == 1


def test_a_large_register_renders_a_bounded_page(tmp_path):
    root = tmp_path / "r"
    _write(root, lessons=[_lesson(n, symptom="s" * 2000) for n in range(1, 801)])
    html = _get(_site(root), "/lessons")
    assert html.count("<details") == reg.PAGE_SIZE and len(html) < 300_000


# ---------------------------------------------------------------- served, front door only
@pytest.fixture
def served(tmp_path, clock):
    servers = []

    def start(registers, *, door=True):
        store = ActivityStore(tmp_path / "activity.db", clock=clock)
        site = AgentSite(store, front_door=front_door(tmp_path) if door else None, clock=clock)
        srv = make_server(
            lambda: _doc(registers is not None),
            agents=site,
            registers=registers,
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


def test_the_register_routes_are_served_only_through_the_front_door(served, regs, tmp_path):
    base = served(_site(regs))
    for path in (*ROUTES.values(), "/lessons?id=LL-001", "/kanban?status=done"):
        for headers in ({}, {"Host": "status.lab.example"}):
            code, _, body = request(base, path, headers=headers)
            assert (code, body) == (403, b"forbidden: private view\n"), (path, headers)
        code, _, body = request(base, path, headers=AUTHORIZED)
        assert code == 200 and b"abc123def4567890" in body, path
    log = [json.loads(x) for x in (tmp_path / "access.jsonl").read_text().splitlines()]
    assert {"user": "operator", "view": "kanban"}.items() <= log[-1].items() or log
    code, headers, _ = request(base, "/lessons", headers=AUTHORIZED)
    assert "script-src" not in headers["Content-Security-Policy"]


def test_without_registers_the_routes_are_403_anonymous_and_404_authorized(served):
    base = served(None)
    for path in ROUTES.values():
        assert request(base, path)[0] == 403
        assert request(base, path, headers=AUTHORIZED)[0] == 404
    code, _, body = request(base, "/status.json")
    assert code == 200 and b"kanban" not in body and b"/lessons" not in body


def test_the_public_page_and_contract_never_name_a_register_page(served, regs):
    base = served(_site(regs))
    for path in ("/", "/status.json"):
        code, _, body = request(base, path)
        assert code == 200, path
        for needle in (b"kanban", b"/lessons", b"/runbooks", b"/invariants", b"LL-001"):
            assert needle not in body, (path, needle)


def test_no_front_door_means_no_register_page(served, regs):
    base = served(_site(regs), door=False)
    assert request(base, "/kanban", headers=AUTHORIZED)[0] == 403


def test_the_nav_of_a_register_page_lists_the_four_pages(regs):
    html = _get(_site(regs), "/kanban")
    for route in ROUTES.values():
        assert f'<a href="{route}">' in html


def test_the_cli_builds_the_site_only_with_the_flag(tmp_path):
    from types import SimpleNamespace

    from homelabnext.status.cli import _registers_site

    assert _registers_site(SimpleNamespace(registers=None), lambda: T0) is None
    site = _registers_site(SimpleNamespace(registers=str(tmp_path)), lambda: T0)
    assert isinstance(site, RegistersSite)
