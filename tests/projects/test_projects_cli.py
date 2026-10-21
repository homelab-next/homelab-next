# SPDX-License-Identifier: Apache-2.0
"""``hnx projects`` and the hub's Projects page."""

import json
import shutil
import threading
import urllib.request
from pathlib import Path

import pytest

from homelabnext.cli import main as hnx
from homelabnext.projects import strategy_records
from homelabnext.projects.cli import main as cli
from homelabnext.projects.markdown import parse_item, render_item
from homelabnext.projects.pages import ROUTES, ProjectsSite

REPO = Path(__file__).resolve().parents[2]
STRATEGY = str(REPO / "examples/strategy")
NOW = 1_792_000_000.0  # 2026-10-15


@pytest.fixture
def run(tmp_path, capsys):
    d = str(tmp_path / "projects")

    def go(*args):
        capsys.readouterr()
        code = cli([*args, "--dir", d, "--strategy", STRATEGY, "--json"])
        out = capsys.readouterr()
        return code, (json.loads(out.out) if out.out.strip() else None), out.err

    go.dir = Path(d)
    return go


def test_new_list_show_move_close_and_the_auto_close(run):
    code, (p,), _ = run("new", "project", "Edge move", "--key", "edge", "--due", "2026-12-01")
    assert code == 0 and p["status"] == "open"
    assert run("new", "project", "Edge move", "--key", "edge")[1][0]["uid"] == p["uid"]
    short = p["uid"][-8:]
    _, (a,), _ = run("new", "step", "Build", "--project", short, "--assignee", "profile:responder")
    _, (b,), _ = run("new", "step", "Switch", "--project", p["uid"])
    assert (a["order"], b["order"]) == (1, 2)
    code, shown, _ = run("show", short)
    assert [s["title"] for s in shown["steps"]] == ["Build", "Switch"]
    assert run("move", a["uid"], "in_progress")[1][0]["version"] == 2
    code, _, err = run("move", a["uid"], "todo", "--version", "1")
    assert code == 1 and "stale" in err
    code, _, err = run("close", p["uid"], "early")
    assert code == 1 and "unfinished step" in err
    run("close", a["uid"], "built")
    run("move", b["uid"], "cancelled", "--result", "not needed")
    assert run("show", p["uid"])[1]["status"] == "closed"  # the last step closed it
    code, _, err = run("new", "step", "late", "--project", p["uid"])
    assert code == 1 and "closed" in err
    assert len(run("list", "--kind", "step", "--project", p["uid"])[1]) == 2


def test_link_by_display_id_and_the_feed(run, capsys):
    recs = {r.id: r.uid for r in strategy_records(STRATEGY)}
    _, (t,), _ = run("new", "task", "Answer the RFI", "--assignee", "profile:reader")
    _, (linked,), _ = run("link", t["uid"], "RFI-002", "answers")
    assert linked["links"] == [{"relation": "answers", "target": recs["RFI-002"]}]
    assert [i["uid"] for i in run("list", "--linked-to", "RFI-002")[1]] == [t["uid"]]
    code, _, err = run("link", t["uid"], "SO-999", "supports")
    assert code == 1 and "uid" in err  # an unknown display id resolves to nothing
    assert run("link", t["uid"], "RFI-002", "answers", "--unlink")[1][0]["links"] == []
    capsys.readouterr()
    assert cli(["feed", "--dir", str(run.dir), "--strategy", STRATEGY]) == 0
    out = capsys.readouterr()
    (ev,) = [json.loads(line) for line in out.out.splitlines()]
    assert ev["type"] == "homelabnext.project.changed" and ev["data"]["version"] == 3
    assert out.err.startswith("cursor: ")


def test_check_fails_on_a_hand_edit_and_passes_on_the_examples(run, capsys):
    _, (p,), _ = run("new", "project", "P")
    _, (s,), _ = run("new", "step", "S", "--project", p["uid"])
    assert run("check")[0] == 0
    f = run.dir / f"{s['uid']}.md"
    f.write_text(render_item({**parse_item(f.read_text(), f.name), "status": "done", "result": "x", "closed_on": "2026-10-01"}))  # fmt: skip
    code, problems, _ = run("check")
    assert code == 1 and any("must be closed" in p for p in problems)
    capsys.readouterr()
    assert hnx(["projects", "check", "--dir", str(REPO / "examples/projects"), "--strategy", STRATEGY]) == 0  # fmt: skip


def test_refs_must_be_unambiguous(run):
    assert run("show", "abc")[0] == 1  # too short
    assert run("show", "0123456789ab")[0] == 1  # matches nothing


# --- the hub page ----------------------------------------------------------------------------------


def _doc(projects=True):
    from homelabnext.registry.model import load
    from homelabnext.status.model import sources_from_registry
    from homelabnext.status.views import build_status, load_views

    reg = load(REPO / "examples/services.yml")
    specs = sources_from_registry(reg)
    views = load_views(REPO / "examples/status/views.yml", reg, specs)
    snap = {"now": "2026-10-20T13:10:00Z", "observations": [], "sources": []}
    return build_status(snap, views, reg, [], projects=projects)


def test_the_page_is_on_the_menu_and_available_only_when_served():
    menu = {m["id"]: m for m in _doc()["menu"]}
    assert menu["projects"]["href"] == ROUTES[0] and menu["projects"]["available"]
    assert not {m["id"]: m for m in _doc(False)["menu"]}["projects"]["available"]


def test_the_page_shows_progress_blocked_work_and_records_escaped(tmp_path):
    lab = tmp_path / "projects"
    shutil.copytree(REPO / "examples/projects", lab)
    f = next(p for p in lab.glob("*.md") if "kind: task" in p.read_text())
    f.write_text(f.read_text().replace("title: Answer", "title: <script>x</script> Answer"))
    site = ProjectsSite(lab, strategy=STRATEGY, clock=lambda: NOW)
    code, ctype, body = site.handle("/projects", "", _doc())
    html = body.decode()
    assert code == 200 and ctype.startswith("text/html")
    assert "<script>x" not in html and "&lt;script&gt;x&lt;/script&gt; Answer" in html
    assert "Move the edge proxy to the new host" in html and "1 of 3 steps done (33%)" in html
    assert "<h3>Blocked</h3>" in html and "Switch the alias and retire the old guest" in html
    assert "<code>OO-001</code>" in html and "<code>RFI-002</code>" in html
    assert site.handle("/projects/x", "", _doc()) is None
    assert sorted(p.name for p in lab.iterdir()) == sorted(p.name for p in (REPO / "examples/projects").iterdir())  # fmt: skip


def test_serve_routes_the_page():
    from homelabnext.status.serve import make_server

    site = ProjectsSite(REPO / "examples/projects", strategy=STRATEGY, clock=lambda: NOW)
    srv = make_server(_doc, projects=site)
    threading.Thread(target=srv.serve_forever, args=(0.05,), daemon=True).start()
    host, port = srv.server_address[:2]
    try:
        with urllib.request.urlopen(f"http://{host}:{port}/projects", timeout=5) as r:  # loopback
            body = r.read().decode()
        assert "<h2>Projects</h2>" in body and '<a href="/projects">Projects</a>' in body
    finally:
        srv.shutdown()
        srv.server_close()
