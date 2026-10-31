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
from tests.front_door_pass import FrontDoorPass

REPO = Path(__file__).resolve().parents[2]
STRATEGY = str(REPO / "examples/strategy")
NOW = 1_792_000_000.0  # 2026-10-15


def by_code(root=REPO / "examples/strategy"):
    """legacy code (aliases.yml, history only) -> the record, to name records in assertions"""
    import yaml

    codes = yaml.safe_load((Path(root) / "aliases.yml").read_text())["aliases"]
    recs = {r.uid: r for r in strategy_records(root)}
    return {code: recs[uid] for code, uid in codes.items() if uid in recs}


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
    recs = {k: r.uid for k, r in by_code().items()}
    _, (t,), _ = run("new", "task", "Answer the RFI", "--assignee", "profile:reader")
    rfi = by_code()["RFI-002"].label  # the computed display number, e.g. "RFI 1.1"
    _, (linked,), _ = run("link", t["uid"], rfi, "answers")
    assert linked["links"] == [{"relation": "answers", "target": recs["RFI-002"]}]
    assert [i["uid"] for i in run("list", "--linked-to", rfi)[1]] == [t["uid"]]
    code, _, err = run("link", t["uid"], "SO-999", "supports")
    assert code == 1 and "uid" in err  # an unknown display id resolves to nothing
    assert run("link", t["uid"], recs["RFI-002"], "answers", "--unlink")[1][0]["links"] == []
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


def test_refs_must_be_unambiguous(run, capsys):
    run("new", "task", "something to point at")
    assert run("show", "abc")[0] == 1  # too short
    assert run("show", "0123456789ab")[0] == 1  # matches nothing
    ex = ["--dir", str(REPO / "examples/projects"), "--strategy", STRATEGY, "--json"]
    project = "01a15edd-032d-77ed-ab75-53a6402b1c8d"
    for ref in ("01a15edd-032d", "01a15edd032d", "53a6402b1c8d", "402b1c8d"):  # prefix, suffix
        capsys.readouterr()
        assert cli(["show", ref, *ex]) == 0, ref
        assert json.loads(capsys.readouterr().out)["uid"] == project
    assert cli(["show", "01a15edd", *ex]) == 1  # a prefix every example shares
    assert "matches 5 items" in capsys.readouterr().err


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
    codes = by_code()
    assert f"<code>{codes['OO-001'].label}</code>" in html
    assert f"<code>{codes['RFI-002'].label}</code>" in html
    assert site.handle("/projects/x", "", _doc()) is None
    assert sorted(p.name for p in lab.iterdir()) == sorted(p.name for p in (REPO / "examples/projects").iterdir())  # fmt: skip


def test_serve_routes_the_page():
    from homelabnext.status.serve import make_server

    site = ProjectsSite(REPO / "examples/projects", strategy=STRATEGY, clock=lambda: NOW)
    srv = make_server(_doc, projects=site, agents=FrontDoorPass())
    threading.Thread(target=srv.serve_forever, args=(0.05,), daemon=True).start()
    host, port = srv.server_address[:2]
    try:
        with urllib.request.urlopen(f"http://{host}:{port}/projects", timeout=5) as r:  # loopback
            body = r.read().decode()
        assert "<h2>Projects</h2>" in body and '<a href="/projects">Projects</a>' in body
    finally:
        srv.shutdown()
        srv.server_close()


def test_the_documented_commands_run_against_the_examples(tmp_path, capsys):
    """Every `hnx projects` line of docs/projects.md's example block runs, in order, against a
    copy of examples/projects (the refs in it are real prefixes and suffixes of example uids)."""
    import re
    import shlex

    d = tmp_path / "projects"
    shutil.copytree(REPO / "examples/projects", d)
    doc = (REPO / "docs/projects.md").read_text()
    block = doc.split("Over `examples/projects`", 1)[1].split("```bash\n", 1)[1].split("```")[0]
    lines = [ln.split("  #")[0] for ln in block.splitlines() if ln.startswith("hnx projects ")]
    assert len(lines) >= 8, lines
    for line in lines:
        args = shlex.split(line)[2:]
        code = cli([*args, "--dir", str(d), "--strategy", STRATEGY])
        out = capsys.readouterr()
        assert code == 0, f"{line}: exit {code}: {out.err}"
    assert cli(["check", "--dir", str(d), "--strategy", STRATEGY]) == 0
    assert re.search(r" 0 problem\(s\) in 6 item\(s\) of ", capsys.readouterr().err)


def test_a_read_needs_an_existing_directory(tmp_path, capsys):
    """check, list, show and feed refuse a --dir that is not there (exit 2) and do not create
    it; only `new` does.  The P-08 invariant cannot pass over a missing or empty board."""
    gone = tmp_path / "nowhere"
    for args in (["check"], ["list"], ["show", "abcdef"], ["feed"]):
        assert cli([*args, "--dir", str(gone), "--strategy", STRATEGY]) == 2, args
        assert "no projects directory" in capsys.readouterr().err
    assert not gone.exists()
    assert cli(["new", "task", "first", "--dir", str(gone), "--strategy", STRATEGY]) == 0
    assert gone.is_dir()
    capsys.readouterr()
    assert cli(["check", "--dir", str(gone), "--strategy", STRATEGY]) == 0
    assert "0 problem(s) in 1 item(s) of" in capsys.readouterr().err


def test_the_p08_invariant_needs_a_non_empty_board():
    import re

    import yaml

    crit = next(
        c
        for c in yaml.safe_load((REPO / "examples/registers/invariants.yml").read_text())[
            "criteria"
        ]
        if c["id"] == "P-08"
    )
    rx = re.compile(crit["expect_regex"])
    assert rx.search("hnx projects check: 0 problem(s) in 5 item(s) of examples/projects")
    assert not rx.search("hnx projects check: 0 problem(s) in 0 item(s) of examples/projects")
    assert not rx.search("hnx projects check: 10 problem(s) in 5 item(s) of examples/projects")
