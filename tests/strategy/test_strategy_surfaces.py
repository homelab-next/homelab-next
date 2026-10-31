# SPDX-License-Identifier: Apache-2.0
"""Where the strategy shows: graph nodes and typed edges, the status hub pages (escaped, on the
menu), the Markdown index and the CLI; and the registers' id tooling over its directories."""

import datetime as dt
import shutil
import subprocess
import threading
import urllib.request

import pytest
from strategy_helpers import EXAMPLE, NOW, REPO, U, edit, rel, uids

from homelabnext.graph import build, is_active
from homelabnext.registers import ids
from homelabnext.strategy.cli import main as cli
from homelabnext.strategy.pages import ROUTES, StrategySite
from tests.front_door_pass import FrontDoorPass


@pytest.fixture(scope="module")
def graph():
    return build(REPO)[0]


def edges(graph, etype):
    return {(e.src, e.dst) for e in graph.edges if e.type == etype}


def n(kind_code: str) -> str:
    """``objective:SO-001`` -> ``objective:<uid>``: graph node ids are uids."""
    return uids(kind_code)


def test_graph_nodes_and_typed_edges(graph):
    assert graph.nodes["strategy:northwind"].kind == "strategy"
    assert {graph.nodes[n(x)].kind for x in ("objective:SO-001", "measure:MOE-001", "req:PIR-001", "rfi:RFI-001")} == {"objective", "measure", "req", "rfi"}  # fmt: skip
    assert (n("req:FFIR-001"), n("objective:OO-001")) in edges(graph, "supports")
    assert {(n("req:FFIR-001"), n("req:CCIR-001")), (n("req:PIR-001"), n("req:FFIR-001"))} <= edges(graph, "serves")  # fmt: skip
    assert {(n("objective:TT-001"), n("objective:TO-001")), (n("objective:SO-001"), "strategy:northwind")} <= edges(graph, "child_of")  # fmt: skip
    assert (n("objective:TO-001"), n("measure:MOP-002")) in edges(graph, "measured_by")
    assert {(n("measure:MOE-006"), "inv:D-02"), (n("measure:MOE-003"), "status:proposals")} <= edges(graph, "binds")  # fmt: skip
    assert {(n("rfi:RFI-001"), n("measure:MOE-001")), (n("rfi:RFI-002"), n("req:PIR-001"))} <= edges(graph, "raised_by")  # fmt: skip
    assert {(n("req:CCIR-001"), "profile:responder"), (n("rfi:RFI-001"), "profile:reader")} <= edges(graph, "tasked_to")  # fmt: skip
    assert graph.nodes[n("objective:OO-001")].attrs["label"] == "OO 1.1"  # computed, not stored
    assert not any(
        src == n("measure:MOE-005") for src, _ in edges(graph, "binds")
    )  # none binds nothing


def test_closed_records_are_inactive_in_the_graph(graph):
    assert not is_active(graph.nodes[n("rfi:RFI-002")])  # no-find
    assert is_active(graph.nodes[n("rfi:RFI-001")])
    assert graph.nodes[n("objective:SO-001")].attrs["reviewed"] == ["agent_check", "audit"]


def _doc(strategy=True):
    from homelabnext.registry.model import load
    from homelabnext.status.model import sources_from_registry
    from homelabnext.status.views import build_status, load_views

    reg = load(REPO / "examples/services.yml")
    specs = sources_from_registry(reg)
    views = load_views(REPO / "examples/status/views.yml", reg, specs)
    snap = {"now": "2026-10-20T13:10:00Z", "observations": [], "sources": []}
    return build_status(snap, views, reg, [], strategy=strategy)


def test_the_pages_are_on_the_menu_and_available_only_when_served():
    menu = {m["id"]: m for m in _doc()["menu"]}
    for panel, href in zip(("strategy", "requirements", "objectives", "rfis"), ROUTES, strict=True):
        assert menu[panel] | {"available": True} == {
            "id": panel, "title": menu[panel]["title"], "kind": "page", "panel": panel,
            "href": href, "available": True, "group": "private",  # withheld (ADR-0033)
        }  # fmt: skip
    off = {m["id"]: m["available"] for m in _doc(strategy=False)["menu"]}
    assert not any(off[p] for p in ("strategy", "requirements", "objectives", "rfis"))


def test_the_pages_render_escaped(lab):
    edit(lab, "requirements/PIR-001.md", "title: Is anyone probing", "title: <script>x</script> Is anyone probing")  # fmt: skip
    edit(lab, "strategy.md", "## Mission\n\n", "## Mission\n\n<b>bold</b> & ")
    site = StrategySite(lab, clock=lambda: NOW.timestamp())
    pages = {r: site.handle(r, "", _doc()) for r in ROUTES}
    assert all(code == 200 and ctype.startswith("text/html") for code, ctype, _ in pages.values())
    req = pages["/requirements"][2].decode()
    assert "<script>x" not in req and "&lt;script&gt;x&lt;/script&gt; Is anyone probing" in req
    assert req.index("<h3>CCIR</h3>") < req.index("<h3>FFIR</h3>") < req.index("<h3>PIR</h3>")
    assert "&lt;b&gt;bold&lt;/b&gt; &amp; Run a small" in pages["/strategy"][2].decode()
    obj = pages["/objectives"][2].decode()
    moe4 = f'class="s warn">amber</span> <code title="{U["MOE-004"]}">MOE 1.1.1.1.1</code>'
    assert moe4 in obj and "self-measured: capped" in obj
    rfis = pages["/rfis"][2].decode()
    assert "Open: collection" in rfis and ">RFI 1</code>" in rfis and "Searched the proxy access logs" in rfis  # fmt: skip
    assert "<li>SIR 1.1 Requests to the status hub" in req  # SIRs numbered under their PIR
    assert site.handle("/strategy/../etc", "", _doc()) is None


def test_serve_routes_the_pages_under_the_hub_csp():
    from homelabnext.status.serve import make_server

    site = StrategySite(EXAMPLE, clock=lambda: NOW.timestamp())
    srv = make_server(_doc, strategy=site, agents=FrontDoorPass())
    threading.Thread(target=srv.serve_forever, args=(0.05,), daemon=True).start()
    host, port = srv.server_address[:2]
    try:
        with urllib.request.urlopen(f"http://{host}:{port}/objectives", timeout=5) as r:  # loopback
            body, csp = r.read().decode(), r.headers["Content-Security-Policy"]
        assert "<h2>Objectives</h2>" in body and "default-src 'none'" in csp
        assert '<a href="/rfis">RFIs</a>' in body  # live menu entry
    finally:
        srv.shutdown()
        srv.server_close()


def test_the_index_is_current_and_the_cli_checks_it(tmp_path, capsys):
    assert cli(["index", str(EXAMPLE), "--out", str(REPO / "docs/strategy/README.md"), "--check"]) == 0  # fmt: skip
    out = tmp_path / "docs/strategy/README.md"
    assert cli(["index", str(EXAMPLE), "--out", str(out), "--check"]) == 1
    assert cli(["index", str(EXAMPLE), "--out", str(out)]) == 0
    text = out.read_text()
    assert "[SO 1 Core services stay available](" in text and f"/{rel('SO-001')})" in text
    assert f"([[{U['SO-001']}|SO 1 Core services stay available]])" in text  # Obsidian alias
    assert f"[[{U['PIR-001']}\\|PIR 1 " in text and "| PIR |" in text  # a table escapes the pipe


def test_cli_check_links_and_rollup(lab, capsys):
    assert cli(["check", str(lab)]) == 0
    assert cli(["links", str(lab), "--check"]) == 0
    edit(lab, "requirements/PIR-001.md", "serves: [FFIR-001]", "serves: [CCIR-001]")
    assert cli(["links", str(lab), "--check"]) == 1  # the Links block is now stale
    assert cli(["links", str(lab)]) == 0 and cli(["links", str(lab), "--check"]) == 0
    assert cli(["check", str(lab)]) == 1  # the content changed: its reviews are stale
    capsys.readouterr()
    assert cli(["rollup", str(lab), "--now", "2026-10-20T13:10:00Z"]) == 0
    assert "TT 1.1.1.1 [amber] Read the proposal inbox every week" in capsys.readouterr().out


def test_cli_rfis_lists_open_by_triage_and_what_expires(capsys):
    clock = lambda: dt.datetime(2026, 11, 15, tzinfo=dt.UTC)  # noqa: E731
    assert cli(["rfis", str(EXAMPLE)], clock=clock) == 0
    out = capsys.readouterr().out
    assert "collection requirements: RFI 1" in out and "expiring soon: RFI 1 (2026-11-19)" in out
    assert "gap: MOE 2.1 -> collection: " in out and f"[{U['MOE-005']}]" in out


def git(cwd, *args):
    subprocess.run(
        ["git", "-c", "user.email=t@example.org", "-c", "user.name=t", "-c", "commit.gpgsign=false",
         "-c", "init.defaultBranch=main", *args],
        cwd=cwd, check=True, capture_output=True,
    )  # fmt: skip


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "repo"
    shutil.copytree(EXAMPLE, r / "strategy")
    git(r, "init")
    git(r, "add", "-A")
    git(r, "commit", "-m", "seed")
    return r


def test_a_new_record_needs_no_allocation(repo):
    """A new record is a new uid: check-dupes and check-lost pass at once, nothing renames."""
    d = repo / "strategy/requirements"
    new = "01a15e4f-0000-7000-8000-000000000001"
    (d / f"{new}.md").write_text(
        (d / rel("PIR-001").split("/")[1]).read_text().replace(U["PIR-001"], new)
    )
    texts = {p.name: p.read_text() for p in d.glob("*.md")}
    spec = ids.spec_for("requirements")
    assert ids.dir_problems(texts, spec) == [] and ids.missing_uids(texts, spec) == []
    assert ids.check_lost(repo, "strategy/requirements") == []


def test_check_lost_covers_the_strategy_directories(repo):
    found = ids.discover(repo)
    assert {f"strategy/{d}" for d in ("objectives", "measures", "requirements", "rfis")} <= set(
        found
    )
    (repo / "strategy" / rel("RFI-002")).unlink()
    assert ids.check_lost(repo, "strategy/rfis") == [U["RFI-002"]]
    assert ids.check_lost(repo, "strategy/measures") == []


def test_the_real_repository_registers_are_discovered():
    found = set(ids.discover(REPO))
    assert "examples/strategy/requirements" in found and "examples/strategy/objectives" in found


def test_hnx_reviews_digest_reads_strategy_records(lab):
    from homelabnext.reviews import file_digest
    from homelabnext.strategy import load_tree
    from homelabnext.strategy.records import record_digest

    tree = load_tree(lab)
    assert file_digest(tree.paths["strategy"]) == record_digest(tree.strategy)
    for key in (U["MOE-002"], U["PIR-001"], U["RFI-002"]):
        assert file_digest(tree.paths[key]) == record_digest(tree.get(key))
    # a reading is not content: the digest of a measure with values ignores them
    moe2 = tree.get(U["MOE-002"])
    assert "values" in moe2 and record_digest(moe2) == record_digest(
        {k: v for k, v in moe2.items() if k != "values"}
    )
    lesson = next((REPO / "examples/registers/lessons").glob("*.md"))
    assert file_digest(lesson).startswith("sha256:")
