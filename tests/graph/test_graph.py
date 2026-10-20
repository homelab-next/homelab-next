# SPDX-License-Identifier: Apache-2.0
"""The knowledge graph: what each source contributes on the real repository, the integrity
check failing on a dangling edge, a duplicate id or a stale file, determinism, and the queries."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

import homelabnext.graph as hg
from homelabnext.graph import sources
from homelabnext.graph.build import GRAPH_JSON, build, check, generate
from homelabnext.graph.cli import main
from homelabnext.graph.model import Edge, Graph, Node, dumps, loads
from homelabnext.graph.query import neighbours, related, seeds_for
from homelabnext.graph.views import render_views
from homelabnext.graph.vocab import EDGE_TYPES, NODE_KINDS

ROOT = Path(__file__).resolve().parents[2]
OPENBAO = "adapter:homelabnext.conform.adapters.openbao:make"


@pytest.fixture(scope="module")
def built():
    return build(ROOT)


@pytest.fixture(scope="module")
def graph(built):
    return built[0]


def has(graph: Graph, src: str, etype: str, dst: str) -> bool:
    return any(e.type == etype and e.dst == dst for e in graph.out_edges(src))


def copy_repo(dest: Path) -> Path:
    """The checkout's files (tracked and untracked-not-ignored) under ``dest``."""
    out = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        capture_output=True,
        check=True,
    )
    for rel in out.stdout.decode().split("\0"):
        src = ROOT / rel
        if rel and src.is_file():
            (dest / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dest / rel)
    return dest


# ------------------------------------------------------------------ sources on the real repo


@pytest.mark.parametrize(
    ("src", "etype", "dst"),
    [
        # registry
        ("svc:secrets", "provides", "cap:secrets"),
        ("svc:secrets", "runs", "product:openbao"),
        ("svc:secrets", "runs_on", "host:secrets-core"),
        ("svc:lake-query", "depends_on", "svc:lake-catalog"),
        ("svc:lake-query", "exposes", "mcp:lake_query"),
        ("host:secrets-core", "in_zone", "zone:mgmt"),
        # capabilities, adapters, compose
        (OPENBAO, "implements", "cap:secrets"),
        (OPENBAO, "for", "product:openbao"),
        ("adapter:homelabnext.conform.adapters.s3:make_object_store", "for", "product:garage"),
        ("adapter:homelabnext.conform.adapters.lake:make_lake", "for", "product:lakekeeper"),
        ("cap:secrets", "faked_by", "adapter:conformance.fakes.secret_store:FakeSecretStore"),
        ("cap:records", "loads_schema", "schema:schemas/records/note.schema.json"),
        ("compose:lab-in-a-box/secrets", "runs", "product:openbao"),
        ("compose:lab-in-a-box/secrets", "provides", "cap:secrets"),
        # schemas
        (
            "schema:schemas/events/alert.created.schema.json",
            "refs",
            "schema:schemas/events/envelope.schema.json",
        ),
        # scripts and registers
        ("script:leak-scan", "enforces", "inv:F-05"),
        ("script:leak-scan", "triggered_by", "make:leak-scan"),
        ("script:leak-scan", "triggered_by", "ci:ci/leak-scan"),
        ("script:schema-check", "triggered_by", "pkg:homelabnext"),
        ("inv:Q-04", "checks", "script:component-tests"),
        ("inv:G-03", "checks", "pkg:homelabnext.agent"),
        ("inv:S-07", "checks", "pkg:homelabnext.lake"),
        ("inv:X-09", "checks", "pkg:homelabnext.customization"),
        ("lesson:LL-002", "verified_by", "script:register-ids"),
        ("lesson:LL-001", "about", "system:proxy"),
        ("lesson:LL-003", "about", "system:backup"),
        ("system:backup", "resolves_to", "cap:backup"),
        ("runbook:RB-002", "invokes", "pkg:homelabnext.registers"),
        # agent
        ("profile:reader", "grants", "cap:lake-query"),
        ("profile:reader", "uses", "skill:triage"),
        ("profile:reader", "uses", "persona:analyst"),
        ("profile:reader", "uses_model", "mdl:fast-classifier"),
        ("profile:operator", "grants", "action:service.restart"),
        ("sso:approver-one", "grants", "broker:example-broker"),
        ("broker:example-broker", "defines", "action:host.reboot"),
        ("manifest:reader-pack", "uses", "mcp:lake"),
        ("mdl:main-reasoner", "falls_back_to", "mdl:fast-classifier"),
        ("mdl:main-reasoner", "backed_by", "svc:inference"),
        # customization, ansible, docs
        ("custom:board-sensor-driver", "applies_to", "cap:monitoring"),
        (
            "custom:board-sensor-driver",
            "governed_by",
            "adr:role-interface-and-capability-groups",
        ),
        ("playbook:example_service", "targets", "cap:monitoring"),
        ("playbook:example_service", "applies", "role:example_service"),
        ("doc:docs/systems/secrets.md", "documents", "svc:secrets"),
        ("doc:docs/capabilities/secrets.md", "documents", "cap:secrets"),
        ("doc:docs/systems/secrets.md", "links", "doc:docs/capabilities/secrets.md"),
        ("doc:docs/README.md", "links", "doc:docs/graph.md"),
    ],
)
def test_known_fact(graph, src, etype, dst):
    assert src in graph.nodes and dst in graph.nodes
    assert has(graph, src, etype, dst), f"{src} -{etype}-> {dst} missing"


def test_every_source_contributes_and_counts(graph):
    kinds = graph.kinds()
    for kind in ("svc", "cap", "adapter", "check", "schema", "lesson", "runbook", "inv"):
        assert kinds.get(kind), kind
    assert kinds["svc"] == 14
    assert kinds["lesson"] == 3 and kinds["runbook"] == 2
    assert len(graph.of_kind("script")) == 25
    assert all(n.attrs.get("status") for n in graph.of_kind("lesson"))


def test_grant_edges_carry_their_level(graph):
    levels = {
        e.dst: e.attrs.get("level") for e in graph.out_edges("profile:reader") if e.type == "grants"
    }
    assert levels["cap:lake-query"] == "read" and levels["mcp:lake"] == "read"


def test_every_emitted_kind_and_type_is_in_the_vocabulary(graph):
    assert set(graph.kinds()) <= set(NODE_KINDS)
    assert set(graph.edge_types()) <= set(EDGE_TYPES)
    guide = (ROOT / "docs" / "graph.md").read_text(encoding="utf-8")
    for t in EDGE_TYPES:
        assert f"    {t} " in (hg.__doc__ or ""), f"{t} missing from the package docstring"
        assert f"| `{t}` |" in guide, f"{t} missing from docs/graph.md"


def test_the_real_repo_is_intact_and_current(built):
    _, integrity = built
    assert integrity.dangling == [] and integrity.duplicates == []
    rep = check(ROOT)
    assert rep.ok(), "\n".join(rep.lines())
    # reported, not failed
    assert "system:proxy" in integrity.unresolved_tags


def test_build_is_deterministic(graph):
    again, _ = build(ROOT)
    assert dumps(again) == dumps(graph)
    assert loads(dumps(graph)).edges == graph.edges
    head = dumps(graph).split('"nodes"')[0]
    assert head.strip() == '{\n  "format": "homelabnext.graph/1",'


# ------------------------------------------------------------------ the check fails


@pytest.fixture(scope="module")
def repo_copy(tmp_path_factory):
    return copy_repo(tmp_path_factory.mktemp("repo"))


def _fresh(tmp_path: Path, repo_copy: Path) -> Path:
    dest = tmp_path / "r"
    shutil.copytree(repo_copy, dest)
    return dest


def test_copy_passes(repo_copy):
    assert check(repo_copy).ok()


def test_dangling_runbook_reference_fails(tmp_path, repo_copy):
    root = _fresh(tmp_path, repo_copy)
    f = root / "examples/registers/lessons.yml"
    text = f.read_text(encoding="utf-8").replace(
        "the result pages through the invariants runner.",
        "the result pages through the invariants runner; RB-999 restores it.",
    )
    f.write_text(text, encoding="utf-8")
    rep = check(root)
    assert not rep.ok()
    assert any(
        e.dst == "runbook:RB-999" and e.type == "controlled_by" for e in rep.integrity.dangling
    )
    assert any("RB-999" in line for line in rep.lines())


def test_dangling_doc_link_fails(tmp_path, repo_copy):
    root = _fresh(tmp_path, repo_copy)
    f = root / "docs/glossary.md"
    f.write_text(
        f.read_text(encoding="utf-8") + "\nSee [[systems/nope|nope]] and [x](missing-page.md).\n",
        encoding="utf-8",
    )
    dangling = {e.dst for e in check(root).integrity.dangling}
    assert {"file:docs/systems/nope.md", "file:docs/missing-page.md"} <= dangling


def test_duplicate_id_fails(tmp_path, repo_copy):
    root = _fresh(tmp_path, repo_copy)
    f = root / "examples/registers/runbooks.yml"
    text = f.read_text(encoding="utf-8")
    second = text[text.index("- id: RB-002") :]
    f.write_text(text + second, encoding="utf-8")
    rep = check(root)
    assert not rep.ok()
    assert [d[0] for d in rep.integrity.duplicates] == ["runbook:RB-002"]


def test_stale_and_orphan_files_fail(tmp_path, repo_copy):
    root = _fresh(tmp_path, repo_copy)
    gj = root / GRAPH_JSON
    gj.write_text(gj.read_text(encoding="utf-8").replace('"svc"', '"service"', 1), encoding="utf-8")
    (root / "docs/graph/extra.md").write_text("# not generated\n", encoding="utf-8")
    rep = check(root)
    assert "graph.json" in rep.stale and rep.orphan_files == ["extra.md"]
    generate(root)
    assert check(root).ok()


def test_lifecycle_fields_become_edges_and_attrs(tmp_path, repo_copy):
    root = _fresh(tmp_path, repo_copy)
    f = root / "examples/registers/lessons.yml"
    text = f.read_text(encoding="utf-8")
    text = text.replace(
        "  systems: [registers, git]\n",
        "  systems: [registers, git]\n  kind: pitfall\n  retired_by: Q-04\n",
    ).replace(
        "  systems: [backup]\n",
        "  systems: [backup]\n  kind: practice\n  superseded_by: LL-002\n",
    )
    text = text.replace("  status: partial\n", "  status: retired\n").replace(
        "  status: open\n", "  status: superseded\n"
    )
    f.write_text(text, encoding="utf-8")
    g, rep = build(root)
    assert rep.dangling == []
    assert has(g, "lesson:LL-002", "retired_by", "inv:Q-04")
    assert has(g, "lesson:LL-003", "superseded_by", "lesson:LL-002")
    assert g.nodes["lesson:LL-002"].attrs["lesson_kind"] == "pitfall"
    assert g.nodes["lesson:LL-002"].attrs["status"] == "retired"
    page = render_views(g)["lesson.md"]
    live, archive = page.split("## Archive")
    assert "lesson:LL-001" in live and "lesson:LL-002" in archive and "lesson:LL-003" in archive
    assert "lesson:LL-002" in render_views(g)["README.md"].split("## Archive")[1]
    # inactive records cost no context
    assert "lesson:LL-002" not in [r.id for r in related(g, ["system:registers"], budget=50)]
    assert "lesson:LL-002" in [
        r.id for r in related(g, ["system:registers"], budget=50, include_inactive=True)
    ]


# ------------------------------------------------------------------ queries


def test_seeds_for_an_adapter_file(graph):
    seeds = seeds_for(graph, paths=["homelabnext/conform/adapters/openbao.py"])
    assert seeds == sorted([OPENBAO, "cap:secrets"])


def test_seeds_for_owning_package_and_text(graph):
    assert seeds_for(graph, paths=["homelabnext/registers/schema.py"]) == [
        "pkg:homelabnext.registers"
    ]
    got = seeds_for(graph, text="rotate the secrets store and check lesson:LL-001")
    assert {"cap:secrets", "svc:secrets", "lesson:LL-001"} <= set(got)
    assert "make:test" not in seeds_for(graph, text="run the test")


def test_related_ranks_direct_neighbours_above_two_hop(graph):
    found = related(graph, ["cap:secrets"], budget=200)
    dists = [r.distance for r in found]
    assert dists == sorted(dists) and 1 in dists and 2 in dists
    direct = {r.id for r in found if r.distance == 1}
    assert {"svc:secrets", OPENBAO, "doc:docs/capabilities/secrets.md"} <= direct
    assert all(r.id != "cap:secrets" for r in found)
    # within a ring the heavier edge type wins; ties break by id
    ring = [r for r in found if r.distance == 1]
    assert ring == sorted(ring, key=lambda r: (-r.score, r.id))
    assert related(graph, ["cap:secrets"], budget=200) == found


def test_related_budget_and_zero_weight(graph):
    assert len(related(graph, ["cap:secrets"], budget=3)) == 3
    w = dict(hg.DEFAULT_WEIGHTS, checked_by=0)
    assert not any(r.id.startswith("check:") for r in related(graph, ["cap:secrets"], 200, w, 1))


def test_neighbours_direction_and_types(graph):
    out = neighbours(graph, ["svc:secrets"], direction="out", edge_types=["provides"])
    assert out == ["cap:secrets"]
    inbound = neighbours(graph, ["cap:secrets"], direction="in", edge_types=["provides"])
    assert "svc:secrets" in inbound and "compose:lab-in-a-box/secrets" in inbound
    two = neighbours(graph, ["svc:secrets"], depth=2, edge_types=["provides", "implements"])
    assert OPENBAO in two and two.index("cap:secrets") < two.index(OPENBAO)
    with pytest.raises(ValueError):
        neighbours(graph, ["svc:secrets"], direction="sideways")


def _tiny() -> Graph:
    nodes = {
        "a": Node("a", "cap"),
        "b": Node("b", "lesson", attrs={"status": "retired"}),
        "c": Node("c", "svc"),
        "d": Node("d", "svc"),
    }
    edges = [
        Edge("a", "b", "about", "t"),
        Edge("b", "c", "about", "t"),
        Edge("a", "d", "links", "t"),
    ]
    return Graph(nodes, edges)


def test_inactive_nodes_are_neither_returned_nor_expanded():
    g = _tiny()
    assert neighbours(g, ["a"], depth=2) == ["d"]
    assert neighbours(g, ["a"], depth=2, include_inactive=True) == ["b", "d", "c"]
    assert [r.id for r in related(g, ["a"])] == ["d"]
    assert seeds_for(g, text="see b and d") == []  # one-letter names never match
    assert render_views(g)["lesson.md"].count("## Archive") == 1


# ------------------------------------------------------------------ helpers and CLI


def test_image_product():
    known = {"lakekeeper", "openbao"}
    assert sources._image_product("quay.io/lakekeeper/catalog:v1@sha256:ab", known) == "lakekeeper"
    assert sources._image_product("dxflrs/garage:v1.0.1@sha256:ab", known) == "garage"
    assert sources._image_product("hnx-lab-fakes:local", known) == ""


def test_command_refs(graph):
    b = sources.Builder(ROOT)
    b.nodes = dict(graph.nodes)
    cmds = sources._commands(b)
    refs = cmds.refs(
        "python3 tools/leak_scan.py . && python3 -m homelabnext.cli scripts reality && "
        "hnx docs capabilities check && make registers && make sure it works"
    )
    assert refs == [
        "make:registers",
        "pkg:homelabnext.scripts",
        "pkg:homelabnext.sop",
        "script:leak-scan",
    ]


def test_register_entries_is_the_one_seam():
    lessons = sources._register_entries(ROOT / "examples/registers/lessons.yml")
    assert [e["id"] for e in lessons] == ["LL-001", "LL-002", "LL-003"]
    assert sources._register_entries(ROOT / "examples/registers/invariants.yml")[0]["id"] == "F-05"


def test_cli_check_and_related(capsys):
    assert main(["check"]) == 0
    assert "graph: ok" in capsys.readouterr().out
    assert main(["related", "homelabnext/conform/adapters/openbao.py", "--json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["seeds"] == sorted([OPENBAO, "cap:secrets"])
    assert doc["related"][0]["distance"] == 1
    assert main(["related", "no-such-thing"]) == 1
    assert main(["related"]) == 2


def test_cli_check_fails_on_a_dangling_edge(tmp_path, repo_copy, capsys):
    root = _fresh(tmp_path, repo_copy)
    g = root / "profiles/board-sensor-driver/customization.yml"
    g.write_text(g.read_text(encoding="utf-8") + "links: {lesson: LL-900}\n", encoding="utf-8")
    assert main(["check", "--root", str(root)]) == 1
    assert "dangling edge: custom:board-sensor-driver -links-> lesson:LL-900" in (
        capsys.readouterr().out
    )


def test_incorporated_lessons_give_way_to_their_runbook(tmp_path, repo_copy):
    root = _fresh(tmp_path, repo_copy)
    f = root / "examples/registers/lessons.yml"
    text = f.read_text(encoding="utf-8").replace(
        "  systems: [proxy, tls]\n  recurrences: 1\n  status: controlled\n",
        "  systems: [proxy, tls]\n  recurrences: 1\n  status: incorporated\n"
        "  incorporated_into: [RB-001, docs/systems/edge-proxy.md]\n"
        "  author: agent:fake-author\n"
        "  reviews:\n"
        "  - {by: agent:fake-checker, kind: agent, role: check, date: 2026-01-13, verdict: pass}\n"
        "  - {by: fake-human, kind: human, role: approve, date: 2026-01-14, verdict: fail}\n"
        "  - {by: fake-human, kind: human, role: approve, date: 2026-01-15, verdict: pass}\n"
        "  - {by: agent:fake-red, kind: agent, role: adversarial, date: 2026-01-15, verdict: fail}\n",
    )
    f.write_text(text, encoding="utf-8")
    r = root / "examples/registers/runbooks.yml"
    r.write_text(
        r.read_text(encoding="utf-8").replace(
            "  - do: Reload the proxy configuration.\n",
            "  - do: Reload the proxy configuration.\n    from_lessons: [LL-001]\n",
        ),
        encoding="utf-8",
    )
    g, rep = build(root)
    assert rep.dangling == [] and rep.duplicates == []
    assert has(g, "lesson:LL-001", "incorporated_into", "runbook:RB-001")
    assert has(g, "lesson:LL-001", "incorporated_into", "doc:docs/systems/edge-proxy.md")
    assert has(g, "runbook:RB-001", "from_lesson", "lesson:LL-001")
    attrs = g.nodes["lesson:LL-001"].attrs
    assert attrs["author"] == "agent:fake-author" and attrs["review_count"] == 4
    assert attrs["reviewed"] == ["agent_check", "human"]  # latest adversarial review failed
    ids = [x.id for x in related(g, ["system:proxy"], budget=50)]
    assert "runbook:RB-001" in ids and "lesson:LL-001" not in ids
    assert "lesson:LL-001" in render_views(g)["lesson.md"].split("## Archive")[1]
    # absent fields add nothing
    assert "reviewed" not in g.nodes["lesson:LL-002"].attrs
