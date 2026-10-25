# SPDX-License-Identifier: Apache-2.0
"""The knowledge graph: what each source contributes on the real repository, the integrity
check failing on a dangling edge, a duplicate id or a stale file, determinism, and the queries."""

from __future__ import annotations

import datetime as dt
import json
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

import homelabnext.graph as hg
from homelabnext.graph import sources
from homelabnext.graph.build import GRAPH_JSON, build, check, generate
from homelabnext.graph.cli import main
from homelabnext.graph.model import Edge, Graph, Node, dumps, loads
from homelabnext.graph.query import neighbours, related, seeds_for
from homelabnext.graph.views import render_views
from homelabnext.graph.vocab import EDGE_TYPES, NODE_KINDS
from homelabnext.identity.aliases import load_aliases
from homelabnext.registers.events import create_event, events_dir
from homelabnext.registers.schema import RegisterError
from homelabnext.registers.write import write_event
from homelabnext.reviews import file_digest

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


LESSONS = "examples/registers/lessons"
RUNBOOKS = "examples/registers/runbooks"
U = load_aliases(ROOT / "examples/registers").codes  # the example records' legacy codes -> uids


def F(code: str) -> str:
    """``LL-001`` -> ``<uid>.md``: a record file is named for its uid (ADR-0019)."""
    return f"{U[code]}.md"


def front(path: Path, **changes) -> None:
    """Rewrite a record file's YAML front matter: set each key (``None`` deletes it)."""
    text = path.read_text(encoding="utf-8")
    _, head, body = text.split("---\n", 2)
    meta = yaml.safe_load(head)
    for k, v in changes.items():
        if v is None:
            meta.pop(k, None)
        else:
            meta[k] = v
    dumped = yaml.safe_dump(meta, sort_keys=False, allow_unicode=True)
    path.write_text(f"---\n{dumped}---\n{body}", encoding="utf-8")


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
        ("svc:lake-query", "exposes", "mcp:lake"),
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
        ("script:trivy-scan", "triggered_by", "role:trivy"),  # timer:trivy/scan and role:trivy
        ("inv:Q-04", "checks", "script:component-tests"),
        ("inv:G-03", "checks", "pkg:homelabnext.agent"),
        ("inv:S-07", "checks", "pkg:homelabnext.lake"),
        ("inv:X-09", "checks", "pkg:homelabnext.customization"),
        (f"lesson:{U['LL-002']}", "verified_by", "script:register-ids"),
        (f"lesson:{U['LL-001']}", "about", "system:proxy"),
        (f"lesson:{U['LL-003']}", "about", "system:backup"),
        ("system:backup", "resolves_to", "cap:backup"),
        (f"runbook:{U['RB-002']}", "invokes", "pkg:homelabnext.registers"),
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
    assert kinds["svc"] == 19
    assert kinds["lesson"] == 5 and kinds["runbook"] == 3
    # one script node per catalogued script (the catalog is the source of truth for the count)
    catalog = json.loads((ROOT / "docs/scripts/catalog.json").read_text(encoding="utf-8"))
    assert len(graph.of_kind("script")) == len(catalog["scripts"])
    assert all(n.attrs.get("status") for n in graph.of_kind("lesson"))
    # each record node points at its own file
    assert graph.nodes[f"lesson:{U['LL-004']}"].path == f"{LESSONS}/{F('LL-004')}"
    assert graph.nodes[f"runbook:{U['RB-002']}"].path == f"{RUNBOOKS}/{F('RB-002')}"
    assert graph.nodes[f"lesson:{U['LL-004']}"].attrs["label"] == "LL 4"  # computed, not stored


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


def test_event_files_are_not_nodes_and_derived_attrs_hold(repo_copy):
    g, _ = build(repo_copy)
    assert list((repo_copy / LESSONS).glob("*.events/*.yml"))  # the copy has sidecars
    assert not [n for n in g.nodes.values() if ".events/" in n.path]
    attrs = g.nodes[f"lesson:{U['LL-001']}"].attrs
    assert attrs["review_count"] == 2 and attrs["recurrences"] == 1


def test_dangling_runbook_reference_fails(tmp_path, repo_copy):
    root = _fresh(tmp_path, repo_copy)
    f = root / LESSONS / F("LL-001")
    text = f.read_text(encoding="utf-8")
    old = "the result pages through the invariants runner."
    assert old in text
    gone = "01a15e4e-0000-7000-8000-00000000000f"  # a uid no record has
    f.write_text(text.replace(old, old[:-1] + f"; [[{gone}]] restores it."), encoding="utf-8")
    rep = check(root)
    assert not rep.ok()
    assert any(
        e.src == f"lesson:{U['LL-001']}" and e.dst == f"record:{gone}" and e.type == "controlled_by"
        for e in rep.integrity.dangling
    )
    assert any(gone in line for line in rep.lines())


def test_dangling_doc_link_fails(tmp_path, repo_copy):
    root = _fresh(tmp_path, repo_copy)
    f = root / "docs/glossary.md"
    f.write_text(
        f.read_text(encoding="utf-8") + "\nSee [[systems/nope|nope]] and [x](missing-page.md).\n",
        encoding="utf-8",
    )
    dangling = {e.dst for e in check(root).integrity.dangling}
    assert {"file:docs/systems/nope.md", "file:docs/missing-page.md"} <= dangling


def test_an_overlong_wiki_link_is_dangling_not_a_crash(tmp_path, repo_copy):
    # [[...]] text is looked up as a file; a name over the system's length limit raised
    # OSError (ENAMETOOLONG) and took the whole graph build down with it
    root = _fresh(tmp_path, repo_copy)
    f = root / "docs/glossary.md"
    long = "a" * 5000
    f.write_text(f.read_text(encoding="utf-8") + f"\nSee [[{long}]].\n", encoding="utf-8")
    dangling = {e.dst for e in check(root).integrity.dangling}
    assert f"file:docs/{long}.md" in dangling


def test_duplicate_id_fails(tmp_path, repo_copy, capsys):
    """Two record files claiming one id never reach the graph: the register loader refuses them
    (a record file is named after its id), and ``hnx graph check`` reports that and fails.  A
    duplicate between two other sources is the graph's own duplicate-id failure."""
    from homelabnext.registers.schema import RegisterError

    root = _fresh(tmp_path, repo_copy)
    other = "01a15e4e-0000-7000-8000-00000000000f"
    shutil.copy(root / RUNBOOKS / F("RB-002"), root / RUNBOOKS / f"{other}.md")
    with pytest.raises(RegisterError, match=rf"{other}\.md: file name and front-matter uid"):
        check(root)
    assert main(["check", "--root", str(root)]) == 1
    assert "a register does not load" in capsys.readouterr().out

    root = _fresh(tmp_path / "b", repo_copy)
    examples = root / "schemas/agent/examples"
    shutil.copy(examples / "profile.reader.json", examples / "profile.reader-copy.json")
    rep = check(root)
    assert not rep.ok()
    assert [d[0] for d in rep.integrity.duplicates] == ["profile:reader"]


def test_two_new_records_are_two_nodes(tmp_path, repo_copy):
    """Two pull requests may each add a lesson: each has its own uid, so each is its own node."""
    root = _fresh(tmp_path, repo_copy)
    for n, new in enumerate(
        ("01a15e4f-0000-7000-8000-000000000001", "01a15e4f-0000-7000-8000-000000000002")
    ):
        f = root / LESSONS / f"{new}.md"
        f.write_text((root / LESSONS / F("LL-005")).read_text().replace(U["LL-005"], new))
        front(f, title=f"New practice {n}")
    g, rep = build(root)
    assert rep.duplicates == [] and rep.dangling == []
    assert g.nodes["lesson:01a15e4f-0000-7000-8000-000000000002"].attrs["label"] == "LL 7"


def test_stale_and_orphan_files_fail(tmp_path, repo_copy):
    """With an explicit output directory the check also compares the generated files."""
    root = _fresh(tmp_path, repo_copy)
    out = root / "docs/graph"
    generate(root)
    assert check(root, out).ok()
    gj = root / GRAPH_JSON
    gj.write_text(gj.read_text(encoding="utf-8").replace('"svc"', '"service"', 1), encoding="utf-8")
    (out / "extra.md").write_text("# not generated\n", encoding="utf-8")
    (out / "svc.md").unlink()
    rep = check(root, out)
    assert not rep.ok()
    assert "graph.json" in rep.stale and rep.orphan_files == ["extra.md"]
    assert rep.missing == ["svc.md"]
    generate(root)
    assert check(root, out).ok()


def test_a_foreign_out_directory_is_written_never_pruned(tmp_path, repo_copy):
    """``hnx graph build --out docs`` writes its files there and deletes nothing it did not
    write; a directory it created (marked ``.hnx-generated``) is pruned like ``docs/graph/``."""
    root = _fresh(tmp_path, repo_copy)
    before = {p.relative_to(root) for p in (root / "docs").rglob("*") if p.is_file()}
    assert any(p.suffix == ".md" for p in before)
    written, removed = generate(root, root / "docs")
    assert removed == [] and written
    after = {p.relative_to(root) for p in (root / "docs").rglob("*") if p.is_file()}
    assert before <= after and not (root / "docs" / ".hnx-generated").exists()
    own = tmp_path / "own"
    generate(root, own)
    assert (own / ".hnx-generated").read_text(encoding="utf-8") == "hnx graph build\n"
    (own / "extra.md").write_text("# not generated\n", encoding="utf-8")
    assert generate(root, own)[1] == ["extra.md"]
    (own / ".hnx-generated").write_text("hnx docs capabilities\n", encoding="utf-8")
    (own / "extra.md").write_text("# another generator's\n", encoding="utf-8")
    assert generate(root, own)[1] == []  # marked as another generator's: not ours to prune


def test_the_default_check_is_integrity_only(tmp_path, repo_copy):
    """docs/graph/ is a local build: a missing or edited copy does not fail the default check."""
    root = _fresh(tmp_path, repo_copy)
    assert check(root).ok()  # nothing generated at all
    (root / GRAPH_JSON).parent.mkdir(parents=True, exist_ok=True)
    (root / GRAPH_JSON).write_text("{}", encoding="utf-8")
    (root / "docs/graph/extra.md").write_text("# stray\n", encoding="utf-8")
    rep = check(root)
    assert rep.ok() and rep.stale == [] and rep.orphan_files == []
    assert not check(root, root / "docs/graph").ok()  # the explicit comparison still sees it


def test_lifecycle_fields_become_edges_and_attrs(graph, tmp_path, repo_copy):
    # the real register: LL-002 is a retired pitfall
    assert has(graph, f"lesson:{U['LL-002']}", "retired_by", "inv:M-17")
    assert has(
        graph,
        f"lesson:{U['LL-002']}",
        "retired_by",
        "test:tests/registers/test_register_records.py",
    )
    attrs = graph.nodes[f"lesson:{U['LL-002']}"].attrs
    assert attrs["lesson_kind"] == "pitfall" and attrs["status"] == "retired"
    # a practice superseded by another lesson
    root = _fresh(tmp_path, repo_copy)
    front(root / LESSONS / F("LL-005"), status="superseded", superseded_by=U["LL-004"])
    g, rep = build(root)
    assert rep.dangling == []
    assert has(g, f"lesson:{U['LL-005']}", "superseded_by", f"lesson:{U['LL-004']}")
    page = render_views(g)["lesson.md"]
    live, archive = page.split("## Archive")
    assert f"lesson:{U['LL-001']}" in live
    assert f"lesson:{U['LL-002']}" in archive and f"lesson:{U['LL-005']}" in archive
    assert f"lesson:{U['LL-002']}" in render_views(g)["README.md"].split("## Archive")[1]
    # inactive records cost no context
    assert f"lesson:{U['LL-005']}" not in [r.id for r in related(g, ["system:tls"], budget=50)]
    assert f"lesson:{U['LL-005']}" in [
        r.id for r in related(g, ["system:tls"], budget=50, include_inactive=True)
    ]


# ------------------------------------------------------------------ queries


def test_seeds_for_an_adapter_file(graph):
    seeds = seeds_for(graph, paths=["homelabnext/conform/adapters/openbao.py"])
    assert seeds == sorted([OPENBAO, "cap:secrets"])


def test_seeds_for_owning_package_and_text(graph):
    assert seeds_for(graph, paths=["homelabnext/registers/schema.py"]) == [
        "pkg:homelabnext.registers"
    ]
    got = seeds_for(graph, text=f"rotate the secrets store and check lesson:{U['LL-001']}")
    assert {"cap:secrets", "svc:secrets", f"lesson:{U['LL-001']}"} <= set(got)
    # a record is also named by its bare uid or its computed number
    assert f"lesson:{U['LL-001']}" in seeds_for(graph, text=f"see {U['LL-001']}")
    assert f"lesson:{U['LL-003']}" in seeds_for(graph, text="the backup gap in LL 3 again")
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
    lessons = sources._register_entries(ROOT / LESSONS)
    assert [e["uid"] for e in lessons] == [U[f"LL-00{n}"] for n in range(1, 6)]
    assert all(e["_path"] == ROOT / LESSONS / f"{e['uid']}.md" for e in lessons)
    assert all(e["_key"] == e["uid"] for e in lessons)
    assert [e["_label"] for e in lessons] == [f"LL {n}" for n in range(1, 6)]
    runbooks = sources._register_entries(ROOT / RUNBOOKS)
    assert [e["uid"] for e in runbooks] == [U["RB-001"], U["RB-002"], U["RB-003"]]
    assert sources._register_entries(ROOT / "examples/registers/invariants.yml")[0]["id"] == "F-05"


def test_step_level_incorporation_resolves_to_the_runbook(graph):
    """LL 4 reads ``incorporated_into: [<uid of RB 2>#1]``: step 1 of RB 2, the runbook node."""
    assert has(graph, f"lesson:{U['LL-004']}", "incorporated_into", f"runbook:{U['RB-002']}")
    assert has(graph, f"runbook:{U['RB-002']}", "from_lesson", f"lesson:{U['LL-004']}")
    assert not any(e.dst.startswith((f"runbook:{U['RB-002']}#", "file:")) for e in graph.edges)


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
    gone = "01a15e4e-0000-7000-8000-00000000000f"
    g.write_text(g.read_text(encoding="utf-8") + f"links: {{lesson: {gone}}}\n", encoding="utf-8")
    assert main(["check", "--root", str(root)]) == 1
    assert f"dangling edge: custom:board-sensor-driver -links-> lesson:{gone}" in (
        capsys.readouterr().out
    )


def test_a_customization_naming_a_legacy_code_resolves_with_a_warning(tmp_path, repo_copy):
    from homelabnext.identity.aliases import LegacyRecordCode

    root = _fresh(tmp_path, repo_copy)
    g = root / "profiles/board-sensor-driver/customization.yml"
    g.write_text(g.read_text(encoding="utf-8") + "links: {lesson: LL-003}\n", encoding="utf-8")
    with pytest.warns(LegacyRecordCode, match="LL-003") as got:
        graph, rep = build(root)
    assert rep.dangling == []
    assert has(graph, "custom:board-sensor-driver", "links", f"lesson:{U['LL-003']}")
    # one warning, naming the uid to write instead; the edge reaches the record, its number
    legacy = [w for w in got if issubclass(w.category, LegacyRecordCode)]
    assert len(legacy) == 1 and U["LL-003"] in str(legacy[0].message)
    assert graph.nodes[f"lesson:{U['LL-003']}"].attrs["label"] == "LL 3"


@pytest.mark.parametrize("retired", [False, True])
def test_a_customization_naming_an_unknown_or_retired_code_fails_the_check(
    tmp_path, repo_copy, capsys, retired
):
    root = _fresh(tmp_path, repo_copy)
    if retired:  # retired before uids, with a successor: still not a link a customization may hold
        a = root / "examples/registers/aliases.yml"
        a.write_text(
            a.read_text(encoding="utf-8")
            + f"retired:\n  LL-006:\n    reason: a duplicate\n    replaced_by: {U['LL-003']}\n",
            encoding="utf-8",
        )
    code = "LL-006" if retired else "LL-900"
    g = root / "profiles/board-sensor-driver/customization.yml"
    g.write_text(g.read_text(encoding="utf-8") + f"links: {{lesson: {code}}}\n", encoding="utf-8")
    assert main(["check", "--root", str(root)]) == 1
    assert f"dangling edge: custom:board-sensor-driver -links-> lesson:{code}" in (
        capsys.readouterr().out
    )


def test_related_resolves_a_uid_or_a_legacy_code(capsys):
    from homelabnext.identity.aliases import LegacyRecordCode

    assert main(["related", U["LL-001"], "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["seeds"] == [f"lesson:{U['LL-001']}"]
    with pytest.warns(LegacyRecordCode, match="LL-001"):
        assert main(["related", "lesson:LL-001", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["seeds"] == [f"lesson:{U['LL-001']}"]


def _review_events(lesson: Path) -> list[Path]:
    return sorted(events_dir(lesson).glob("*-review-*.yml"))


def _drop_reviews(lesson: Path) -> None:
    """Remove the example's review events (as if they had never been filed), keeping the rest."""
    for f in _review_events(lesson):
        f.unlink()


def _at(i: int) -> dt.datetime:
    return dt.datetime(2026, 10, 19, 0, 0, i, tzinfo=dt.UTC)


def test_incorporated_lessons_give_way_to_their_runbook(tmp_path, repo_copy):
    root = _fresh(tmp_path, repo_copy)
    lesson = root / LESSONS / F("LL-005")
    rb = root / RUNBOOKS / F("RB-001")
    text = rb.read_text(encoding="utf-8")
    old = "   - verify: the reload command exits 0 and the proxy health endpoint returns 200\n"
    assert old in text
    rb.write_text(
        text.replace(old, old + f"   - from_lessons: [[{U['LL-005']}]]\n"), encoding="utf-8"
    )
    front(
        lesson,
        status="incorporated",
        incorporated_into=[f"{U['RB-001']}#2", "docs/systems/edge-proxy.md#use"],
        author="agent:fake-author",
    )
    _drop_reviews(lesson)
    digest = file_digest(lesson)  # what `hnx reviews digest` prints for the record as loaded
    keys = ("by", "kind", "role", "date", "verdict")
    for i, r in enumerate(
        [
            ("agent:fake-checker", "agent", "check", "2026-01-13", "pass"),
            ("human:example-operator", "human", "approve", "2026-01-14", "changes"),
            ("human:example-operator", "human", "approve", "2026-01-15", "pass"),
            ("agent:fake-red", "agent", "audit", "2026-01-15", "reject"),
        ]
    ):
        review = {"event": "review", **dict(zip(keys, r, strict=True)), "digest": digest}
        write_event(lesson, review, when=_at(i))
    g, rep = build(root)
    assert rep.dangling == [] and rep.duplicates == []
    assert has(g, f"lesson:{U['LL-005']}", "incorporated_into", f"runbook:{U['RB-001']}")
    assert has(g, f"lesson:{U['LL-005']}", "incorporated_into", "doc:docs/systems/edge-proxy.md")
    assert has(g, f"runbook:{U['RB-001']}", "from_lesson", f"lesson:{U['LL-005']}")
    attrs = g.nodes[f"lesson:{U['LL-005']}"].attrs
    assert attrs["author"] == "agent:fake-author" and attrs["review_count"] == 4
    assert attrs["reviewed"] == ["agent_check", "human"]  # the only audit review rejected
    ids = [x.id for x in related(g, ["system:proxy"], budget=50)]
    assert f"runbook:{U['RB-001']}" in ids and f"lesson:{U['LL-005']}" not in ids
    assert f"lesson:{U['LL-005']}" in render_views(g)["lesson.md"].split("## Archive")[1]
    # a record without reviews or author gets no summary attrs
    assert "reviewed" not in g.nodes[f"lesson:{U['LL-003']}"].attrs


def test_a_runbooks_own_lessons_are_from_lesson_edges(tmp_path, repo_copy):
    """``lessons:`` on a runbook (runbook schema 2.1) names lesson uids: each is an edge, and
    one naming no lesson is dangling."""
    root = _fresh(tmp_path, repo_copy)
    front(root / RUNBOOKS / F("RB-001"), lessons=[U["LL-001"]])
    g, rep = build(root)
    assert rep.dangling == []
    assert has(g, f"runbook:{U['RB-001']}", "from_lesson", f"lesson:{U['LL-001']}")
    (e,) = [x for x in g.out_edges(f"runbook:{U['RB-001']}") if x.dst == f"lesson:{U['LL-001']}"]
    assert e.source.endswith(".lessons")
    nobody = "01a15e4e-0000-7000-8000-00000000000f"  # a valid uid no record has
    front(root / RUNBOOKS / F("RB-001"), lessons=[nobody])
    _, rep = build(root)
    assert any(nobody in str(d) for d in rep.dangling)


def test_reviewed_counts_only_current_valid_passing_reviews(tmp_path, repo_copy):
    """The graph's ``reviewed`` is what the register validation accepts of the reviews derived
    from the sidecar events: a review of an earlier content, a self-review, an audit by the
    checker and an agent in a human slot count for no tier."""
    root = _fresh(tmp_path, repo_copy)
    lesson = root / LESSONS / F("LL-001")

    def reviewed():
        return build(root)[0].nodes[f"lesson:{U['LL-001']}"].attrs.get("reviewed")

    assert reviewed() == ["agent_check", "audit"]
    check, audit = (yaml.safe_load(f.read_text("utf-8")) for f in _review_events(lesson))
    meta = yaml.safe_load(lesson.read_text(encoding="utf-8").split("---\n", 2)[1])
    front(lesson, title=meta["title"] + " (edited after review)")  # content changed
    attrs = build(root)[0].nodes[f"lesson:{U['LL-001']}"].attrs
    assert "reviewed" not in attrs and attrs["review_count"] == 2

    def stamp(author, reviews, *, refused=None):
        """Replace the review events by ``reviews`` of the content as it is with ``author``.
        The writer refuses review ``refused`` (the register would not validate); a hand edit or
        a merge can still land it, and every later one with it."""
        front(lesson, author=author)
        _drop_reviews(lesson)
        digest = file_digest(lesson)
        for i, r in enumerate(reviews):
            data = {**r, "digest": digest}
            if refused is None or i < refused:
                write_event(lesson, data, when=_at(i))
                continue
            if i == refused:
                with pytest.raises(RegisterError, match="review #"):
                    write_event(lesson, data, when=_at(i))
            create_event(events_dir(lesson), data, when=_at(i))
        return reviewed()

    assert stamp("unknown", [check, audit]) == ["agent_check", "audit"]
    # the checker is the author: its check counts for nothing
    assert stamp(check["by"], [check, audit], refused=0) == ["audit"]
    # an audit by the checker: the validation drops that reviewer's reviews altogether
    assert stamp("unknown", [check, {**audit, "by": check["by"]}], refused=1) is None
    human_slot = {**check, "kind": "human", "role": "approve"}  # an agent in a human slot
    assert stamp("unknown", [human_slot], refused=0) is None
