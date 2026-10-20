# SPDX-License-Identifier: Apache-2.0
"""The knowledge graph: what each source contributes on the real repository, the integrity
check failing on a dangling edge, a duplicate id or a stale file, determinism, and the queries."""

from __future__ import annotations

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
    assert kinds["svc"] == 15
    assert kinds["lesson"] == 5 and kinds["runbook"] == 2
    # one script node per catalogued script (the catalog is the source of truth for the count)
    catalog = json.loads((ROOT / "docs/scripts/catalog.json").read_text(encoding="utf-8"))
    assert len(graph.of_kind("script")) == len(catalog["scripts"])
    assert all(n.attrs.get("status") for n in graph.of_kind("lesson"))
    # each record node points at its own file
    assert graph.nodes["lesson:LL-004"].path == f"{LESSONS}/LL-004.md"
    assert graph.nodes["runbook:RB-002"].path == f"{RUNBOOKS}/RB-002.md"


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
    attrs = g.nodes["lesson:LL-001"].attrs
    assert attrs["review_count"] == 2 and attrs["recurrences"] == 1


def test_dangling_runbook_reference_fails(tmp_path, repo_copy):
    root = _fresh(tmp_path, repo_copy)
    f = root / LESSONS / "LL-001.md"
    text = f.read_text(encoding="utf-8")
    old = "the result pages through the invariants runner."
    assert old in text
    f.write_text(text.replace(old, old[:-1] + "; RB-999 restores it."), encoding="utf-8")
    rep = check(root)
    assert not rep.ok()
    assert any(
        e.src == "lesson:LL-001" and e.dst == "runbook:RB-999" and e.type == "controlled_by"
        for e in rep.integrity.dangling
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


def test_duplicate_id_fails(tmp_path, repo_copy, capsys):
    """Two record files claiming one id never reach the graph: the register loader refuses them
    (a record file is named after its id), and ``hnx graph check`` reports that and fails.  A
    duplicate between two other sources is the graph's own duplicate-id failure."""
    from homelabnext.registers.schema import RegisterError

    root = _fresh(tmp_path, repo_copy)
    shutil.copy(root / RUNBOOKS / "RB-002.md", root / RUNBOOKS / "RB-003.md")
    with pytest.raises(RegisterError, match=r"RB-003\.md: file name and front-matter id RB-002"):
        check(root)
    assert main(["check", "--root", str(root)]) == 1
    assert "a register does not load" in capsys.readouterr().out

    root = _fresh(tmp_path / "b", repo_copy)
    examples = root / "schemas/agent/examples"
    shutil.copy(examples / "profile.reader.json", examples / "profile.reader-copy.json")
    rep = check(root)
    assert not rep.ok()
    assert [d[0] for d in rep.integrity.duplicates] == ["profile:reader"]


def test_placeholder_records_are_distinct_nodes(tmp_path, repo_copy):
    """A pull request may add several ``LL-NEW`` records; each is its own node, not a duplicate."""
    root = _fresh(tmp_path, repo_copy)
    for slug in ("alpha", "beta"):
        f = root / LESSONS / f"LL-NEW-{slug}.md"
        shutil.copy(root / LESSONS / "LL-005.md", f)
        front(f, id="LL-NEW", title=f"Placeholder practice {slug}")
    g, rep = build(root)
    assert rep.duplicates == [] and rep.dangling == []
    assert g.nodes["lesson:LL-NEW-alpha"].path == f"{LESSONS}/LL-NEW-alpha.md"
    assert g.nodes["lesson:LL-NEW-beta"].title == "Placeholder practice beta"


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
    assert has(graph, "lesson:LL-002", "retired_by", "inv:M-17")
    assert has(
        graph, "lesson:LL-002", "retired_by", "test:tests/registers/test_register_records.py"
    )
    attrs = graph.nodes["lesson:LL-002"].attrs
    assert attrs["lesson_kind"] == "pitfall" and attrs["status"] == "retired"
    # a practice superseded by another lesson
    root = _fresh(tmp_path, repo_copy)
    front(root / LESSONS / "LL-005.md", status="superseded", superseded_by=["LL-004"])
    g, rep = build(root)
    assert rep.dangling == []
    assert has(g, "lesson:LL-005", "superseded_by", "lesson:LL-004")
    page = render_views(g)["lesson.md"]
    live, archive = page.split("## Archive")
    assert "lesson:LL-001" in live
    assert "lesson:LL-002" in archive and "lesson:LL-005" in archive
    assert "lesson:LL-002" in render_views(g)["README.md"].split("## Archive")[1]
    # inactive records cost no context
    assert "lesson:LL-005" not in [r.id for r in related(g, ["system:tls"], budget=50)]
    assert "lesson:LL-005" in [
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
    lessons = sources._register_entries(ROOT / LESSONS)
    assert [e["id"] for e in lessons] == ["LL-001", "LL-002", "LL-003", "LL-004", "LL-005"]
    assert all(e["_path"] == ROOT / LESSONS / f"{e['id']}.md" for e in lessons)
    assert all(e["_key"] == e["id"] for e in lessons)
    assert [e["id"] for e in sources._register_entries(ROOT / RUNBOOKS)] == ["RB-001", "RB-002"]
    assert sources._register_entries(ROOT / "examples/registers/invariants.yml")[0]["id"] == "F-05"


def test_step_level_incorporation_resolves_to_the_runbook(graph):
    """LL-004 reads ``incorporated_into: [RB-002#1]``: step 1 of RB-002, the runbook node."""
    assert has(graph, "lesson:LL-004", "incorporated_into", "runbook:RB-002")
    assert has(graph, "runbook:RB-002", "from_lesson", "lesson:LL-004")
    assert not any(e.dst.startswith(("runbook:RB-002#", "file:")) for e in graph.edges)


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
    lesson = root / LESSONS / "LL-001.md"
    front(
        lesson,
        status="incorporated",
        incorporated_into=["RB-001#2", "docs/systems/edge-proxy.md#use"],
        author="agent:fake-author",
        reviews=None,
    )
    digest = file_digest(lesson)

    def review(by, kind, role, date, verdict):
        keys = ("by", "kind", "role", "date", "verdict", "digest")
        return dict(zip(keys, (by, kind, role, date, verdict, digest), strict=True))

    front(
        lesson,
        reviews=[
            review("agent:fake-checker", "agent", "check", "2026-01-13", "pass"),
            review("human:example-operator", "human", "approve", "2026-01-14", "changes"),
            review("human:example-operator", "human", "approve", "2026-01-15", "pass"),
            review("agent:fake-red", "agent", "challenge", "2026-01-15", "reject"),
        ],
    )
    shutil.rmtree(root / LESSONS / "LL-001.events")  # the inline list above is every review
    rb = root / RUNBOOKS / "RB-001.md"
    text = rb.read_text(encoding="utf-8")
    old = "   - verify: the reload command exits 0 and the proxy health endpoint returns 200\n"
    assert old in text
    rb.write_text(text.replace(old, old + "   - from_lessons: [[LL-001]]\n"), encoding="utf-8")
    g, rep = build(root)
    assert rep.dangling == [] and rep.duplicates == []
    assert has(g, "lesson:LL-001", "incorporated_into", "runbook:RB-001")
    assert has(g, "lesson:LL-001", "incorporated_into", "doc:docs/systems/edge-proxy.md")
    assert has(g, "runbook:RB-001", "from_lesson", "lesson:LL-001")
    attrs = g.nodes["lesson:LL-001"].attrs
    assert attrs["author"] == "agent:fake-author" and attrs["review_count"] == 4
    assert attrs["reviewed"] == ["agent_check", "human"]  # the only challenge review rejected
    ids = [x.id for x in related(g, ["system:proxy"], budget=50)]
    assert "runbook:RB-001" in ids and "lesson:LL-001" not in ids
    assert "lesson:LL-001" in render_views(g)["lesson.md"].split("## Archive")[1]
    # a record without reviews or author gets no summary attrs
    assert "reviewed" not in g.nodes["lesson:LL-003"].attrs


def test_reviewed_counts_only_current_valid_passing_reviews(tmp_path, repo_copy):
    """The graph's ``reviewed`` is what the register validation would accept: a review of an
    earlier content, a self-review and a challenge from the checker count for no tier."""
    root = _fresh(tmp_path, repo_copy)
    lesson = root / LESSONS / "LL-001.md"
    assert build(root)[0].nodes["lesson:LL-001"].attrs["reviewed"] == ["agent_check", "challenge"]
    meta = yaml.safe_load(lesson.read_text(encoding="utf-8").split("---\n", 2)[1])
    front(lesson, title=meta["title"] + " (edited after review)")  # content changed
    attrs = build(root)[0].nodes["lesson:LL-001"].attrs
    assert "reviewed" not in attrs and attrs["review_count"] == 2

    def stamp(author, reviews):  # reviews of the content as it is with this author
        front(lesson, author=author)
        digest = file_digest(lesson)
        front(lesson, reviews=[{**r, "digest": digest} for r in reviews])
        return build(root)[0].nodes["lesson:LL-001"].attrs.get("reviewed")

    check, challenge = meta["reviews"]
    assert stamp("unknown", [check, challenge]) == ["agent_check", "challenge"]
    assert stamp(check["by"], [check, challenge]) == ["challenge"]  # the checker is the author
    # a challenge from the checker: the validation drops that reviewer's reviews altogether
    assert stamp("unknown", [check, {**challenge, "by": check["by"]}]) is None
    human_slot = {**check, "kind": "human", "role": "approve"}  # an agent in a human slot
    assert stamp("unknown", [human_slot]) is None
