# SPDX-License-Identifier: Apache-2.0
"""G-13: actors act only through the broker (ADR-0030).

Any profile, reader or not, may hold a grant in a ``broker_only`` class (exec, file-write,
credential) only through the broker: an acting MCP server whose catalog record says ``acts_via:
broker``, or an ``acts_via: direct`` one with a direct_reason, a current human approve review and
the ceiling policy's ``direct_mcp`` entry for the profile; no acting capability but
``cap:broker``; and an acting tier only with ``cap:broker``.  The compiler, ``verify``, ``hnx agent
lint`` and the client render all refuse the rest.
"""

from __future__ import annotations

import copy
import json
import shutil
from pathlib import Path

import pytest
import yaml
from agent_support import PARTS, library, spec

from homelabnext import cli
from homelabnext.agent import (
    BrokerViolation,
    CeilingPolicy,
    SpecError,
    ToolClasses,
    broker_problems,
    compile_profile,
    lint_paths,
    profile_digest,
    verify_profile,
)
from homelabnext.agent.readers import (
    BROKER,
    DEFAULT_CLASSES,
    READERS,
    default_classes,
    manifest_problems,
)
from homelabnext.mcp import clients, servers

ROOT = Path(__file__).resolve().parents[2]
CATALOG = ROOT / "examples" / "mcp"
LIB = library(
    {
        **PARTS,
        "cap:broker": "Ask the broker for named actions.",
        "cap:hypervisor": "Manage guests.",
        "cap:secrets": "Read secrets.",
        "cap:idp": "Manage identities.",
        "cap:orchestration": "Run workflows.",
        "cap:object-store": "Read and write objects.",
        "cap:notify": "Send notifications.",
    }
)

#: the actor of the front-door gap analysis (Rule 3): a privileged profile with four acting MCP
#: servers and the hypervisor capability, which every gate passed before the broker rule
ROGUE_CEILING = {
    "mcp": ["ansible", "hnx-catalog", "kubernetes", "shell", "ssh"],
    "capabilities": ["cap:broker", "cap:hypervisor"],
    "tier": "privileged",
    "data_tier": "local-only",
    "model_role": "mdl:main-reasoner",
    "budgets": {"max_input_tokens": 16000, "max_output_tokens": 2000, "max_runtime_s": 600,
                "max_tool_calls": 20},
}  # fmt: skip


def _rogue() -> tuple[dict, CeilingPolicy]:
    """The rogue actor as a compiled profile (the example actor, re-granted) and its policy."""
    doc = json.loads((ROOT / "schemas/agent/examples/profile.actor.json").read_text())
    doc["id"] = "profile:rogue-actor"
    grants = {k: ROGUE_CEILING[k] for k in ("mcp", "capabilities", "tier")}
    doc["grants"] = copy.deepcopy(grants)
    doc["ceiling"] = {**copy.deepcopy(grants), "budgets": ROGUE_CEILING["budgets"]}
    doc["digest"] = profile_digest(doc)
    policy = CeilingPolicy.from_mapping({"ceilings": {"profile:rogue-actor": ROGUE_CEILING}})
    return doc, policy


def _actor(**grants) -> dict:
    s = spec()
    s.update(id="profile:actor", reads_untrusted=False, **grants)
    return s


def _policy(s: dict, **extra) -> CeilingPolicy:
    """A policy whose ceiling allows every grant the spec asks for (only a rule can refuse)."""
    entry = {"mcp": sorted(s["mcp"]), "capabilities": sorted(s["capabilities"]),
             "tier": "privileged", "budgets": s["ceiling"]["budgets"],
             "data_tier": s["data_tier"], "internet_mcp": sorted(s["mcp"]), **extra}  # fmt: skip
    return CeilingPolicy.from_mapping({"ceilings": {s["id"]: entry}})


def _catalog_copy(tmp_path: Path) -> Path:
    d = tmp_path / "mcp"
    shutil.copytree(CATALOG, d, ignore=shutil.ignore_patterns("clients"))
    shutil.copy(ROOT / "examples" / "review-policy.yml", tmp_path / "review-policy.yml")
    return d


def _reviewed_copy(tmp_path: Path) -> Path:
    """The catalog as a lab that reviewed its direct servers would have it: the shipped direct
    servers are unreviewed drafts (no example may carry a human approve, ADR-0030), so these tests
    make them active with check, audit and approve reviews of their current content."""
    d = _catalog_copy(tmp_path)
    for f in sorted(d.glob("*.yml")):
        rec = yaml.safe_load(f.read_text())
        if rec.get("acts_via") != "direct" or rec.get("status") != "draft":
            continue
        rec["status"] = "active"
        rec.pop("reviews", None)
        digest = servers.record_digest(rec)[: len("sha256:") + 12]
        rec["reviews"] = [
            {"by": f"{who}", "kind": kind, "role": role, "date": "2026-10-23", "verdict": "pass",
             "digest": digest}
            for who, kind, role in (("agent:example-checker", "agent", "check"),
                                    ("agent:example-auditor", "agent", "audit"),
                                    ("human:example-operator", "human", "approve"))
        ]  # fmt: skip
        f.write_text(yaml.safe_dump(rec, sort_keys=False))
    return d


REVIEWED: dict[str, ToolClasses] = {}


@pytest.fixture(scope="module", autouse=True)
def _reviewed(tmp_path_factory):
    d = _reviewed_copy(tmp_path_factory.mktemp("reviewed"))
    REVIEWED["table"] = ToolClasses.from_catalog(servers.load(d))
    REVIEWED["dir"] = d
    yield
    REVIEWED.clear()


def _table() -> ToolClasses:
    return REVIEWED["table"]


def _compile(s: dict, **extra) -> dict:
    policy = _policy(s, **extra)
    return compile_profile(
        {k: v for k, v in s.items() if k != "ceiling"}, LIB, policy=policy, classes=_table()
    )


def _edit(d: Path, sid: str, fn) -> ToolClasses:
    f = d / f"{sid}.yml"
    rec = yaml.safe_load(f.read_text())
    fn(rec)
    f.write_text(yaml.safe_dump(rec, sort_keys=False))
    return ToolClasses.from_catalog(servers.load(d))  # load(catalog=) caches per directory


# ---------------------------------------------------------------- the gap analysis' rogue actor
def test_the_rogue_actor_is_refused_by_verify_lint_and_render(tmp_path, capsys):
    doc, policy = _rogue()
    problems = "\n".join(verify_profile(doc, policy=policy, classes=_table()))
    for name in ("'ssh'", "'shell'", "'ansible'", "'kubernetes'", "'cap:hypervisor'"):
        assert f"{name} (" in problems, name
    assert "hnx-catalog" not in problems  # a read-only server is not an acting grant
    path = tmp_path / "profile.rogue-actor.json"
    path.write_text(json.dumps(doc))
    found, counts = lint_paths([path], _table(), rules=(BROKER,))
    assert counts["profile"] == 1 and len(found) == 5
    assert cli.main(["agent", "lint", str(path)]) == 1
    err = capsys.readouterr().err
    assert "actors-act-via-broker: 1 profile(s), 0 manifest(s), 5 problem(s)" in err
    # against the shipped catalog the four direct servers are unreviewed drafts besides
    assert "readers-cannot-act: 1 profile(s), 0 manifest(s), 4 problem(s)" in err
    with pytest.raises(clients.RenderError, match="agents act only through the broker"):
        clients.render_profile(
            servers.load(REVIEWED["dir"]), path, "claude-code", policy=policy,
            npm_prefix="/var/lib/hnx/npm-prefix",
        )  # fmt: skip


def test_the_rogue_actor_does_not_compile():
    s = _actor(mcp=ROGUE_CEILING["mcp"], capabilities=ROGUE_CEILING["capabilities"],
               tier="privileged", model_role="mdl:main-reasoner")  # fmt: skip
    with pytest.raises(BrokerViolation) as exc:
        _compile(s, model_role="mdl:main-reasoner")
    assert len(exc.value.problems) == 5


# ---------------------------------------------------------------- what an actor may hold
def test_an_actor_acts_through_the_broker():
    p = _compile(_actor(mcp=["hnx-broker", "lake"], capabilities=["cap:broker", "cap:lake-query"],
                        tier="execute"))  # fmt: skip
    assert p["grants"]["tier"] == "execute" and verify_profile(p, classes=_table()) == []
    # egress and record-write are not broker-only: a non-reader may hold them
    p = _compile(_actor(mcp=["fetch"], capabilities=["cap:records-propose"],
                        tier="write", data_tier="cloud-allowed"))  # fmt: skip
    assert verify_profile(p, classes=_table()) == []


@pytest.mark.parametrize(
    ("kind", "name", "needle"),
    [
        ("mcp", "shell", "'shell' (exec)"),
        ("mcp", "ssh", "'ssh' (exec)"),
        ("mcp", "filesystem", "'filesystem' (file-write)"),
        ("mcp", "git", "'git' (file-write)"),
        ("mcp", "vault", "'vault' (credential)"),
        ("mcp", "slack", "'slack' (send)"),
        ("capabilities", "cap:notify", "'cap:notify' (send)"),
        ("capabilities", "cap:hypervisor", "'cap:hypervisor' (exec)"),
        ("capabilities", "cap:secrets", "'cap:secrets' (credential)"),
        ("capabilities", "cap:idp", "'cap:idp' (credential)"),
        ("capabilities", "cap:orchestration", "'cap:orchestration' (exec)"),
        ("capabilities", "cap:object-store", "'cap:object-store' (file-write)"),
        ("tier", "execute", "tier 'execute' (exec) without cap:broker"),
        ("tier", "privileged", "tier 'privileged' (credential, exec) without cap:broker"),
    ],
)
def test_every_acting_grant_outside_the_broker_is_refused(kind, name, needle):
    s = _actor()
    if kind == "tier":
        s["tier"] = name
    else:
        s[kind] = sorted({*s[kind], name})
    with pytest.raises(BrokerViolation, match="agents act only through the broker") as exc:
        _compile(s)
    assert any(needle in p for p in exc.value.problems), exc.value.problems
    # verify refuses a compiled profile edited into that state, whatever its ceiling says
    p = _compile(_actor(mcp=["hnx-broker"], capabilities=["cap:broker"], tier="execute"))
    grants = p["grants"]
    if kind == "tier":
        grants["tier"] = name
        grants["capabilities"] = []
    else:
        grants[kind] = sorted({*grants[kind], name})
    p["ceiling"] = {**copy.deepcopy(grants), "budgets": p["ceiling"]["budgets"]}
    p["digest"] = profile_digest(p)
    got = verify_profile(p, classes=_table())
    assert any(needle in x for x in got), got


def test_a_reader_is_judged_by_both_rules():
    s = spec()  # a reader (reads_untrusted defaults to true)
    s["mcp"] = ["lake", "shell"]
    problems = broker_problems({"mcp": s["mcp"]}, who=s["id"])
    assert len(problems) == 1 and "'shell' (exec)" in problems[0]


def test_a_manifest_tool_acts_only_through_the_broker():
    doc = {"id": "m", "persona": "persona:a", "sections": [], "tools": ["shell", "hnx-broker"]}
    problems = manifest_problems(doc, _table())
    assert len(problems) == 1 and "'shell' (exec)" in problems[0]
    assert manifest_problems(doc, _table(), rules=(READERS,)) == []


# ---------------------------------------------------------------- the direct exception
def test_a_direct_server_needs_a_reason_a_human_approve_and_the_policy(tmp_path):
    shipped = yaml.safe_load((CATALOG / "shell.yml").read_text())
    assert shipped["status"] == "draft" and not shipped.get("reviews")  # no shipped approve
    d = _reviewed_copy(tmp_path)
    table = ToolClasses.from_catalog(servers.load(d))
    grants = {"mcp": ["shell"], "capabilities": [], "tier": "read"}
    # a reviewed shell: direct, with a reason and a current human approve review
    assert "(none given)" in broker_problems(grants, table, "profile:a")[0]
    assert "direct_mcp entry" in broker_problems(grants, table, "profile:a", ())[0]
    assert broker_problems(grants, table, "profile:a", ["shell"]) == []
    # the record edited after its review: the human approve no longer counts
    table = _edit(d, "shell", lambda r: r.update(description="Runs anything."))
    got = broker_problems(grants, table, "profile:a", ["shell"])
    assert got and "a current human approve review" in got[0]
    # an agent's approve is not a human's
    table = _edit(d, "shell", lambda r: r.update(
        description="Runs shell commands on the agent's host.",
        reviews=[x for x in r["reviews"] if x["kind"] == "agent"]))  # fmt: skip
    got = broker_problems(grants, table, "profile:a", ["shell"])
    assert got and "a current human approve review" in got[0]
    # no acts_via at all: never grantable
    table = _edit(d, "shell", lambda r: [r.pop("acts_via"), r.pop("direct_reason")])
    got = broker_problems(grants, table, "profile:a", ["shell"])
    assert got and "does not say acts_via: broker" in got[0]


def test_a_reviewed_direct_server_compiles_only_with_the_policy_listing():
    s = _actor(mcp=["shell"])
    with pytest.raises(BrokerViolation, match="direct_mcp entry"):
        _compile(s)
    p = _compile(s, direct_mcp=["shell"])
    t = _table()
    assert any("(none given)" in x for x in verify_profile(p, classes=t))  # no policy, none
    policy = _policy(s, direct_mcp=["shell"])
    assert verify_profile(p, policy=policy, classes=t) == []
    assert any("direct_mcp entry" in x for x in verify_profile(p, policy=_policy(s), classes=t))


def test_a_spec_ceiling_cannot_grant_a_direct_exception():
    s = _actor(mcp=["shell"])
    s["ceiling"]["mcp"] = [*s["ceiling"]["mcp"], "shell"]
    s["ceiling"]["direct_mcp"] = ["shell"]  # not a ceiling key: only a policy makes the exception
    with pytest.raises(BrokerViolation, match="none given"):
        compile_profile(s, LIB, classes=_table())


def test_direct_mcp_is_a_list_of_server_ids():
    s = _actor()
    for bad in ("shell", ["Shell"], [1]):
        with pytest.raises(SpecError, match="direct_mcp is a list of MCP server ids"):
            _policy(s, direct_mcp=bad)


# ---------------------------------------------------------------- the table
def test_the_table_lists_the_broker_only_classes():
    table = default_classes()
    assert table.broker_only == {"exec", "file-write", "send", "credential"}
    assert table.broker_only <= table.reader_forbidden  # a reader may hold none of them either


def test_a_classes_file_cannot_narrow_broker_only(tmp_path, capsys):
    doc = yaml.safe_load(DEFAULT_CLASSES.read_text())
    doc["broker_only"] = ["credential"]
    (tmp_path / "classes.yml").write_text(yaml.safe_dump(doc))
    with pytest.raises(SpecError, match=r"broker_only leaves out \['exec', 'file-write', 'send'\]"):
        ToolClasses.load(tmp_path / "classes.yml")
    assert cli.main(["agent", "lint", str(ROOT / "schemas"), "--classes",
                     str(tmp_path / "classes.yml")]) == 1  # fmt: skip
    doc["broker_only"] = ["credential", "exec", "file-write", "send", "egress"]  # more is fine
    (tmp_path / "classes.yml").write_text(yaml.safe_dump(doc))
    assert "egress" in ToolClasses.load(tmp_path / "classes.yml").broker_only
    doc.pop("broker_only")
    with pytest.raises(SpecError, match="'broker_only' is empty"):
        ToolClasses({**doc, "mcp": {}})


# ---------------------------------------------------------------- lint
def test_lint_rules_and_policy(tmp_path, capsys, monkeypatch):
    from homelabnext.agent import readers

    monkeypatch.setattr(readers, "default_classes", _table)  # a lab that reviewed its shell
    prof = tmp_path / "actor.yml"
    prof.write_text(yaml.safe_dump(_actor(mcp=["shell"])))
    assert cli.main(["agent", "lint", str(prof), "--rule", READERS]) == 0
    assert cli.main(["agent", "lint", str(prof), "--rule", BROKER]) == 1
    pol = tmp_path / "policy.yml"
    entry = {"mcp": ["lake", "records", "shell"], "capabilities": ["cap:lake-query"],
             "tier": "read", "direct_mcp": ["shell"]}  # fmt: skip
    pol.write_text(yaml.safe_dump({"ceilings": {"profile:actor": entry}}))
    capsys.readouterr()
    assert cli.main(["agent", "lint", str(prof), "--policy", str(pol)]) == 0
    assert "actors-act-via-broker: 1 profile(s), 0 manifest(s), 0 problem(s)" in (
        capsys.readouterr().err
    )


# ---------------------------------------------------------------- every capability is classed
def _named_capabilities() -> dict[str, str]:
    """Every capability the repository names: registry services, the conformance contracts, the
    capability list and the module slots, each with where it was found."""
    from homelabnext.conform.registry import CAPABILITIES, EXTENDED
    from homelabnext.registry.model import load

    out = {
        f"cap:{s.capability}": f"registry svc:{n}"
        for n, s in load(ROOT / "examples" / "services.yml").services.items()
        if s.capability
    }
    out |= {f"cap:{c}": "conformance" for c in (*CAPABILITIES, *EXTENDED)}
    out |= {
        f"cap:{c}": "capabilities.yml"
        for c in yaml.safe_load((ROOT / "capabilities.yml").read_text())["capabilities"]
    }
    slots = yaml.safe_load((ROOT / "examples" / "modules" / "slots.yml").read_text())["slots"]
    out |= {f"cap:{c}": "module slot" for c in slots}
    return out  # fmt: skip


def test_every_capability_the_repository_names_is_classed():
    """B1: the broker rule fails closed on an unclassified capability, so every capability an
    agent could be granted is classed (a registry alias such as cap:automation, StackStorm, or
    cap:records-db, the raw database, would otherwise be unjudged authority)."""
    table = default_classes()
    missing = {c: w for c, w in _named_capabilities().items()
               if table.classify("capabilities", c) is None}  # fmt: skip
    assert missing == {}
    for cap in ("cap:automation", "cap:agent-runtime", "cap:records-db", "cap:dns", "cap:backup"):
        assert set(table.classify("capabilities", cap)) & table.broker_only, cap


def test_an_unclassified_capability_is_refused():
    s = _actor(capabilities=["cap:made-up-thing"])
    got = broker_problems({"capabilities": s["capabilities"]}, who=s["id"])
    assert got == [
        f"profile:actor holds an unknown capability (capabilities entry 1), which is not "
        f"classified in {default_classes().source} (unknown is never assumed not to act)"
    ]
    for cap in ("cap:automation", "cap:agent-runtime", "cap:records-db", "cap:dns"):
        got = broker_problems({"capabilities": [cap], "tier": "privileged"}, who="profile:a")
        assert any(f"{cap!r} (" in p for p in got), (cap, got)


# ---------------------------------------------------------------- only the broker's front is broker
def _restamp(rec: dict) -> None:
    digest = servers.record_digest(rec)[: len("sha256:") + 12]
    for x in rec.get("reviews") or ():
        x["digest"] = digest


def test_a_relabelled_server_is_not_the_broker(tmp_path):
    """B2 (P2, P4, P5): acts_via: broker is honoured only on the broker's own front with exactly
    its tools and current reviews; a re-stamped relabel, an extra tool or a new record claiming it
    is refused at grant time too (lint, verify, compile, render)."""
    d = _catalog_copy(tmp_path)
    grants = {"mcp": ["ssh"], "capabilities": [], "tier": "read"}

    def relabel(r):
        r.pop("direct_reason")
        r["acts_via"] = "broker"
        _restamp(r)

    table = _edit(d, "ssh", relabel)
    got = broker_problems(grants, table, "profile:a")
    assert got and "is not the broker's own MCP front" in got[0]

    def raw_shell(r):
        r["tools"].append({"name": "raw_shell", "classes": ["exec"], "approval": False})
        _restamp(r)

    table = _edit(d, "hnx-broker", raw_shell)
    got = broker_problems({"mcp": ["hnx-broker"]}, table, "profile:a")
    assert got and "is not the broker's own MCP front" in got[0]


def test_the_brokers_front_with_stale_reviews_is_refused(tmp_path):
    """S5/P2b: lint, verify and compile used to accept a broker record edited after its reviews."""
    d = _catalog_copy(tmp_path)
    table = _edit(d, "hnx-broker", lambda r: r.update(description="Changed after review."))
    got = broker_problems({"mcp": ["hnx-broker"]}, table, "profile:a")
    assert got and "lacks current reviews" in got[0]
    table = ToolClasses.from_catalog(servers.load(_catalog_copy(tmp_path / "fresh")))
    assert broker_problems({"mcp": ["hnx-broker"]}, table, "profile:a") == []


def test_a_server_below_its_class_floor_is_refused_at_grant_time(tmp_path):
    """VERIFY1: a record whose tools are declared below their floor (a camelCase createIssue
    classed egress) failed only the catalog check and the render; lint (so G-13), verify and
    compile judged the grant on what the record declared, and passed it."""
    d = _catalog_copy(tmp_path)
    rec = yaml.safe_load((d / "fetch.yml").read_text())
    rec.update(id="tickets", tools=[{"name": "createIssue", "classes": ["egress"],
                                     "approval": False}])  # fmt: skip
    _restamp(rec)
    (d / "tickets.yml").write_text(yaml.safe_dump(rec, sort_keys=False))
    table = ToolClasses.from_catalog(servers.load(d))
    got = broker_problems({"mcp": ["tickets"]}, table, "profile:a")
    assert got and "below their class floor" in got[0]
    s = _actor(mcp=["tickets"], capabilities=[], tier="read")
    with pytest.raises(BrokerViolation, match="below their class floor"):
        compile_profile({k: v for k, v in s.items() if k != "ceiling"}, LIB, policy=_policy(s),
                        classes=table)  # fmt: skip
    assert broker_problems({"mcp": ["fetch"]}, table, "profile:a") == []


def test_lint_walks_the_tree_once_for_both_rules(tmp_path, monkeypatch, capsys):
    """N1: the lint walked the repository once per rule (twice the scan)."""
    from homelabnext.agent import readers

    walks: list[Path] = []
    real = readers._candidates
    monkeypatch.setattr(readers, "_candidates", lambda p: walks.append(p) or real(p))
    (tmp_path / "a.yml").write_text(yaml.safe_dump({**_actor(mcp=["lake"]), "id": "profile:a"}))
    assert cli.main(["agent", "lint", str(tmp_path)]) == 0
    assert len(walks) == 1
    err = capsys.readouterr().err
    assert (
        "readers-cannot-act: 1 profile(s)" in err and "actors-act-via-broker: 1 profile(s)" in err
    )


def test_an_unused_direct_mcp_entry_is_a_note(tmp_path, capsys):
    """N5: a direct_mcp entry naming a server that is not acts_via: direct (or none at all) is an
    exception for nothing; lint with --policy says so (a note, not a refusal)."""
    prof = tmp_path / "actor.yml"
    prof.write_text(yaml.safe_dump(_actor(mcp=["lake"])))
    pol = tmp_path / "policy.yml"
    entry = {"mcp": ["lake"], "capabilities": ["cap:lake-query"], "tier": "read",
             "direct_mcp": ["lake", "hnx-broker", "nothing-here"]}  # fmt: skip
    pol.write_text(yaml.safe_dump({"ceilings": {"profile:actor": entry}}))
    assert cli.main(["agent", "lint", str(prof), "--policy", str(pol)]) == 0
    err = capsys.readouterr().err
    for name in ("lake", "hnx-broker", "nothing-here"):
        assert f"profile:actor lists {name!r} in direct_mcp, which is not an acts_via" in err
    entry["direct_mcp"] = ["shell"]
    pol.write_text(yaml.safe_dump({"ceilings": {"profile:actor": entry}}))
    assert cli.main(["agent", "lint", str(prof), "--policy", str(pol)]) == 0
    assert "in direct_mcp" not in capsys.readouterr().err
