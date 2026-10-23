# SPDX-License-Identifier: Apache-2.0
"""G-03: readers cannot act.

A profile that reads untrusted content may hold no shell/exec, file-write, egress or credential
grant: the compiler refuses one whatever the ceiling policy allows, `verify` refuses a compiled
profile edited into that state, and `hnx agent lint` checks every profile in the repository.
"""

import copy
import json
from pathlib import Path

import pytest
import yaml
from agent_support import PARTS, library, spec

from homelabnext import cli
from homelabnext.agent import (
    CatalogViolation,
    CeilingPolicy,
    ReaderViolation,
    SpecError,
    ToolClasses,
    compile_profile,
    lint_paths,
    profile_digest,
    reader_problems,
    verify_profile,
)
from homelabnext.agent.readers import (
    DEFAULT_CLASSES,
    default_classes,
    manifest_problems,
    profile_problems,
)

ROOT = Path(__file__).resolve().parents[2]
EXTRA_PARTS = {
    "cap:orchestration": "Run workflows.",
    "cap:object-store": "Read and write objects.",
    "cap:notify": "Send notifications.",
    "cap:secrets": "Read secrets.",
    "cap:made-up": "Not classified anywhere.",
}

# one grant per forbidden class, through each kind of grant (MCP server, capability, tier)
FORBIDDEN = [
    ("mcp", "shell", "exec"),
    ("mcp", "filesystem", "file-write"),
    ("mcp", "fetch", "egress"),
    ("mcp", "vault", "credential"),
    ("capabilities", "cap:orchestration", "exec"),
    ("capabilities", "cap:object-store", "file-write"),
    ("capabilities", "cap:notify", "egress"),
    ("capabilities", "cap:secrets", "credential"),
    ("tier", "execute", "exec"),
    ("tier", "privileged", "credential, exec"),
]


def _lib():
    return library({**PARTS, **EXTRA_PARTS})


def _table_doc() -> dict:
    """The packaged table with its mcp section written out (derived from the MCP catalog), the
    shape ToolClasses takes."""
    doc = yaml.safe_load(DEFAULT_CLASSES.read_text())
    doc["mcp"] = {k: list(v) for k, v in default_classes().table["mcp"].items()}
    return doc


def _with(s: dict, kind: str, name: str) -> dict:
    s = copy.deepcopy(s)
    if kind == "tier":
        s["tier"] = name
    else:
        s[kind] = [*s.get(kind, []), name]
    return s


def _permissive_policy(s: dict) -> CeilingPolicy:
    """A policy whose ceiling allows every grant the spec asks for (so only G-03 can refuse)."""
    ceiling = {
        "mcp": sorted({*s["mcp"], *s["ceiling"]["mcp"]}),
        "capabilities": sorted({*s["capabilities"], *s["ceiling"]["capabilities"]}),
        "tier": "privileged",
        "budgets": s["ceiling"]["budgets"],
        "data_tier": s["data_tier"],
        "internet_mcp": sorted(s["mcp"]),  # every internet exception too
    }
    return CeilingPolicy.from_mapping({"ceilings": {s["id"]: ceiling}})


@pytest.mark.parametrize(("kind", "name", "cls"), FORBIDDEN, ids=[f[1] for f in FORBIDDEN])
def test_reader_holding_an_acting_grant_is_refused_whatever_the_ceiling(kind, name, cls):
    s = _with(spec(), kind, name)
    policy = _permissive_policy(s)
    s.pop("ceiling")  # the policy alone bounds it, and allows every grant
    with pytest.raises(ReaderViolation) as exc:
        compile_profile(s, _lib(), policy=policy)
    msg = str(exc.value)
    assert repr(name) in msg and f"({cls})" in msg and "readers cannot act" in msg
    # the same refusal without a policy, from a spec whose own ceiling allows everything
    s["ceiling"] = policy.ceiling(s["id"])
    with pytest.raises(ReaderViolation):
        compile_profile(s, _lib())


def test_unclassified_grant_is_refused_for_a_reader():
    s = _with(spec(), "capabilities", "cap:made-up")
    s["ceiling"]["capabilities"].append("cap:made-up")
    with pytest.raises(ReaderViolation, match="not classified"):
        compile_profile(s, _lib())
    s = _with(spec(), "mcp", "mystery-server")
    s["ceiling"]["mcp"].append("mystery-server")
    with pytest.raises(
        ReaderViolation, match=r"unknown mcp server \(mcp entry \d+\), which is not classified"
    ):
        compile_profile(s, _lib())


def test_every_forbidden_grant_is_reported_together():
    s = spec()
    s["mcp"] += ["shell", "fetch"]
    s["ceiling"]["mcp"] += ["shell", "fetch"]
    with pytest.raises(ReaderViolation) as exc:
        compile_profile(s, _lib())
    assert len(exc.value.problems) == 2


def test_passing_reader_compiles_and_records_the_declaration():
    s = spec()
    s["reads_untrusted"] = True
    p = compile_profile(s, library())
    assert p["reads_untrusted"] is True
    assert verify_profile(p) == []
    assert profile_problems(p) == []


def test_reader_is_the_default_fail_closed():
    s = spec()
    assert "reads_untrusted" not in s
    assert compile_profile(s, library())["reads_untrusted"] is True
    s["mcp"].append("shell")
    s["ceiling"]["mcp"].append("shell")
    with pytest.raises(ReaderViolation):
        compile_profile(s, _lib())


def test_non_reader_actor_may_hold_acting_grants():
    s = _with(
        _with(_with(spec(), "mcp", "shell"), "capabilities", "cap:orchestration"), "tier", "execute"
    )
    s["reads_untrusted"] = False
    policy = _permissive_policy(s)
    s.pop("ceiling")
    p = compile_profile(s, _lib(), policy=policy)
    assert p["reads_untrusted"] is False and "shell" in p["grants"]["mcp"]
    assert verify_profile(p) == []


def test_policy_can_force_a_reader_and_the_spec_cannot_undo_it():
    s = spec()
    s["reads_untrusted"] = False
    doc = {"ceilings": {"profile:reader": {**s["ceiling"], "reads_untrusted": True,
                                          "data_tier": s["data_tier"]}}}  # fmt: skip
    policy = CeilingPolicy.from_mapping(doc)
    with pytest.raises(ReaderViolation, match="may not declare reads_untrusted: false"):
        compile_profile({k: v for k, v in s.items() if k != "ceiling"}, library(), policy=policy)
    s["reads_untrusted"] = True
    p = compile_profile({k: v for k, v in s.items() if k != "ceiling"}, library(), policy=policy)
    assert verify_profile(p, policy=policy) == []
    # flipping the flag after compile (digest honestly recomputed) is caught against the policy
    p["reads_untrusted"] = False
    p["digest"] = profile_digest(p)
    assert any("marks profile:reader" in x for x in verify_profile(p, policy=policy))


@pytest.mark.parametrize("bad", ["yes", 1, None])
def test_reads_untrusted_must_be_boolean(bad):
    s = spec()
    s["reads_untrusted"] = bad
    with pytest.raises(SpecError, match="reads_untrusted"):
        compile_profile(s, library())
    with pytest.raises(SpecError, match="reads_untrusted"):
        CeilingPolicy.from_mapping(
            {"ceilings": {"profile:x": {**spec()["ceiling"], "reads_untrusted": bad or 2}}}
        )


# ---------------------------------------------------------------- verify catches tampering
def _tampered_reader() -> dict:
    """A compiled reader, then hand-edited to hold a shell, with the digest recomputed."""
    p = compile_profile(spec(), library())
    p["grants"]["mcp"] = sorted([*p["grants"]["mcp"], "shell"])
    p["ceiling"]["mcp"] = sorted([*p["ceiling"]["mcp"], "shell"])
    p["digest"] = profile_digest(p)
    return p


def test_verify_refuses_a_hand_edited_reader_even_with_a_permissive_policy():
    p = _tampered_reader()
    assert any("'shell' (exec)" in x for x in verify_profile(p))
    policy = CeilingPolicy.from_mapping({"ceilings": {"profile:reader": p["ceiling"]}})
    assert any("readers cannot act" in x for x in verify_profile(p, policy=policy))


def test_verify_treats_a_profile_without_the_flag_as_a_reader():
    p = _tampered_reader()
    del p["reads_untrusted"]
    p["digest"] = profile_digest(p)
    assert any("'shell' (exec)" in x for x in verify_profile(p))


def test_cli_verify_refuses_a_tampered_profile(tmp_path, capsys):
    p = _tampered_reader()
    (tmp_path / "profile.json").write_text(json.dumps(p))
    (tmp_path / "policy.yml").write_text(
        yaml.safe_dump({"ceilings": {"profile:reader": p["ceiling"]}})
    )
    rc = cli.main(
        [
            "agent",
            "verify",
            str(tmp_path / "profile.json"),
            "--policy",
            str(tmp_path / "policy.yml"),
        ]
    )
    assert rc == 1 and "readers cannot act" in capsys.readouterr().err


def test_cli_compile_refuses_a_reader(tmp_path, capsys):
    s = spec()
    s["mcp"].append("fetch")
    s["ceiling"]["mcp"].append("fetch")
    lib = tmp_path / "lib"
    lib.mkdir()
    for k, v in PARTS.items():
        (lib / (k.replace(":", "-") + ".md")).write_text(v)
    (lib / "library.yml").write_text(
        yaml.safe_dump({"parts": {k: k.replace(":", "-") + ".md" for k in PARTS}})
    )
    (tmp_path / "spec.yml").write_text(yaml.safe_dump(s))
    rc = cli.main(
        ["agent", "compile", str(tmp_path / "spec.yml"), "--library", str(lib / "library.yml")]
    )
    assert rc == 1 and "'fetch' (egress)" in capsys.readouterr().err


# ---------------------------------------------------------------- the classification table
def test_every_platform_capability_is_classified():
    caps = yaml.safe_load((ROOT / "capabilities.yml").read_text())["capabilities"]
    table = ToolClasses.load()
    missing = [c for c in caps if table.classify("capabilities", f"cap:{c}") is None]
    assert missing == []


def test_every_tier_is_classified_and_the_ban_covers_the_three_named_classes():
    table = ToolClasses.load()
    assert {"exec", "file-write", "egress"} <= table.reader_forbidden
    for tier in ("read", "write", "execute", "privileged"):
        assert table.classify("tiers", tier)
    assert not set(table.classify("tiers", "read")) & table.reader_forbidden


@pytest.mark.parametrize(
    ("doc", "match"),
    [
        ({}, "'classes'"),
        ({"classes": {"read": "r"}}, "reader_forbidden"),
        ({"classes": {"read": "r"}, "reader_forbidden": ["exec"]}, "undeclared classes"),
        (
            {"classes": {"read": "r"}, "reader_forbidden": ["read"], "mcp": {"x": ["nope"]}},
            "undeclared classes",
        ),
        (
            {"classes": {"read": "r"}, "reader_forbidden": ["read"], "mcp": {"x": []}},
            "at least one",
        ),
        ({"classes": {"read": "r"}, "reader_forbidden": ["read"], "mcp": ["x"]}, "mapping"),
        ([], "expected a mapping"),
    ],
)
def test_malformed_classification_is_refused(doc, match):
    with pytest.raises(SpecError, match=match):
        ToolClasses(doc)


def test_a_custom_table_changes_the_verdict(tmp_path):
    doc = _table_doc()
    doc["mcp"]["lake"] = ["egress"]
    custom = ToolClasses(doc)
    assert reader_problems({"mcp": ["lake"]}) == []
    assert reader_problems({"mcp": ["lake"]}, custom)
    # a --classes file changes the non-MCP classes; its mcp section is the catalog's
    table = yaml.safe_load(DEFAULT_CLASSES.read_text())
    table["capabilities"]["cap:lake-query"] = ["egress"]
    path = tmp_path / "classes.yml"
    path.write_text(yaml.safe_dump(table))
    with pytest.raises(ReaderViolation):
        compile_profile(spec(), library(), classes=ToolClasses.load(path))


def test_a_classes_file_cannot_reclass_an_mcp_server(tmp_path, capsys):
    """A --classes table with its own mcp section used to replace the catalog's: shell classed
    read passed the reader rule, and the catalog's status and data-tier rules were skipped."""
    doc = _table_doc()
    doc["mcp"]["shell"] = ["read"]
    _write(tmp_path / "classes.yml", doc)
    with pytest.raises(SpecError, match="classed only by the MCP catalog"):
        ToolClasses.load(tmp_path / "classes.yml")
    _write(tmp_path / "spec.yml", {**spec(), "mcp": ["shell"]})
    args = ["agent", "lint", str(tmp_path / "spec.yml"), "--classes", str(tmp_path / "classes.yml")]
    assert cli.main(args) == 1
    assert "classed only by the MCP catalog" in capsys.readouterr().err


def test_a_classes_file_cannot_narrow_the_reader_ban(tmp_path, capsys):
    """A --classes table with reader_forbidden: [credential] let a reader hold exec, egress and
    file-write grants; a table may add to the ban, never drop a packaged class from it."""
    table = yaml.safe_load(DEFAULT_CLASSES.read_text())
    table["reader_forbidden"] = ["credential"]
    _write(tmp_path / "classes.yml", table)
    with pytest.raises(SpecError, match=r"leaves out .*'egress'.*'exec'"):
        ToolClasses.load(tmp_path / "classes.yml")
    _write(tmp_path / "spec.yml", {**spec(), "mcp": ["shell"]})
    args = ["agent", "lint", str(tmp_path / "spec.yml"), "--classes", str(tmp_path / "classes.yml")]
    assert cli.main(args) == 1
    assert "never less" in capsys.readouterr().err
    table["reader_forbidden"] = [*yaml.safe_load(DEFAULT_CLASSES.read_text())["reader_forbidden"]]
    table["reader_forbidden"].append("record-write")  # forbidding more is fine
    _write(tmp_path / "classes.yml", table)
    assert "record-write" in ToolClasses.load(tmp_path / "classes.yml").reader_forbidden


# ---------------------------------------------------------------- lint
def test_lint_passes_on_the_repository():
    problems, counts = lint_paths([ROOT])
    assert problems == []
    assert counts["profile"] >= 3 and counts["manifest"] >= 1


def test_make_check_and_ci_run_the_lint():
    assert "agent-lint" in (ROOT / "Makefile").read_text().split("check:", 1)[1].splitlines()[0]
    assert "homelabnext.cli agent lint" in (ROOT / ".github" / "workflows" / "ci.yml").read_text()


def _write(path: Path, doc) -> Path:
    path.write_text(json.dumps(doc) if path.suffix == ".json" else yaml.safe_dump(doc))
    return path


def test_lint_fails_on_a_reader_profile_and_on_a_reader_manifest(tmp_path):
    bad = compile_profile(spec(), library())
    bad["grants"]["mcp"].append("shell")
    _write(tmp_path / "agent.json", bad)
    _write(
        tmp_path / "actor.yml",
        {**spec(), "id": "profile:actor", "mcp": ["shell"], "reads_untrusted": False},
    )
    lean = {"id": "profile:lean", "persona": "persona:a", "mcp": ["browser"], "capabilities": []}
    _write(tmp_path / "lean.yml", lean)
    manifest = {
        "id": "m",
        "persona": "persona:a",
        "tools": ["lake", "http"],
        "sections": [{"name": "feed", "source": "input"}],
    }
    _write(tmp_path / "manifest.yml", manifest)
    (tmp_path / "negative").mkdir()
    _write(tmp_path / "negative" / "skip.json", bad)  # schema negatives are not linted
    problems, counts = lint_paths([tmp_path])
    where = sorted({Path(f).name for f, _ in problems})
    assert where == ["agent.json", "lean.yml", "manifest.yml"]
    assert counts == {"profile": 3, "manifest": 1}


def test_manifest_without_input_sections_is_not_a_reader():
    doc = {"id": "m", "tools": ["shell"], "sections": [{"name": "c", "source": "static"}]}
    assert manifest_problems(doc) == []


def test_cli_lint_exit_codes(tmp_path, capsys):
    assert cli.main(["agent", "lint", str(ROOT / "schemas")]) == 0
    assert "0 problem(s)" in capsys.readouterr().err
    bad = {**spec(), "mcp": ["shell"]}
    _write(tmp_path / "spec.yml", bad)
    assert cli.main(["agent", "lint", str(tmp_path)]) == 1
    assert "'shell' (exec)" in capsys.readouterr().err
    empty = tmp_path / "empty"
    empty.mkdir()
    assert cli.main(["agent", "lint", str(empty)]) == 1
    assert "no agent profile found" in capsys.readouterr().err
    assert cli.main(["agent", "lint", str(tmp_path / "missing")]) == 1
    (tmp_path / "broken.json").write_text("{not json")
    assert cli.main(["agent", "lint", str(tmp_path / "broken.json")]) == 1
    assert "cannot parse" in capsys.readouterr().err


def test_cli_lint_accepts_a_custom_table(tmp_path, capsys):
    doc = yaml.safe_load(DEFAULT_CLASSES.read_text())
    doc["capabilities"]["cap:notify"] = ["read"]
    _write(tmp_path / "classes.yml", doc)
    _write(tmp_path / "spec.yml", {**spec(), "capabilities": ["cap:notify"]})
    assert (
        cli.main(
            [
                "agent",
                "lint",
                str(tmp_path / "spec.yml"),
                "--classes",
                str(tmp_path / "classes.yml"),
            ]
        )
        == 0
    )


def test_the_compiler_refuses_an_actor_granted_a_retired_server():
    s = copy.deepcopy(spec())
    s["reads_untrusted"] = False
    s["mcp"] = ["puppeteer"]
    s["ceiling"]["mcp"] = ["puppeteer"]
    with pytest.raises(CatalogViolation, match="retired"):
        compile_profile(s, library())
    s["mcp"] = s["ceiling"]["mcp"] = ["playwright"]
    assert compile_profile(s, library())["grants"]["mcp"] == ["playwright"]


# ------------------------------------------------- grants are judged against a sound catalog
def _catalog_copy(tmp_path: Path) -> Path:
    import shutil

    d = tmp_path / "mcp"
    shutil.copytree(ROOT / "examples" / "mcp", d, ignore=shutil.ignore_patterns("clients"))
    return d


def test_a_shadow_record_cannot_reclassify_a_server(tmp_path):
    """A record whose id is not its file name, sorted before the real one, used to win the id
    (first file wins) with a status the schema does not allow: shell became ``read``."""
    d = _catalog_copy(tmp_path)
    shadow = yaml.safe_load((d / "lake.yml").read_text())
    shadow.update(id="shell", status="Active")
    (d / "aa-shadow.yml").write_text(yaml.safe_dump(shadow))
    with pytest.raises(SpecError, match="is not valid, so no grant can be judged"):
        ToolClasses.load(catalog=d)


def test_grantable_is_an_allowlist_and_a_data_tier_is_required():
    from homelabnext.agent.readers import grant_problems

    doc = yaml.safe_load(DEFAULT_CLASSES.read_text())
    meta = {
        "odd": {"status": "Active", "data_tier": "local-only"},
        "untiered": {"status": "active", "data_tier": None},
        "ok": {"status": "active", "data_tier": "cloud-allowed"},
    }
    table = ToolClasses({**doc, "mcp": {k: ["read"] for k in meta}}, catalog=meta)
    odd = grant_problems({"mcp": ["odd"]}, table)
    assert odd and "whose status 'Active' is not grantable" in odd[0]
    assert "declares no known data_tier" in grant_problems({"mcp": ["untiered"]}, table)[0]
    assert grant_problems({"mcp": ["ok"]}, table, "p", "cloud-allowed") == []
    # an unknown profile tier is treated as one that may reach the cloud
    local = {**meta, "ok": {"status": "active", "data_tier": "local-only"}}
    table = ToolClasses({**doc, "mcp": {k: ["read"] for k in local}}, catalog=local)
    assert "whose data is local-only" in grant_problems({"mcp": ["ok"]}, table, "p", "public")[0]


def test_a_deprecated_grant_is_reported_with_its_replacement(tmp_path, capsys, monkeypatch):
    from homelabnext.agent import readers
    from homelabnext.agent.readers import grant_notes

    # the shipped catalog deprecates nothing since ADR-0030 retired bash, exec and terminal
    d = _catalog_copy(tmp_path)
    rec = yaml.safe_load((d / "ntfy.yml").read_text())
    rec.update(status="deprecated", reason="moved to slack", replaced_by="slack")
    (d / "ntfy.yml").write_text(yaml.safe_dump(rec))
    monkeypatch.setattr(readers, "default_classes", lambda: ToolClasses.load(catalog=d))
    notes = grant_notes({"mcp": ["ntfy", "slack"]})
    assert len(notes) == 1 and "'ntfy', which is deprecated" in notes[0]
    assert "grant 'slack' instead" in notes[0]
    p = tmp_path / "p.yml"
    p.write_text(yaml.safe_dump({"id": "profile:x", "persona": "persona:a", "mcp": ["ntfy"],
                                 "capabilities": [], "reads_untrusted": False}))  # fmt: skip
    assert cli.main(["agent", "lint", str(p)]) == 0  # a warning, not a refusal
    err = capsys.readouterr().err
    assert "note:" in err and "grant 'slack' instead" in err
    found: list[tuple[str, str]] = []
    lint_paths([p], None, found)
    assert found and "deprecated" in found[0][1]
