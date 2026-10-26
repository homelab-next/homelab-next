# SPDX-License-Identifier: Apache-2.0
"""Additive-evolution: a v1.0 document must validate against every v1.x schema."""

import copy
import json
from pathlib import Path

import pytest
import schema_check as sc

ROOT = Path(__file__).resolve().parents[2]
REG = sc.build_registry(ROOT)
OWNED = ["ids", "events", "records", "registers", "platform"]
SCHEMAS = [
    p
    for p in sc.schema_files(ROOT, OWNED)
    if p.relative_to(ROOT / "schemas").as_posix() != "platform/service.json"
    and not sc.is_draft(json.loads(p.read_text()))
]
#: schemas still drafts (x-draft: proposed, no loader or pilot yet): no frozen baseline, free to
#: change until their ADR is accepted; joining or leaving this set is a reviewed change
DRAFTS = {
    "platform/module.schema.json",
    "platform/lake_table.schema.json",
    "platform/module_selection.schema.json",
    "platform/slot.schema.json",
    "platform/module_swap.schema.json",
    "codemode/execution_request.schema.json",
    "codemode/execution_result.schema.json",
    "codemode/token.schema.json",
    "codemode/journal_step.schema.json",
}


def _major(path) -> int:
    return sc.parse_id(json.loads(path.read_text()))[1]


@pytest.mark.parametrize("path", SCHEMAS, ids=lambda p: p.relative_to(ROOT / "schemas").as_posix())
def test_current_schema_is_additive_over_frozen_v1_0(path):
    """Additive over the x.0 baseline of its own major; a major bump (a breaking change, ADR-0001:
    the registers' lesson and runbook 2.0 require a uid, ADR-0019) keeps every earlier major's
    baseline frozen, for the migration that reads it."""
    major = _major(path)
    for m in range(1, major + 1):
        assert sc.frozen_path(ROOT, path, m, 0).is_file(), f"missing baseline {m}.0 of {path}"
    old = json.loads(sc.frozen_path(ROOT, path, major, 0).read_text())
    new = json.loads(path.read_text())
    assert sc.additive_problems(old, new, sc.parse_id(new)[0], f"{major}.0") == []


# examples of a feature added after the 1.0 freeze (1.0 rightly refuses them)
NEWER_THAN_1_0 = {
    "note.register-transition.md": "records/note 1.1: type register-transition",
    "note.strategy-transition.md": "records/note 1.3: type strategy-transition",
    "note.strategy-rfi.md": "records/note 1.3: type strategy-rfi",
    "register_event.value.yml": "registers/register_event 1.1: event value",
    "register_event.value-finding.yml": "registers/register_event 1.1: event value",
    "register_event.review-audit.yml": "registers/register_event 1.2: review role audit",
    "register_event.rekey.yml": "registers/register_event 1.3: event rekey",
    "note.register-transition-legacy-code.md": "records/note 1.1: type register-transition",
    "site.tailnet-deploy.yml": "platform/site 1.2: tailnet.deploy",
    "site.port-mirror.yml": "platform/site 1.3: port kind mirror, mirror_from",
    "decision.returned.agent-approved.json": "events/decision.returned 1.1: tier_used agent",
    "agent.job.failed.auto-retried.json": "events/agent.job.failed 1.1: auto_retry_scheduled",
    "mcp_server.broker.yml": "platform/mcp_server 1.1: acts_via",
    "mcp_server.direct.yml": "platform/mcp_server 1.1: acts_via, direct_reason",
    "mcp_server.codemode.yml": "platform/mcp_server 1.2: class codemode",
}


@pytest.mark.parametrize("name", sorted(NEWER_THAN_1_0))
def test_an_example_newer_than_1_0_names_a_version_its_schema_really_has(name):
    """Excusing an example from the 1.0 check claims a later minor added its feature: the schema
    must carry that version (its $id at or past it) and a frozen copy of it, or the excuse hides an
    additive change that never bumped the id."""
    ref, _, _ = NEWER_THAN_1_0[name].partition(":")
    schema_ref, ver = ref.split()
    major, minor = (int(x) for x in ver.split("."))
    path = ROOT / "schemas" / f"{schema_ref}.schema.json"
    _, cur_major, cur_minor = sc.parse_id(json.loads(path.read_text()))
    assert (cur_major, cur_minor) >= (major, minor), f"{path.name} is {cur_major}.{cur_minor}"
    assert sc.frozen_path(ROOT, path, major, minor).is_file(), f"no frozen {ver} of {path.name}"


def _validation_only(doc):
    """``doc`` without its annotations (a description may be reworded without a new version)."""
    if isinstance(doc, dict):
        skip = ("description", "title", "$comment", "examples")
        return {k: _validation_only(v) for k, v in doc.items() if k not in skip}
    if isinstance(doc, list):
        return [_validation_only(v) for v in doc]
    return doc


# changed after their version was frozen, before this test existed: the next change to one of
# these bumps its id (and the entry goes); nothing may join the list
UNBUMPED = {
    "events/envelope.schema.json": "assetid, assetowner, assetcriticality added at 1.0",
    "status/observation.schema.json": "patterns changed at 1.0",
    "status/agent_activity.schema.json": "changed at 1.0",
    "status/agent_activity_detail.schema.json": "changed at 1.0",
}
FROZEN_AT_CURRENT = [
    p
    for p in sc.schema_files(ROOT)
    if (pid := sc.parse_id(json.loads(p.read_text())))
    and sc.frozen_path(ROOT, p, pid[1], pid[2]).is_file()
]


@pytest.mark.parametrize(
    "path", FROZEN_AT_CURRENT, ids=lambda p: p.relative_to(ROOT / "schemas").as_posix()
)
def test_a_change_after_the_freeze_bumps_the_id(path):
    """A schema whose $id names a frozen version validates exactly what that frozen copy does:
    an additive change (agent.job.failed's four fields, the stackstorm binding's approved_run)
    is a new minor with its own frozen copy, never an edit under the old $id."""
    rel = path.relative_to(ROOT / "schemas").as_posix()
    _, major, minor = sc.parse_id(json.loads(path.read_text()))
    frozen = json.loads(sc.frozen_path(ROOT, path, major, minor).read_text())
    same = _validation_only(frozen) == _validation_only(json.loads(path.read_text()))
    assert same or rel in UNBUMPED, f"{rel} changed since {major}.{minor} was frozen: bump $id"
    assert not (same and rel in UNBUMPED), f"{rel} is no longer drifted: drop it from UNBUMPED"


def test_the_agent_job_failed_1_1_negative_is_what_1_1_added():
    """The new negative (auto_retry_scheduled false) is refused by 1.1 and, as the open 1.0 data
    shows, was accepted by 1.0: it tests the 1.1 field, not something 1.0 already refused."""
    path = ROOT / "schemas/events/agent.job.failed.schema.json"
    neg = sc.load_instance(ROOT / "schemas/events/negative/agent.job.failed.auto-retry-false.json")
    assert sc.errors_for(json.loads(path.read_text()), neg, REG)
    assert sc.errors_for(json.loads(sc.frozen_path(ROOT, path, 1, 0).read_text()), neg, REG) == []


@pytest.mark.parametrize("path", SCHEMAS, ids=lambda p: p.relative_to(ROOT / "schemas").as_posix())
def test_v1_0_examples_validate_against_current_schema(path):
    """The frozen v1.0 schema accepted these examples; the current v1.x must still accept them."""
    frozen = json.loads(sc.frozen_path(ROOT, path, 1, 0).read_text())
    current = json.loads(path.read_text())
    for f in sc.instances_for(path, "examples"):
        doc = sc.load_instance(f)
        if f.name not in NEWER_THAN_1_0 and _major(path) == 1:
            assert sc.errors_for(frozen, doc, REG) == [], f.name
        assert sc.errors_for(current, doc, REG) == [], f.name


# ----- the evolution rules themselves, on a worked v1.0 -> v1.1 example -----
V10 = {
    "$id": "https://schemas.example.internal/homelabnext/events/demo/1.0",
    "type": "object",
    "properties": {"a": {"type": "string", "maxLength": 10}, "kind": {"enum": ["x", "y"]}},
    "required": ["a"],
}
DOC10 = {"a": "hello", "kind": "x"}


def v11(mutator):
    s = copy.deepcopy(V10)
    s["$id"] = s["$id"].replace("1.0", "1.1")
    mutator(s)
    return s


def test_worked_example_additive_changes_pass_and_old_document_still_validates():
    def add(s):
        s["properties"]["b"] = {"type": "integer"}  # new optional property
        s["properties"]["kind"]["enum"].append("z")  # widened enum
        s["properties"]["a"]["maxLength"] = 20  # relaxed bound
        s["properties"]["a"]["description"] = "documented"  # annotation

    new = v11(add)
    assert sc.is_additive(V10, new) == []
    assert sc.errors_for(new, DOC10, REG) == []
    assert sc.errors_for(new, {**DOC10, "b": 3, "kind": "z"}, REG) == []


@pytest.mark.parametrize(
    "label,mutator",
    [
        ("new required", lambda s: s["required"].append("b")),
        ("removed property", lambda s: s["properties"].pop("kind")),
        ("narrowed enum", lambda s: s["properties"]["kind"].__setitem__("enum", ["x"])),
        ("tightened bound", lambda s: s["properties"]["a"].__setitem__("maxLength", 3)),
        ("narrowed type", lambda s: s["properties"]["a"].__setitem__("type", "integer")),
        ("closed object", lambda s: s.__setitem__("additionalProperties", False)),
        ("new pattern", lambda s: s["properties"]["a"].__setitem__("pattern", "^z")),
        ("new minLength", lambda s: s["properties"]["a"].__setitem__("minLength", 2)),
    ],
)
def test_breaking_changes_are_detected(label, mutator):
    assert sc.is_additive(V10, v11(mutator)), label


def test_breaking_change_really_breaks_a_v1_document():
    broken = v11(lambda s: s["required"].append("b"))
    assert sc.errors_for(broken, DOC10, REG)  # proves the detector is guarding something real


def test_checker_flags_non_additive_schema_in_repo(tmp_path):
    import shutil

    shutil.copytree(ROOT / "schemas", tmp_path / "schemas")
    p = tmp_path / "schemas/registers/lesson.schema.json"
    s = json.loads(p.read_text())
    s["required"].append("owner")
    p.write_text(json.dumps(s))
    probs = sc.check_repo(tmp_path, ["registers"])
    assert any("not additive" in x.message and "owner" in x.message for x in probs)


def test_major_bump_is_allowed_to_break(tmp_path):
    import shutil

    shutil.copytree(ROOT / "schemas", tmp_path / "schemas")
    p = tmp_path / "schemas/registers/lesson.schema.json"
    s = json.loads(p.read_text())
    s["required"].append("owner")
    base, _, ver = s["$id"].rpartition("/")
    s["$id"] = f"{base}/{int(ver.split('.')[0]) + 1}.0"  # the next major
    p.write_text(json.dumps(s))
    probs = [
        x
        for x in sc.check_repo(tmp_path, ["registers"])
        if "lesson.schema.json" in x.where and "additive" in x.message
    ]
    assert probs == []


@pytest.mark.parametrize(
    ("old", "new", "additive"),
    [
        ("^[a-z]+$", "^[a-z]+$(?!\\n)", True),  # ECMA-262 `$` is end of input: same language
        ("^a$|^b$", "^a$|^b$(?!\\n)", True),
        ("^[a-z]+\\$", "^[a-z]+\\$(?!\\n)", False),  # an escaped dollar is a literal
        ("^[a-z]+$", "^[a-z]+$(?!\\r)", False),
        ("^[a-z]+$", "^[a-y]+$(?!\\n)", False),
        ("^[a-z]+", "^[a-z]+(?!\\n)", False),  # no closing anchor: a real tightening
    ],
)
def test_a_trailing_newline_guard_is_the_only_pattern_change_proved_compatible(old, new, additive):
    s_old = {"type": "string", "pattern": old}
    assert (sc.is_additive(s_old, {**s_old, "pattern": new}) == []) is additive


def test_the_newline_guard_rejects_what_python_alone_accepted():
    """Python's ``$`` matches before a trailing newline; the guard closes that, nothing else."""
    old, new = {"pattern": "^[a-z]+$"}, {"pattern": "^[a-z]+$(?!\\n)"}
    assert sc.errors_for(old, "abc\n", REG) == []  # the defect, under Python's re
    assert sc.errors_for(new, "abc\n", REG) and sc.errors_for(new, "abc", REG) == []


# ----- draft schemas (x-draft): not frozen until their ADR is accepted -----
def test_the_draft_schemas_are_exactly_the_listed_ones():
    found = {
        p.relative_to(ROOT / "schemas").as_posix()
        for p in sc.schema_files(ROOT)
        if sc.is_draft(json.loads(p.read_text()))
    }
    assert found == DRAFTS


@pytest.mark.parametrize("rel", sorted(DRAFTS))
def test_a_draft_has_no_frozen_copy_and_passes_strict(rel):
    path = ROOT / "schemas" / rel
    _, major, minor = sc.parse_id(json.loads(path.read_text()))
    assert not sc.frozen_path(ROOT, path, major, minor).is_file()
    assert sc.check_schema(ROOT, path, sc.build_registry(ROOT), strict=True) == []


def _draft_repo(tmp_path):
    """A copy of the schemas where platform/module is a draft with no frozen copy."""
    import shutil

    shutil.copytree(ROOT / "schemas", tmp_path / "schemas")
    p = tmp_path / "schemas/platform/module.schema.json"
    s = json.loads(p.read_text())
    s["x-draft"] = "ADR-0027 (proposed): a test draft"
    p.write_text(json.dumps(s))
    sc.frozen_path(tmp_path, p, 1, 0).unlink(missing_ok=True)
    return p


def test_a_frozen_copy_of_a_draft_is_an_error(tmp_path):
    p = _draft_repo(tmp_path)
    dest = sc.frozen_path(tmp_path, p, 1, 0)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(p.read_text())
    probs = sc.check_repo(tmp_path, ["platform"], strict=True, only=["platform/module.schema.json"])
    assert any("draft schema has a frozen copy" in x.message for x in probs)


def test_freeze_skips_a_draft_and_removing_x_draft_requires_a_baseline(tmp_path):
    p = _draft_repo(tmp_path)
    assert all("module.schema.json" not in str(w) for w in sc.freeze(tmp_path))
    s = json.loads(p.read_text())
    del s["x-draft"]
    p.write_text(json.dumps(s))
    probs = sc.check_repo(tmp_path, ["platform"], strict=True, only=["platform/module.schema.json"])
    assert any("no frozen baseline" in x.message for x in probs)


def test_an_empty_x_draft_is_refused(tmp_path):
    p = _draft_repo(tmp_path)
    s = json.loads(p.read_text())
    s["x-draft"] = " "
    p.write_text(json.dumps(s))
    probs = sc.check_repo(tmp_path, ["platform"], strict=True, only=["platform/module.schema.json"])
    assert any("x-draft must say why" in x.message for x in probs)


def _bump(s, version):
    s["$id"] = s["$id"].rsplit("/", 1)[0] + "/" + version


@pytest.mark.parametrize(
    "rel",
    [
        "platform/guest.schema.json",
        "platform/swap_record.schema.json",
        "platform/capability.schema.json",
    ],
)
def test_x_draft_on_a_released_major_is_refused_even_with_a_minor_bump(tmp_path, rel):
    """Negative: x-draft cannot lift the additivity gate off a frozen schema, whatever the version."""
    import shutil

    shutil.copytree(ROOT / "schemas", tmp_path / "schemas")
    p = tmp_path / "schemas" / rel
    s = json.loads(p.read_text())
    _, major, minor = sc.parse_id(s)
    optional = next(k for k in s["properties"] if k not in s.get("required", []))
    s["properties"].pop(optional)  # a non-additive change
    _bump(s, f"{major}.{minor + 1}")
    s["x-draft"] = "ADR-0000 (proposed): a planted bypass"
    p.write_text(json.dumps(s))
    probs = sc.check_repo(tmp_path, ["platform"], strict=True, only=[rel])
    assert any("x-draft on a released major" in x.message for x in probs), probs
    # a new major may still be drafted: it has no frozen baseline of its own major
    _bump(s, f"{major + 1}.0")
    p.write_text(json.dumps(s))
    probs = sc.check_repo(tmp_path, ["platform"], strict=True, only=[rel])
    assert not any("x-draft on a released major" in x.message for x in probs), probs


def _copy_schemas(tmp_path):
    import shutil

    shutil.copytree(ROOT / "schemas", tmp_path / "schemas")
    return tmp_path / "schemas/platform"


def _rename(d, old, new):
    (d / f"{old}.schema.json").rename(d / f"{new}.schema.json")
    for kind in ("examples", "negative"):
        for f in list((d / kind).glob(f"{old}.*")):
            f.rename(d / kind / (new + f.name[len(old) :]))


def test_baselines_follow_the_id_not_the_file_name(tmp_path):
    """Negative: renaming capability.schema.json does not shed its frozen 1.0 baseline, so x-draft
    with a breaking change is still refused."""
    d = _copy_schemas(tmp_path)
    s = json.loads((d / "capability.schema.json").read_text())
    s["properties"].pop(next(k for k in s["properties"] if k not in s.get("required", [])))
    s["x-draft"] = "ADR-0000 (proposed): a planted rename"
    (d / "capability.schema.json").write_text(json.dumps(s))
    _rename(d, "capability", "capability_v2")
    probs = [x.message for x in sc.check_repo(tmp_path, strict=True)]
    assert any("draft schema has a frozen copy of its own version" in m for m in probs), probs
    assert any("x-draft on a released major" in m for m in probs), probs


def test_two_files_with_one_id_are_refused(tmp_path):
    """Negative: a second file carrying swap_record 1.1's $id would win $ref resolution."""
    d = _copy_schemas(tmp_path)
    (d / "zzswap_record.schema.json").write_text((d / "swap_record.schema.json").read_text())
    for kind in ("examples", "negative"):
        for f in (d / kind).glob("swap_record.*"):
            (d / kind / ("zz" + f.name)).write_text(f.read_text())
    probs = [x.message for x in sc.check_repo(tmp_path, strict=True)]
    assert any("/platform/swap_record/1.1 is also carried by" in m for m in probs), probs


def test_a_frozen_name_no_live_schema_carries_is_refused(tmp_path):
    """Negative: renaming a schema's $id orphans its frozen copies."""
    d = _copy_schemas(tmp_path)
    s = json.loads((d / "capability.schema.json").read_text())
    s["$id"] = s["$id"].replace("/platform/capability/", "/platform/capability-renamed/")
    (d / "capability.schema.json").write_text(json.dumps(s))
    probs = [x.message for x in sc.check_repo(tmp_path, strict=True)]
    assert any("frozen platform/capability is carried by no live schema" in m for m in probs)


def test_frozen_is_append_only_against_the_base(tmp_path):
    """Negative: with --base, deleting capability 1.0's only frozen copy (which lifts the gate for a
    draft) or editing a frozen file is refused; adding one is not."""
    import subprocess

    _copy_schemas(tmp_path)

    def git(*a):
        subprocess.run(["git", "-C", str(tmp_path), *a], check=True, capture_output=True)

    git("init", "-q")
    git("add", "schemas")
    git("-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-qm", "base")
    assert sc.frozen_lost(tmp_path, "HEAD") == []
    (tmp_path / "schemas/_frozen/1.0/platform/capability.schema.json").unlink()
    g = tmp_path / "schemas/_frozen/1.0/platform/guest.schema.json"
    g.write_text(g.read_text() + " ")
    (tmp_path / "schemas/_frozen/1.0/platform/new.schema.json").write_text("{}")
    probs = {p.where: p.message for p in sc.frozen_lost(tmp_path, "HEAD")}
    assert "removed" in probs["schemas/_frozen/1.0/platform/capability.schema.json"]
    assert "changed" in probs["schemas/_frozen/1.0/platform/guest.schema.json"]
    assert len(probs) == 2
    assert sc.main(["--root", str(tmp_path), "--base", "HEAD"]) == 1


def _git_repo(tmp_path):
    import subprocess

    def git(*a):
        return subprocess.run(
            [
                "git",
                "-C",
                str(tmp_path),
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@example.invalid",
                *a,
            ],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    git("init", "-q")
    return git


def test_ci_base_is_the_pr_base_or_the_push_tip_or_head_parent(tmp_path):
    """A pull request's unreadable base is an error, never a skip; a push whose previous tip is
    zero (a new branch) or gone (a force-push) falls back to HEAD^; a root commit has none."""
    git = _git_repo(tmp_path)
    (tmp_path / "a").write_text("1")
    git("add", "a")
    git("commit", "-qm", "one")
    one = git("rev-parse", "HEAD")
    assert sc.ci_base(tmp_path, "push", "", sc.ZERO_SHA) == (
        None,
        "none: a root commit (a new branch: the push's previous tip is zero)",
    )
    (tmp_path / "a").write_text("2")
    git("commit", "-qam", "two")
    assert sc.ci_base(tmp_path, "pull_request", one, "") == (one, "the pull request's base")
    for bad in ("", "f" * 40):
        with pytest.raises(ValueError, match="pull request's base"):
            sc.ci_base(tmp_path, "pull_request", bad, "")
    assert sc.ci_base(tmp_path, "push", "", one) == (one, "the push's previous tip")
    assert sc.ci_base(tmp_path, "push", "", sc.ZERO_SHA) == (
        one,
        "HEAD^ (a new branch: the push's previous tip is zero)",
    )
    assert sc.ci_base(tmp_path, "push", "", "f" * 40) == (
        one,
        f"HEAD^ (the push's previous tip {'f' * 40} is not fetchable (a force-push))",
    )
    for event in ("merge_group", "workflow_dispatch", "schedule", "pull_request_target", ""):
        with pytest.raises(ValueError, match="only push and pull_request have a base rule"):
            sc.ci_base(tmp_path, event, one, one)


def test_ci_base_refuses_a_shallow_push_with_no_parent(tmp_path):
    """Negative: in a depth-1 clone HEAD^ is missing because history was cut, not because HEAD is
    a root commit, so a push there is an error rather than a pass with no base."""
    import subprocess

    src = tmp_path / "src"
    src.mkdir()
    git = _git_repo(src)
    for n in ("1", "2"):
        (src / "a").write_text(n)
        git("add", "a")
        git("commit", "-qm", n)
    shallow = tmp_path / "shallow"
    subprocess.run(
        ["git", "clone", "-q", "--depth", "1", f"file://{src}", str(shallow)],
        check=True,
        capture_output=True,
    )
    with pytest.raises(ValueError, match="the checkout is shallow"):
        sc.ci_base(shallow, "push", "", sc.ZERO_SHA)


def test_ci_base_from_the_environment_prints_the_base_and_fails_a_bad_pr_base(
    tmp_path, monkeypatch, capsys
):
    import shutil

    shutil.copytree(ROOT / "schemas", tmp_path / "schemas")
    git = _git_repo(tmp_path)
    git("add", "schemas")
    git("commit", "-qm", "base")
    base = git("rev-parse", "HEAD")
    (tmp_path / "schemas/_frozen/1.0/platform/capability.schema.json").unlink()
    git("commit", "-qam", "drop capability's only frozen copy")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "push")
    monkeypatch.setenv("HNX_PUSH_BEFORE", sc.ZERO_SHA)  # a branch creation: HEAD^ instead
    assert sc.main(["--root", str(tmp_path), "--ci-base"]) == 1
    out = capsys.readouterr().out
    assert f"append-only _frozen/ base: {base} (HEAD^" in out
    assert "capability.schema.json: frozen at" in out and "removed" in out
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    monkeypatch.setenv("HNX_PR_BASE", "f" * 40)
    assert sc.main(["--root", str(tmp_path), "--ci-base"]) == 1
    assert "is not readable" in capsys.readouterr().err


def test_frozen_symlinks_and_byte_changes_are_refused(tmp_path):
    """Negative: a symlinked baseline is refused; a CRLF rewrite that a text filter would hide is
    still a change (hash-object --no-filters); a quoted (non-ASCII) frozen path is read exactly
    (ls-tree -z), so an untouched one is not reported."""
    import shutil

    shutil.copytree(ROOT / "schemas", tmp_path / "schemas")
    fz = tmp_path / "schemas/_frozen/1.0/platform"
    (fz / "capabilité.json").write_text("{}")
    (tmp_path / ".gitattributes").write_text("*.json text eol=crlf\n")
    git = _git_repo(tmp_path)
    git("add", ".")
    git("commit", "-qm", "base")
    assert sc.frozen_lost(tmp_path, "HEAD") == []
    g = fz / "guest.schema.json"
    g.write_bytes(g.read_bytes().replace(b"\n", b"\r\n"))
    c = fz / "capability.schema.json"
    c.unlink()
    c.symlink_to(tmp_path / "schemas/platform/capability.schema.json")
    probs = {p.where: p.message for p in sc.frozen_lost(tmp_path, "HEAD")}
    assert "changed" in probs["schemas/_frozen/1.0/platform/guest.schema.json"]
    assert "now a symlink" in probs["schemas/_frozen/1.0/platform/capability.schema.json"]
    assert len(probs) == 2
    probs = [p.message for p in sc.check_repo(tmp_path, strict=True)]
    assert "a frozen baseline is a symlink (copy the file)" in probs


def test_a_symlinked_frozen_root_is_refused(tmp_path):
    """Negative: schemas/_frozen itself as a symlink (to a copy that could be edited freely)."""
    import shutil

    shutil.copytree(ROOT / "schemas", tmp_path / "schemas")
    real = tmp_path / "elsewhere"
    (tmp_path / "schemas/_frozen").rename(real)
    (tmp_path / "schemas/_frozen").symlink_to(real)
    probs = [p.message for p in sc.check_repo(tmp_path, strict=True)]
    assert "schemas/_frozen is a symlink (it is a directory)" in probs


# ----- dependentSchemas, dependentRequired and a new anyOf/oneOf are judged, not waved through -----
def _mcp(version: str) -> dict:
    path = ROOT / "schemas" / "_frozen" / version / "platform" / "mcp_server.schema.json"
    return json.loads(path.read_text())


def test_mcp_server_1_1s_dependent_schemas_are_additive():
    """acts_via and direct_reason are new properties: their dependentSchemas can only constrain a
    document that carries them, which no 1.0 document did."""
    assert sc.is_additive(_mcp("1.0"), _mcp("1.1")) == []


@pytest.mark.parametrize(
    ("base", "mutate"),
    [
        # the review's repros: each one breaks documents the old schema accepted
        ("1.1", lambda s: s["dependentSchemas"].update(status={"required": ["acts_via"]})),
        ("1.0", lambda s: s.update(dependentSchemas={"tools": {"required": ["acts_via"]}})),
        ("1.0", lambda s: s.update(dependentRequired={"tools": ["acts_via"]})),
        ("1.0", lambda s: s.update(anyOf=[{"required": ["acts_via"]}])),
        ("1.0", lambda s: s.update(oneOf=[{"required": ["capabilities"]}])),
        ("1.1", lambda s: s["dependentSchemas"]["acts_via"].update(required=["capabilities"])),
    ],
)
def test_a_tightening_dependent_or_alternative_is_not_additive(base, mutate):
    old = _mcp(base)
    new = copy.deepcopy(old)
    mutate(new)
    assert sc.is_additive(old, new), new


def test_a_new_alternative_the_old_schema_implies_is_additive():
    """customization 1.2 moved review_by from required into anyOf [required review_by, ...]:
    every old document has review_by, so it meets the first branch."""
    old = {"type": "object", "properties": {"a": {"type": "string"}}, "required": ["a"]}
    new = {"type": "object", "properties": {"a": {"type": "string"}},
           "anyOf": [{"required": ["a"]}, {"required": ["b"]}]}  # fmt: skip
    assert sc.is_additive(old, new) == []
    new["anyOf"] = [{"required": ["b"]}]
    assert sc.is_additive(old, new)


# ----- VERIFY1: a new alternative is proven only from constraints the check really compares -----
_CLOSED = {"type": "object", "properties": {"a": {"type": "string"}, "b": {"type": "string"}},
           "required": ["a"], "additionalProperties": False,
           "$defs": {"strict": {"required": ["b"]}, "short": {"maxLength": 0}}}  # fmt: skip
_OPEN = {"type": "object", "properties": {"a": {"type": "string"}, "l": {"type": "array"}},
         "required": ["a"]}  # fmt: skip


@pytest.mark.parametrize(
    ("old", "change", "broken"),
    [
        # oneOf: {a, b} met both branches and now fails "exactly one"
        (_CLOSED, {"oneOf": [{"required": ["a"]}, {"required": ["b"]}]}, {"a": "x", "b": "y"}),
        # a $ref branch was never compared, so any definition passed as "implied"
        (_CLOSED, {"anyOf": [{"$ref": "#/$defs/strict"}]}, {"a": "x"}),
        # a property the old schema left open (additional properties allowed)
        (_OPEN, {"anyOf": [{"properties": {"z": {"type": "string"}}}]}, {"a": "x", "z": 1}),
        (_OPEN, {"anyOf": [{"additionalProperties": {"type": "integer"}}]}, {"a": "x", "q": "s"}),
        (
            _OPEN,
            {
                "properties": {
                    "a": {"type": "string"},
                    "l": {"type": "array", "anyOf": [{"items": {"type": "integer"}}]},
                }
            },
            {"a": "x", "l": ["s"]},
        ),
        (
            _OPEN,
            {
                "properties": {
                    "a": {"type": "string"},
                    "l": {"type": "array", "anyOf": [{"contains": {"type": "integer"}}]},
                }
            },
            {"a": "x", "l": ["s"]},
        ),
        # a new $ref, or a property widened into an anyOf of one
        (
            _CLOSED,
            {
                "properties": {
                    "a": {"type": "string", "$ref": "#/$defs/short"},
                    "b": {"type": "string"},
                }
            },
            {"a": "x"},
        ),
        # a dependentSchemas key a pattern property already admitted
        (
            {"type": "object", "patternProperties": {"^x-": {}}, "additionalProperties": False},
            {"dependentSchemas": {"x-new": {"required": ["zz"]}}},
            {"x-new": 1},
        ),
    ],
)
def test_a_new_alternative_that_breaks_documents_is_not_additive(old, change, broken):
    from jsonschema import Draft202012Validator as V

    new = {**copy.deepcopy(old), **copy.deepcopy(change)}
    assert V(old).is_valid(broken) and not V(new).is_valid(broken)  # the probe is a real break
    assert sc.is_additive(old, new), new


@pytest.mark.parametrize("key", ["dependentSchemas", "dependentRequired"])
def test_removing_a_dependent_entry_is_additive(key):
    """Removing one entry removes a constraint: every old document stays valid."""
    entry = {"b": {"required": ["a"]}, "a": {"required": ["a"]}} if key == "dependentSchemas" \
        else {"b": ["a"], "a": ["a"]}  # fmt: skip
    old = {**_CLOSED, key: entry}
    new = {**_CLOSED, key: {"a": entry["a"]}}
    assert sc.is_additive(old, new) == []
    assert sc.is_additive(_CLOSED, {**_CLOSED, "oneOf": [{"required": ["a"]}]}) == []
