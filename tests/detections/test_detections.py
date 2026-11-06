# SPDX-License-Identifier: Apache-2.0
import json
import os
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from homelabnext.detections import detmap, lint
from homelabnext.detections.adapters import (
    MissingEngineId,
    Target,
    UnsupportedConstruct,
    get_backend,
)
from homelabnext.detections.backends.wazuh import WazuhStubBackend
from homelabnext.detections.cli import main
from homelabnext.detections.fixtures import FixtureError, load_fixtures
from homelabnext.detections.runner import run_all
from homelabnext.detections.sigma import (
    RuleError,
    load_mapping,
    load_rule,
    load_rules,
    rule_matches,
)

REPO = Path(__file__).resolve().parents[2]
DET = REPO / "detections"
GOLDEN = Path(__file__).parent / "golden"
DATA = Path(__file__).parent / "data"
MAPPING = load_mapping(DET / "mappings" / "generic.yml")
STUB = WazuhStubBackend.name  # the XML stub backend


def golden(name: str, text: str):
    p = GOLDEN / name
    if os.environ.get("UPDATE_GOLDEN"):
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    assert p.read_text(encoding="utf-8") == text, (
        f"golden drift: {name} (UPDATE_GOLDEN=1 to refresh)"
    )


@pytest.fixture
def tree(tmp_path):
    shutil.copytree(DET, tmp_path / "d")
    return tmp_path / "d"


def rule_text(cond="sel", sel="    Image|endswith: '\\x.exe'"):
    return (
        "title: t\nlogsource: {category: process_creation}\nlevel: low\n"
        "tags: [attack.execution, attack.t1059]\n"
        f"detection:\n  sel:\n{sel}\n  condition: {cond}\n"
    )


# ---- shipped content
def test_eleven_rules_across_tactics():
    rules = load_rules(DET)
    assert len(rules) == 11
    assert len({r.path.parent.name for r in rules}) >= 7
    assert all(r.attack_techniques for r in rules)


def test_runner_all_green_and_evasions_reported():
    rep = run_all(DET)
    assert rep.ok
    text = rep.render()
    assert "EVADED" in text and "RESULT: ok" in text
    evaded = [r for rr in rep.rules for r in rr.evaded]
    assert len(evaded) == 12  # documented gaps; never failures


def test_repo_lint_clean_and_map_current():
    assert lint.lint_rules(DET) == []
    assert detmap.check_current(load_rules(DET), detmap.load(DET / "det_map.yml")) == []


# ---- runner semantics
def test_must_fire_miss_fails(tree):
    f = tree / "fixtures/new-service-creation/must_fire/sc-create.json"
    d = json.loads(f.read_text())
    d["event"]["process"]["command_line"] = "sc.exe query x"
    f.write_text(json.dumps(d))
    rep = run_all(tree)
    assert not rep.ok and "MISSED" in rep.render()


def test_must_not_fire_firing_fails(tree):
    src = tree / "fixtures/new-service-creation/must_fire/sc-create.json"
    dst = tree / "fixtures/new-service-creation/must_not_fire/oops.json"
    dst.write_text(src.read_text())
    rep = run_all(tree)
    assert not rep.ok and "FALSE-POSITIVE" in rep.render()


def test_evasion_that_fires_is_reported_caught_not_failure(tree):
    src = tree / "fixtures/new-service-creation/must_fire/sc-create.json"
    d = json.loads(src.read_text())
    d["note"] = "variant"
    (tree / "fixtures/new-service-creation/evasion/new-service-cmdlet.json").write_text(
        json.dumps(d)
    )
    rep = run_all(tree)
    assert rep.ok and "caught" in rep.render()


# ---- lint: rule without fixtures fails
def test_rule_without_fixtures_fails_lint(tree):
    shutil.rmtree(tree / "fixtures/web-shell-write")
    probs = lint.lint_rules(tree)
    assert any("det:web-shell-write" in p and "must_fire" in p for p in probs)
    assert main(["--root", str(tree), "lint"]) == 1


def test_rule_with_only_must_fire_fails_lint(tree):
    shutil.rmtree(tree / "fixtures/web-shell-write/must_not_fire")
    assert any("must_not_fire" in p for p in lint.lint_rules(tree))


def test_orphan_fixtures_and_bad_dir_flagged(tree):
    shutil.copytree(tree / "fixtures/web-shell-write", tree / "fixtures/ghost")
    assert any("orphan" in p for p in lint.lint_rules(tree))


def test_tactic_dir_must_match_tags(tree):
    shutil.move(
        tree / "sigma/impact/mass-file-rename-ransom-extension.yml",
        tree / "sigma/execution/mass-file-rename-ransom-extension.yml",
    )
    assert any("tactic" in p for p in lint.lint_rules(tree))


def test_missing_attack_tag_flagged(tree):
    p = tree / "sigma/impact/mass-file-rename-ransom-extension.yml"
    p.write_text(p.read_text().replace("attack.t1486", "custom"))
    assert any("ATT&CK technique" in x for x in lint.lint_rules(tree))


# ---- fixture schema negatives
@pytest.mark.parametrize(
    "mutate,msg",
    [
        (lambda d: d.update(schema="nope"), "schema"),
        (lambda d: d.pop("event"), "event"),
        (lambda d: d.update(event={}), "event"),
        (lambda d: d.update(extra=1), "unknown keys"),
        (lambda d: d.update(name=""), "name"),
    ],
)
def test_fixture_schema_rejects(tree, mutate, msg):
    f = tree / "fixtures/web-shell-write/must_fire/php-fpm-drops-php.json"
    d = json.loads(f.read_text())
    mutate(d)
    f.write_text(json.dumps(d))
    with pytest.raises(FixtureError, match=msg):
        load_fixtures(tree, "web-shell-write")


def test_evasion_needs_note(tree):
    f = tree / "fixtures/web-shell-write/evasion/double-extension.json"
    d = json.loads(f.read_text())
    del d["note"]
    f.write_text(json.dumps(d))
    with pytest.raises(FixtureError, match="note"):
        load_fixtures(tree, "web-shell-write")


def test_unknown_fixture_kind_rejected(tree):
    (tree / "fixtures/web-shell-write/maybe").mkdir()
    with pytest.raises(FixtureError, match="unknown fixture kind"):
        load_fixtures(tree, "web-shell-write")


# ---- Sigma-subset evaluator
def mk(tmp_path, cond="sel", sel="    Image|endswith: '\\x.exe'", name="r-one"):
    p = tmp_path / f"{name}.yml"
    p.write_text(rule_text(cond, sel))
    return load_rule(p)


def test_modifiers(tmp_path):
    ev = {"Image": "C:\\Tools\\X.EXE", "CommandLine": "run --Foo bar"}
    assert rule_matches(mk(tmp_path), ev)
    assert rule_matches(mk(tmp_path, sel="    CommandLine|contains: '--foo'"), ev)
    assert rule_matches(mk(tmp_path, sel="    CommandLine|startswith: 'run'"), ev)
    assert rule_matches(mk(tmp_path, sel="    CommandLine|re: 'Foo\\s+b.r'"), ev)
    assert not rule_matches(
        mk(tmp_path, sel="    CommandLine|re: 'foo'"), ev
    )  # re is case-sensitive
    assert rule_matches(mk(tmp_path, sel="    CommandLine|contains|all: ['run', 'bar']"), ev)
    assert not rule_matches(mk(tmp_path, sel="    CommandLine|contains|all: ['run', 'nope']"), ev)
    assert rule_matches(mk(tmp_path, sel="    Image: '*\\x.exe'"), ev)
    assert rule_matches(mk(tmp_path, sel="    Missing: null"), ev)
    assert not rule_matches(mk(tmp_path, sel="    Image: null"), ev)


def test_condition_logic(tmp_path):
    body = "  a:\n    k: 1\n  b:\n    k: 2\n  c:\n    z: 9\n"

    def rule(cond):
        p = tmp_path / "c.yml"
        p.write_text(
            "title: t\nlogsource: {category: x}\nlevel: low\ntags: [attack.execution]\n"
            f"detection:\n{body}  condition: {cond}\n"
        )
        return load_rule(p)

    assert rule_matches(rule("a or b"), {"k": 2})
    assert not rule_matches(rule("a and b"), {"k": 2})
    assert rule_matches(rule("a and not b"), {"k": 1})
    assert rule_matches(rule("not (a or b)"), {"k": 3})
    assert rule_matches(rule("1 of a*"), {"k": 1})
    assert rule_matches(rule("all of them"), {"k": 1, "z": 9}) is False  # a and b and c
    assert rule_matches(rule("any of them"), {"z": 9})


@pytest.mark.parametrize(
    "cond", ["sel | count() > 3", "sel and nope", "(sel", "sel sel", "1 of zzz*"]
)
def test_bad_conditions_rejected(tmp_path, cond):
    p = tmp_path / "bad.yml"
    p.write_text(rule_text(cond))
    with pytest.raises(RuleError):
        load_rule(p)


def test_unsupported_modifier_and_bad_slug_rejected(tmp_path):
    with pytest.raises(RuleError, match="modifier"):
        mk(tmp_path, sel="    CommandLine|base64offset|contains: x")
    with pytest.raises(RuleError, match="slug"):
        mk(tmp_path, name="Bad_Name")


def test_det_field_must_match_filename(tmp_path):
    p = tmp_path / "r-one.yml"
    p.write_text("det: det:other\n" + rule_text())
    with pytest.raises(RuleError, match="det"):
        load_rule(p)


# ---- backends: goldens
def target(name):
    return Target(
        name, MAPPING, detmap.load(DET / "det_map.yml")["entries"], {"if_group": "hnx_generic"}
    )


@pytest.mark.parametrize("slug", [r.slug for r in load_rules(DET)])
def test_generic_compile_golden(slug):
    rule = next(r for r in load_rules(DET) if r.slug == slug)
    art = get_backend("generic").compile(rule, target("generic"))
    golden(f"generic/{slug}.txt", art.content)


@pytest.mark.parametrize("slug", [r.slug for r in load_rules(DET)])
def test_wazuh_stub_golden_wellformed_and_keeps_logical_id(slug):
    rule = next(r for r in load_rules(DET) if r.slug == slug)
    art = get_backend(STUB).compile(rule, target(STUB))
    golden(f"{STUB}/{slug}.xml", art.content)
    root = ET.fromstring(art.content)
    assert root.tag == "rule" and root.get("id") == str(target(STUB).det_map[rule.det_id])
    assert f"<!-- {rule.det_id} -->" in art.content


def test_wazuh_bundle_wellformed_golden():
    be = WazuhStubBackend()
    arts = [be.compile(r, target("wazuh")) for r in load_rules(DET) if r.deployable]
    text = be.bundle(arts)
    golden("wazuh/_bundle.xml", text)
    root = ET.fromstring(text)
    assert len(root.findall("rule")) == 11  # every rule is deployable


#: the rules armed by the log pipeline's runtime label (docs/log-pipeline.md); inert before it
MODEL_RUNTIME = {
    "det:model-runtime-egress-drop",
    "det:model-runtime-object-store-lookup",
    "det:model-runtime-object-store-request",
}


def test_no_shipped_rule_is_inert():
    rules = load_rules(DET)
    assert [r.det_id for r in rules if not r.deployable] == []
    assert {r.det_id for r in rules} >= MODEL_RUNTIME


def test_inert_rules_are_tested_but_neither_counted_nor_bundled(tmp_path, capsys):
    root = tmp_path / "detections"
    shutil.copytree(DET, root)
    inert = set()
    for d in MODEL_RUNTIME:
        p = next(root.glob(f"sigma/*/{d.removeprefix('det:')}.yml"))
        p.write_text(p.read_text().replace("status: experimental", "status: unsupported"))
        inert.add(d)
    rules = load_rules(root)
    assert {r.det_id for r in rules if not r.deployable} == inert
    rep = run_all(root)
    assert {rr.det_id for rr in rep.rules} >= inert  # their fixtures still run
    from homelabnext.detections.coverage import coverage_report

    cov = coverage_report(rules, rep)
    counted = {d for t in cov["techniques"].values() for d in t["rules"]}
    assert not counted & inert
    assert {u["rule"] for u in cov["uncounted"]} == inert
    assert cov["summary"]["rules_counted"] == len(rules) - len(inert)
    assert main(["--root", str(root), "compile", "generic"]) == 0
    out = capsys.readouterr().out
    assert "-- det:cloud-metadata-refused" in out
    assert not any(f"-- {d}\n" in out for d in inert)


def test_a_rule_status_outside_sigmas_is_a_lint_problem(tmp_path):
    d = tmp_path / "detections"
    shutil.copytree(DET, d)
    p = d / "sigma/credential-access/cloud-metadata-refused.yml"
    p.write_text(p.read_text().replace("status: experimental", "status: maybe"))
    assert any("status 'maybe' is not one of" in x for x in lint.lint_rules(d))


def test_wazuh_rejects_inexpressible_and_missing_id(tmp_path):
    p = tmp_path / "or-rule.yml"
    p.write_text(
        "title: t\nlogsource: {category: x}\nlevel: low\ntags: [attack.execution]\n"
        "detection:\n  a:\n    k: 1\n  b:\n    k: 2\n  condition: a or b\n"
    )
    rule = load_rule(p)
    tgt = Target("wazuh", {}, {"det:or-rule": 900100})
    with pytest.raises(UnsupportedConstruct):
        get_backend("wazuh").compile(rule, tgt)
    with pytest.raises(MissingEngineId):
        get_backend("wazuh").compile(rule, Target("wazuh"))


def test_xml_escaping(tmp_path):
    p = tmp_path / "esc.yml"
    p.write_text(
        "title: 'a < b & c'\nlogsource: {category: x}\nlevel: low\ntags: [attack.execution]\n"
        "detection:\n  s:\n    k|contains: '<tag> & \"q\"'\n  condition: s\n"
    )
    art = get_backend("wazuh").compile(load_rule(p), Target("wazuh", {}, {"det:esc": 900200}))
    ET.fromstring(art.content)


# ---- det map
def test_detmap_stable_retire_never_reuse(tmp_path):
    rules = load_rules(DET)
    m1 = detmap.generate(rules)
    assert m1 == detmap.generate(rules, m1)  # idempotent
    fewer = [r for r in rules if r.slug != "web-shell-write"]
    m2 = detmap.generate(fewer, m1)
    gone = m1["entries"]["det:web-shell-write"]
    assert gone in m2["retired"] and "det:web-shell-write" not in m2["entries"]
    m3 = detmap.generate(rules, m2)  # rule comes back: gets a NEW number
    assert m3["entries"]["det:web-shell-write"] not in (gone, *m2["entries"].values())
    assert detmap.reverse(m1)[900001] == "det:cloud-api-key-new-asn"


def test_detmap_check_flags_stale(tree):
    shutil.move(tree / "sigma/impact/mass-file-rename-ransom-extension.yml", tree / "x.yml")
    probs = detmap.check_current(load_rules(tree), detmap.load(tree / "det_map.yml"))
    assert any("no rule exists" in p for p in probs)
    assert main(["--root", str(tree), "map", "--check"]) == 1


def test_map_cli_generates(tree):
    (tree / "det_map.yml").unlink()
    assert main(["--root", str(tree), "map"]) == 0
    assert main(["--root", str(tree), "map", "--check"]) == 0


# ---- rule-number lint
def test_lint_catches_planted_rule_number():
    probs = lint.lint_no_rule_numbers([DATA / "charters/triage-agent-charter.md"])
    assert len(probs) == 1 and "900299" in probs[0]


def test_lint_clean_charter_passes():
    assert lint.lint_no_rule_numbers([DATA / "charters/clean-agent-charter.md"]) == []


def test_lint_catches_bare_map_number_in_charter(tmp_path):
    f = tmp_path / "ops-charter.md"
    f.write_text("watch 900003 closely\n")
    m = detmap.load(DET / "det_map.yml")
    assert lint.lint_no_rule_numbers([f], m)
    assert not lint.lint_no_rule_numbers([f], None)


def test_find_agent_files_and_cli(tmp_path, capsys):
    shutil.copytree(DATA / "charters", tmp_path / "charters")
    files = lint.find_agent_files(tmp_path)
    assert len(files) == 2
    assert (
        main(["--root", str(DET), "lint-ids", str(tmp_path / "charters/triage-agent-charter.md")])
        == 1
    )
    assert (
        main(["--root", str(DET), "lint-ids", str(tmp_path / "charters/clean-agent-charter.md")])
        == 0
    )


def test_find_agent_files_skips_test_fixtures_and_build_output(tmp_path):
    for d in ("tests/data/charters", "build/charters", ".venv/charters", "charters"):
        shutil.copytree(DATA / "charters", tmp_path / d)
    files = lint.find_agent_files(tmp_path)
    assert sorted(f.relative_to(tmp_path).as_posix() for f in files) == [
        "charters/clean-agent-charter.md",
        "charters/triage-agent-charter.md",
    ]


def test_repository_agent_files_carry_no_engine_rule_numbers():
    # the `make detections` / CI gate: `lint-ids` with no paths scans the checkout
    repo = DET.parent
    files = lint.find_agent_files(repo)
    assert files, "no agent-facing files found"
    assert not any("tests" in f.relative_to(repo).parts for f in files)
    assert lint.lint_no_rule_numbers(files, detmap.load(DET / "det_map.yml")) == []


def test_det_map_itself_only_place_for_numbers():
    # the shipped example charters/rules contain no engine numbers
    files = list((DET / "sigma").rglob("*.yml"))
    assert lint.lint_no_rule_numbers(files, detmap.load(DET / "det_map.yml")) == []


def test_cli_run_and_compile(capsys):
    assert main(["--root", str(DET), "run"]) == 0
    assert main(["--root", str(DET), "compile", "generic"]) == 0
    assert "WHERE" in capsys.readouterr().out


# ---- det map --check judges the numbers, not only the key sets
def _stored_map():
    return detmap.load(DET / "det_map.yml")


def test_detmap_check_flags_a_duplicated_engine_number():
    m = _stored_map()
    m["entries"]["det:web-shell-write"] = m["entries"]["det:cloud-api-key-new-asn"]
    probs = detmap.check_current(load_rules(DET), m)
    assert any("is assigned to det:cloud-api-key-new-asn, det:web-shell-write" in p for p in probs)


def test_detmap_check_flags_a_reused_retired_number():
    m = _stored_map()
    m["retired"] = [m["entries"]["det:web-shell-write"]]
    probs = detmap.check_current(load_rules(DET), m)
    assert any("det:web-shell-write: engine number" in p and "retired" in p for p in probs)


def test_detmap_check_flags_a_non_integer_and_a_map_regeneration_would_change(tmp_path):
    m = _stored_map()
    m["entries"]["det:web-shell-write"] = "900006"
    assert any("not an integer" in p for p in detmap.check_current(load_rules(DET), m))
    m = _stored_map()
    m["retired"] = [900099, 900098]  # unsorted: not what `map` writes
    assert any("regenerate" in p for p in detmap.check_current(load_rules(DET), m))
    assert detmap.check_current(load_rules(DET), _stored_map()) == []


def test_map_check_cli_fails_on_a_hand_edited_duplicate(tree):
    p = tree / "det_map.yml"
    p.write_text(
        p.read_text().replace("det:web-shell-write: 900006", "det:web-shell-write: 900001")
    )
    assert main(["--root", str(tree), "map", "--check"]) == 1


# ---- compile: per-backend field mapping; an inexpressible rule never aborts the bundle
def test_compile_uses_the_backends_own_mapping_when_it_has_one(tree, capsys):
    assert main(["--root", str(tree), "compile", STUB]) == 0
    captured = capsys.readouterr()
    assert f"no mappings/{STUB}.yml" in captured.err
    assert 'name="process.executable"' in captured.out
    (tree / "mappings" / f"{STUB}.yml").write_text("fields:\n  Image: win.eventdata.image\n")
    assert main(["--root", str(tree), "compile", STUB]) == 0
    captured = capsys.readouterr()
    assert 'name="win.eventdata.image"' in captured.out
    assert 'name="process.executable"' not in captured.out
    assert "warning" not in captured.err


def test_compile_leaves_out_an_inexpressible_rule_and_writes_the_rest(tree, capsys):
    (tree / "sigma/execution/or-rule.yml").write_text(
        "title: t\nlogsource: {category: x}\nlevel: low\n"
        "tags: [attack.execution, attack.t1059]\n"
        "detection:\n  a:\n    k: 1\n  b:\n    k: 2\n  condition: a or b\n"
    )
    for kind, k in (("must_fire", 1), ("must_not_fire", 3)):
        f = tree / f"fixtures/or-rule/{kind}/a.json"
        f.parent.mkdir(parents=True)
        f.write_text(json.dumps({"k": k}))
    assert main(["--root", str(tree), "map"]) == 0
    capsys.readouterr()
    assert main(["--root", str(tree), "compile", STUB]) == 1
    captured = capsys.readouterr()
    assert f"det:or-rule: not expressible in {STUB}" in captured.err
    ET.fromstring(captured.out)  # the bundle is still written, well-formed
    assert "<!-- det:web-shell-write -->" in captured.out
    assert "<!-- det:or-rule -->" not in captured.out


# ---- ATT&CK tags: a fixed tactic vocabulary
def test_only_vocabulary_tactics_count_and_other_attack_tags_are_lint_problems(tmp_path):
    root = tmp_path / "d"
    shutil.copytree(DET, root)
    p = root / "sigma/persistence/ssh-authorized-key-added.yml"
    text = p.read_text()
    p.write_text(
        text.replace(
            "tags: [attack.persistence",
            "tags: [attack.persistance, attack.g0016, attack.s0002, attack.T1059, attack.persistence",
        )
    )
    rule = next(r for r in load_rules(root) if r.slug == "ssh-authorized-key-added")
    assert rule.attack_tactics == ["persistence"]
    assert "T1059" not in rule.attack_techniques
    probs = [x for x in lint.lint_rules(root) if x.startswith("det:ssh-authorized-key-added")]
    assert any("'attack.persistance' is not a tactic" in x for x in probs)
    assert any("'attack.T1059' must be lower-case" in x for x in probs)
    assert not any("g0016" in x or "s0002" in x for x in probs)


def test_a_misspelt_tactic_directory_fails_lint(tmp_path):
    root = tmp_path / "d"
    shutil.copytree(DET, root)
    (root / "sigma/persistance").mkdir()
    src = root / "sigma/persistence/ssh-authorized-key-added.yml"
    dst = root / "sigma/persistance/ssh-authorized-key-added.yml"
    dst.write_text(src.read_text().replace("attack.persistence", "attack.persistance"))
    src.unlink()
    probs = lint.lint_rules(root)
    assert any("directory 'persistance' is not one of its tactic tags" in x for x in probs)


# ---- a rule file no gate would load is a lint problem
@pytest.mark.parametrize("rel", ["stray.yml", "execution/rule.yaml", "execution/nested/rule.yml"])
def test_a_rule_file_outside_the_layout_fails_lint(tree, rel):
    f = tree / "sigma" / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text("title: t\n")
    assert any(
        x.startswith(f"sigma/{rel}: not sigma/<tactic>/<slug>.yml") for x in lint.lint_rules(tree)
    )


def test_the_shipped_tree_has_no_stray_rule_files():
    assert not [x for x in lint.lint_rules(DET) if "not sigma/<tactic>" in x]


# ---- lint-ids: dates are not rule numbers; det: ids must resolve
def test_a_date_after_the_word_rule_is_not_an_engine_number(tmp_path):
    f = tmp_path / "x-charter.md"
    f.write_text("This rule was revised on 2026-10-15 and again on 2026/10/20.\n")
    assert lint.lint_no_rule_numbers([f]) == []
    f.write_text("This rule 900299 was revised on 2026-10-15.\n")
    assert len(lint.lint_no_rule_numbers([f])) == 1


def test_lint_ids_fails_on_a_det_id_the_map_lacks(tmp_path, capsys):
    f = tmp_path / "x-charter.md"
    f.write_text("Watch det:web-shell-write and det:no-such-detection.\n")
    assert main(["--root", str(DET), "lint-ids", str(f)]) == 1
    out = capsys.readouterr().out
    assert "det:no-such-detection is not in" in out and "web-shell-write" not in out


def test_decision_specs_are_agent_facing_files(tmp_path):
    for rel in (
        "workflows/decisions/page.yml",
        "homelabnext/decide/examples/decision_spec.yml",
    ):
        f = tmp_path / rel
        f.parent.mkdir(parents=True)
        f.write_text("when: rule 900300 fires\n")
    found = {p.relative_to(tmp_path).as_posix() for p in lint.find_agent_files(tmp_path)}
    assert found == {
        "workflows/decisions/page.yml",
        "homelabnext/decide/examples/decision_spec.yml",
    }
    assert len(lint.lint_agent_ids(lint.find_agent_files(tmp_path))) == 2


# ---- workflow packs are agent-facing: an undefined det: id in one fails lint-ids ----


def test_workflow_packs_are_agent_facing_and_undefined_det_ids_fail(tmp_path, monkeypatch, capsys):
    pack = tmp_path / "workflows/packs/p.yml"
    pack.parent.mkdir(parents=True)
    pack.write_text("trigger: {where: [{ref: $event.data.detection, equals: det:no-such-det}]}\n")
    assert pack in lint.find_agent_files(tmp_path)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "detections").mkdir()
    (tmp_path / "detections/det_map.yml").write_text((REPO / "detections/det_map.yml").read_text())
    assert main(["--root", "detections", "lint-ids"]) == 1
    assert "det:no-such-det" in capsys.readouterr().out


def test_shipped_workflow_packs_cite_only_defined_det_ids():
    import yaml

    repo = REPO
    det_map = yaml.safe_load((repo / "detections/det_map.yml").read_text())
    packs = sorted((repo / "workflows/packs").glob("*.yml"))
    assert packs and set(packs) <= set(lint.find_agent_files(repo))
    assert lint.lint_agent_ids(packs, det_map) == []
