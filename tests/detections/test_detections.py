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
    art = get_backend("wazuh").compile(rule, target("wazuh"))
    golden(f"wazuh/{slug}.xml", art.content)
    root = ET.fromstring(art.content)
    assert root.tag == "rule" and root.get("id") == str(target("wazuh").det_map[rule.det_id])
    assert f"<!-- {rule.det_id} -->" in art.content


def test_wazuh_bundle_wellformed_golden():
    be = WazuhStubBackend()
    arts = [be.compile(r, target("wazuh")) for r in load_rules(DET)]
    text = be.bundle(arts)
    golden("wazuh/_bundle.xml", text)
    root = ET.fromstring(text)
    assert len(root.findall("rule")) == 11


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
