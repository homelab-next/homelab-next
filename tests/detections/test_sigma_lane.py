# SPDX-License-Identifier: Apache-2.0
"""The Sigma lane on the engine (docs/detections.md, "The Sigma lane on the engine").

* Logsource bindings (``mappings/<backend>.yml`` ``logsources:``): a rule chains from its
  logsource's engine base and reads only the binding's field names; a rule no binding names, a
  field the binding does not name, a multi-valued parent and a second raw-line condition are
  refused, never passed through.
* A raw-line field compiles to one ``<regex type="pcre2">`` whose pattern matches the raw line.
* ``hnx_source: awaiting-source``: tested and compiled, never in the bundle, never coverage.
* ``compile --out`` writes the bundle; ``map --base`` starts a new map's numbers.
* Engine fixtures: raw lines through the engine's tester, the expected rule from the det map; a
  deployed rule with none fails; a fixture naming its own rule number is refused.
"""

from __future__ import annotations

import json
import re
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
import yaml

from homelabnext.detections import detmap, engine, lint
from homelabnext.detections.adapters import (
    Binding,
    BindingError,
    Target,
    UnsupportedConstruct,
    get_backend,
    load_bindings,
    select_binding,
)
from homelabnext.detections.cli import main
from homelabnext.detections.coverage import report_for
from homelabnext.detections.runner import compiled_backends, run_all, run_compiled
from homelabnext.detections.sigma import load_rule, load_rules

DET = Path(__file__).resolve().parents[2] / "detections"
(XML,) = compiled_backends()  # the XML backend, named by the registry
BE = get_backend(XML)

HTTP = {
    "name": "sensor-http",
    "match": {"product": "sensor", "service": "http"},
    "parent": {"if_sid": 900380},
    "fields": {"c-uri": "uri", "DestinationIp": 'raw:"id\\.resp_h":"{}"'},
}
CONN = {
    "name": "sensor-conn",
    "match": {"product": "sensor", "service": "conn"},
    "parent": {"if_sid": 900388},
    "fields": {"DestinationIp": 'raw:"id\\.resp_h":"{}"', "DestinationPort": "dstport"},
}
SENSOR = {"name": "sensor-any", "match": {"product": "sensor"}, "parent": {"if_group": "sensor"},
          "fields": {"c-uri": "uri"}}  # fmt: skip
# addresses built from parts (no address literal in the tree; the endpoint lint reads them)
IP_A, IP_B, IP_C = (".".join(p) for p in (["203", "0", "113", "9"], ["198", "51", "100", "7"],
                                          ["203", "0", "113", "90"]))  # fmt: skip
SRC = ".".join(["192", "0", "2", "5"])
RAW_LINE = (
    f'{{"ts":1795220646.57,"uid":"Cq","id.orig_h":"{SRC}","id.orig_p":45130,'
    f'"id.resp_h":"{IP_A}","id.resp_p":80,"method":"GET","uri":"/api/checkStatus",'
    '"status_code":200}'
)


def rule_file(tmp_path: Path, slug: str, logsource: str, detection: str, **extra) -> Path:
    p = tmp_path / f"{slug}.yml"
    head = "".join(f"{k}: {v}\n" for k, v in extra.items())
    p.write_text(
        f"title: t {slug}\nlogsource: {logsource}\nlevel: high\n"
        f"tags: [attack.command_and_control, attack.t1071.001]\n{head}detection:\n{detection}",
        encoding="utf-8",
    )
    return p


def target(*bindings: dict, det: str = "det:r") -> Target:
    return Target(XML, {}, {det: 900501}, logsources=load_bindings({"logsources": list(bindings)}))


# ---------------------------------------------------------------- bindings
def test_a_bound_rule_chains_from_its_base_and_reads_the_bindings_field_names(tmp_path):
    p = rule_file(tmp_path, "r", "{product: sensor, service: http}",
                  "  sel:\n    c-uri|startswith: ['/api/checkStatus', '/cldbs']\n  condition: sel\n")  # fmt: skip
    art = BE.compile(load_rule(p), target(HTTP, CONN))
    rule = ET.fromstring(art.content)
    assert rule.get("id") == "900501" and rule.get("level") == "12"
    assert rule.findtext("if_sid") == "900380"
    assert rule.find("if_group") is None
    (f,) = rule.findall("field")
    assert f.get("name") == "uri" and f.get("type") == "pcre2"
    assert re.search(f.text, "/api/checkStatus?x=1") and not re.search(f.text, "/index.html")


def test_a_raw_line_field_is_one_pcre2_regex_on_the_line(tmp_path):
    p = rule_file(tmp_path, "r", "{product: sensor, service: conn}",
                  f"  sel:\n    DestinationIp: ['{IP_A}', '{IP_B}']\n  condition: sel\n")  # fmt: skip
    rule = ET.fromstring(BE.compile(load_rule(p), target(CONN)).content)
    (rx,) = rule.findall("regex")
    assert rx.get("type") == "pcre2" and rx.get("negate") is None
    assert rule.findtext("if_sid") == "900388"
    assert re.search(rx.text, RAW_LINE)
    assert not re.search(rx.text, RAW_LINE.replace(IP_A, IP_C))
    assert not re.search(rx.text, RAW_LINE.replace(f'"id.resp_h":"{IP_A}"', '"id.orig_h":"x"'))
    # a raw condition is the engine's to prove: the compiled-form evaluator refuses it
    with pytest.raises(UnsupportedConstruct):
        BE.evaluate(BE.compile(load_rule(p), target(CONN)), {"destination": {"ip": "x"}})


def test_the_most_specific_binding_wins():
    bs = load_bindings({"logsources": [SENSOR, HTTP]})
    assert select_binding(bs, {"product": "Sensor", "service": "http"}).name == "sensor-http"
    assert select_binding(bs, {"product": "sensor", "service": "dns"}).name == "sensor-any"
    assert select_binding(bs, {"product": "other"}) is None


@pytest.mark.parametrize(
    "logsource,detection,why",
    [
        ("{product: other}", "  s:\n    c-uri: /x\n  condition: s\n", "no engine binding"),
        ("{product: sensor, service: http}", "  s:\n    Image: /x\n  condition: s\n",
         "has no engine name"),
        ("{product: sensor, service: conn}",
         f"  s:\n    DestinationIp: {IP_A}\n  f:\n    DestinationIp: {IP_B}\n"
         "  condition: s and not f\n", "more than one raw-line"),
        ("{product: sensor, service: conn}", "  s:\n    DestinationIp|re: '^203'\n  condition: s\n",
         "raw-line field takes"),
        ("{product: sensor, service: conn}", "  s:\n    DestinationIp: 'a\"b'\n  condition: s\n",
         "quote or a backslash"),
    ],
)  # fmt: skip
def test_what_the_binding_cannot_carry_is_refused(tmp_path, logsource, detection, why):
    rule = load_rule(rule_file(tmp_path, "r", logsource, detection))
    with pytest.raises(UnsupportedConstruct, match=why):
        BE.compile(rule, target(HTTP, CONN))


@pytest.mark.parametrize("parent", [{"if_sid": "900380, 900388"}, {"if_group": "a b"},
                                    {"if_matched_sid": 1}])  # fmt: skip
def test_a_parent_must_be_one_base(tmp_path, parent):
    rule = load_rule(rule_file(tmp_path, "r", "{product: sensor, service: http}",
                               "  s:\n    c-uri: /x\n  condition: s\n"))  # fmt: skip
    with pytest.raises(UnsupportedConstruct, match="parent must be one"):
        BE.compile(rule, target({**HTTP, "parent": parent}))


@pytest.mark.parametrize(
    "bad",
    [
        {"match": {"product": "x"}, "parent": {"if_sid": 1}, "fields": {"a": "b"}},
        {**HTTP, "match": {}},
        {**HTTP, "match": {"vendor": "x"}},
        {**HTTP, "parent": {"if_sid": 1, "if_group": "g"}},
        {**HTTP, "fields": {}},
        {**HTTP, "extra": 1},
    ],
)
def test_a_malformed_binding_is_refused(bad):
    with pytest.raises(BindingError):
        load_bindings({"logsources": [bad]})
    with pytest.raises(BindingError, match="unique"):
        load_bindings({"logsources": [HTTP, HTTP]})


def test_without_bindings_the_compiled_form_is_unchanged(tmp_path):
    rule = load_rule(
        rule_file(tmp_path, "r", "{product: other}", "  s:\n    c-uri: /x\n  condition: s\n")
    )
    art = BE.compile(rule, Target(XML, {"c-uri": "url.original"}, {"det:r": 1}))
    assert ET.fromstring(art.content).findtext("if_group") == "hnx_generic"
    assert isinstance(Binding("n", {}, {}, {}), Binding)


# ------------------------------------------------------- a detections tree
@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "detections"
    shutil.copytree(DET, root)
    (root / "mappings" / f"{XML}.yml").write_text(
        yaml.safe_dump({"fields": {}, "logsources": [HTTP, CONN]}), encoding="utf-8"
    )
    return root


def plant(root: Path, slug: str, logsource: str, sel: str, fixtures: dict, **extra) -> None:
    d = root / "sigma" / "command-and-control"
    d.mkdir(parents=True, exist_ok=True)
    rule_file(d, slug, logsource, f"  sel:\n{sel}  condition: sel\n", **extra)
    for name, event in fixtures.items():
        kind, stem = name.split("/")
        fd = root / "fixtures" / slug / kind
        fd.mkdir(parents=True, exist_ok=True)
        fd.joinpath(f"{stem}.json").write_text(json.dumps({
            "schema": "homelabnext.detections.fixture/v1", "name": stem,
            "description": "planted", "event": event}), encoding="utf-8")  # fmt: skip


def http_rule(root: Path, slug: str = "c2-path", **extra) -> None:
    plant(root, slug, "{product: sensor, service: http}", "    c-uri|startswith: /api/checkStatus\n",
          {"must_fire/hit": {"url": {"original": "/api/checkStatus"}},
           "must_not_fire/miss": {"url": {"original": "/index.html"}}}, **extra)  # fmt: skip


def test_compile_out_writes_only_the_bound_rules_and_names_the_rest(tree, capsys):
    http_rule(tree)
    assert main(["--root", str(tree), "map"]) == 0
    capsys.readouterr()
    out = tree.parent / "bundle.xml"
    # the example rules have no binding in this target: each is named and left out
    assert main(["--root", str(tree), "compile", XML, "--out", str(out)]) == 1
    err = capsys.readouterr().err
    assert "det:web-shell-write: not expressible" in err and "no engine binding" in err
    bundle = ET.fromstring(out.read_text())
    assert "<!-- det:c2-path -->" in out.read_text()
    assert bundle.find("rule/if_sid").text == "900380"
    assert not out.with_name("bundle.xml.tmp").exists()


def test_a_rule_awaiting_its_source_is_tested_compiled_and_never_shipped_or_counted(tree, capsys):
    for p in (tree / "sigma").glob("*/*.yml"):  # only the planted rules in this tree
        shutil.rmtree(tree / "fixtures" / p.stem)
        p.unlink()
    http_rule(tree)
    http_rule(tree, "c2-path-later", hnx_source="awaiting-source")
    (tree / "det_map.yml").unlink()
    assert main(["--root", str(tree), "map", "--base", "900501"]) == 0
    assert sorted(detmap.load(tree / "det_map.yml")["entries"].values()) == [900501, 900502]
    capsys.readouterr()
    assert main(["--root", str(tree), "compile", XML]) == 0
    cap = capsys.readouterr()
    assert "<!-- det:c2-path -->" in cap.out and "c2-path-later" not in cap.out
    assert "awaiting source, compiled and left out: det:c2-path-later" in cap.err
    rules = {r.slug: r for r in load_rules(tree)}
    assert rules["c2-path-later"].awaiting_source and not rules["c2-path-later"].deployable
    b = run_compiled(tree, XML, run_all(tree))
    assert "det:c2-path-later" in [rr.det_id for rr in b.report.rules]  # tested compiled too
    rep = report_for(tree)
    assert {"rule": "det:c2-path-later",
            "reason": "awaiting-source: its telemetry is not collected yet, so not coverage"} in rep["uncounted"]  # fmt: skip
    assert "det:c2-path" in rep["techniques"]["T1071.001"]["rules"]


def test_an_unknown_source_marker_is_a_lint_problem(tree):
    http_rule(tree, hnx_source="soon")
    assert any("hnx_source 'soon' is not one of" in p for p in lint.lint_rules(tree))


def test_an_awaiting_rule_the_engine_cannot_take_fails_compile_now(tree, capsys):
    plant(tree, "later", "{product: endpoint, category: process_creation}",
          "    c-uri: /x\n", {"must_fire/a": {"url": {"original": "/x"}},
                              "must_not_fire/b": {"url": {"original": "/y"}}},
          hnx_source="awaiting-source")  # fmt: skip
    assert main(["--root", str(tree), "map"]) == 0
    capsys.readouterr()
    assert main(["--root", str(tree), "compile", XML]) == 1
    assert "det:later: not expressible" in capsys.readouterr().err


def test_map_base_starts_a_new_map_and_an_existing_map_continues(tree):
    (tree / "det_map.yml").unlink()
    assert main(["--root", str(tree), "map", "--base", "900501"]) == 0
    first = detmap.load(tree / "det_map.yml")["entries"]
    assert min(first.values()) == 900501
    http_rule(tree)
    assert main(["--root", str(tree), "map", "--base", "5"]) == 0
    again = detmap.load(tree / "det_map.yml")["entries"]
    assert {k: again[k] for k in first} == first and again["det:c2-path"] == max(first.values()) + 1


# --------------------------------------------------------- engine fixtures
def engine_fixture(root: Path, slug: str, kind: str, name: str, line: str, **extra) -> None:
    d = root / engine.DIR / slug / kind
    d.mkdir(parents=True, exist_ok=True)
    doc = {"event": line, "location": "/var/log/sensor/http.log", "format": "json",
           "provenance": "a captured line, the uri replaced", **extra}  # fmt: skip
    d.joinpath(f"{name}.json").write_text(json.dumps(doc), encoding="utf-8")


class FakeTester:
    """The engine's rule tester, faked: it answers the number it was told for a line."""

    def __init__(self, answers: dict[str, int | None]):
        self.answers, self.seen = answers, []

    def __call__(self, fx):
        self.seen.append((fx.location, fx.format))
        return self.answers.get(fx.event)


def engine_tree(tree: Path) -> tuple[list, dict[str, int]]:
    for p in (tree / "sigma").glob("*/*.yml"):
        shutil.rmtree(tree / "fixtures" / p.stem)
        p.unlink()
    http_rule(tree)
    http_rule(tree, "c2-path-later", hnx_source="awaiting-source")
    assert main(["--root", str(tree), "map"]) == 0
    return load_rules(tree), detmap.load(tree / "det_map.yml")["entries"]


def test_engine_fixtures_pass_when_the_engine_answers_the_rules_own_number(tree):
    rules, m = engine_tree(tree)
    engine_fixture(tree, "c2-path", "must_fire", "hit", RAW_LINE)
    engine_fixture(tree, "c2-path", "must_not_fire", "miss", RAW_LINE.replace("checkStatus", "ok"))
    t = FakeTester({RAW_LINE: m["det:c2-path"], RAW_LINE.replace("checkStatus", "ok"): 900380})
    problems, ran = engine.run_engine(tree, rules, m, t)
    assert (problems, ran) == ([], 2)  # the awaiting rule needs no engine fixture yet
    assert t.seen == [("/var/log/sensor/http.log", "json")] * 2
    assert lint.lint_rules(tree) == []


def test_a_miss_a_false_positive_and_a_rule_never_seen_on_the_engine_fail(tree):
    rules, m = engine_tree(tree)
    problems, ran = engine.run_engine(tree, rules, m, FakeTester({}))
    assert ran == 0
    assert problems == [
        "det:c2-path: no must_fire engine fixture (a deployed rule is proved on the engine)",
        "det:c2-path: no must_not_fire engine fixture (a deployed rule is proved on the engine)",
    ]
    engine_fixture(tree, "c2-path", "must_fire", "hit", RAW_LINE)
    engine_fixture(tree, "c2-path", "must_not_fire", "miss", "other line")
    problems, _ = engine.run_engine(
        tree, rules, m, FakeTester({RAW_LINE: 900380, "other line": m["det:c2-path"]})
    )
    assert problems == [
        "det:c2-path must_fire/hit.json: expected the rule's own number, the engine matched 900380",
        "det:c2-path must_not_fire/miss.json: the rule fired and must not",
    ]


@pytest.mark.parametrize(
    "extra,why",
    [({"rule_id": 1}, "from the det map"), ({"provenance": ""}, "provenance")],
)
def test_a_fixture_naming_its_own_number_or_no_provenance_is_refused(tree, extra, why):
    rules, m = engine_tree(tree)
    engine_fixture(tree, "c2-path", "must_fire", "hit", RAW_LINE, **extra)
    with pytest.raises(ValueError, match=why):
        engine.run_engine(tree, rules, m, FakeTester({}))
    assert any(why in p for p in lint.lint_rules(tree))


def test_orphan_engine_fixtures_and_unknown_kinds_are_lint_problems(tree):
    engine_tree(tree)
    engine_fixture(tree, "gone", "must_fire", "a", RAW_LINE)
    engine_fixture(tree, "c2-path", "evasion", "a", RAW_LINE)
    probs = lint.lint_rules(tree)
    assert "engine_fixtures/gone: orphan engine fixtures, no rule det:gone" in probs
    assert any("engine_fixtures/c2-path/evasion: unknown kind" in p for p in probs)


def test_run_engine_needs_the_manager_and_its_credential(tree, monkeypatch, capsys):
    monkeypatch.delenv("HNX_MANAGER_API_PASSWORD", raising=False)
    assert main(["--root", str(tree), "run", "--engine"]) == 2
    assert "needs --manager-url" in capsys.readouterr().err
