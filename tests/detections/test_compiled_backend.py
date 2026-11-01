# SPDX-License-Identifier: Apache-2.0
"""The fixtures run through the compiled engine artefact, not only the reference evaluator: the
compiled patterns are valid, every shipped rule fires there where it fires in the evaluator, and a
compiled form that differs fails `run` and is uncounted for that backend in the coverage report."""

from __future__ import annotations

import json
import re
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from homelabnext.detections import detmap
from homelabnext.detections.adapters import Target, get_backend
from homelabnext.detections.cli import main
from homelabnext.detections.coverage import report_for
from homelabnext.detections.runner import compiled_backends, run_all, run_compiled
from homelabnext.detections.sigma import load_mapping, load_rules

DET = Path(__file__).resolve().parents[2] / "detections"


@pytest.fixture
def det(tmp_path):
    shutil.copytree(DET, tmp_path / "detections")
    return tmp_path / "detections"


def plant(root: Path, slug: str, detection: str, fixtures: dict[str, dict]) -> None:
    (root / "sigma" / "execution" / f"{slug}.yml").write_text(
        f"title: planted\nlogsource: {{category: process_creation}}\nlevel: low\n"
        f"tags: [attack.execution, attack.t1059]\ndetection:\n{detection}",
        encoding="utf-8",
    )
    for name, event in fixtures.items():
        kind, stem = name.split("/")
        d = root / "fixtures" / slug / kind
        d.mkdir(parents=True, exist_ok=True)
        doc = {
            "schema": "homelabnext.detections.fixture/v1",
            "spdx": "Apache-2.0",
            "name": stem,
            "description": "planted",
            "event": event,
        }
        (d / f"{stem}.json").write_text(json.dumps(doc), encoding="utf-8")


def test_the_wazuh_stub_is_a_compiled_backend():
    assert "wazuh" in compiled_backends()


@pytest.mark.parametrize("rule", load_rules(DET), ids=lambda r: r.slug)
def test_every_compiled_pattern_is_a_valid_regular_expression(rule):
    mapping = load_mapping(DET / "mappings" / "generic.yml")
    tgt = Target("wazuh", mapping, detmap.load(DET / "det_map.yml")["entries"])
    art = get_backend("wazuh").compile(rule, tgt)
    for f in ET.fromstring(art.content).findall("field"):
        re.compile(f.text or "")  # a bare (?i) inside an alternation is refused here


def test_every_shipped_rule_fires_compiled_where_it_fires_in_the_evaluator():
    b = run_compiled(DET, "wazuh", run_all(DET))
    assert b.ok, b.divergent
    assert b.not_expressible == {}
    assert b.report.ok
    assert len(b.report.rules) == len([r for r in load_rules(DET) if r.deployable])


def test_case_is_ignored_inside_each_alternative():
    rule = next(r for r in load_rules(DET) if r.slug == "cloud-api-key-new-asn")
    engine_art = get_backend("wazuh").compile(
        rule, Target("wazuh", load_mapping(DET / "mappings/generic.yml"), {rule.det_id: 0})
    )
    event = {
        "cloud": {
            "credential": {"type": "ACCESS_KEY", "first_seen_asn": True},
            "api": {"action": "getObject"},
        }
    }
    assert get_backend("wazuh").evaluate(engine_art, event) is False  # filtered, any case
    event["cloud"]["api"]["action"] = "PutObject"
    assert get_backend("wazuh").evaluate(engine_art, event) is True


def test_a_compiled_form_that_does_not_fire_fails_run_and_is_uncounted(det, capsys):
    # the evaluator reads a missing filter field as "not filtered"; the engine skips a rule whose
    # negated field is missing, so the compiled form stays silent on this must_fire
    plant(
        det,
        "planted-negation",
        "  sel:\n    Image|endswith: '/x'\n  filter:\n    CommandLine|contains: safe\n"
        "  condition: sel and not filter\n",
        {
            "must_fire/no-command-line": {"process": {"executable": "/bin/x"}},
            "must_not_fire/other": {"process": {"executable": "/bin/y"}},
        },
    )
    ref = run_all(det)
    assert ref.ok
    b = run_compiled(det, "wazuh", ref)
    assert not b.ok
    assert b.divergent == [
        "det:planted-negation must_fire/no-command-line.json: fires in the reference "
        "evaluator, silent compiled"
    ]
    assert main(["--root", str(det), "run"]) == 1
    assert "[DIVERGES] det:planted-negation" in capsys.readouterr().out
    rep = report_for(det)
    assert "det:planted-negation" not in [u["rule"] for u in rep["uncounted"]]
    assert {"rule": "det:planted-negation", "reason": "must_fire missed: no-command-line.json"} in (
        rep["backends"]["wazuh"]["uncounted"]
    )
    assert rep["backends"]["wazuh"]["rules_counted"] == rep["summary"]["rules_counted"] - 1


def test_a_rule_the_backend_cannot_express_is_uncounted_for_it_only(det, capsys):
    plant(
        det,
        "planted-or",
        "  a:\n    Image|endswith: '/x'\n  b:\n    Image|endswith: '/y'\n  condition: a or b\n",
        {
            "must_fire/x": {"process": {"executable": "/bin/x"}},
            "must_not_fire/z": {"process": {"executable": "/bin/z"}},
        },
    )
    b = run_compiled(det, "wazuh", run_all(det))
    assert b.ok and "det:planted-or" in b.not_expressible
    assert main(["--root", str(det), "run"]) == 0
    assert "[not expressible] det:planted-or" in capsys.readouterr().out
    rep = report_for(det)
    uncounted = {u["rule"]: u["reason"] for u in rep["backends"]["wazuh"]["uncounted"]}
    assert uncounted["det:planted-or"].startswith("not expressible in wazuh: ")
    assert "det:planted-or" not in [u["rule"] for u in rep["uncounted"]]


def test_the_committed_coverage_report_counts_the_compiled_backend():
    rep = json.loads((DET / "attack_coverage.json").read_text(encoding="utf-8"))
    wazuh = rep["backends"]["wazuh"]
    assert wazuh["must_fire"]["fired"] == wazuh["must_fire"]["total"] > 0
    assert wazuh["rules_counted"] == rep["summary"]["rules_counted"]
