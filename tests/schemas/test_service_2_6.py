# SPDX-License-Identifier: Apache-2.0
"""platform/service 2.6 (additive): the ``job-last-run`` built-in mapper of ``poll-file`` (the
role timers' last-run records); the registry rules keep it to poll-file and its two keys."""

import json
from pathlib import Path

import schema_check as sc
import yaml

from homelabnext.registry.model import build_registry, schema_problems, semantic_problems

ROOT = Path(__file__).resolve().parents[2]
REG = sc.build_registry(ROOT)
CURRENT = json.loads((ROOT / "schemas/platform/service.json").read_text())
FROZEN_25 = json.loads((ROOT / "schemas/_frozen/2.5/platform/service.json").read_text())
FROZEN_26 = json.loads((ROOT / "schemas/_frozen/2.6/platform/service.json").read_text())

DOC = yaml.safe_load(
    (Path(__file__).parent / "fixtures" / "service.2_6.job-last-run.yml").read_text()
)


def validate_registry(doc):
    return schema_problems(doc) + semantic_problems(doc)


def _src(doc):
    return doc["services"]["status-hub"]["status_sources"][0]


def test_version_is_2_6_frozen_and_additive():
    assert CURRENT["$id"].endswith("/platform/service/2.6")
    assert CURRENT == FROZEN_26
    assert sc.is_additive(FROZEN_25, CURRENT) == []


def test_job_last_run_validates_in_2_6_only_and_reaches_the_model():
    assert sc.errors_for(CURRENT, DOC, REG) == []
    assert sc.errors_for(FROZEN_25, DOC, REG) != []
    assert validate_registry(DOC) == []
    src = build_registry(DOC).services["status-hub"].status_sources[0]
    assert src["mapping"]["builtin"] == "job-last-run"


def test_the_registry_keeps_job_last_run_to_poll_file_and_its_keys():
    bad = json.loads(json.dumps(DOC))
    _src(bad).update(kind="poll-http-json", target={"path": "/x"})
    assert any("job-last-run is for poll-file only" in p for p in validate_registry(bad))
    bad = json.loads(json.dumps(DOC))
    _src(bad)["mapping"]["state"] = "s"
    assert any("takes no selectors" in p for p in validate_registry(bad))
