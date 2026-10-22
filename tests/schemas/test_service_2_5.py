# SPDX-License-Identifier: Apache-2.0
"""platform/service 2.5 (additive): the ``poll-nut`` status kind (a UPS read from a NUT upsd),
``auth.username`` and the poll-nut mapping keys; the registry rules refuse what the schema
cannot state (a non-tcp target, an HTTP header on a NUT credential, plaintext flags on TLS)."""

import json
from pathlib import Path

import schema_check as sc
import yaml

from homelabnext.registry.model import build_registry, schema_problems, semantic_problems


def validate_registry(doc):
    return schema_problems(doc) + semantic_problems(doc)


ROOT = Path(__file__).resolve().parents[2]
REG = sc.build_registry(ROOT)
CURRENT = json.loads((ROOT / "schemas/platform/service.json").read_text())
FROZEN_24 = json.loads((ROOT / "schemas/_frozen/2.4/platform/service.json").read_text())
FROZEN_25 = json.loads((ROOT / "schemas/_frozen/2.5/platform/service.json").read_text())

DOC = yaml.safe_load((Path(__file__).parent / "fixtures" / "service.2_5.nut.yml").read_text())


def _copy():
    return json.loads(json.dumps(DOC))


def _src(doc):
    return doc["services"]["ups-monitor"]["status_sources"][0]


def test_version_2_5_is_frozen_and_additive():
    assert FROZEN_25["$id"].endswith("/platform/service/2.5")
    assert sc.is_additive(FROZEN_24, FROZEN_25) == []
    assert sc.is_additive(FROZEN_25, CURRENT) == []


def test_poll_nut_validates_in_2_5_only_and_reaches_the_model():
    assert sc.errors_for(CURRENT, DOC, REG) == []
    assert sc.errors_for(FROZEN_24, DOC, REG) != []
    assert validate_registry(DOC) == []
    src = build_registry(DOC).services["ups-monitor"].status_sources[0]
    assert src["kind"] == "poll-nut" and src["auth"]["username"] == "hub-monitor"


def test_the_registry_refuses_what_the_schema_cannot_state():
    bad = _copy()
    bad["services"]["ups-monitor"]["protocol"] = "http"
    assert any("is not tcp" in p for p in validate_registry(bad))
    bad = _copy()
    _src(bad)["auth"] = {"secret": "secret:nut/monitor-password", "header": "X-Key"}
    assert any("{username, secret}" in p for p in validate_registry(bad))
    bad = _copy()
    _src(bad)["mapping"]["allow_plaintext"] = True
    assert any("allow_plaintext only" in p for p in validate_registry(bad))
    bad = _copy()
    _src(bad)["target"] = {"path": "/x"}
    assert any("only target.service" in p for p in validate_registry(bad))
    bad = _copy()
    _src(bad)["mapping"]["query"] = "up"
    assert any("poll-nut mapping takes only" in p for p in validate_registry(bad))


def test_username_is_for_poll_nut_only():
    bad = _copy()
    svc = bad["services"]["ups-monitor"]
    svc["protocol"], svc["port"] = "http", 8080
    _src(bad).update(kind="poll-http-json", target={"path": "/x"}, mapping={"state": "s"})
    assert any("auth.username is for poll-nut only" in p for p in validate_registry(bad))
