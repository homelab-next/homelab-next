# SPDX-License-Identifier: Apache-2.0
"""platform/service 2.11: metrics listener scheme and secret-reference scrape auth."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import schema_check as sc
import yaml

from homelabnext.registry.model import build_registry

ROOT = Path(__file__).resolve().parents[2]
REG = sc.build_registry(ROOT)
CURRENT = json.loads((ROOT / "schemas/platform/service.json").read_text())
FROZEN_210 = json.loads((ROOT / "schemas/_frozen/2.10/platform/service.json").read_text())
DOC = yaml.safe_load((ROOT / "examples/services.yml").read_text())


def test_version_is_2_11_frozen_and_additive():
    assert CURRENT["$id"].endswith("/platform/service/2.11")
    assert json.loads((ROOT / "schemas/_frozen/2.11/platform/service.json").read_text()) == CURRENT
    assert sc.is_additive(FROZEN_210, CURRENT) == []


def test_metrics_scheme_and_auth_are_retained_by_the_model():
    assert sc.errors_for(CURRENT, DOC, REG) == []
    services = build_registry(DOC).services
    assert services["lake-catalog"].metrics["scheme"] == "http"
    assert services["lake-query"].metrics["auth"] == {
        "kind": "basic",
        "username": "prometheus-scraper",
        "secret": "secret:lake/trino-scraper-password",
    }


def test_metrics_auth_requires_a_secret_reference_and_kind_specific_fields():
    literal = yaml.safe_load(
        (ROOT / "tests/schemas/fixtures/service.2_11.literal-secret.yml").read_text()
    )
    for auth in (
        literal,
        {"kind": "bearer", "secret": "plaintext-token"},
        {"kind": "basic", "secret": "secret:metrics/password"},
        {"kind": "bearer", "username": "scraper", "secret": "secret:metrics/token"},
    ):
        doc = copy.deepcopy(DOC)
        doc["services"]["lake-query"]["metrics"]["auth"] = auth
        assert sc.errors_for(CURRENT, doc, REG), auth


def test_2_10_registry_still_validates():
    legacy = copy.deepcopy(DOC)
    legacy["services"]["lake-catalog"]["metrics"].pop("scheme")
    legacy["services"]["lake-query"]["metrics"].pop("auth")
    assert sc.errors_for(CURRENT, legacy, REG) == []
