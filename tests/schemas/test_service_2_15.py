# SPDX-License-Identifier: Apache-2.0
"""platform/service 2.15 (additive): ``oidc.pkce`` (false only) with its required ``oidc.why``, a
confidential client exempt from the realm's PKCE-only rule.  The realm, the registry note and the
public-client refusal are in ``tests/registry/test_service_oidc_pkce.py``."""

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
FROZEN_214 = json.loads((ROOT / "schemas/_frozen/2.14/platform/service.json").read_text())
FROZEN_215 = json.loads((ROOT / "schemas/_frozen/2.15/platform/service.json").read_text())
EXAMPLE = yaml.safe_load(
    (ROOT / "schemas/platform/examples/service.oidc-pkce-exempt.yml").read_text()
)
DOC = yaml.safe_load((ROOT / "examples/services.yml").read_text())


def test_version_is_2_15_frozen_and_additive():
    assert CURRENT["$id"].endswith("/platform/service/2.15")
    assert FROZEN_215 == CURRENT
    assert sc.is_additive(FROZEN_214, CURRENT) == []


def test_the_exemption_validates_in_2_15_only_and_reaches_the_model():
    assert sc.errors_for(CURRENT, EXAMPLE, REG) == []
    assert sc.errors_for(FROZEN_214, EXAMPLE, REG) != []
    forge = build_registry(EXAMPLE).services["forge"]
    assert forge.oidc_pkce is False and "code challenge" in forge.oidc_why


def test_every_2_14_registry_still_validates_and_requires_pkce():
    assert sc.errors_for(CURRENT, DOC, REG) == []
    assert all(s.oidc_pkce for s in build_registry(DOC).services.values())


def _oidc(**kw):
    doc = copy.deepcopy(EXAMPLE)
    oidc = doc["services"]["forge"]["oidc"]
    for k, v in kw.items():
        if v is None:
            oidc.pop(k, None)
        else:
            oidc[k] = v
    return doc


def test_pkce_takes_false_only_and_always_with_its_why():
    assert sc.errors_for(CURRENT, _oidc(pkce=True), REG) != []
    assert sc.errors_for(CURRENT, _oidc(pkce="false"), REG) != []
    assert sc.errors_for(CURRENT, _oidc(why=None), REG) != []  # no reason
    assert sc.errors_for(CURRENT, _oidc(pkce=None), REG) != []  # a reason for nothing
    for why in ("short", "x" * 301, "one line\nand another"):
        assert sc.errors_for(CURRENT, _oidc(why=why), REG) != [], why
