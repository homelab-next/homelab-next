# SPDX-License-Identifier: Apache-2.0
"""platform/service 2.7 (additive): a service's ``roles``, the group-to-role table of single
sign-on (ADR-0034); the registry keeps it to ``auth: idp`` services and the model carries it."""

import copy
import json
from pathlib import Path

import schema_check as sc
import yaml

from homelabnext.registry.model import build_registry, schema_problems, semantic_problems

ROOT = Path(__file__).resolve().parents[2]
REG = sc.build_registry(ROOT)
CURRENT = json.loads((ROOT / "schemas/platform/service.json").read_text())
FROZEN_26 = json.loads((ROOT / "schemas/_frozen/2.6/platform/service.json").read_text())
FROZEN_27 = json.loads((ROOT / "schemas/_frozen/2.7/platform/service.json").read_text())
DOC = yaml.safe_load((ROOT / "examples/services.yml").read_text())


def _problems(doc):
    return schema_problems(doc) + semantic_problems(doc)


def test_version_is_2_7_frozen_and_additive():
    assert CURRENT["$id"].endswith("/platform/service/2.7")
    assert CURRENT == FROZEN_27
    assert sc.is_additive(FROZEN_26, CURRENT) == []


def test_roles_validate_in_2_7_only_and_reach_the_model():
    assert DOC["services"]["status-hub"]["roles"]
    assert sc.errors_for(CURRENT, DOC, REG) == []
    assert sc.errors_for(FROZEN_26, DOC, REG) != []
    hub = build_registry(DOC).services["status-hub"]
    assert hub.roles == {"approver": ("hub-approvers",), "viewer": ("hub-private-viewers",)}


def test_roles_need_auth_idp():
    bad = copy.deepcopy(DOC)
    bad["services"]["metrics"].pop("public_hostname")
    bad["services"]["metrics"].update(auth="own", roles={"viewer": ["lab-viewers"]})
    assert any("roles needs auth: idp" in p for p in _problems(bad))


def test_a_group_name_cannot_hold_the_groups_separator():
    bad = copy.deepcopy(DOC)
    bad["services"]["status-hub"]["roles"] = {"viewer": ["staff,hub-private-viewers"]}
    assert any("roles/viewer/0" in p for p in _problems(bad))
