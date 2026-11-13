# SPDX-License-Identifier: Apache-2.0
"""platform/service 2.10 (additive): a public row's ``edge_tls``, how the edge reaches it over
TLS (the lab CA, and for ``tls: mtls`` the edge's client certificate).  Absent ``edge_tls`` is
what every 2.9 registry has, so each still validates; the cross-field rules (``tls``,
``public_hostname``) are in ``tests/generators/edge/test_edge_tls.py``."""

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
FROZEN_29 = json.loads((ROOT / "schemas/_frozen/2.9/platform/service.json").read_text())
FROZEN_210 = json.loads((ROOT / "schemas/_frozen/2.10/platform/service.json").read_text())
EXAMPLE = yaml.safe_load((ROOT / "schemas/platform/examples/service.edge-tls.yml").read_text())
DOC = yaml.safe_load((ROOT / "examples/services.yml").read_text())


def test_version_is_2_10_frozen_and_additive():
    assert CURRENT["$id"].endswith("/platform/service/2.10")
    assert CURRENT == FROZEN_210
    assert sc.is_additive(FROZEN_29, CURRENT) == []


def test_edge_tls_validates_in_2_10_only_and_reaches_the_model():
    assert sc.errors_for(CURRENT, EXAMPLE, REG) == []
    assert sc.errors_for(FROZEN_29, EXAMPLE, REG) != []
    hub = build_registry(EXAMPLE).services["status-hub"]
    assert hub.edge_tls == {
        "client_cert": "secret:edge/hub-client-cert",
        "client_key": "secret:edge/hub-client-key",
        "ca": "secret:pki/internal-ca",
        "server_name": "status-hub.svc.example.internal",
    }


def test_a_2_9_registry_still_validates():
    assert sc.errors_for(CURRENT, DOC, REG) == []
    assert all(s.edge_tls is None for s in build_registry(DOC).services.values())


def test_a_client_certificate_and_its_key_go_together():
    for drop in ("client_cert", "client_key"):
        doc = copy.deepcopy(EXAMPLE)
        doc["services"]["status-hub"]["edge_tls"].pop(drop)
        assert sc.errors_for(CURRENT, doc, REG) != [], drop
