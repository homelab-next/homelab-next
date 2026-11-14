# SPDX-License-Identifier: Apache-2.0
"""Deployment scoping for IdP realm clients, using the shared two-lab registry fixture."""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest
import yaml

from homelabnext.generators import GeneratorRefusal, generate
from homelabnext.registry import load
from homelabnext.registry.cli import main as registry_main

HERE = Path(__file__).resolve().parent
FIXTURE = HERE / "fixtures" / "two-lab.services.yml"
_base_reg = load(FIXTURE)
REG = dataclasses.replace(
    _base_reg,
    services={
        **_base_reg.services,
        "idp": dataclasses.replace(_base_reg.services["idp"], impl="keycloak"),
    },
)
NEW_LAB = ("core-01", "edge-01", "idp-01")


def _realm(hosts=NEW_LAB) -> dict:
    options = {"edge_hosts": hosts} if hosts is not None else None
    text = generate(REG, ["idp_realm"], options)["idp_realm"]["idp/realm.json"]
    return json.loads(text)


def test_scoped_realm_contains_only_this_deployments_clients_and_redirects():
    realm = _realm()
    clients = {c["clientId"]: c for c in realm["clients"]}
    assert set(clients) == {"status-hub", "auth-proxy"}
    assert clients["status-hub"]["redirectUris"] == ["https://hub.example.internal/*"]
    assert clients["auth-proxy"]["redirectUris"] == ["https://hub.example.internal/oauth2/callback"]
    rendered = json.dumps(realm)
    assert "old-app" not in rendered and "dashboards.example.internal" not in rendered
    assert "https://wiki.example.internal" not in rendered
    assert realm["groups"] == [
        {
            "clientRoles": {"status-hub": ["viewer"]},
            "name": "lab-admins",
            "path": "/lab-admins",
        },
        {
            "clientRoles": {"status-hub": ["approver"]},
            "name": "lab-approvers",
            "path": "/lab-approvers",
        },
    ]


def test_without_edge_hosts_every_deployment_client_remains():
    realm = _realm(hosts=None)
    clients = {c["clientId"]: c for c in realm["clients"]}
    assert set(clients) == {"status-hub", "old-app", "auth-proxy"}
    assert clients["auth-proxy"]["redirectUris"] == [
        "https://dashboards.example.internal/oauth2/callback",
        "https://hub.example.internal/oauth2/callback",
    ]


@pytest.mark.parametrize(
    ("hosts", "match"),
    [
        (("idp-01", "typo-01"), "typo-01 not in the registry"),
        (("idp-01",), "no auth: idp row is on the edge hosts"),
    ],
)
def test_unknown_or_empty_realm_scope_is_refused(hosts, match):
    with pytest.raises(GeneratorRefusal, match=match):
        _realm(hosts)


def test_cli_applies_edge_host_to_the_realm_and_refuses_unknown_hosts(tmp_path, capsys):
    doc = yaml.safe_load(FIXTURE.read_text(encoding="utf-8"))
    doc["services"]["idp"]["impl"] = "keycloak"
    registry = tmp_path / "services.yml"
    registry.write_text(yaml.safe_dump(doc), encoding="utf-8")
    hosts = [arg for host in NEW_LAB for arg in ("--edge-host", host)]
    args = ["generate", str(registry), str(tmp_path), "--only", "idp_realm", *hosts]
    assert registry_main(args) == 0
    realm = json.loads((tmp_path / "idp/realm.json").read_text())
    assert {c["clientId"] for c in realm["clients"]} == {"status-hub", "auth-proxy"}
    bad = ["generate", str(registry), str(tmp_path), "--only", "idp_realm", "--edge-host", "nope"]
    assert registry_main(bad) == 1
    assert "nope not in the registry" in capsys.readouterr().err
