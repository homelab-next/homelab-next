# SPDX-License-Identifier: Apache-2.0
"""``oidc.pkce: false`` (service schema 2.15, ADR-0034 amendment 2026-11-25): the realm drops the
S256 requirement for that row's confidential client alone, keeps its exact redirect URIs, refuses
the exemption on a public client, and ``hnx registry validate`` lists every exemption."""

from __future__ import annotations

import copy
import dataclasses
import io
import json
from pathlib import Path

import pytest
import yaml

from homelabnext.generators import builtin, generate
from homelabnext.generators.builtin import REALM_PRODUCT
from homelabnext.registry import cli as rcli
from homelabnext.registry.model import RegistryError, build_registry, oidc_problems

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = yaml.safe_load(
    (ROOT / "schemas/platform/examples/service.oidc-pkce-exempt.yml").read_text()
)
CALLBACK = EXAMPLE["services"]["forge"]["oidc"]["redirect_uris"][0]


def _clients(doc) -> dict:
    reg = build_registry(doc)
    # the realm is rendered for the row providing the idp capability: name its product
    idp = dataclasses.replace(reg.services["idp"], impl=REALM_PRODUCT)
    reg = dataclasses.replace(reg, services={**reg.services, "idp": idp})
    realm = json.loads(generate(reg, ["idp_realm"])["idp_realm"]["idp/realm.json"])
    return {c["clientId"]: c for c in realm["clients"]}


def test_the_exempt_client_requires_no_code_challenge_and_keeps_its_exact_redirects():
    forge = _clients(EXAMPLE)["forge"]
    assert "pkce.code.challenge.method" not in forge["attributes"]
    assert forge["publicClient"] is False and forge["clientAuthenticatorType"] == "client-secret"
    assert forge["redirectUris"] == [CALLBACK]


def test_every_other_client_still_requires_s256():
    doc = copy.deepcopy(EXAMPLE)
    for k in ("pkce", "why"):
        doc["services"]["forge"]["oidc"].pop(k)
    forge = _clients(doc)["forge"]
    assert forge["attributes"]["pkce.code.challenge.method"] == "S256"


def test_the_exemption_is_refused_on_a_public_client():
    """A public client has no secret: the code challenge is all that binds its codes."""
    with pytest.raises(ValueError, match="public client"):
        builtin._client("forge", "o", [CALLBACK], None, pkce=False, public=True)
    assert builtin._client("forge", "o", [CALLBACK], None, pkce=False)["publicClient"] is False


def test_an_exemption_without_its_why_is_a_registry_problem():
    s = copy.deepcopy(EXAMPLE["services"]["forge"])
    s["oidc"].pop("why")
    assert oidc_problems("forge", s, EXAMPLE["lab"]) == [
        "service forge: oidc.pkce false needs oidc.why (the upstream gap that makes it necessary)"
    ]
    doc = copy.deepcopy(EXAMPLE)
    doc["services"]["forge"] = s
    with pytest.raises(RegistryError):
        build_registry(doc)


def test_validate_lists_every_exemption(tmp_path):
    reg = tmp_path / "services.yml"
    reg.write_text(yaml.safe_dump(EXAMPLE))
    out, err = io.StringIO(), io.StringIO()
    assert rcli.main(["validate", str(reg)], out=out, err=err) == 0, err.getvalue()
    notes = [
        line for line in out.getvalue().splitlines() if line.startswith("note: pkce exemption")
    ]
    assert notes == [
        "note: pkce exemption: forge (oidc.pkce false): "
        + EXAMPLE["services"]["forge"]["oidc"]["why"]
    ]
