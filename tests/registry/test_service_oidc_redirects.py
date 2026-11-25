# SPDX-License-Identifier: Apache-2.0
"""Service schema 2.13 ``oidc.redirect_uris``: the registry holds a declared callback to the row
that declares it, and the IdP realm gives that row's client exactly those redirects.

The generic rule is untouched: a row with no public hostname and no declaration still gets a
client with no redirect (``tests/generators/test_gen_golden.py`` pins that for lake-query)."""

from __future__ import annotations

import copy
import dataclasses
import json
from pathlib import Path

import pytest
import yaml

from homelabnext.generators import generate
from homelabnext.generators.builtin import REALM_PRODUCT
from homelabnext.registry.model import RegistryError, build_registry

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = yaml.safe_load(
    (ROOT / "schemas/platform/examples/service.oidc-redirects.yml").read_text(encoding="utf-8")
)
CALLBACK = "/user/oauth2/sso/callback"


def _uri(host: str, port: int | None = None, path: str = CALLBACK) -> str:
    return "https://" + host + (f":{port}" if port else "") + path


FORGE = "forge.svc.example.internal"
OWN = _uri("forge.svc.example.internal", 3443)


def _problems(doc) -> list[str]:
    try:
        build_registry(doc)
    except RegistryError as exc:
        return exc.problems
    return []


def _doc(mutate=None) -> dict:
    doc = copy.deepcopy(EXAMPLE)
    if mutate:
        mutate(doc["services"]["forge"], doc)
    return doc


def _realm(doc) -> dict:
    reg = build_registry(doc)
    # the realm is rendered for the row providing the idp capability: name its product
    idp = dataclasses.replace(reg.services["idp"], impl=REALM_PRODUCT)
    reg = dataclasses.replace(reg, services={**reg.services, "idp": idp})
    return json.loads(generate(reg, ["idp_realm"])["idp_realm"]["idp/realm.json"])


def test_the_example_is_valid():
    assert _problems(_doc()) == []


def test_the_realm_client_carries_the_declared_redirect_and_nothing_else():
    clients = {c["clientId"]: c for c in _realm(_doc())["clients"]}
    forge = clients["forge"]
    assert forge["redirectUris"] == [OWN]
    assert forge["standardFlowEnabled"] is True
    assert forge["attributes"]["pkce.code.challenge.method"] == "S256"
    # no public route: no root URL and no logout wildcard are invented for it
    assert "rootUrl" not in forge
    assert "post.logout.redirect.uris" not in forge["attributes"]
    # the auth proxy's callbacks are for public routes only
    assert clients.get("auth-proxy", {}).get("redirectUris", []) == []


def test_without_a_declaration_the_client_still_has_no_redirect():
    doc = _doc(lambda s, d: s.pop("oidc"))
    forge = {c["clientId"]: c for c in _realm(doc)["clients"]}["forge"]
    assert forge["redirectUris"] == [] and forge["standardFlowEnabled"] is False


def test_a_public_row_keeps_its_wildcard_and_adds_the_declared_callback():
    def make_public(s, d):
        s["public_hostname"] = "forge.example.internal"
        s["oidc"]["redirect_uris"] = ["https://forge.example.internal/user/oauth2/sso/callback"]
        d["services"]["auth-proxy"] = {
            "capability": "auth-proxy",
            "host": "apps-01",
            "protocol": "http",
            "port": 4180,
            "owner": "platform-team",
            "version": "7.15.5",
            "tls": "none",
            "auth": "own",
        }

    forge = {c["clientId"]: c for c in _realm(_doc(make_public))["clients"]}["forge"]
    assert forge["redirectUris"] == [
        "https://forge.example.internal/*",
        "https://forge.example.internal/user/oauth2/sso/callback",
    ]


@pytest.mark.parametrize(
    ("uri", "match"),
    [
        (_uri("other.svc.example.internal", 3443), "not this row's own"),
        (_uri("forge.example.internal"), "not this row's own"),
        (_uri("idp.svc.example.internal", 3443), "not this row's own"),
        (_uri("forge.svc.example.internal", 4443), "port"),
        (_uri("forge.svc.example.internal"), "port"),
        (_uri(FORGE, 3443, "/a/../cb"), "dot segment"),
        (_uri(FORGE, 3443, "/a//cb"), "dot segment"),
        (_uri(FORGE, 3443, "/%2e%2e/cb"), "dot segment"),
        (_uri(FORGE, 3443, "/a%2fcb"), "dot segment"),
    ],
)
def test_the_registry_holds_a_callback_to_the_rows_own_name_and_port(uri, match):
    problems = _problems(_doc(lambda s, d: s["oidc"].update(redirect_uris=[uri])))
    assert any(match in p for p in problems), problems


def test_oidc_needs_auth_idp():
    problems = _problems(_doc(lambda s, d: s.update(auth="own")))
    assert any("oidc needs auth: idp" in p for p in problems), problems


def test_a_public_hostname_is_an_allowed_host_on_a_public_row_only():
    uri = "https://forge.example.internal/user/oauth2/sso/callback"
    problems = _problems(_doc(lambda s, d: s["oidc"].update(redirect_uris=[uri])))
    assert any("not this row's own" in p for p in problems), problems


def _with_candidate(uri):
    doc = _doc()
    primary = doc["services"]["forge"]
    primary.pop("oidc")
    primary["auth"] = "own"
    doc["services"]["forge-candidate"] = {
        **primary,
        "port": 3444,
        "auth": "idp",
        "standing": {"tier": "eval", "until": "2027-03-31", "why": "a candidate forge"},
        "oidc": {"redirect_uris": [uri]},
    }
    return doc


def test_an_eval_row_answers_by_its_row_name_not_its_capability():
    theirs = _uri(FORGE, 3444)
    mine = _uri("forge-candidate.svc.example.internal", 3444)
    # the capability's alias belongs to the primary
    problems = _problems(_with_candidate(theirs))
    assert any("not this row's own" in p for p in problems), problems
    assert _problems(_with_candidate(mine)) == []
