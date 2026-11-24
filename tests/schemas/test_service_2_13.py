# SPDX-License-Identifier: Apache-2.0
"""platform/service 2.13 (additive): a row's ``oidc.redirect_uris``, the callbacks its own
product serves for a sign-in at the IdP.  Absent ``oidc`` is what every 2.12 registry has, so
each still validates; the cross-field rules (host, port, ``auth: idp``) and the realm they feed
are in ``tests/registry/test_service_oidc_redirects.py``."""

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
FROZEN_212 = json.loads((ROOT / "schemas/_frozen/2.12/platform/service.json").read_text())
FROZEN_213 = json.loads((ROOT / "schemas/_frozen/2.13/platform/service.json").read_text())
EXAMPLE = yaml.safe_load(
    (ROOT / "schemas/platform/examples/service.oidc-redirects.yml").read_text()
)
DOC = yaml.safe_load((ROOT / "examples/services.yml").read_text())


FORGE = "forge.svc.example.internal"


def _uri(host: str, port: int | None, path: str) -> str:
    return "https://" + host + (f":{port}" if port else "") + path


def test_version_is_2_13_frozen_and_additive():
    assert CURRENT["$id"].endswith("/platform/service/2.13")
    assert FROZEN_213 == CURRENT
    assert sc.is_additive(FROZEN_212, CURRENT) == []


def test_oidc_validates_in_2_13_only_and_reaches_the_model():
    assert sc.errors_for(CURRENT, EXAMPLE, REG) == []
    assert sc.errors_for(FROZEN_212, EXAMPLE, REG) != []
    forge = build_registry(EXAMPLE).services["forge"]
    assert forge.oidc_redirect_uris == (_uri(FORGE, 3443, "/user/oauth2/sso/callback"),)


def test_a_2_12_registry_still_validates():
    assert sc.errors_for(CURRENT, DOC, REG) == []
    assert all(s.oidc_redirect_uris == () for s in build_registry(DOC).services.values())


def _with(uris):
    doc = copy.deepcopy(EXAMPLE)
    doc["services"]["forge"]["oidc"]["redirect_uris"] = uris
    return doc


def test_a_redirect_uri_is_one_explicit_https_url():
    good = _uri(FORGE, 3443, "/user/oauth2/sso/callback")
    for bad in (
        _uri(FORGE, 3443, "/user/oauth2/*"),
        _uri("*.svc.example.internal", None, "/cb"),
        _uri(FORGE, 3443, "/cb").replace("https", "http"),
        _uri(FORGE, 3443, "/cb?x=1"),
        _uri(FORGE, 3443, "/cb#frag"),
        _uri("who@" + FORGE, 3443, "/cb"),
        _uri(FORGE, 3443, ""),
        _uri(FORGE, 3443, "/cb\n"),
        "/relative/callback",
    ):
        assert sc.errors_for(CURRENT, _with([bad]), REG) != [], bad
    assert sc.errors_for(CURRENT, _with([good, good + "2"]), REG) == []


def test_the_list_is_non_empty_unique_and_bounded():
    uri = _uri(FORGE, 3443, "/cb")
    assert sc.errors_for(CURRENT, _with([]), REG) != []
    assert sc.errors_for(CURRENT, _with([uri, uri]), REG) != []
    many = [f"{uri}{n}" for n in range(9)]
    assert sc.errors_for(CURRENT, _with(many), REG) != []


def test_oidc_takes_nothing_but_redirect_uris():
    doc = _with([_uri(FORGE, 3443, "/cb")])
    doc["services"]["forge"]["oidc"]["client_secret"] = "x"
    assert sc.errors_for(CURRENT, doc, REG) != []
