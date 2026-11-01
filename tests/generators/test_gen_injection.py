# SPDX-License-Identifier: Apache-2.0
"""Registry free text must never change the structure of a generated file.

Two layers: the schema refuses the payload (``build_registry``), and the renderers refuse it again
when a model is built by hand and skips validation.
"""

import dataclasses
import json
from pathlib import Path

import pytest
import yaml

from homelabnext.generators import builtin, generate
from homelabnext.generators.safe import UnsafeValueError, checked, control_char_paths
from homelabnext.registry import RegistryError, load
from homelabnext.registry.model import build_registry

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "examples" / "services.yml"
PAYLOAD = Path(__file__).resolve().parent / "fixtures" / "inj-owner.services.yml"
REG = load(EXAMPLE)

CADDY_BREAKOUT = "x\n\treverse_proxy evil-upstream.lab.example\n}\nevil.lab.example {\n\treverse_proxy evil-upstream.lab.example"
#: a JSON break-out: an owner closing its string to add a realm user (an admin)
REALM_ENTRY = 'x", "users": [{"username": "backdoor", "realmRoles": ["admin"]}], "y": "'


def _with(reg, service: str, **changes):
    """A registry with one service changed, bypassing validation (as a hand-built model would)."""
    svcs = dict(reg.services)
    svcs[service] = dataclasses.replace(svcs[service], **changes)
    return dataclasses.replace(reg, services=svcs)


# ---------------------------------------------------------------- layer 1: the registry
def test_review_payload_is_rejected_by_the_registry():
    with pytest.raises(RegistryError) as ei:
        load(PAYLOAD)
    msg = str(ei.value)
    assert "services/idp/owner" in msg and "services/lake-query/owner" in msg


@pytest.mark.parametrize(
    "path,value",
    [
        (("services", "edge-proxy", "owner"), CADDY_BREAKOUT),
        (("services", "idp", "owner"), REALM_ENTRY),
        (("services", "idp", "owner"), "identity-team\n"),
        (("services", "idp", "impl"), "keycloak\n"),
        (("services", "idp", "backup_job"), "daily-core\n"),
        (("services", "idp", "health", "path"), "/-/health/live/\n"),
        (("hosts", "idp-core", "role"), "identity\n"),
        (("zones", "mgmt", "description"), "management\nservices"),
        (("lab", "owner"), "platform-team\n"),
        (("lab", "name"), "northwind\n"),
    ],
)
def test_newlines_and_metacharacters_are_refused_by_the_registry(path, value):
    doc = yaml.safe_load(EXAMPLE.read_text())
    node = doc
    for k in path[:-1]:
        node = node[k]
    node[path[-1]] = value
    with pytest.raises(RegistryError, match="/".join(path)):
        build_registry(doc)


def test_trailing_newline_in_a_mapping_key_is_refused():
    doc = yaml.safe_load(EXAMPLE.read_text())
    doc["services"]["notify\n"] = doc["services"].pop("notify")
    with pytest.raises(RegistryError, match="notify"):
        build_registry(doc)


# ---------------------------------------------------------------- layer 2: the renderers
def test_caddy_refuses_a_multiline_owner():
    reg = _with(REG, "dashboards", owner=CADDY_BREAKOUT)
    with pytest.raises(UnsafeValueError, match="owner"):
        generate(reg, ["caddy"])


@pytest.mark.parametrize("value", ["platform-team }", "platform-team # x", "a{b"])
def test_caddy_refuses_format_metacharacters(value):
    with pytest.raises(UnsafeValueError, match="caddy metacharacter"):
        generate(_with(REG, "dashboards", owner=value), ["caddy"])


def test_service_docs_refuse_multiline_and_markdown_breakouts():
    for field, value in [("owner", "a\n# heading"), ("impl", "x | y"), ("backup_job", "<b>")]:
        with pytest.raises(UnsafeValueError):
            generate(_with(REG, "dashboards", **{field: value}), ["service_docs"])
    with pytest.raises(UnsafeValueError, match=r"health\.path"):
        generate(
            _with(REG, "dashboards", health={"kind": "http", "path": "/x<script>"}),
            ["service_docs"],
        )


def test_idp_realm_is_data_so_a_payload_stays_a_string():
    """The realm is emitted with a JSON encoder, so an owner is one string, never a new key or a
    new user, and a placeholder-looking value is not substituted by anything here.

    Calls the generator function directly: ``generate`` would refuse a newline before it runs.
    """
    clients = len(json.loads(builtin.idp_realm(REG)["idp/realm.json"])["clients"])
    for payload in (REALM_ENTRY, REALM_ENTRY + "\n#", "x $(env:HNX_SECRET_ADMIN) ${vault.k}"):
        reg = _with(REG, "dashboards", owner=payload)
        doc = json.loads(builtin.idp_realm(reg)["idp/realm.json"])
        assert "users" not in doc and len(doc["clients"]) == clients
        client = next(c for c in doc["clients"] if c["clientId"] == "dashboards")
        assert client["description"] == f"owner {payload}"


@pytest.mark.parametrize("name", sorted(generate(REG)))
def test_every_generator_refuses_a_control_character_anywhere(name):
    reg = _with(REG, "dashboards", owner="platform-team\r")
    with pytest.raises(UnsafeValueError, match="control character"):
        generate(reg, [name])


# ---------------------------------------------------------------- the helper
@pytest.mark.parametrize("value", ["a\n", "a\rb", "a\x00", "a\x1b[31m", "a\u2028b", "a\x7f"])
def test_checked_refuses_control_characters(value):
    with pytest.raises(UnsafeValueError, match="control character"):
        checked(value, "f")


def test_checked_returns_clean_values_and_names_the_field():
    assert checked("platform-team", "owner", "caddy") == "platform-team"
    with pytest.raises(UnsafeValueError, match=r"^owner: caddy metacharacter"):
        checked("a}", "owner", "caddy")


def test_control_char_paths_walks_keys_and_values():
    found = list(control_char_paths({"a": ["ok", "x\n"], "b\n": 1, "c": {"d": "e\r"}}))
    assert len(found) == 3
    assert any(p.startswith("a/1:") for p in found) and any(p.startswith("c/d:") for p in found)
