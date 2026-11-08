# SPDX-License-Identifier: Apache-2.0
"""Registry 2.9 (ADR-0039 step 2): a non-primary row is validated but no consumer sees it.

Until step 3 widens each generator, resolver and reader by tier, ``build_registry`` holds every
``eval``, ``retiring`` and ``legacy`` row back (``Registry.non_primary``): a candidate or an old
lab's row must change no generated file, no endpoint variable and no lookup.  Each case here is a
reproduction from the security audit of the step, on the four-box example lab."""

from __future__ import annotations

import copy
from pathlib import Path

import pytest
import yaml

from homelabnext import tlp
from homelabnext.generators import flatten, generate
from homelabnext.notify.ceiling import channel_ceiling
from homelabnext.registry import RegistryError
from homelabnext.registry.model import build_registry, schema_problems, semantic_problems

ROOT = Path(__file__).resolve().parents[2]
FOUR_BOX = yaml.safe_load((ROOT / "examples/four-box-lab/services.yml").read_text())
UNTIL = {"until": "2026-12-01"}


def _doc():
    return copy.deepcopy(FOUR_BOX)


def _first(doc, name, row):
    """``row`` added as ``name`` *before* every other row: a first-match lookup would find it."""
    doc["services"] = {name: row, **doc["services"]}
    return doc


def _problems(doc):
    return schema_problems(doc) or semantic_problems(doc)


def _eval_idp():
    doc = _doc()
    row = copy.deepcopy(doc["services"]["idp"])
    row.update(impl="keycloak", host="hub-1")
    row["standing"] = {"tier": "eval", **UNTIL, "why": "candidate IdP"}
    return _first(doc, "aaa-idp", row)


def _rendered(doc):
    reg = build_registry(doc)
    out = flatten(generate(reg))
    return {k: v.replace(reg.digest[:16], "<digest>") for k, v in out.items()}


def test_an_eval_row_changes_no_generated_file_but_the_digest():
    assert _problems(_eval_idp()) == []
    assert _rendered(_eval_idp()) == _rendered(_doc())


def test_an_eval_row_adds_no_dns_record_no_variable_and_moves_no_firewall_rule():
    out = flatten(generate(build_registry(_eval_idp())))
    zone = next(v for k, v in out.items() if k.startswith("dns/") and "hosts" not in k)
    lines = zone.splitlines()
    assert sum(ln.startswith("idp IN A ") for ln in lines) == 1
    assert sum(ln.startswith("_idp._tcp IN SRV ") for ln in lines) == 1
    assert sum(ln.startswith("_idp._tcp IN TXT ") for ln in lines) == 1
    assert not any("aaa-idp" in ln for ln in lines)
    env = out["env/_all.env.generated"].splitlines()
    assert sum(ln.startswith("HNX_ENDPOINT_IDP=") for ln in env) == 1
    assert not any(k.startswith("env/aaa-idp") for k in out)
    # the firewall matrix is by zone: the idp rule is the primary's, unchanged by the candidate
    fw = {k: v for k, v in out.items() if k.startswith("firewall/")}
    base = flatten(generate(build_registry(_doc())))
    old, new = build_registry(_doc()).digest[:16], build_registry(_eval_idp()).digest[:16]
    assert fw and fw == {k: v.replace(old, new) for k, v in base.items() if k in fw}
    assert any("| idp |" in v for v in fw.values()) and not any("aaa-idp" in v for v in fw.values())


def test_by_capability_is_the_primary_and_the_rows_are_held_back():
    reg = build_registry(_eval_idp())
    assert reg.by_capability("idp").name == "idp"
    assert "aaa-idp" not in reg.services and reg.non_primary["aaa-idp"].standing == "eval"
    # its own variable is its row name's, never the capability's
    assert reg.non_primary["aaa-idp"].endpoint_env_var == "HNX_ENDPOINT_AAA_IDP"
    assert reg.by_capability("idp").endpoint_env_var == "HNX_ENDPOINT_IDP"


def test_a_legacy_egress_row_above_the_primarys_ceiling_is_refused_and_never_read():
    doc = _doc()
    doc["services"]["notify"] = {
        "capability": "notify",
        "impl": "pager",
        "host": "egress-1",
        "protocol": "https",
        "port": 8443,
        "owner": "platform-team",
        "version": "2.11",
        "tls": "internal",
        "tlp_ceiling": "green",
    }
    old = copy.deepcopy(doc["services"]["notify"])
    old.update(host="hub-1", port=8444, tlp_ceiling="red")
    old["standing"] = {"tier": "legacy", **UNTIL, "why": "old lab pager"}
    above = _first(copy.deepcopy(doc), "aaa-pager-old", old)
    assert any("tlp_ceiling red is above the primary's (green)" in p for p in _problems(above))
    # a legacy row's ceiling at or below the primary's is allowed: the channel is still the
    # primary's, whichever row comes first
    old["tlp_ceiling"] = "clear"
    reg = build_registry(_first(doc, "aaa-pager-old", old))
    assert channel_ceiling(None, reg) == tlp.Label.GREEN


def test_a_legacy_rows_explicit_env_var_is_held_unique():
    doc = _doc()
    row = copy.deepcopy(doc["services"]["detections"])
    row.update(capability="siem-archive", host="hub-1", port=8443, env_var="HNX_ENDPOINT_IDP")
    row.pop("auth", None)
    row["standing"] = {"tier": "legacy", **UNTIL, "why": "old siem"}
    doc["services"]["siem-old"] = row
    with pytest.raises(RegistryError, match="env var HNX_ENDPOINT_IDP already used by idp"):
        build_registry(doc)


def test_a_legacy_rows_mcp_name_is_held_unique():
    doc = _doc()
    doc["services"]["detections"]["mcp"] = {"name": "detections"}
    row = copy.deepcopy(doc["services"]["detections"])
    row.update(host="hub-1", port=8445)
    row.pop("public_hostname", None)
    row["standing"] = {"tier": "legacy", **UNTIL, "why": "old copy"}
    doc["services"]["zz-old"] = row
    assert any("mcp name" in p and "already used" in p for p in _problems(doc))


def test_a_public_idp_route_needs_a_primary_auth_proxy():
    doc = _doc()
    for k in [k for k, v in doc["services"].items() if v["capability"] == "auth-proxy"]:
        del doc["services"][k]
    doc["services"]["detections"].update(
        public_hostname="siem.lab.example", roles={"viewer": ["soc-viewers"]}
    )
    doc["services"]["detections"]["auth"] = "idp"
    doc["services"]["oauth-old"] = {
        "capability": "auth-proxy",
        "impl": "forward-auth",
        "host": "proxy-1",
        "protocol": "http",
        "port": 4180,
        "owner": "platform-team",
        "version": "7.6",
        "tls": "none",
        "standing": {"tier": "legacy", **UNTIL, "why": "old lab forward auth"},
    }
    problems = _problems(doc)
    assert any("public auth: idp route needs a primary 'auth-proxy'" in p for p in problems), (
        problems
    )


def test_a_customization_scoped_to_a_capability_reaches_its_primarys_host_only():
    from homelabnext.customization.universe import Universe

    doc = _eval_idp()
    assert Universe(registry=doc).capability_hosts("cap:idp") == {
        FOUR_BOX["services"]["idp"]["host"]
    }
