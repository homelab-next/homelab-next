# SPDX-License-Identifier: Apache-2.0
"""Registry 2.9 (ADR-0039 steps 2 and 3): a non-primary row is validated, held back from every
consumer that does not ask for its tier (``Registry.non_primary``), and reaches only the outputs
decision 2 gives that tier.  Each case here is a reproduction from the security audit of a step,
on the four-box example lab."""

from __future__ import annotations

import copy
from pathlib import Path

import pytest
import yaml

from homelabnext import tlp
from homelabnext.generators import GeneratorRefusal, flatten, generate
from homelabnext.generators.realm_format import REALM_PRODUCT
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
    row.update(impl=REALM_PRODUCT, host="hub-1")
    row["standing"] = {"tier": "eval", **UNTIL, "why": "candidate IdP"}
    return _first(doc, "aaa-idp", row)


def _rendered(doc, names=None):
    reg = build_registry(doc)
    out = flatten(generate(reg, names))
    return {k: v.replace(reg.digest[:16], "<digest>") for k, v in out.items()}


def _added(old: str, new: str) -> list[str]:
    """The lines ``new`` has beyond ``old``, which must be all that changed."""
    a, b = old.splitlines(), new.splitlines()
    assert [ln for ln in a if ln not in b] == [], "a line was removed"
    return [ln for ln in b if ln not in a]


def test_an_eval_row_reaches_only_the_outputs_its_tier_is_given():
    """Step 3: an eval IdP gets its row-name address record (DNS zone and hosts block), its
    row-named endpoint variable and an uptime target, and the realm, which the Authentik primary
    alone does not get; every other generated file is byte-identical."""
    assert _problems(_eval_idp()) == []
    base, cand = _rendered(_doc()), _rendered(_eval_idp())
    assert set(cand) - set(base) == {"idp/realm.json"} and set(base) <= set(cand)
    changed = {k for k in base if base[k] != cand[k]}
    zone = next(k for k in base if k.startswith("dns/") and "hosts" not in k)
    assert changed == {
        zone,
        "hosts/hosts.block",
        "env/_all.env.generated",
        "blackbox/targets_http.yml",
    }
    assert _added(base[zone], cand[zone]) == [
        "aaa-idp IN A " + FOUR_BOX["hosts"]["hub-1"]["address"]
    ]
    assert _added(base["env/_all.env.generated"], cand["env/_all.env.generated"]) == [
        "HNX_ENDPOINT_AAA_IDP=https://aaa-idp.svc.example.internal:" + "9443"
    ]
    hosts = cand["hosts/hosts.block"]
    assert hosts.count(" aaa-idp.svc.example.internal") == 1
    assert hosts.replace(" aaa-idp.svc.example.internal", "") == base["hosts/hosts.block"]
    assert "https://aaa-idp.svc.example.internal:" + "9443/-/health/live/" in "".join(
        _added(base["blackbox/targets_http.yml"], cand["blackbox/targets_http.yml"])
    )
    # the realm: none for the Authentik primary alone (asked for by name, refused)
    with pytest.raises(
        GeneratorRefusal, match=f"no primary or eval idp row has impl '{REALM_PRODUCT}'"
    ):
        generate(build_registry(_doc()), ["idp_realm"])


def test_an_eval_row_adds_no_capability_record_no_own_files_and_moves_no_firewall_rule():
    out = flatten(generate(build_registry(_eval_idp())))
    zone = next(v for k, v in out.items() if k.startswith("dns/") and "hosts" not in k)
    lines = zone.splitlines()
    assert sum(ln.startswith("idp IN A ") for ln in lines) == 1
    assert sum(ln.startswith("_idp._tcp IN SRV ") for ln in lines) == 1
    assert sum(ln.startswith("_idp._tcp IN TXT ") for ln in lines) == 1
    # its row name is an address record only: no SRV or TXT of its own
    assert [ln for ln in lines if "aaa-idp" in ln] == [
        "aaa-idp IN A " + FOUR_BOX["hosts"]["hub-1"]["address"]
    ]
    env = out["env/_all.env.generated"].splitlines()
    assert sum(ln.startswith("HNX_ENDPOINT_IDP=") for ln in env) == 1
    assert not any(k.startswith(("env/aaa-idp", "systemd/aaa-idp")) for k in out)
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


# ---- a non-primary row never claims a capability's alias or default variable (#333 audit) ----
def _search_row(tier="eval", **extra):
    """A row of capability ``search``, which no row of the four-box lab provides."""
    return {
        "capability": "search",
        "impl": "candidate-search",
        "host": "hub-1",
        "protocol": "https",
        "port": 9201,
        "owner": "platform-team",
        "version": "1.0",
        "tls": "internal",
        "standing": {"tier": tier, **UNTIL, "why": "under test"},
        **extra,
    }


def _with_rows(**rows):
    doc = _doc()
    for name, row in rows.items():
        doc["services"][name] = row
    return doc


@pytest.mark.parametrize(
    "rows,name",
    [
        # named like a capability of this registry (the lab's events row replaced, so no row
        # of it is left) or one the platform knows
        ({"events": _search_row()}, "events"),
        ({"lake-query": _search_row()}, "lake-query"),
        # named like its own capability, which has no primary
        ({"search": _search_row()}, "search"),
        # named like another eval-only capability of the registry
        ({"s1": _search_row(), "search": {**_search_row(), "capability": "ranker", "port": 9202}},
         "search"),
    ],
)  # fmt: skip
def test_an_eval_row_named_like_any_capability_is_refused(rows, name):
    problems = _problems(_with_rows(**rows))
    assert any(
        p.startswith(f"service {name}: an eval row answers by its row name") for p in problems
    ), problems


def test_a_retiring_row_named_like_its_capability_is_refused_after_the_primary_goes():
    doc = _doc()
    row = doc["services"]["status-hub"]
    row["standing"] = {"tier": "retiring", **UNTIL, "why": "replaced"}
    problems = _problems(doc)
    assert any(
        p.startswith("service status-hub: a retiring row answers by its row name") for p in problems
    ), problems


@pytest.mark.parametrize(
    "env_var", ["HNX_ENDPOINT_SEARCH", "HNX_ENDPOINT_EVENTS", "HNX_ENDPOINT_S_CAND_OWN"]
)
def test_an_eval_row_declares_no_env_var(env_var):
    problems = _problems(_with_rows(**{"s-cand": _search_row(env_var=env_var)}))
    assert any(
        p.startswith("service s-cand: env_var is for a primary or legacy row") for p in problems
    ), problems


def test_a_capabilitys_default_variable_stays_reserved_when_its_primary_names_another():
    """The primary moves to its own env_var: its capability's default is still its alone, so a
    legacy row (which may declare one) cannot take it."""
    doc = _doc()
    doc["services"]["status-hub"]["env_var"] = "HNX_HUB_URL"
    old = copy.deepcopy(doc["services"]["status-hub"])
    old.update(host="vault-1", port=8091, env_var="HNX_ENDPOINT_STATUS_HUB", impl="old-hub")
    old["standing"] = {"tier": "legacy", **UNTIL, "why": "old lab hub"}
    doc["services"]["hub-old"] = old
    problems = _problems(doc)
    assert any(
        "service hub-old: env_var HNX_ENDPOINT_STATUS_HUB is reserved for capability "
        "'status-hub''s primary" in p
        for p in problems
    ), problems
    # the primary itself may still spell its own default out
    doc = _doc()
    doc["services"]["status-hub"]["env_var"] = "HNX_ENDPOINT_STATUS_HUB"
    assert _problems(doc) == []
