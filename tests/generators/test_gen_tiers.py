# SPDX-License-Identifier: Apache-2.0
"""Generators by tier (ADR-0039 decision 2, step 3): an all-tiers golden render, and one rule per
generator for which tiers it renders.

The fixture (``fixtures/all-tiers.services.yml``) holds a primary for every capability, and beside
the ``status-hub`` and ``idp`` primaries an ``eval``, a ``retiring`` and a ``legacy`` row that each
declare every field a generator could render (metrics, health, ``auth: idp`` with roles, an MCP
endpoint, upstreams, client zones, a backup job).  Whatever a tier may not have would show up as a
row name in an artefact, so the tests read the row names out of every output."""

from __future__ import annotations

import dataclasses
import json
import re
from pathlib import Path

import pytest
import yaml

from homelabnext.generators import GENERATORS, GeneratorRefusal, flatten, generate
from homelabnext.generators.builtin import REALM_PRODUCT, realm_idp
from homelabnext.registry import load
from homelabnext.registry.model import STANDINGS, build_registry

HERE = Path(__file__).resolve().parent
FIXTURE = HERE / "fixtures" / "all-tiers.services.yml"
GOLDEN = HERE / "tiers" / "golden"
REG = load(FIXTURE)
FILES = flatten(generate(REG))

#: the fixture's non-primary rows by tier
ROWS = {
    "eval": ("hub-candidate", "kc-trial"),
    "retiring": ("hub-rollback",),
    "legacy": ("hub-oldlab",),
}
EVAL, RETIRING = set(ROWS["eval"]), set(ROWS["retiring"])


def _named(text: str) -> set[str]:
    """The fixture's non-primary row names that appear in ``text`` as a whole name."""
    return {
        n
        for names in ROWS.values()
        for n in names
        if re.search(rf"(?<![\w-]){re.escape(n)}(?![\w-])", text)
    }


def _doc() -> dict:
    return yaml.safe_load(FIXTURE.read_text(encoding="utf-8"))


def test_the_fixture_holds_every_tier():
    tiers = {s.name: s.standing for s in REG.rows(*STANDINGS)}
    assert set(tiers.values()) == set(STANDINGS)
    assert {n for n, t in tiers.items() if t != "primary"} == {n for v in ROWS.values() for n in v}
    assert sorted(REG.non_primary) == sorted(n for v in ROWS.values() for n in v)


# ------------------------------------------------------------------ the all-tiers golden render
def test_an_all_tiers_registry_renders_its_golden():
    on_disk = {p.relative_to(GOLDEN).as_posix() for p in GOLDEN.rglob("*") if p.is_file()}
    assert on_disk == set(FILES)
    for rel, text in FILES.items():
        assert (GOLDEN / rel).read_text(encoding="utf-8") == text, f"{rel} differs from golden"


#: every artefact a non-primary tier may appear in, and which (ADR-0039 decision 2); every other
#: generated file carries the primaries only
MAY_CARRY = {
    "dns/svc.example.internal.zone": {"eval", "retiring"},
    "hosts/hosts.block": {"eval", "retiring"},
    "env/_all.env.generated": {"eval", "retiring"},
    "prometheus/scrape_configs.yml": {"eval"},
    "blackbox/targets_http.yml": {"eval"},
    "blackbox/targets_tcp.yml": {"eval"},
    "idp/realm.json": {"eval"},
}


@pytest.mark.parametrize("rel", sorted(FILES))
def test_no_artefact_carries_a_tier_it_may_not_have(rel):
    allowed = {n for t in MAY_CARRY.get(rel, ()) for n in ROWS[t]}
    assert _named(FILES[rel]) <= allowed, rel
    # a non-primary row gets no file of its own (env, systemd drop-in)
    assert not _named(rel), rel


def test_a_legacy_row_reaches_no_artefact():
    assert not any("hub-oldlab" in t for t in FILES.values())


# ------------------------------------------------------------------ one rule per generator
#: generator -> the non-primary rows of the fixture its output names, exactly
TIER_RULE = {
    # a row-name address record for eval and retiring rows
    "dns_zone": EVAL | RETIRING,
    "hosts_file": EVAL | RETIRING,
    # HNX_ENDPOINT_<ROW> for eval and retiring rows (the aggregate env file)
    "env_files": EVAL | RETIRING,
    # metrics and uptime targets: primary and eval
    "prometheus": EVAL,
    "blackbox": EVAL,
    # clients for auth: idp rows that are primary or eval (kc-trial is auth: own)
    "idp_realm": {"hub-candidate"},
    # the edge: primaries only
    "caddy": set(),
    # bindings and the catalogue: primaries only (not widened by decision 2)
    "systemd_env": set(),
    "mcp_config": set(),
    "firewall_matrix": set(),
    "service_docs": set(),
}


def test_every_generator_has_a_tier_rule():
    assert set(TIER_RULE) == set(GENERATORS)


@pytest.mark.parametrize("gen", sorted(TIER_RULE))
def test_generator_tier_rule(gen):
    out = generate(REG, [gen])[gen]
    assert set().union(*(_named(t) for t in out.values())) == TIER_RULE[gen], gen


def test_dns_zone_gives_a_row_its_address_record_and_the_capability_alias_to_the_primary():
    zone = FILES["dns/svc.example.internal.zone"].splitlines()
    for name in EVAL | RETIRING:
        addr = REG.hosts[REG.row(name, *STANDINGS).host].address
        assert [ln for ln in zone if name in ln] == [f"{name} IN A {addr}"]
    # the capability alias, its SRV and TXT are the primary's alone
    assert [ln for ln in zone if ln.startswith("status-hub IN ")] == [
        "status-hub IN A " + REG.hosts["hub-core"].address
    ]
    assert sum(ln.startswith("_status-hub._tcp IN SRV ") for ln in zone) == 1
    assert sum(ln.startswith("_status-hub._tcp IN TXT ") for ln in zone) == 1
    assert [ln for ln in zone if ln.startswith("idp IN ")] == [
        "idp IN A " + REG.hosts["idp-core"].address
    ]


def test_endpoint_variables_name_a_rows_own_record():
    env = FILES["env/_all.env.generated"].splitlines()
    assert "HNX_ENDPOINT_STATUS_HUB=https://status-hub.svc.example.internal:" + "8443" in env
    assert "HNX_ENDPOINT_HUB_CANDIDATE=https://hub-candidate.svc.example.internal:" + "8443" in env
    assert "HNX_ENDPOINT_HUB_ROLLBACK=https://hub-rollback.svc.example.internal:" + "8443" in env
    assert not any(ln.startswith("HNX_ENDPOINT_HUB_OLDLAB") for ln in env)
    # a consumer's upstream is the primary
    reports = FILES["env/reports.env.generated"]
    assert "HNX_ENDPOINT_STATUS_HUB=https://status-hub.svc.example.internal:" + "8443" in reports
    assert "hub-" not in reports


def test_metrics_jobs_are_the_primaries_and_eval_rows_by_the_name_each_answers_by():
    prom = yaml.safe_load(FILES["prometheus/scrape_configs.yml"])
    jobs = {j["job_name"]: j["static_configs"][0]["targets"] for j in prom["scrape_configs"]}
    assert jobs == {
        "status-hub": ["status-hub.svc.example.internal:" + "8443"],
        "hub-candidate": ["hub-candidate.svc.example.internal:" + "8443"],
        "kc-trial": ["kc-trial.svc.example.internal:" + "9000"],
    }


def test_uptime_targets_are_the_primaries_and_eval_rows():
    http = yaml.safe_load(FILES["blackbox/targets_http.yml"])
    services = {t["labels"]["service"]: t["targets"] for t in http}
    assert services["hub-candidate"] == [
        "https://hub-candidate.svc.example.internal:" + "8443/healthz"
    ]
    assert services["kc-trial"] == ["https://kc-trial.svc.example.internal:" + "8443/health/ready"]
    primaries_with_http = {s.name for s in REG.sorted_services() if s.health["kind"] == "http"}
    assert set(services) == primaries_with_http | EVAL


def _realm(reg) -> dict:
    return json.loads(generate(reg, ["idp_realm"])["idp_realm"]["idp/realm.json"])


def test_the_realm_is_rendered_for_a_keycloak_eval_row_beside_another_primary():
    assert REG.by_capability("idp").impl != REALM_PRODUCT
    assert realm_idp(REG).name == "kc-trial" and realm_idp(REG).standing == "eval"
    realm = _realm(REG)
    clients = {c["clientId"]: c for c in realm["clients"]}
    # auth: idp rows that are primary or eval; the retiring and legacy ones get none
    assert set(clients) == {"auth-proxy", "status-hub", "hub-candidate"}
    # an eval row has no public route, so its client has no redirect
    assert clients["hub-candidate"]["redirectUris"] == []
    assert clients["hub-candidate"]["standardFlowEnabled"] is False
    # the auth proxy's callbacks are the primaries' public sites
    assert clients["auth-proxy"]["redirectUris"] == ["https://status.lab.example/oauth2/callback"]
    groups = {g["name"] for g in realm["groups"]}
    assert "hub-rollback-viewers" not in groups and "hub-oldlab-viewers" not in groups


def _with_idp_tiers(**tier_by_row) -> dict:
    """The fixture with ``kc-trial`` (Keycloak) given the tier named, or dropped (None)."""
    doc = _doc()
    for name, tier in tier_by_row.items():
        if tier is None:
            del doc["services"][name]
        elif tier == "primary":
            doc["services"][name].pop("standing")
        else:
            doc["services"][name]["standing"]["tier"] = tier
    return doc


@pytest.mark.parametrize("tier", ["retiring", "legacy", None])
def test_no_realm_is_rendered_when_no_primary_or_eval_row_is_its_product(tier):
    """A full render has no realm (and so prunes a stale one); asked for by name, it refuses."""
    reg = build_registry(_with_idp_tiers(**{"kc-trial": tier}))
    files = flatten(generate(reg))
    assert "idp/realm.json" not in files and "dns/svc.example.internal.zone" in files
    with pytest.raises(GeneratorRefusal, match="no primary or eval idp row has impl 'keycloak'"):
        generate(reg, ["idp_realm"])


def test_no_realm_is_rendered_for_a_hand_built_row_whose_standing_is_retiring():
    """The rule is on the standing, not on which of the two maps holds the row."""
    kc = dataclasses.replace(REG.non_primary["kc-trial"], standing="retiring")
    reg = dataclasses.replace(
        REG,
        services={**REG.services, "kc-trial": kc},
        non_primary={k: v for k, v in REG.non_primary.items() if k != "kc-trial"},
    )
    assert generate(reg)["idp_realm"] == {}
    with pytest.raises(GeneratorRefusal, match="no primary or eval idp row"):
        generate(reg, ["idp_realm"])


def test_the_realm_prefers_a_keycloak_primary_over_a_keycloak_eval():
    doc = _with_idp_tiers(idp=None)
    # a Keycloak upgrade under test, sorted before the primary: the primary still wins
    nxt = {**doc["services"]["kc-trial"], "port": 8444, "version": "27.0.0"}
    doc["services"]["kc-trial"].pop("standing")
    doc["services"] = {"aa-kc-next": nxt, **doc["services"]}
    reg = build_registry(doc)
    assert realm_idp(reg).name == "kc-trial" and realm_idp(reg).is_primary


def _edge(reg) -> str:
    return generate(reg, ["caddy"])["caddy"]["caddy/sites.caddy"]


def test_the_edge_auth_proxy_check_needs_a_primary():
    """A public auth: idp site behind an eval auth proxy would be published with no login the
    lab relies on, so the edge refuses, whichever of the two maps holds the eval row."""
    proxy = dataclasses.replace(REG.services["auth-proxy"], standing="eval")
    rest = {k: v for k, v in REG.services.items() if k != "auth-proxy"}
    held_back = dataclasses.replace(
        REG, services=rest, non_primary={**REG.non_primary, "auth-proxy": proxy}
    )
    mislabelled = dataclasses.replace(REG, services={**rest, "auth-proxy": proxy})
    for reg in (held_back, mislabelled):
        with pytest.raises(ValueError, match="no primary provides capability 'auth-proxy'"):
            _edge(reg)
    assert "import hnx_forward_auth hub-viewers" in _edge(REG)


def test_the_edge_publishes_no_non_primary_row():
    """A hand-built model is held to the rule the registry states: a non-primary row with a
    public hostname is not published."""
    cand = dataclasses.replace(REG.non_primary["hub-candidate"], public_hostname="next.lab.example")
    reg = dataclasses.replace(REG, services={**REG.services, "hub-candidate": cand})
    assert "next.lab.example" not in _edge(reg)
    assert "status.lab.example {" in _edge(reg)


# ------------------------------------------------------------------ the keyring (not a generator)
def test_keyring_rows_are_the_primaries_and_eval_rows():
    from homelabnext.agent.keyring import build_keyring

    zones = {
        r["principal"]: r for r in build_keyring(REG, [])["principals"] if r["kind"] == "network"
    }
    mgmt = zones["zone:mgmt"]
    granted = {g["resource"]: g["endpoint"] for g in mgmt["grants"]}
    assert granted["svc:hub-candidate"] == "hub-candidate.svc.example.internal"
    assert granted["svc:kc-trial"] == "kc-trial.svc.example.internal"
    assert granted["svc:status-hub"] == "status-hub.svc.example.internal"
    for row in zones.values():
        named = {g["resource"] for g in row["grants"]} | {d["resource"] for d in row["denials"]}
        assert {"svc:hub-rollback", "svc:hub-oldlab"} & named == set(), row["principal"]
        assert {"svc:hub-candidate", "svc:kc-trial"} <= named, row["principal"]


def test_an_upstream_reaches_the_primary_never_its_eval_row():
    """A zone reaches an eval row only as its own zone or a declared client: an upstream binds to
    the capability's primary (ADR-0039 decision 3)."""
    from homelabnext.agent.keyring import build_keyring

    doc = _doc()
    doc["services"]["edge-proxy"]["upstreams"] = ["idp"]
    reg = build_registry(doc)
    edge = next(r for r in build_keyring(reg, [])["principals"] if r["principal"] == "zone:edge")
    assert "svc:idp" in {g["resource"] for g in edge["grants"]}
    assert "svc:kc-trial" in {d["resource"] for d in edge["denials"]}


def test_the_realm_gives_a_non_primary_row_no_redirect_and_no_callback():
    """A hand-built model is held to it too: a redirect or an auth-proxy callback is under a
    public route, which is a primary's alone."""
    cand = dataclasses.replace(REG.non_primary["hub-candidate"], public_hostname="next.lab.example")
    reg = dataclasses.replace(REG, non_primary={**REG.non_primary, "hub-candidate": cand})
    clients = {c["clientId"]: c for c in _realm(reg)["clients"]}
    assert (
        clients["hub-candidate"]["redirectUris"] == [] and "rootUrl" not in clients["hub-candidate"]
    )
    assert not any("next.lab.example" in u for u in clients["auth-proxy"]["redirectUris"])
