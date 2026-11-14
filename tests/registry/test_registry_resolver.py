# SPDX-License-Identifier: Apache-2.0
"""Resolver order: env override, registry shape, DNS, hosts file; failures raise."""

import dataclasses
import re
from pathlib import Path

import pytest

from homelabnext.registry import (
    FakeDNS,
    InvalidOverride,
    ResolutionError,
    Resolver,
    UnknownCapability,
    load,
    parse_hosts,
)

REG = load(Path(__file__).resolve().parents[2] / "examples" / "services.yml")
ALIAS = "lake-query.svc.example.internal"
ADDR = REG.hosts["lake-core"].address


def u(scheme, host, port):
    return f"{scheme}://{host}:{port}"


def make(env=None, dns=None, hosts=None, registry=REG, **kw):
    return Resolver(
        registry,
        dns=dns if dns is not None else FakeDNS(),
        hosts=hosts if hosts is not None else {},
        environ=env or {},
        **kw,
    )


def test_env_override_wins_and_skips_dns():
    dns = FakeDNS(a={ALIAS: [ADDR]})
    ep = make(
        env={"HNX_ENDPOINT_LAKE_QUERY": u("https", "staging-query.test", 9999)}, dns=dns
    ).resolve("lake-query")
    assert (ep.scheme, ep.host, ep.port, ep.source) == ("https", "staging-query.test", 9999, "env")
    assert dns.queries == []


def test_registry_shape_with_dns_answer():
    ep = make(dns=FakeDNS(a={ALIAS: [ADDR]})).resolve("lake-query")
    assert ep.url == u("https", ALIAS, 8443) and ep.source == "dns"


def test_url_names_alias_never_an_address():
    ep = make(dns=FakeDNS(a={ALIAS: [ADDR]})).resolve("lake-query")
    assert ADDR not in ep.url


def test_hosts_fallback_when_dns_silent():
    ep = make(hosts=parse_hosts(f"{ADDR} {ALIAS} lake-core.example.internal\n")).resolve(
        "lake-query"
    )
    assert ep.source == "hosts" and ep.url == u("https", ALIAS, 8443)


def test_dns_preferred_over_hosts():
    ep = make(dns=FakeDNS(a={ALIAS: [ADDR]}), hosts=parse_hosts(f"{ADDR} {ALIAS}")).resolve(
        "lake-query"
    )
    assert ep.source == "dns"


def test_unresolvable_raises_with_trail_and_never_defaults():
    with pytest.raises(ResolutionError) as exc:
        make().resolve("lake-query")
    msg = str(exc.value)
    assert "HNX_ENDPOINT_LAKE_QUERY" in msg and "dns" in msg and "hosts file" in msg
    assert ADDR not in msg and ":8443" not in msg.split("tried")[0]
    assert exc.value.trail


def test_unknown_capability():
    with pytest.raises(UnknownCapability):
        make().resolve("teleporter")


@pytest.mark.parametrize(
    "value",
    [
        "",
        "   ",
        "lake:8443",
        u("ftp", "x", 21),
        "https://host-without-port",
        "https://:8443",
        "nonsense",
    ],
)
def test_bad_override_is_rejected_not_ignored(value):
    with pytest.raises(InvalidOverride):
        make(env={"HNX_ENDPOINT_LAKE_QUERY": value}).resolve("lake-query")


def test_custom_env_var_name_is_honoured():
    import yaml

    from homelabnext.registry.model import build_registry

    doc = yaml.safe_load(
        (Path(__file__).resolve().parents[2] / "examples" / "services.yml").read_text()
    )
    doc["services"]["notify"]["env_var"] = "ALERT_SINK_URL"
    reg = build_registry(doc)
    ep = Resolver(
        reg, dns=FakeDNS(), hosts={}, environ={"ALERT_SINK_URL": u("http", "sink.test", 1)}
    ).resolve("notify")
    assert ep.source == "env" and ep.port == 1
    with pytest.raises(ResolutionError):  # the default name no longer applies
        Resolver(
            reg, dns=FakeDNS(), hosts={}, environ={"HNX_ENDPOINT_NOTIFY": u("http", "sink.test", 1)}
        ).resolve("notify")


def test_without_registry_uses_srv_and_txt():
    srv = "_lake-query._tcp.svc.example.internal"
    dns = FakeDNS(
        srv={srv: ("lake-query.svc.example.internal.", 8443)}, txt={srv: ["scheme=https"]}
    )
    ep = Resolver(domain="example.internal", dns=dns, hosts={}, environ={}).resolve("lake-query")
    assert ep.url == u("https", "lake-query.svc.example.internal", 8443) and ep.source == "dns"


def test_without_registry_no_srv_raises_even_if_hosts_has_alias():
    with pytest.raises(ResolutionError, match="no registry loaded"):
        Resolver(
            domain="example.internal",
            dns=FakeDNS(),
            hosts=parse_hosts(f"{ADDR} {ALIAS}"),
            environ={},
        ).resolve("lake-query")


def test_without_registry_srv_without_scheme_raises():
    srv = "_lake-query._tcp.svc.example.internal"
    with pytest.raises(ResolutionError, match="scheme"):
        Resolver(
            domain="example.internal",
            dns=FakeDNS(srv={srv: ("t.example.internal.", 1)}),
            hosts={},
            environ={},
        ).resolve("lake-query")


def test_without_registry_env_override_still_works():
    ep = Resolver(
        domain="example.internal",
        dns=FakeDNS(),
        hosts={},
        environ={"HNX_ENDPOINT_LAKE_QUERY": u("https", "q.test", 1)},
    ).resolve("lake-query")
    assert ep.source == "env"


def test_resolver_needs_registry_or_domain():
    with pytest.raises(ValueError):
        Resolver()


def test_zone_served_by_generated_dns_matches_resolver_expectations():
    """Resolver and dns_zone generator agree on alias, SRV and TXT naming."""
    from homelabnext.generators import generate

    zone = generate(REG, ["dns_zone"])["dns_zone"]["dns/svc.example.internal.zone"]
    assert "lake-query IN A" in zone
    assert "_lake-query._tcp IN SRV 0 0 8443 lake-query.svc.example.internal." in zone
    assert '_lake-query._tcp IN TXT "scheme=https"' in zone


def test_parse_hosts_handles_comments_and_blank_lines():
    h = parse_hosts(f"# c\n\n{ADDR} A.example.internal b  # trailing\nbroken\n")
    assert h == {"a.example.internal": [ADDR], "b": [ADDR]}


# ---- ADR-0039 decision 2: a capability answers by its primary, a row by its own name ----------
TIERS = load(
    Path(__file__).resolve().parents[2] / "tests/generators/fixtures/all-tiers.services.yml"
)
HUB, CAND = "status-hub.svc.example.internal", "hub-candidate.svc.example.internal"
#: a DNS answering every name a row could have, the legacy row's included
EVERY_NAME = {
    f"{s.name if not s.is_primary else s.capability}.svc.example.internal": [
        TIERS.hosts[s.host].address
    ]
    for s in TIERS.rows("primary", "eval", "retiring", "legacy")
}


def test_an_eval_row_is_reachable_by_its_row_name_and_never_by_the_capability_alias():
    r = make(registry=TIERS, dns=FakeDNS(a=EVERY_NAME))
    ep = r.resolve_row("hub-candidate")
    assert ep.url == u("https", CAND, 8443) and ep.source == "dns"
    # the capability alias is the primary's, whatever rows share the capability
    assert r.resolve("status-hub").url == u("https", HUB, 8443)
    # and a row name is no capability: the error says so and names the way to reach it
    with pytest.raises(UnknownCapability, match=r"is an eval row, not a capability.*--row"):
        r.resolve("hub-candidate")
    with pytest.raises(UnknownCapability, match=r"is a retiring row, not a capability"):
        r.resolve("hub-rollback")


def test_a_row_name_override_is_its_own_variable_never_the_capabilitys():
    env = {"HNX_ENDPOINT_HUB_CANDIDATE": u("https", "shadow.test", 9443)}
    r = make(registry=TIERS, env=env, dns=FakeDNS(a=EVERY_NAME))
    assert r.resolve_row("hub-candidate").url == u("https", "shadow.test", 9443)
    assert r.resolve("status-hub").url == u("https", HUB, 8443)
    env = {"HNX_ENDPOINT_STATUS_HUB": u("https", "break-glass.test", 9443)}
    r = make(registry=TIERS, env=env, dns=FakeDNS(a=EVERY_NAME))
    assert r.resolve_row("hub-candidate").url == u("https", CAND, 8443)


def test_a_retiring_row_is_reachable_by_its_row_name_through_the_hosts_fallback():
    hosts = parse_hosts(TIERS.hosts["prev-core"].address + " hub-rollback.svc.example.internal\n")
    ep = make(registry=TIERS, hosts=hosts).resolve_row("hub-rollback")
    assert ep.source == "hosts" and ep.url == u("https", "hub-rollback.svc.example.internal", 8443)


@pytest.mark.parametrize(
    "name,why",
    [
        ("hub-oldlab", "a legacy row answers by no name"),
        ("status-hub", "a primary answers by its capability; resolve 'status-hub'"),
        ("reports", "a primary answers by its capability"),
        ("nope", "no such registry row"),
    ],
)
def test_resolve_row_refuses_a_legacy_row_a_primary_and_an_unknown_name(name, why):
    with pytest.raises(UnknownCapability, match=re.escape(why)):
        make(registry=TIERS, dns=FakeDNS(a=EVERY_NAME)).resolve_row(name)


def test_resolve_row_needs_a_registry():
    with pytest.raises(ResolutionError, match="only with a registry"):
        make(registry=None, domain="example.internal").resolve_row("hub-candidate")


def test_a_capability_with_no_primary_names_its_rows():
    reg = dataclasses.replace(
        TIERS, services={k: v for k, v in TIERS.services.items() if k != "status-hub"}
    )
    with pytest.raises(UnknownCapability, match=r"no primary .*hub-candidate.*answer only by"):
        make(registry=reg).resolve("status-hub")


def test_a_row_lookup_names_a_row_not_a_capability():
    """resolve_row's errors are about a row (the capability wording would send a reader to the
    wrong table), the override and DNS failures included."""
    r = make(registry=TIERS)
    for name in ("hub-oldlab", "nope", "hub-candidate"):
        with pytest.raises(ResolutionError) as ei:
            r.resolve_row(name)
        assert str(ei.value).startswith(f"cannot resolve row {name!r}: "), ei.value
        assert ei.value.what == "row"
    env = {"HNX_ENDPOINT_HUB_CANDIDATE": "not a url"}
    with pytest.raises(InvalidOverride, match=r"^cannot resolve row 'hub-candidate'"):
        make(registry=TIERS, env=env).resolve_row("hub-candidate")
    with pytest.raises(ResolutionError, match=r"^cannot resolve capability 'status-hub'"):
        r.resolve("status-hub")
