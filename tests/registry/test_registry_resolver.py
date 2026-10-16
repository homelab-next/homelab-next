# SPDX-License-Identifier: Apache-2.0
"""Resolver order: env override, registry shape, DNS, hosts file; failures raise."""

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
