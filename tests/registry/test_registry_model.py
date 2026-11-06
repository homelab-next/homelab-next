# SPDX-License-Identifier: Apache-2.0
"""Registry format: the example is valid, every kind of defect is refused."""

import copy
import ipaddress
from pathlib import Path

import pytest
import yaml

from homelabnext.registry import RegistryError, load, loads

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "examples" / "services.yml"
DOC_NETS = [
    ipaddress.ip_network(".".join(o) + "/24")
    for o in (("192", "0", "2", "0"), ("198", "51", "100", "0"), ("203", "0", "113", "0"))
]


def base_doc():
    return yaml.safe_load(EXAMPLE.read_text(encoding="utf-8"))


def test_example_loads_and_counts():
    reg = load(EXAMPLE)
    assert len(reg.services) == 21
    assert reg.alias("lake-query") == "lake-query.svc.example.internal"
    assert reg.by_capability("lake-query").scheme == "https"
    assert reg.by_capability("inference").scheme == "http"
    assert reg.by_capability("events").scheme == "nats"


def test_example_uses_only_documentation_ranges_and_reserved_names():
    doc = base_doc()
    for host in doc["hosts"].values():
        assert any(ipaddress.ip_address(host["address"]) in n for n in DOC_NETS)
    for z in doc["zones"].values():
        assert any(ipaddress.ip_network(z["cidr"]).subnet_of(n) for n in DOC_NETS)
    assert doc["lab"]["domain"] == "example.internal"
    for s in doc["services"].values():
        if "public_hostname" in s:
            assert s["public_hostname"].endswith(".lab.example")


def test_digest_is_stable_and_content_sensitive():
    a = load(EXAMPLE)
    assert a.digest == load(EXAMPLE).digest
    doc = base_doc()
    doc["services"]["notify"]["version"] = "2.12"
    from homelabnext.registry.model import build_registry

    assert build_registry(doc).digest != a.digest


def mutate(fn):
    doc = copy.deepcopy(base_doc())
    fn(doc)
    return doc


NEGATIVES = {
    "unknown-host": (lambda d: d["services"]["notify"].update(host="nowhere"), "unknown host"),
    "duplicate-capability": (
        lambda d: d["services"]["metrics"].update(capability="notify"),
        "already provided",
    ),
    "duplicate-port-on-host": (
        lambda d: d["services"]["metrics"].update(port=8080),
        "already used",
    ),
    "unknown-upstream": (
        lambda d: d["services"]["metrics"].update(upstreams=["ghost"]),
        "not a registered capability",
    ),
    "self-upstream": (
        lambda d: d["services"]["metrics"].update(upstreams=["metrics"]),
        "itself as upstream",
    ),
    "bad-version": (lambda d: d["services"]["metrics"].update(version="latest"), "version"),
    "extra-field": (lambda d: d["services"]["metrics"].update(colour="red"), "colour"),
    "missing-owner": (lambda d: d["services"]["metrics"].pop("owner"), "owner"),
    "port-out-of-range": (lambda d: d["services"]["metrics"].update(port=70000), "port"),
    "bad-protocol": (
        lambda d: d["services"]["metrics"].update(protocol="carrier-pigeon"),
        "protocol",
    ),
    "address-outside-zone": (
        lambda d: d["hosts"]["mon-core"].update(address=".".join(("203", "0", "113", "99"))),
        "outside zone",
    ),
    "duplicate-address": (
        lambda d: d["hosts"]["mon-core"].update(address=base_doc()["hosts"]["dns-core"]["address"]),
        "already used",
    ),
    "unknown-zone": (lambda d: d["hosts"]["mon-core"].update(zone="moon"), "unknown zone"),
    "unknown-client-zone": (
        lambda d: d["services"]["notify"].update(clients=["moon"]),
        "unknown zone",
    ),
    "http-health-without-path": (
        lambda d: d["services"]["notify"].update(health={"kind": "http"}),
        "path",
    ),
    "duplicate-public-hostname": (
        lambda d: d["services"]["idp"].update(public_hostname="dashboards.lab.example"),
        "public_hostname",
    ),
    "mcp-on-non-http": (
        lambda d: d["services"]["events"].update(mcp={"name": "bus"}),
        "mcp requires",
    ),
    "duplicate-mcp-name": (
        lambda d: d["services"]["agent-runtime"]["mcp"].update(name="lake"),
        "mcp name",
    ),
    "wrong-registry-version": (lambda d: d.update(registry_version=2), "registry_version"),
    "bad-domain": (lambda d: d["lab"].update(domain="nodots"), "domain"),
    "env-var-collision": (
        lambda d: d["services"]["metrics"].update(env_var="HNX_ENDPOINT_NOTIFY"),
        "env var",
    ),
    # a public route needs auth (the same rule and message as a module's rows, rules.py)
    "public-route-without-auth": (
        lambda d: d["services"]["inference"].update(public_hostname="inference.lab.example"),
        "service inference: a public route needs auth",
    ),
    "public-route-auth-none": (
        lambda d: d["services"]["inference"].update(
            public_hostname="inference.lab.example", auth="none"
        ),
        "service inference: a public route needs auth",
    ),
    "public-route-auth-mtls": (
        lambda d: d["services"]["inference"].update(
            public_hostname="inference.lab.example", auth="mtls"
        ),
        "mtls is never checked",
    ),
    "overlapping-zone-cidrs": (
        lambda d: d["zones"]["data"].update(cidr=d["zones"]["mgmt"]["cidr"]),
        "overlaps zone",
    ),
    "zone-cidr-inside-another": (
        lambda d: d["zones"]["edge"].update(
            cidr=str(next(ipaddress.ip_network(d["zones"]["mgmt"]["cidr"]).subnets(new_prefix=28)))
        ),
        "overlaps zone",
    ),
}


@pytest.mark.parametrize("name", sorted(NEGATIVES))
def test_negative_is_refused(name):
    fn, needle = NEGATIVES[name]
    from homelabnext.registry.model import build_registry

    with pytest.raises(RegistryError) as exc:
        build_registry(mutate(fn))
    assert needle in str(exc.value)
    assert exc.value.problems


def test_duplicate_yaml_key_is_refused():
    text = EXAMPLE.read_text(encoding="utf-8").replace(
        "  notify:\n    capability: notify",
        "  notify:\n    capability: notify\n    capability: notify2",
        1,
    )
    with pytest.raises(RegistryError, match="duplicate key"):
        loads(text)


def test_not_yaml_and_not_mapping_and_missing_file(tmp_path):
    with pytest.raises(RegistryError):
        loads("a: [unclosed")
    with pytest.raises(RegistryError):
        loads("- just\n- a list\n")
    with pytest.raises(RegistryError, match="cannot read"):
        load(tmp_path / "absent.yml")


def test_schema_file_is_valid_json_schema():
    import jsonschema

    from homelabnext.registry.model import schema

    jsonschema.Draft202012Validator.check_schema(schema())


def test_two_secret_references_with_one_env_name_are_refused():
    """``secret_env_name`` maps every non-alphanumeric to ``_``, so ``nifi/status-token`` and
    ``nifi/status_token`` both arrive in ``HNX_SECRET_NIFI_STATUS_TOKEN``: one would silently get
    the other's value.  The registry refuses the pair (the mapping is documented and in use)."""
    doc = base_doc()
    loads(yaml.safe_dump(doc))  # the same reference twice is fine: one secret
    hub = doc["services"]["status-hub"]
    hub["front_door"]["secret"] = "secret:nifi/status_token"
    with pytest.raises(RegistryError, match="HNX_SECRET_NIFI_STATUS_TOKEN"):
        loads(yaml.safe_dump(doc))


@pytest.mark.parametrize("auth", ["own", "idp"])
def test_a_public_route_with_its_own_login_or_the_idp_is_accepted(auth):
    from homelabnext.registry.model import build_registry

    pub = {"public_hostname": "inference.lab.example", "auth": auth}
    reg = build_registry(mutate(lambda d: d["services"]["inference"].update(pub)))
    assert reg.services["inference"].public_hostname == "inference.lab.example"


def test_two_spellings_of_one_ipv6_host_address_are_one_address():
    from homelabnext.registry.model import semantic_problems

    def v6(d):
        d["zones"]["v6"] = {"cidr": "2001:db8::/64"}
        d["hosts"]["a6"] = {"address": "2001:db8::10", "zone": "v6"}
        d["hosts"]["b6"] = {"address": "2001:db8:0:0::10", "zone": "v6"}

    problems = semantic_problems(mutate(v6))
    assert "host b6: address 2001:db8:0:0::10 already used by a6" in problems


def test_an_ipv4_and_an_ipv6_zone_never_overlap():
    # pins the stdlib behaviour the overlap loop relies on (no version guard): ipaddress never
    # reports an IPv4 and an IPv6 network as overlapping
    from homelabnext.registry.model import semantic_problems

    doc = mutate(lambda d: d["zones"].update(v6={"cidr": "2001:db8::/64"}))
    assert not [p for p in semantic_problems(doc) if "overlaps" in p]


@pytest.mark.parametrize(
    "path", [ROOT / "examples" / "services.yml", ROOT / "examples" / "minimal" / "services.yml"]
)
def test_every_public_site_of_the_examples_has_a_login(path):
    from homelabnext.generators import flatten, generate

    reg = load(path)
    # every generator's output: the edge's site file is the one with a "<host> {" block
    out = "".join(flatten(generate(reg)).values())
    for s in reg.sorted_services():
        if s.public_hostname:
            assert s.auth in ("idp", "own"), s.name
            if s.auth == "idp":
                site = out.split(s.public_hostname + " {", 1)[1].split("\n}\n", 1)[0]
                assert "import hnx_forward_auth" in site, s.name


def test_an_ipv4_mapped_zone_or_host_address_is_refused():
    """An IPv4-mapped IPv6 zone or address names an IPv4 address a second time, so it would get
    past the zone-overlap and duplicate-address checks next to the IPv4 zone it shadows."""
    from homelabnext.registry.model import semantic_problems

    def mapped(d):
        v4 = ipaddress.ip_network(d["zones"]["mgmt"]["cidr"])
        d["zones"]["m6"] = {"cidr": f"::ffff:{v4.network_address}/{96 + v4.prefixlen}"}
        d["hosts"]["m6host"] = {"address": f"::ffff:{v4.network_address + 9}", "zone": "mgmt"}

    problems = semantic_problems(mutate(mapped))
    assert any(p.startswith("zone m6: cidr ") and "IPv4-mapped" in p for p in problems), problems
    assert any(p.startswith("host m6host: address ") and "IPv4-mapped" in p for p in problems), (
        problems
    )
