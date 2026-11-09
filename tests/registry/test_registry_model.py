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
        "capability notify has two primaries: notify, metrics",
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
        lambda d: d["services"]["orchestrator"]["mcp"].update(name="lake"),
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


# 2.9 (ADR-0039): a row's standing; at most one primary per capability ----------------------


def _row(base, **over):
    row = copy.deepcopy(base)
    row.update(over)
    return row


def _eval_notify(tier="eval", **over):
    """A second ``notify`` row beside the example's primary: a candidate on its own port."""

    def fn(d):
        d["services"]["notify"]["tlp_ceiling"] = "amber"
        row = {
            "capability": "notify",
            "impl": "notifier-b",
            "host": d["services"]["notify"]["host"],
            "protocol": "http",
            "port": 8081,
            "owner": "platform-team",
            "version": "2.6",
            "tls": "none",
            "standing": {"tier": tier, "until": "2026-12-31", "why": "a candidate under test"},
            "tlp_ceiling": "green",
        }
        row.update(over)
        d["services"]["notify-candidate"] = row

    return fn


def _problems(doc):
    from homelabnext.registry.model import schema_problems, semantic_problems

    return schema_problems(doc) or semantic_problems(doc)


@pytest.mark.parametrize("tier", ["eval", "retiring", "legacy"])
def test_a_non_primary_row_shares_its_primarys_capability(tier):
    from homelabnext.registry.model import build_registry

    reg = build_registry(mutate(_eval_notify(tier)))
    row = reg.non_primary["notify-candidate"]
    assert (row.capability, row.standing, row.until) == ("notify", tier, "2026-12-31")
    assert row.why == "a candidate under test" and not row.is_primary
    assert reg.services["notify"].standing == "primary" and reg.services["notify"].is_primary
    # held back from every consumer until ADR-0039 step 3 widens each by tier
    assert "notify-candidate" not in reg.services and reg.by_capability("notify").name == "notify"


def test_an_explicit_primary_standing_is_the_default():
    def fn(d):
        d["services"]["notify"]["standing"] = {"tier": "primary"}

    assert _problems(mutate(fn)) == []


def test_two_non_primary_rows_of_one_capability_are_fine():
    def fn(d):
        _eval_notify()(d)
        d["services"]["notify-old"] = _row(
            d["services"]["notify-candidate"], impl="notifier-c", port=8082
        )

    assert _problems(mutate(fn)) == []


def test_a_second_explicit_primary_is_refused():
    def fn(d):
        _eval_notify()(d)
        d["services"]["notify-candidate"]["standing"] = {"tier": "primary"}

    problems = _problems(mutate(fn))
    assert "capability notify has two primaries: notify, notify-candidate" in problems
    # one defect, one line: the shared name and variable of the two primaries are not repeated
    assert not [p for p in problems if "already used by" in p], problems


@pytest.mark.parametrize("missing", ["until", "why"])
def test_a_non_primary_row_needs_until_and_why(missing):
    def fn(d):
        _eval_notify()(d)
        del d["services"]["notify-candidate"]["standing"][missing]

    assert any(missing in p for p in _problems(mutate(fn)))


def test_until_is_a_calendar_date():
    def fn(d):
        _eval_notify()(d)
        d["services"]["notify-candidate"]["standing"]["until"] = "2026-02-30"

    assert any("is not a calendar date" in p for p in _problems(mutate(fn)))


@pytest.mark.parametrize(
    "cap",
    [
        "notify-legacy",
        "notify-old",
        "notify-new",
        "notify-next",
        "notify-eval",
        "notify-test",
        "notify-candidate",
        "notify-v2",
    ],
)
def test_a_capability_name_carries_no_tier(cap):
    def fn(d):
        d["services"]["notify"]["capability"] = cap

    assert any("carries a tier in its name" in p for p in _problems(mutate(fn)))


@pytest.mark.parametrize("cap", ["dns-secondary", "dns-tertiary", "dns-replica"])
def test_a_replica_suffix_needs_replica_of(cap):
    def bare(d):
        d["services"]["dns2"] = _row(d["services"]["dns"], capability=cap, host="mon-core")

    def declared(d):
        bare(d)
        d["services"]["dns2"]["replica_of"] = "dns"

    assert any("declare replica_of" in p for p in _problems(mutate(bare)))
    assert _problems(mutate(declared)) == []


def test_replica_of_names_a_primary_of_the_same_impl():
    def replica(**over):
        def fn(d):
            d["services"]["dns2"] = _row(
                d["services"]["dns"],
                capability="dns-secondary",
                host="mon-core",
                **{"replica_of": "dns", **over},
            )

        return _problems(mutate(fn))

    assert any("needs the primary's impl" in p for p in replica(impl="unbound"))
    assert not replica()  # the same impl
    # a replica capability is named for what it replicates
    assert any(
        "named for what it replicates: dns-secondary" in p
        for p in _problems(
            mutate(
                lambda d: d["services"].update(
                    dns2=_row(
                        d["services"]["dns"],
                        capability="zone-secondary",
                        host="mon-core",
                        replica_of="dns",
                    )
                )
            )
        )
    )

    def no_impl(d):
        d["services"]["dns"].pop("impl")
        d["services"]["dns2"] = _row(
            d["services"]["dns"], capability="dns-secondary", host="mon-core", replica_of="dns"
        )

    assert any("needs an impl on both rows" in p for p in _problems(mutate(no_impl)))
    assert any("has no primary" in p for p in replica(replica_of="ghost"))
    assert any("names its own capability" in p for p in replica(replica_of="dns-secondary"))

    def eval_only(d):  # the named capability's only row is not a primary
        d["services"]["dns"]["standing"] = {"tier": "eval", "until": "2026-12-31", "why": "trial"}
        d["services"]["dns2"] = _row(
            d["services"]["dns"], capability="dns-secondary", host="mon-core", replica_of="dns"
        )
        del d["services"]["dns2"]["standing"]

    assert any("replica_of 'dns' has no primary" in p for p in _problems(mutate(eval_only)))


@pytest.mark.parametrize("tier", ["eval", "retiring", "legacy"])
def test_public_hostname_is_for_a_primary_row_only(tier):
    problems = _problems(
        mutate(_eval_notify(tier, public_hostname="notify2.lab.example", auth="own"))
    )
    assert (
        f"service notify-candidate: public_hostname is for a primary row only, not a {tier} one"
        in problems
    )


@pytest.mark.parametrize("tier", ["eval", "retiring"])
def test_a_non_primary_egress_row_is_held_to_the_primarys_ceiling(tier):
    assert _problems(mutate(_eval_notify(tier, tlp_ceiling="amber"))) == []  # equal: fine
    above = _problems(mutate(_eval_notify(tier, tlp_ceiling="red")))
    assert "service notify-candidate: tlp_ceiling red is above the primary's (amber)" in above

    def undeclared(d):
        _eval_notify(tier)(d)
        del d["services"]["notify-candidate"]["tlp_ceiling"]

    assert any("declares its own tlp_ceiling" in p for p in _problems(mutate(undeclared)))

    def primary_undeclared(d):
        _eval_notify(tier)(d)
        del d["services"]["notify"]["tlp_ceiling"]

    assert any(
        "no primary of 'notify' declares one" in p for p in _problems(mutate(primary_undeclared))
    )


def test_a_legacy_egress_row_needs_no_ceiling():
    def fn(d):
        _eval_notify("legacy")(d)
        del d["services"]["notify-candidate"]["tlp_ceiling"]

    assert _problems(mutate(fn)) == []


def test_auth_idp_needs_a_primary_idp():
    def fn(d):
        d["services"]["idp"]["standing"] = {"tier": "eval", "until": "2026-12-31", "why": "trial"}
        d["services"]["idp"].pop("public_hostname")

    problems = _problems(mutate(fn))
    assert any("auth=idp but no primary provides capability 'idp'" in p for p in problems)


def test_an_upstream_needs_a_primary():
    def fn(d):
        d["services"]["notify"]["standing"] = {
            "tier": "retiring",
            "until": "2026-12-31",
            "why": "replaced",
        }

    problems = _problems(mutate(fn))
    assert any("upstream 'notify' has no primary" in p for p in problems), problems


def test_an_eval_row_named_like_another_capability_is_refused():
    def fn(d):
        _eval_notify()(d)
        d["services"]["dashboards-app"] = d["services"].pop("dashboards")  # the dashboards primary
        # the eval notify row is named "dashboards": its row-named record and variable would be
        # the dashboards primary's
        d["services"]["dashboards"] = d["services"].pop("notify-candidate")

    problems = _problems(mutate(fn))
    assert (
        "service dashboards: alias-zone name 'dashboards' already used by dashboards-app"
        in problems
    )


def test_a_legacy_row_answers_by_no_name():
    def fn(d):
        _eval_notify("legacy")(d)
        # the metrics primary's row has another name, and the legacy notify row is named
        # "metrics", like that capability: harmless, as a legacy row gets no record or variable
        d["services"]["metrics-server"] = d["services"].pop("metrics")
        d["services"]["metrics"] = d["services"].pop("notify-candidate")

    doc = mutate(fn)
    assert doc["services"]["metrics"]["capability"] == "notify"
    assert doc["services"]["metrics-server"]["capability"] == "metrics"
    assert _problems(doc) == []

    def as_eval(d):  # the same name on an eval row answers by it, so it is refused
        fn(d)
        d["services"]["metrics"]["standing"]["tier"] = "eval"

    assert any("alias-zone name 'metrics' already used by" in p for p in _problems(mutate(as_eval)))


@pytest.mark.parametrize("field", ["until", "why"])
def test_until_and_why_are_refused_on_a_primary(field):
    def fn(d):
        value = "2026-12-31" if field == "until" else "the decided product"
        d["services"]["notify"]["standing"] = {"tier": "primary", field: value}

    assert any(f"standing {field} is for a non-primary row" in p for p in _problems(mutate(fn)))


def test_a_self_upstream_is_reported_before_a_missing_primary():
    def fn(d):
        d["services"]["metrics"]["standing"] = {
            "tier": "eval",
            "until": "2026-12-31",
            "why": "trial",
        }
        d["services"]["metrics"]["upstreams"] = ["metrics"]

    problems = [p for p in _problems(mutate(fn)) if p.startswith("service metrics:")]
    assert any("lists itself as upstream" in p for p in problems), problems
    assert not any("upstream 'metrics' has no primary" in p for p in problems), problems
