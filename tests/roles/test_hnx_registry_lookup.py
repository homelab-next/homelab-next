# SPDX-License-Identifier: Apache-2.0
"""The ``hnx_registry`` lookup plugin, called directly (the role renders exercise it end to end)."""

import importlib.util
from pathlib import Path

import pytest

pytest.importorskip("ansible.errors")  # the repo's own ansible/ dir also imports as "ansible"
from ansible.errors import AnsibleLookupError

PLUGIN = Path(__file__).resolve().parents[2] / "ansible/plugins/lookup/hnx_registry.py"


@pytest.fixture
def lookup(tmp_path):
    spec = importlib.util.spec_from_file_location("hnx_registry", PLUGIN)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    reg = tmp_path / "registry.yml"
    reg.write_text(
        "services:\n"
        "  query-core: {host: query.example.test, port: 8443, scheme: https,"
        " public_hostname: query.lab.example}\n"
        "  bus-core: {host: bus.example.test, port: 4222, scheme: tcp}\n"
        "  no-port: {host: x.example.test, scheme: udp}\n"
        "  no-host: {port: 53}\n"
        "  not-a-row: just text\n"
    )
    plugin = mod.LookupModule()
    return lambda terms, **kw: plugin.run(terms, {"hnx_registry_file": str(reg)}, **kw)


def test_url_host_and_port(lookup):
    want = "https://query.example.test:8443"  # no-raw-endpoint: allow the lookup's own output
    assert lookup(["query-core"]) == [want]
    assert lookup(["query-core", "bus-core"], field="host") == [
        "query.example.test",
        "bus.example.test",
    ]
    assert lookup(["bus-core"], field="port") == [4222]
    assert lookup(["query-core"], field="public_hostname") == ["query.lab.example"]


@pytest.mark.parametrize(
    ("terms", "kwargs", "message"),
    [
        (["nope"], {}, "unknown service id 'nope'"),
        (["query-core"], {"field": "scheme"}, "unknown field 'scheme'"),
        # a row missing what the field needs is refused by name, never a bare KeyError
        (["no-port"], {}, "service 'no-port' has no port"),
        (["no-port"], {"field": "port"}, "service 'no-port' has no port"),
        (["no-host"], {"field": "host"}, "service 'no-host' has no host"),
        (["bus-core"], {"field": "public_hostname"}, "service 'bus-core' has no public_hostname"),
        (["no-host"], {}, "service 'no-host' has no host"),
        (["not-a-row"], {}, "service 'not-a-row' is not a mapping"),
    ],
)
def test_refusals(lookup, terms, kwargs, message):
    with pytest.raises(AnsibleLookupError, match=message):
        lookup(terms, **kwargs)


def test_registry_file_must_be_set_and_readable(tmp_path):
    spec = importlib.util.spec_from_file_location("hnx_registry", PLUGIN)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    with pytest.raises(AnsibleLookupError, match="hnx_registry_file is not set"):
        mod.LookupModule().run(["query-core"], {})
    with pytest.raises(AnsibleLookupError, match="cannot read registry"):
        mod.LookupModule().run(["query-core"], {"hnx_registry_file": str(tmp_path / "missing")})


def test_a_templated_registry_path_is_resolved(tmp_path):
    """An overlay inventory names the registry relative to itself (``{{ inventory_dir }}/...``):
    the lookup templates the variable it is handed before opening it."""
    from ansible.parsing.dataloader import DataLoader
    from ansible.template import Templar, trust_as_template

    spec = importlib.util.spec_from_file_location("hnx_registry", PLUGIN)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    (tmp_path / "registry.yml").write_text("services:\n  bus: {host: b.example.test, port: 4222}\n")
    # an inventory's value is trusted as a template (ansible-core 2.19+); a lookup gets it as written
    variables = {
        "base_dir": str(tmp_path),
        "hnx_registry_file": trust_as_template("{{ base_dir }}/registry.yml"),
    }
    loader = DataLoader()
    plugin = mod.LookupModule(loader=loader, templar=Templar(loader=loader, variables=variables))
    assert plugin.run(["bus"], variables, field="port") == [4222]


# ------------------------------------------------ the platform shape (protocol/tls, a hosts map)
PLATFORM = """\
lab: {name: demo, domain: example.internal, svc_label: svc, owner: platform-team}
hosts:
  hnx-apps-01: {zone: mgmt}
services:
  alert: {capability: notify, host: hnx-apps-01, protocol: http, port: 80, tls: none}
  alert-tls: {capability: notify-tls, host: hnx-apps-01, protocol: http, port: 443, tls: internal}
  gateway: {capability: llm-gateway, host: hnx-apps-01, protocol: https, port: 4000, tls: public}
  bus: {capability: events, host: hnx-apps-01, protocol: nats, port: 4222, tls: none}
  alert-eval: {capability: notify, host: hnx-apps-01, protocol: http, port: 8080, tls: none,
              standing: {tier: eval, until: "2027-01-01", why: trial}}
  alert-old: {capability: notify, host: hnx-apps-01, protocol: http, port: 81, tls: none,
             standing: {tier: legacy, until: "2027-01-01", why: old lab}}
  lost: {capability: lost, host: hnx-gone-01, protocol: http, port: 80, tls: none}
"""


@pytest.fixture
def platform(tmp_path):
    spec = importlib.util.spec_from_file_location("hnx_registry", PLUGIN)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    reg = tmp_path / "platform.yml"
    reg.write_text(PLATFORM)
    plugin = mod.LookupModule()
    return lambda terms, **kw: plugin.run(terms, {"hnx_registry_file": str(reg)}, **kw)


def test_a_platform_row_takes_its_scheme_from_protocol_and_tls_and_names_its_alias(platform):
    # protocol http + tls none: plain http, on the alias a client resolves, never the host id
    zone = "svc.example.internal"
    want = {  # row: (scheme, the label it answers by, port)
        "alert": ("http", "notify", 80),
        "alert-tls": ("https", "notify-tls", 443),
        "gateway": ("https", "llm-gateway", 4000),
        "bus": ("nats", "events", 4222),
        "alert-eval": ("http", "alert-eval", 8080),
    }
    for row, (scheme, label, port) in want.items():
        assert platform([row]) == [f"{scheme}://{label}.{zone}:{port}"], row
    assert platform(["alert"], field="host") == ["notify.svc.example.internal"]
    assert platform(["alert"], field="port") == [80]


@pytest.mark.parametrize(
    ("terms", "message"),
    [
        (["nope"], "unknown service id 'nope'"),
        (["lost"], "names host 'hnx-gone-01', which is not in the registry's hosts map"),
        (["alert-old"], "is a legacy row: it answers by no name"),
    ],
)
def test_a_platform_row_with_an_unknown_host_or_no_name_is_refused(platform, terms, message):
    with pytest.raises(AnsibleLookupError, match=message):
        platform(terms)


def test_the_scheme_agrees_with_the_registry_model_for_every_protocol_and_tls():
    """The plugin restates ``Service.scheme`` so it needs only PyYAML; this pins the two."""
    model = pytest.importorskip("homelabnext.registry.model")
    spec = importlib.util.spec_from_file_location("hnx_registry", PLUGIN)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    for protocol in ("http", "https", "grpc", "tcp", "udp", "postgres", "nats", "dns", "ssh"):
        for tls in ("none", "internal", "public", "mtls"):
            svc = model.Service(
                name="x", capability="x", host="h", protocol=protocol, port=1,
                owner="o", version="1", tls=tls,
            )  # fmt: skip
            assert mod._platform_scheme({"protocol": protocol, "tls": tls}) == svc.scheme


def test_impl_is_the_product_that_provides_the_capability(platform, tmp_path):
    """Two kinds of provider can answer one capability (a gateway and an engine behind it): the
    row's ``impl`` tells them apart; a row that does not say reads empty."""
    reg = tmp_path / "impl.yml"
    reg.write_text(
        PLATFORM + "  front: {capability: inference, impl: gate, host: hnx-apps-01, protocol: http,"
        " port: 4100, tls: none}\n"
    )
    spec = importlib.util.spec_from_file_location("hnx_registry", PLUGIN)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    run = mod.LookupModule().run
    assert run(["front"], {"hnx_registry_file": str(reg)}, field="impl") == ["gate"]
    assert run(["alert"], {"hnx_registry_file": str(reg)}, field="impl") == [""]


def test_host_id_is_the_placement_while_host_stays_the_alias(platform):
    """Placement is not addressing: ``host_id`` is the row's logical host id, ``host`` its alias."""
    assert platform(["alert", "bus"], field="host_id") == ["hnx-apps-01", "hnx-apps-01"]
    assert platform(["alert"], field="host") == ["notify.svc.example.internal"]


def test_host_id_of_a_row_outside_the_hosts_map_is_refused(platform):
    with pytest.raises(AnsibleLookupError, match="'lost' names host 'hnx-gone-01'"):
        platform(["lost"], field="host_id")


def test_host_id_in_the_stub_shape_is_the_rows_host(lookup):
    assert lookup(["query-core", "bus-core"], field="host_id") == [
        "query.example.test",
        "bus.example.test",
    ]
    with pytest.raises(AnsibleLookupError, match="service 'no-host' has no host"):
        lookup(["no-host"], field="host_id")
