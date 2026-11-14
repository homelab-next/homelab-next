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
