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
        "  query-core: {host: query.example.test, port: 8443, scheme: https}\n"
        "  bus-core: {host: bus.example.test, port: 4222, scheme: tcp}\n"
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


@pytest.mark.parametrize(
    ("terms", "kwargs", "message"),
    [
        (["nope"], {}, "unknown service id 'nope'"),
        (["query-core"], {"field": "scheme"}, "unknown field 'scheme'"),
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
