# SPDX-License-Identifier: Apache-2.0
"""The metrics generator's host-metrics target list (the ``node_targets`` option): every host of
this registry on one port, less the hosts that run no exporter; absent when the option is not
given, so the generator's existing output is byte-for-byte unchanged."""

from __future__ import annotations

import io
from pathlib import Path

import pytest
import yaml

from homelabnext.generators import GeneratorRefusal, generate
from homelabnext.registry import cli as registry_cli
from homelabnext.registry import load

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "examples" / "services.yml"
REG = load(EXAMPLE)
TARGETS = "prometheus/node_targets.yml"


def _render(spec):
    return generate(REG, ["prometheus"], {"node_targets": spec})["prometheus"]


def test_no_option_renders_no_target_list():
    assert TARGETS not in generate(REG, ["prometheus"])["prometheus"]


def test_every_registry_host_is_a_target_on_the_port():
    entries = yaml.safe_load(_render({"port": 9100})[TARGETS])
    assert [e["labels"]["host"] for e in entries] == sorted(REG.hosts)
    for e in entries:
        host = REG.hosts[e["labels"]["host"]]
        assert e["targets"] == [f"{host.address}:9100"]
        assert e["labels"] == {"host": e["labels"]["host"], "role": host.role, "zone": host.zone}


def test_an_excluded_host_is_left_out_and_the_rest_unchanged():
    gone = sorted(REG.hosts)[0]
    entries = yaml.safe_load(_render({"port": 9100, "exclude": [gone]})[TARGETS])
    assert gone not in [e["labels"]["host"] for e in entries]
    assert len(entries) == len(REG.hosts) - 1


def test_the_other_files_do_not_change_with_the_option():
    plain = generate(REG, ["prometheus"])["prometheus"]
    both = _render({"port": 9100})
    assert {k: v for k, v in both.items() if k != TARGETS} == plain


def test_output_is_deterministic():
    assert _render({"port": 9100}) == _render({"port": 9100})


@pytest.mark.parametrize(
    "spec",
    [
        {},
        {"port": 0},
        {"port": 70000},
        {"port": True},
        {"port": "9100"},
        {"port": 9100, "exclude": "dns-core"},
        {"port": 9100, "exclude": ["no-such-host"]},
        {"port": 9100, "extra": 1},
        "9100",
    ],
)
def test_a_malformed_spec_is_refused(spec):
    with pytest.raises(GeneratorRefusal, match="node_targets"):
        _render(spec)


def test_the_cli_flags_render_the_list_and_exclude_needs_the_port(tmp_path):
    out, err = io.StringIO(), io.StringIO()
    code = registry_cli.main(
        ["generate", str(EXAMPLE), str(tmp_path), "--only", "prometheus",
         "--node-exporter-port", "9100", "--node-exporter-exclude", "dns-core"],
        out, err,
    )  # fmt: skip
    assert code == 0, err.getvalue()
    entries = yaml.safe_load((tmp_path / TARGETS).read_text())
    assert "dns-core" not in [e["labels"]["host"] for e in entries]
    err = io.StringIO()
    code = registry_cli.main(
        ["generate", str(EXAMPLE), str(tmp_path / "x"), "--node-exporter-exclude", "dns-core"],
        io.StringIO(), err,
    )  # fmt: skip
    assert code == 2 and "--node-exporter-port" in err.getvalue()
