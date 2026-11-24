# SPDX-License-Identifier: Apache-2.0
"""The metrics generator's host-metrics target list (the ``node_targets`` option): every host of
this registry on one port, less the hosts that run no exporter; absent when the option is not
given, so the generator's existing output is byte-for-byte unchanged.  Below it: the HTTP(S) probe
target list (the ``probe_targets`` option)."""

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


# ----------------------------------------------------------------------------- HTTP(S) probe targets
# The ``probe_targets`` option: a row published at the edge is probed by its edge name, a row with an
# http health endpoint by the name it answers by, any other row not at all; absent without the option.

LISTING = "prometheus/probe_targets.yml"


def _render_probes(spec):
    return generate(REG, ["prometheus"], {"probe_targets": spec})["prometheus"]


def _entries(spec=None):
    return yaml.safe_load(_render_probes({} if spec is None else spec)[LISTING])


def _by_service(entries):
    return {e["labels"]["service"]: e for e in entries}


def test_no_option_renders_no_probe_list():
    assert LISTING not in generate(REG, ["prometheus"])["prometheus"]


def test_the_other_files_do_not_change_with_the_probe_option():
    plain = generate(REG, ["prometheus"])["prometheus"]
    both = _render_probes({})
    assert {k: v for k, v in both.items() if k != LISTING} == plain


def test_a_row_published_at_the_edge_is_probed_by_its_edge_name():
    rows = [s for s in REG.rows("primary", "eval") if s.public_hostname]
    assert rows, "the example registry has edge rows"
    got = _by_service(_entries())
    for s in rows:
        e = got[s.name]
        assert e["targets"][0].startswith(f"https://{s.public_hostname}/")
        assert e["labels"]["via"] == "edge" and e["labels"]["module"] == "http_edge"


def test_a_row_with_an_http_health_endpoint_is_probed_by_the_name_it_answers_by():
    rows = [
        s
        for s in REG.rows("primary", "eval")
        if s.health.get("kind") == "http" and not s.public_hostname
    ]
    assert rows
    got = _by_service(_entries())
    for s in rows:
        e = got[s.name]
        assert e["targets"] == [f"{s.scheme}://{REG.address_of(s)}:{s.port}{s.health['path']}"]
        assert e["labels"]["via"] == "service"
        assert e["labels"]["expect_status"] == str(s.health.get("expect_status", 200))


def test_a_row_neither_routed_nor_http_checked_is_not_probed():
    got = _by_service(_entries())
    for s in REG.rows("primary", "eval"):
        probed = bool(s.public_hostname) or s.health.get("kind") == "http"
        assert (s.name in got) is probed, s.name


def test_an_excluded_row_is_left_out_and_the_rest_unchanged():
    all_ = _by_service(_entries())
    gone = sorted(all_)[0]
    rest = _by_service(_entries({"exclude": [gone]}))
    assert gone not in rest and set(rest) == set(all_) - {gone}


def test_every_target_is_one_http_or_https_url():
    for e in _entries():
        assert len(e["targets"]) == 1 and e["targets"][0].split("://")[0] in ("http", "https")
        assert e["labels"]["module"] in ("http_edge", "http_2xx")


def test_probe_output_is_deterministic():
    assert _render_probes({}) == _render_probes({})


@pytest.mark.parametrize(
    "spec",
    [
        {"extra": 1},
        {"exclude": "idp"},
        {"exclude": [1]},
        {"exclude": ["no-such-row"]},
        "all",
    ],
)
def test_a_malformed_probe_spec_is_refused(spec):
    with pytest.raises(GeneratorRefusal, match="probe_targets"):
        _render_probes(spec)


def test_the_cli_flags_render_the_list_and_exclude_needs_the_flag(tmp_path):
    gone = sorted(_by_service(_entries()))[0]
    out, err = io.StringIO(), io.StringIO()
    code = registry_cli.main(
        ["generate", str(EXAMPLE), str(tmp_path), "--only", "prometheus",
         "--probe-targets", "--probe-exclude", gone],
        out, err,
    )  # fmt: skip
    assert code == 0, err.getvalue()
    listed = _by_service(yaml.safe_load((tmp_path / LISTING).read_text()))
    assert gone not in listed and listed
    err = io.StringIO()
    code = registry_cli.main(
        ["generate", str(EXAMPLE), str(tmp_path / "x"), "--probe-exclude", gone],
        io.StringIO(), err,
    )  # fmt: skip
    assert code == 2 and "--probe-targets" in err.getvalue()
