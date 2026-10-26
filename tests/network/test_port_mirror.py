# SPDX-License-Identifier: Apache-2.0
"""Site 1.3 mirror ports: a SPAN destination for a physical sensor, validated, planned and
rendered by the UniFi dry run."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from netutil import render

from homelabnext.network import build_ir, load_site, validate

EXAMPLE = Path(__file__).resolve().parents[2] / "schemas/platform/examples/site.port-mirror.yml"


@pytest.fixture
def mdoc() -> dict:
    return copy.deepcopy(load_site(EXAMPLE))


def _pas(d):
    return d["switches"][0]["port_assignments"]


def _mirror(d):
    return next(pa for pa in _pas(d) if pa["kind"] == "mirror")


def test_the_mirror_example_is_clean(mdoc, registry):
    rep = validate(mdoc, registry)
    assert rep.ok, rep.errors


def test_the_plan_carries_the_mirror_and_its_source(mdoc, registry):
    ports = {p.port: p for p in build_ir(mdoc, registry).switches[0].ports}
    assert (ports[9].kind, ports[9].mirror_from, ports[9].native_vlan) == ("mirror", (1,), None)
    assert ports[1].mirror_from == ()


def test_unifi_renders_a_mirror_override_and_no_profile(mdoc, registry):
    out = render("unifi", build_ir(mdoc, registry))
    overrides = {o["port_idx"]: o for o in json.loads(out["switch-ports.json"])["objects"]}
    assert overrides[9] == {
        "name": "core-sw-1/9",
        "device": "core-sw-1",
        "device_mac": "00:00:5e:00:53:10",
        "port_idx": 9,
        "op_mode": "mirror",
        "op_mirror_from_idx": 1,
    }
    profiles = json.loads(out["port-profiles.json"])["objects"]
    assert not [p for p in profiles if "mirror" in p["name"]]


def _no_source(d):
    del _mirror(d)["mirror_from"]


def _with_vlan(d):
    _mirror(d)["vlan"] = 20


def _with_vlans(d):
    _mirror(d)["vlans"] = [20]


def _source_on_access(d):
    _pas(d)[1]["mirror_from"] = [1]


def _source_unassigned(d):
    _mirror(d)["mirror_from"] = [42]


def _source_is_itself(d):
    _mirror(d)["mirror_from"] = [9]


def _source_is_another_mirror(d):
    _pas(d).append({"ports": [10], "kind": "mirror", "mirror_from": [9]})


def _source_mirrored_twice(d):
    _pas(d).append({"ports": [10], "kind": "mirror", "mirror_from": [1]})


def _reversed_source_range(d):
    _mirror(d)["mirror_from"] = ["4-2"]


def _unifi_two_sources(d):
    _mirror(d)["mirror_from"] = [1, 2]


def _unifi_two_destinations(d):
    _mirror(d)["ports"] = [9, 10]


def _uplink_is_mirror(d):
    d["switches"][0]["uplink_port"] = 9


CASES = [
    (_no_source, "needs mirror_from"),
    (_with_vlan, "carries no vlan"),
    (_with_vlans, "carries no vlan"),
    (_source_on_access, "mirror_from is only for kind: mirror"),
    (_source_unassigned, "mirror_from port 42 is not assigned"),
    (_source_is_itself, "mirror_from port 9 is itself a mirror port"),
    (_source_is_another_mirror, "mirror_from port 9 is itself a mirror port"),
    (_source_mirrored_twice, "port 1 is already mirrored"),
    (_reversed_source_range, "mirror_from: bad port range"),
    (_unifi_two_sources, "one source port to one port"),
    (_unifi_two_destinations, "one source port to one port"),
    (_uplink_is_mirror, "uplink_port 9 is not assigned as a trunk"),
]


@pytest.mark.parametrize(("mutate", "needle"), CASES, ids=[c[0].__name__.strip("_") for c in CASES])
def test_a_bad_mirror_is_refused(mdoc, registry, mutate, needle):
    mutate(mdoc)
    errs = validate(mdoc, registry).errors
    assert any(needle in e for e in errs), (needle, errs)


def test_other_models_may_mirror_several_sources_to_one_port(mdoc, registry):
    """The one-source limit is the UniFi adapter's, not the model's: a SPAN session on another
    switch may copy several ports to one destination."""
    mdoc["switches"][0]["model"] = "linux"
    _mirror(mdoc)["mirror_from"] = [1, "2-3"]
    assert validate(mdoc, registry).ok, validate(mdoc, registry).errors
    port = next(p for p in build_ir(mdoc, registry).switches[0].ports if p.port == 9)
    assert port.mirror_from == (1, 2, 3)
