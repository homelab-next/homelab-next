# SPDX-License-Identifier: Apache-2.0
"""Review follow-ups to ADR-0039 step 6 (``hnx guests validate --registry``): addresses compared
as addresses, the runner's capability held to its host role, a row-less guest's own role and
status, and the group of a capability no row serves."""

from __future__ import annotations

import dataclasses
import json
import shutil
from pathlib import Path
from types import SimpleNamespace

from homelabnext import cli as hnx
from homelabnext.compute import load_fleet, open_site
from homelabnext.compute.gen import registry_hosts
from homelabnext.compute.model import Guest

REPO = Path(__file__).resolve().parents[2]


def _validate(lab: Path) -> int:
    return hnx.main(["guests", "validate", str(lab / "guests"), "--site", str(lab / "site.yml")])


def _lab(tmp_path: Path, name: str = "four-box-lab") -> Path:
    shutil.copytree(REPO / "examples" / name, tmp_path / "lab")
    return tmp_path / "lab"


def _edit(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    assert old in text
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def _set_capability(lab: Path, guest: str, cap: str) -> None:
    path = lab / "guests" / f"{guest}.yml"
    old = next(ln for ln in path.read_text().splitlines() if ln.startswith("capability: "))
    _edit(path, old, f"capability: {cap}")


def test_addresses_are_compared_as_addresses_not_text():
    """A registry host whose IPv6 address is written uncompressed is the same address as a
    guest's compressed one: the alias check used to compare the text and miss it."""
    lab = REPO / "examples" / "four-box-lab"
    zones, domain = open_site(lab / "site.yml")
    fleet = load_fleet(lab / "guests", zones, domain=domain or "example.internal")
    guests = []
    for g in fleet.guests:
        if g.name == "hub-1":
            raw = json.loads(json.dumps(g.raw))
            raw["network"]["extra_addresses"] = [{"address": "2001:db8:0:20::14", "why": "v6"}]
            g = Guest(raw, g.source)
        guests.append(g)
    fleet = dataclasses.replace(fleet, guests=tuple(guests))
    hosts = {"mirror-1": SimpleNamespace(address="2001:db8:0:20:0:0:0:14", role="mirror")}
    out = registry_hosts.capability_problems(fleet, [], hosts)
    assert any("address 2001:db8:0:20::14 is registry host mirror-1's" in p for p in out), out
    same = {"hub-1": SimpleNamespace(address="192.0.2.75", zone="services")}
    assert registry_hosts.registry_problems(fleet, same) == []
    assert registry_hosts._ip("2001:DB8::0:1") == "2001:db8::1"


def test_agent_runtime_is_declared_only_where_the_registry_role_says_so(tmp_path, capsys):
    """Without a row a guest used to take cap:agent-runtime anywhere (it was row-free), so a
    runner hnx agent access can never find passed."""
    lab = _lab(tmp_path)
    _set_capability(lab, "main-1", "cap:agent-runtime")  # a row-less registry host, role hypervisor
    assert _validate(lab) == 1
    assert (
        "guest main-1: declares cap:agent-runtime, but its registry host's role is hypervisor"
        in (capsys.readouterr().err)
    )
    lab2 = _lab(tmp_path / "b", "lab-topology")
    _set_capability(lab2, "decoy-1", "cap:agent-runtime")  # no registry host at all
    assert _validate(lab2) == 1
    assert "guest decoy-1: declares cap:agent-runtime, but decoy-1 is no registry host" in (
        capsys.readouterr().err
    )


def test_a_row_less_guest_may_declare_its_registry_host_s_own_role(tmp_path):
    """A site names its own row-free roles in the registry's hosts; the runner was the only one."""
    lab = _lab(tmp_path, "lab-topology")
    _edit(
        lab / "services.yml",
        "  harbor-gw: {address: 192.0.2.1,     zone: mgmt,     role: router}\n",
        "  harbor-gw: {address: 192.0.2.1,     zone: mgmt,     role: router}\n"
        "  decoy-1: {address: 203.0.113.21, zone: lab, role: tarpit}\n",
    )
    _set_capability(lab, "decoy-1", "cap:tarpit")
    assert _validate(lab) == 0
    _set_capability(lab, "decoy-1", "cap:tidepool")
    assert _validate(lab) == 1


def test_a_planned_guest_holds_no_row_yet(tmp_path):
    lab = _lab(tmp_path, "lab-topology")
    _set_capability(lab, "decoy-1", "cap:backup")
    assert _validate(lab) == 1
    _edit(lab / "guests" / "decoy-1.yml", "kind: lxc\n", "kind: lxc\nstatus: planned\n")
    assert _validate(lab) == 0


def test_the_group_of_a_capability_no_row_serves_is_the_declaring_guest_s_only(tmp_path, capsys):
    lab = _lab(tmp_path)
    _edit(
        lab / "guests" / "bus-1.yml",
        "capability: cap:events\n",
        "capability: cap:events\ncapability_groups: [cap_codemode_runner]\n",
    )
    assert _validate(lab) == 1
    assert (
        "guest bus-1: capability_groups cap_codemode_runner is the group of a capability no "
        in (capsys.readouterr().err)
    )
