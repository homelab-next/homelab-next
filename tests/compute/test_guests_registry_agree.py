# SPDX-License-Identifier: Apache-2.0
"""``hnx guests validate`` holds each guest's address and zone against the service registry's
hosts: the router, DNS and DHCP read the registry, the hypervisor and the guest read the guest
file, so the two must agree."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from homelabnext import cli as hnx

REPO = Path(__file__).resolve().parents[2]


def _validate(lab: Path, *extra: str) -> int:
    return hnx.main(
        ["guests", "validate", str(lab / "guests"), "--site", str(lab / "site.yml"), *extra]
    )


@pytest.mark.parametrize("lab", ["four-box-lab", "minimal", "lab-topology"])
def test_every_example_lab_agrees_with_its_registry(lab):
    assert _validate(REPO / "examples" / lab) == 0


@pytest.fixture
def lab(tmp_path: Path) -> Path:
    shutil.copytree(REPO / "examples" / "four-box-lab", tmp_path / "lab")
    return tmp_path / "lab"


def _edit_registry(lab: Path, old: str, new: str) -> None:
    reg = lab / "services.yml"
    text = reg.read_text(encoding="utf-8")
    assert old in text
    reg.write_text(text.replace(old, new, 1), encoding="utf-8")


#: bus-1's registry line, and the same host at another free address of its zone
BUS = "bus-1:        {address: 192.0.2.140,"
MOVED = "bus-1:        {address: 192.0.2.150,"


def test_an_address_the_registry_gives_differently_is_refused(lab, capsys):
    _edit_registry(lab, BUS, MOVED)
    assert _validate(lab) == 1
    err = capsys.readouterr().err
    assert (
        "guest bus-1: registry hosts.bus-1.address is 192.0.2.150, the guest file says 192.0.2.140"
        in err
    )


def test_a_registry_named_explicitly_must_exist(lab, tmp_path):
    assert _validate(lab, "--registry", str(tmp_path / "nowhere.yml")) == 2


def test_without_a_registry_next_to_the_site_nothing_is_compared(lab):
    _edit_registry(lab, BUS, MOVED)
    moved = lab.parent / "elsewhere.yml"
    (lab / "services.yml").rename(moved)
    assert _validate(lab) == 0
    assert _validate(lab, "--registry", str(moved)) == 1
