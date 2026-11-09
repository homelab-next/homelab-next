# SPDX-License-Identifier: Apache-2.0
"""``hnx guests validate --registry`` holds a guest's ``capability`` to the registry rows on its
own host (ADR-0039 decision 7): ``cap:orchestration`` fits only the guest that runs the
orchestrator, so a guest can no longer borrow the nearest capability name as a catch-all."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from homelabnext import cli as hnx

REPO = Path(__file__).resolve().parents[2]
LABS = ("four-box-lab", "minimal", "lab-topology")


def _validate(lab: Path, *extra: str) -> int:
    return hnx.main(
        ["guests", "validate", str(lab / "guests"), "--site", str(lab / "site.yml"), *extra]
    )


def _lab(tmp_path: Path, name: str = "four-box-lab") -> Path:
    shutil.copytree(REPO / "examples" / name, tmp_path / "lab")
    return tmp_path / "lab"


def _set_capability(lab: Path, guest: str, cap: str) -> None:
    path = lab / "guests" / f"{guest}.yml"
    text = path.read_text(encoding="utf-8")
    old = next(ln for ln in text.splitlines() if ln.startswith("capability: "))
    path.write_text(text.replace(old, f"capability: {cap}", 1), encoding="utf-8")


def _edit(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    assert old in text
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


@pytest.mark.parametrize("lab", LABS)
def test_every_example_guest_declares_a_capability_its_host_serves(lab):
    examples = REPO / "examples" / lab
    assert _validate(examples, "--registry", str(examples / "services.yml")) == 0


def test_a_capability_no_row_on_the_guest_s_host_has_is_refused(tmp_path, capsys):
    """The secondary resolver declaring the primary's capability: a known capability, served,
    but on another host."""
    lab = _lab(tmp_path)
    _set_capability(lab, "dns-2", "cap:dns")
    assert _validate(lab, "--registry", str(lab / "services.yml")) == 1
    err = capsys.readouterr().err
    assert (
        "guest dns-2: capability cap:dns is not served on dns-2: the registry places dns on "
        "dns-1; the rows on dns-2 serve dns-secondary (dns-secondary)"
    ) in err


def test_a_catch_all_on_a_host_with_rows_is_refused(tmp_path, capsys):
    """A known capability no row anywhere serves is still not the capability of this host."""
    lab = _lab(tmp_path)
    _set_capability(lab, "proxy-1", "cap:edge")
    assert _validate(lab, "--registry", str(lab / "services.yml")) == 1
    assert (
        "guest proxy-1: capability cap:edge is no capability of a registry row on proxy-1; the "
        "rows there serve edge-proxy (edge-proxy)"
    ) in capsys.readouterr().err


def test_the_registry_next_to_the_site_is_held_by_default(tmp_path, capsys):
    lab = _lab(tmp_path)
    _set_capability(lab, "sensor-1", "cap:detections")
    assert _validate(lab) == 1
    assert "the registry places detections on siem-1" in capsys.readouterr().err


def test_a_guest_with_no_row_may_not_claim_another_host_s_capability(tmp_path, capsys):
    """The hypervisor hosts no row; it keeps a platform role, not a borrowed service."""
    lab = _lab(tmp_path)
    assert _validate(lab) == 0  # cap:hypervisor: served by no row, held to the vocabulary
    _set_capability(lab, "main-1", "cap:idp")
    assert _validate(lab) == 1
    assert (
        "guest main-1: capability cap:idp is not served on main-1: the registry places idp on idp-1"
    ) in capsys.readouterr().err


def test_a_non_primary_row_places_its_capability_on_its_host(tmp_path):
    """A guest runs its eval candidate as surely as a primary: the row's standing does not
    matter, only that the registry hosts it there."""
    lab = _lab(tmp_path)
    _edit(
        lab / "services.yml",
        "  status-hub:\n",
        "  sso-trial:\n"
        "    capability: idp\n"
        "    impl: keycloak\n"
        "    host: hub-1\n"
        "    port: 8443\n"
        "    protocol: https\n"
        "    owner: platform-team\n"
        '    version: "1.0"\n'
        "    tls: internal\n"
        "    standing: {tier: eval, until: '2026-12-01', why: the candidate under test}\n"
        "  status-hub:\n",
    )
    _set_capability(lab, "hub-1", "cap:idp")
    assert _validate(lab) == 0
    assert _validate(lab, "--registry", str(lab / "services.yml")) == 0


# ---- review follow-ups: a guest cannot rename its way off its host's rows ---------------------


def test_a_guest_renamed_away_from_its_registry_host_is_refused(tmp_path, capsys):
    """hub-1's guest renamed to a name no registry host has, keeping hub-1's address, used to be
    judged as a row-less guest and pass with a borrowed capability."""
    lab = _lab(tmp_path)
    old = lab / "guests" / "hub-1.yml"
    text = old.read_text(encoding="utf-8").replace("id: guest:hub-1", "id: guest:statusbox", 1)
    old.unlink()
    (lab / "guests" / "statusbox.yml").write_text(text, encoding="utf-8")
    _set_capability(lab, "statusbox", "cap:orchestration")
    assert _validate(lab) == 1
    err = capsys.readouterr().err
    assert "guest statusbox: address 192.0.2.75 is registry host hub-1's" in err


def test_a_row_less_guest_that_is_no_host_must_serve_nothing(tmp_path, capsys):
    lab = _lab(tmp_path, "lab-topology")
    assert _validate(lab) == 0  # decoy-1: no row, cap:siem-source serves no consumer
    _set_capability(lab, "decoy-1", "cap:backup")
    assert _validate(lab) == 1
    assert "guest decoy-1: hosts no registry row, yet declares cap:backup" in (
        capsys.readouterr().err
    )


def test_a_capability_group_of_another_host_s_capability_is_refused(tmp_path, capsys):
    lab = _lab(tmp_path)
    _edit(
        lab / "guests" / "bus-1.yml",
        "capability: cap:events\n",
        "capability: cap:events\ncapability_groups: [cap_idp]\n",
    )
    assert _validate(lab) == 1
    assert (
        "guest bus-1: capability_groups cap_idp is capability idp's, which the registry places "
        "on idp-1, not on bus-1"
    ) in capsys.readouterr().err


def test_a_runner_beside_rows_declares_agent_runtime_where_the_host_role_says_so(tmp_path):
    """ADR-0039 decision 7: no row carries agent-runtime; the runner's host is found by its
    registry role, so a runner guest on a host with rows may declare it there, and only there."""
    lab = _lab(tmp_path)
    _set_capability(lab, "bus-1", "cap:agent-runtime")
    assert _validate(lab) == 1
    _edit(
        lab / "services.yml",
        "zone: data,     role: events}",
        "zone: data,     role: agent-runtime}",
    )
    assert _validate(lab) == 0
