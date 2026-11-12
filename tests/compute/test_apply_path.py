# SPDX-License-Identifier: Apache-2.0
"""What the first real apply (a guest file to a running VM on a standalone hypervisor node through
the terraform target's provider, then the baseline playbook) found missing from the renders.

* A standalone node's Terraform must not carry another node's guests: ``--node`` renders one
  node's guests after the whole set has validated, and refuses a node nothing names.
* The provider's ``user_account`` block cannot carry a sudo rule or packages, so a VM whose
  cloud-init asks for either takes the ``cloudinit`` target's user-data as a snippet
  (``user_data_file_id``), indexed so a missing snippet fails the plan.
* A cloud image that lacks qemu-guest-agent gets it from cloud-init, but Debian's unit is bound to
  a device that appeared before the package: the user-data starts it, or Terraform waits for an
  agent that never answers.
* The baseline roles change the system, so every play escalates.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
import yaml

from homelabnext import cli as hnx
from homelabnext.compute import render
from homelabnext.compute.loader import load_fleet
from homelabnext.compute.render import TARGETS
from homelabnext.compute.zones import site_facts

HERE = Path(__file__).resolve().parent
FLEET = HERE / "fleet"
SITE = HERE / "site.yml"
KEYS = HERE / "keys.yml"
#: the Terraform target, named by its prefix (the slot, not the product: X-11)
TF = next(t for t in TARGETS if t.startswith("terraform-"))


@pytest.fixture(scope="module")
def good():
    return load_fleet(FLEET, site_facts(SITE)["zones"], keys_path=KEYS)


def _two_nodes(tmp_path: Path) -> Path:
    guests = tmp_path / "guests"
    shutil.copytree(FLEET, guests)
    p = guests / "lake-core.yml"
    doc = yaml.safe_load(p.read_text(encoding="utf-8"))
    doc["placement"]["node"] = "hv-b"
    p.write_text(
        "# SPDX-License-Identifier: Apache-2.0\n" + yaml.safe_dump(doc, sort_keys=False),
        encoding="utf-8",
    )
    return guests


def _render_tf(guests: Path, out: Path, *extra: str) -> int:
    args = ["guests", "render", str(guests), "--site", str(SITE)]
    return hnx.main([*args, "--target", TF, "--out", str(out), *extra])


def test_node_renders_only_the_guests_placed_on_it(tmp_path):
    guests = _two_nodes(tmp_path)
    assert _render_tf(guests, tmp_path / "a", "--node", "hv-a") == 0
    assert _render_tf(guests, tmp_path / "b", "--node", "hv-b") == 0
    a = {p.name for p in (tmp_path / "a").glob("*.tf")}
    b = {p.name for p in (tmp_path / "b").glob("*.tf")}
    assert "vm-lake-core.tf" not in a and "vm-bus-core.tf" in a
    assert b == {"vm-lake-core.tf", "providers.tf", "variables.tf"}
    assert 'node_name = "hv-b"' in (tmp_path / "b" / "vm-lake-core.tf").read_text()


def test_node_nothing_names_is_refused(tmp_path, capsys):
    guests = _two_nodes(tmp_path)
    assert _render_tf(guests, tmp_path / "x", "--node", "hv-typo") == 1
    assert "--node 'hv-typo': no guest is placed on it" in capsys.readouterr().err
    assert not (tmp_path / "x").exists()


def test_without_node_every_node_is_rendered(tmp_path):
    guests = _two_nodes(tmp_path)
    assert _render_tf(guests, tmp_path / "all") == 0
    names = {p.name for p in (tmp_path / "all").glob("*.tf")}
    assert {"vm-lake-core.tf", "vm-bus-core.tf"} <= names


def test_user_data_snippet_replaces_user_account_when_it_cannot_express_the_guest(good):
    tf = render(good, TF)
    # sudo: password, packages, and both: user_account would silently drop them
    for name in ("bus-core", "edge-core", "lake-core"):
        vm = tf[f"vm-{name}.tf"]
        assert f'user_data_file_id = var.cloudinit_user_data["{name}"]' in vm, name
        assert "user_account" not in vm, name
    # a user and keys only: the provider's own block says all of it
    infer = tf["vm-infer-core.tf"]
    assert "user_account" in infer and "user_data_file_id" not in infer
    variables = tf["variables.tf"]
    assert 'variable "cloudinit_user_data"' in variables and "default     = {}" in variables


def test_cloudinit_starts_the_guest_agent_it_installs(good):
    ci = render(good, "cloudinit")
    edge = ci["edge-core/user-data"]
    assert "runcmd:\n  - [systemctl, start, qemu-guest-agent]\n" in edge
    assert yaml.safe_load(edge)["runcmd"] == [["systemctl", "start", "qemu-guest-agent"]]
    assert "runcmd" not in ci["bus-core/user-data"]  # installs nothing


def test_every_baseline_play_escalates(good):
    plays = yaml.safe_load(render(good, "baseline-playbook")["baseline.yml"])
    bound = [p for p in plays if p["hosts"] != "localhost"]
    assert bound and all(p.get("become") is True for p in bound)
