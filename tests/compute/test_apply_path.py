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
from homelabnext.compute.cli import PER_NODE_TARGETS
from homelabnext.compute.gen._text import hqlist
from homelabnext.compute.loader import load_fleet
from homelabnext.compute.model import ComputeError
from homelabnext.compute.render import TARGETS
from homelabnext.compute.zones import site_facts

HERE = Path(__file__).resolve().parent
FLEET = HERE / "fleet"
SITE = HERE / "site.yml"
KEYS = HERE / "keys.yml"
#: the Terraform target, named by its prefix (the slot, not the product: X-11)
TF = next(t for t in TARGETS if t.startswith("terraform-"))
#: the tailnet policy target, likewise
ACL = next(t for t in TARGETS if t.endswith("-acl"))


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


FLEET_WIDE = sorted(set(TARGETS) - PER_NODE_TARGETS)


def test_the_per_node_and_fleet_wide_targets_are_every_target():
    assert set(TARGETS) >= PER_NODE_TARGETS
    assert set(FLEET_WIDE) == {
        "inventory",
        "registry-hosts",
        ACL,
        "backup-jobs",
        "baseline-playbook",
        "runtime-labels",
    }


@pytest.mark.parametrize("target", FLEET_WIDE)
@pytest.mark.parametrize("cmd", ["render", "plan"])
def test_node_is_refused_for_a_fleet_wide_target(tmp_path, capsys, target, cmd):
    """One inventory, registry, policy or playbook serves every node: narrowed to one, it would
    silently drop the others' guests from it."""
    guests = _two_nodes(tmp_path)
    args = ["guests", cmd, str(guests), "--site", str(SITE), "--target", target, "--node", "hv-a"]
    args += ["--against", str(tmp_path)] if cmd == "plan" else ["--out", str(tmp_path / "o")]
    assert hnx.main(args) == 2
    err = capsys.readouterr().err
    assert f"{target} is fleet-wide" in err and "without --node" in err
    assert not (tmp_path / "o").exists()


@pytest.mark.parametrize("target", sorted(PER_NODE_TARGETS))
def test_node_is_taken_by_every_per_node_target(tmp_path, target):
    guests = _two_nodes(tmp_path)
    args = ["guests", "render", str(guests), "--site", str(SITE), "--keys", str(KEYS)]
    argv = [*args, "--target", target, "--node", "hv-b", "--out", str(tmp_path / "o")]
    if target == "libvirt":  # past --node: the example fleet's VLAN tagging virt-install refuses
        with pytest.raises(ComputeError, match="cannot isolate"):
            hnx.main(argv)
    else:
        assert hnx.main(argv) == 0


def _empty_node(tmp_path: Path) -> Path:
    """The example fleet plus ``_nodes.yml`` naming hv-a (every guest's) and hv-empty (none)."""
    guests = tmp_path / "guests"
    shutil.copytree(FLEET, guests)
    nodes = {"nodes": {"hv-a": {"firewall": "enabled"}, "hv-empty": {"firewall": "enabled"}}}
    (guests / "_nodes.yml").write_text(
        "# SPDX-License-Identifier: Apache-2.0\n" + yaml.safe_dump(nodes), encoding="utf-8"
    )
    return guests


def test_a_known_node_with_no_guests_is_refused_without_allow_empty(tmp_path, capsys):
    """An empty Terraform render applied to that node's state destroys everything in it."""
    guests = _empty_node(tmp_path)
    assert _render_tf(guests, tmp_path / "e", "--node", "hv-empty") == 1
    assert "--allow-empty" in capsys.readouterr().err
    assert not (tmp_path / "e").exists()
    assert _render_tf(guests, tmp_path / "e", "--node", "hv-empty", "--allow-empty") == 0
    assert not list((tmp_path / "e").glob("vm-*.tf"))
    assert _render_tf(guests, tmp_path / "a", "--node", "hv-a") == 0  # a node with guests


def test_allow_empty_needs_node(tmp_path, capsys):
    assert _render_tf(FLEET, tmp_path / "o", "--allow-empty") == 2
    assert "--allow-empty needs --node" in capsys.readouterr().err


def test_node_narrows_the_mirror_to_that_node(tmp_path):
    guests = _empty_node(tmp_path)
    mirror = {"to": "eth9", "bridges": ["vmbr0"]}
    nodes = {"nodes": {"hv-a": {"mirror": mirror}, "hv-empty": {"mirror": mirror}}}
    (guests / "_nodes.yml").write_text(
        "# SPDX-License-Identifier: Apache-2.0\n" + yaml.safe_dump(nodes), encoding="utf-8"
    )
    args = ["guests", "render", str(guests), "--site", str(SITE), "--target", "node-mirror"]
    assert hnx.main([*args, "--node", "hv-a", "--out", str(tmp_path / "m")]) == 0
    assert {p.name for p in (tmp_path / "m" / "mirror").iterdir()} == {"README.md", "hv-a"}


def test_node_narrows_the_notify_target_to_that_node(tmp_path):
    guests = _empty_node(tmp_path)
    notify = {"url": "https://notify.example.org/", "topic": "node-alerts"}
    nodes = {"nodes": {"hv-a": {"notify": notify}, "hv-empty": {"notify": notify}}}
    (guests / "_nodes.yml").write_text(
        "# SPDX-License-Identifier: Apache-2.0\n" + yaml.safe_dump(nodes), encoding="utf-8"
    )
    args = ["guests", "render", str(guests), "--site", str(SITE), "--target", "node-notify"]
    # made of the node's own entry, so a node with no guests renders without --allow-empty
    assert hnx.main([*args, "--node", "hv-empty", "--out", str(tmp_path / "n")]) == 0
    assert {p.name for p in (tmp_path / "n" / "notify").iterdir()} == {"README.md", "hv-empty"}


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


def test_the_api_token_is_ephemeral(good):
    """Never in a saved plan or in state: an ephemeral variable, so Terraform >= 1.10."""
    tf = render(good, TF)
    token = tf["variables.tf"].split('_api_token" {', 1)[1].split("}", 1)[0]
    assert "ephemeral   = true" in token and "sensitive   = true" in token
    assert 'required_version = "~> 1.10"' in tf["providers.tf"]


def test_the_render_names_every_vm_that_needs_a_snippet_and_its_digest(good, tmp_path, capsys):
    import hashlib

    tf, ci = render(good, TF), render(good, "cloudinit")
    need = sorted(n[len("vm-") : -len(".tf")] for n, t in tf.items() if "user_data_file_id" in t)
    assert need == ["bus-core", "edge-core", "lake-core"]
    variables = tf["variables.tf"]
    assert f"length(setsubtract({hqlist(need)}, keys(var.cloudinit_user_data))) == 0" in variables
    assert ", ".join(need) in variables.split("error_message", 1)[1]
    table = tf["USER_DATA.md"]
    for name in need:
        digest = hashlib.sha256(ci[f"{name}/user-data"].encode()).hexdigest()
        assert f"| `{name}` | `hv-a` |" in table and f"`{digest}`" in table, name
    assert "vm-infer-core" not in table and "`infer-core`" not in table
    args = ["guests", "render", str(FLEET), "--site", str(SITE), "--keys", str(KEYS)]
    assert hnx.main([*args, "--target", TF, "--out", str(tmp_path / "tf")]) == 0
    out = capsys.readouterr().out
    assert "3 VMs need a cloudinit_user_data snippet" in out
    assert (
        f"  edge-core (node hv-a): sha256 {hashlib.sha256(ci['edge-core/user-data'].encode()).hexdigest()}"
        in out
    )


def test_without_keys_the_table_names_no_digest(tmp_path):
    fleet = load_fleet(FLEET, site_facts(SITE)["zones"])  # no keys file: placeholders
    table = render(fleet, TF)["USER_DATA.md"]
    assert "unresolved key names" in table and "sha256 of" in table
    assert not any(len(w) == 66 for w in table.split())  # no `<64 hex>` digest anywhere


def test_a_fleet_needing_no_snippet_has_no_validation(good):
    import dataclasses

    infer = tuple(g for g in good.guests if g.name == "infer-core")
    tf = render(dataclasses.replace(good, guests=infer), TF)
    assert "validation" not in tf["variables.tf"]
    assert "None: no VM here needs one." in tf["USER_DATA.md"]


def test_cloudinit_starts_the_guest_agent_it_installs(good):
    ci = render(good, "cloudinit")
    edge = ci["edge-core/user-data"]
    assert "runcmd:\n  - [systemctl, start, qemu-guest-agent]\n" in edge
    assert yaml.safe_load(edge)["runcmd"] == [["systemctl", "start", "qemu-guest-agent"]]
    assert "runcmd" not in ci["bus-core/user-data"]  # installs nothing


def test_user_data_has_each_top_level_key_once(good):
    """YAML keeps only the last of two equal keys, so a second ``runcmd:`` (or any key) would
    silently drop the first one's commands."""
    for name, text in render(good, "cloudinit").items():
        if name.endswith("/user-data"):
            top = [ln.split(":", 1)[0] for ln in text.splitlines() if ln[:1].isalpha()]
            assert len(top) == len(set(top)), (name, top)


def test_every_baseline_play_escalates(good):
    plays = yaml.safe_load(render(good, "baseline-playbook")["baseline.yml"])
    bound = [p for p in plays if p["hosts"] != "localhost"]
    assert bound and all(p.get("become") is True for p in bound)
