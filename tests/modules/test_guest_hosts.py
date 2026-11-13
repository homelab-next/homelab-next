# SPDX-License-Identifier: Apache-2.0
"""Selection hosts that reference guest records (ADR-0027 decision 9; docs/modules/selection.md,
"Hosts that are guests"): ``hosts.<name>: {guest: guest:<id>}``.  The loader reads the guest files
with the guest loader ``hnx guests`` uses, takes the host's kind, capacity and addresses from the
guest, and refuses an unknown, invalid, retired or resource-less guest, a guest two hosts name,
and a placed role whose kind, footprint or guest requirements the guest does not meet, each by
name.  The stand-in form keeps working.  Each rule is shown refusing a planted defect."""

from __future__ import annotations

import copy
import dataclasses
import json
import re
import shutil
from pathlib import Path

import pytest
import yaml

from homelabnext.modules import cli as mcli
from homelabnext.modules import guest_hosts as gh
from homelabnext.modules import loader as ld

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "examples" / "modules"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
GUESTS = FIXTURES / "guests"
SITE = FIXTURES / "selection.guest-hosts.yml"
SMALL_LAB = EXAMPLES / "sites" / "small-lab.yml"
SLOTS = ld.load_yaml(EXAMPLES / "slots.yml")["slots"]
ROLES = json.loads((ROOT / "examples" / "model_roles.json").read_text())["roles"]
CORE, _ = ld.core_names(ld.load_yaml(ROOT / "examples" / "services.yml"))


@pytest.fixture(scope="module")
def tree():
    tree, found = ld.discover(fixtures=EXAMPLES)
    assert found == []
    return tree


@pytest.fixture(scope="module")
def guests():
    return gh.read(GUESTS)


def site() -> dict:
    return ld.load_yaml(SITE)


def check(tree, s, guests):
    return ld.check(
        tree, slots=SLOTS, roles=ROLES, in_tree_roots=(EXAMPLES,), core=CORE, site=s, guests=guests
    )


def site_problems(tree, s, guests) -> list[str]:
    return [p.message for p in check(tree, s, guests).problems if p.where == "site"]


def _cli(capsys, *args: str) -> tuple[int, dict]:
    code = mcli.main(["check", "--root", str(ROOT), "--examples", "--json", *args])
    return code, json.loads(capsys.readouterr().out)


# ----------------------------------------------------------------------------- reading the guests


def test_the_guests_are_read_by_the_guest_loader(guests):
    data = guests.hosts["guest:data-1"]
    assert (data.kind, data.status, data.capability) == ("vm", "live", "cap:object-store")
    assert data.capacity == {"cpu": 8, "memory_mb": 16384, "disk_gb": 4000}  # disks summed
    net = ld.load_yaml(GUESTS / "data-1.yml")["network"]
    want = (net["ip"], *(e["address"] for e in net["extra_addresses"]))
    assert data.addresses == want and len(want) == 2  # ip, then extra_addresses
    # the baseline set is read, so server's parent base is carried too
    assert guests.baselines_read and data.baselines == {"server", "base"}
    assert guests.hosts["guest:box-1"].capacity is None
    assert guests.invalid == {}


def test_a_missing_guest_directory_is_unreadable(tmp_path):
    with pytest.raises(gh.GuestsUnreadable):
        gh.read(tmp_path / "absent")


# ----------------------------------------------------------------------------- resolution


def test_a_guest_host_resolves_to_the_stand_in_it_replaces(guests):
    """The fixture's data host, resolved, is exactly small-lab's stand-in data host."""
    resolved, problems = gh.resolve(site(), guests)
    assert problems == []
    stand_in = ld.load_yaml(SMALL_LAB)["hosts"]["data"]
    got = resolved["hosts"]["data"]
    assert got.pop("guest") == "guest:data-1"
    assert got == stand_in


def test_the_fixture_passes_the_loader_and_renders_what_the_stand_in_renders(
    tree, guests, tmp_path, capsys
):
    report = check(tree, site(), guests)
    assert report.problems == []
    assert report.site["hosts"]["data"]["capacity"]["cpu"] == 8
    code, doc = _cli(capsys, "--site", str(SITE), "--guests", str(GUESTS))
    assert (code, doc["problems"]) == (0, [])
    outs = {}
    runs = {
        "guest": ["--site", str(SITE), "--guests", str(GUESTS)],
        "stand-in": ["--site", str(SMALL_LAB)],
    }
    for name, extra in runs.items():
        out = tmp_path / name
        code = mcli.main(["render", "--root", str(ROOT), "--examples", "--out", str(out), *extra])
        capsys.readouterr()
        assert code == 0
        outs[name] = {
            p.relative_to(out).as_posix(): p.read_text() for p in out.rglob("*") if p.is_file()
        }
    # the same slices and egress policy: the guest's addresses and capacity reached the renderers
    assert outs["guest"] == outs["stand-in"]


def test_the_stand_in_form_still_needs_no_guests(tree):
    assert check(tree, ld.load_yaml(SMALL_LAB), None).problems == []


def test_a_reference_with_no_guests_read_is_refused(tree, capsys):
    want = (
        "hosts.data: references guest:data-1, but no guest records were read "
        "(--guests DIR, or --overlay with lab/guests/)"
    )
    assert site_problems(tree, site(), None) == [want]
    code, doc = _cli(capsys, "--site", str(SITE))
    assert (code, doc["problems"]) == (1, [f"site: {want}"])


def test_an_unknown_guest_is_refused(tree, guests):
    s = site()
    s["hosts"]["data"]["guest"] = "guest:data-9"
    assert site_problems(tree, s, guests) == [
        "hosts.data: unknown guest guest:data-9 (no such guest record)"
    ]


def test_a_guest_whose_file_fails_its_schema_is_refused(tree, tmp_path):
    d = tmp_path / "guests"
    shutil.copytree(GUESTS, d)
    doc = yaml.safe_load((d / "data-1.yml").read_text())
    del doc["owners"]
    (d / "data-1.yml").write_text(yaml.safe_dump(doc))
    got = site_problems(tree, site(), gh.read(d))
    assert got == [
        "hosts.data: guest:data-1's guest file has problems (hnx guests validate): "
        "schema: <root>: 'owners' is a required property"
    ]


def test_a_retired_guest_is_refused(tree, guests):
    s = site()
    s["hosts"]["data"]["guest"] = "guest:gone-1"
    assert site_problems(tree, s, guests) == [
        "hosts.data: guest:gone-1 is retired; only a live or planned guest takes a placement"
    ]


def test_a_guest_without_resources_is_refused(tree, guests):
    s = site()
    s["hosts"]["data"]["guest"] = "guest:box-1"
    assert site_problems(tree, s, guests) == [
        "hosts.data: guest:box-1 declares no resources, so its capacity is unknown"
    ]


def test_a_guest_two_hosts_name_is_refused(tree, guests):
    s = site()
    s["hosts"]["spare"] = {"guest": "guest:data-1"}
    got = site_problems(tree, s, guests)
    assert (
        "hosts: data, spare all reference guest:data-1 (one guest is one host; its capacity "
        "would count once per name)"
    ) in got


# ----------------------------------------------------------------------------- the role vs the guest


def test_a_role_kind_the_guest_is_not_is_refused(tree, guests):
    s = site()
    s["hosts"]["data"]["guest"] = "guest:small-1"
    got = site_problems(tree, s, guests)
    assert "external-collector/receiver: a vm role, but host data (guest:small-1) is a lxc" in got


def test_each_footprint_dimension_the_guest_lacks_is_named(tree, guests):
    s = site()
    s["hosts"]["data"]["guest"] = "guest:small-1"
    got = site_problems(tree, s, guests)
    # the receiver alone needs 1 vCPU, 384 MB and 10 GB: the container's 8 GB disk is short
    assert "external-collector/receiver: needs disk_gb 10, host data (guest:small-1) has 8" in got
    # the receiver fits the container's one vCPU, so no vCPU line names it
    assert not [p for p in got if p.startswith("external-collector/receiver: needs vCPU")]
    # the whole host's sum names the guest too
    assert any(p.startswith("data (guest:small-1): memory_mb ") for p in got)


def test_a_memory_minimum_is_judged_less_the_headroom(tree, guests):
    s = site()
    s["hosts"]["data"]["headroom"] = {"memory_mb": 16384 - 383}  # leaves 383 MB of 16384
    got = site_problems(tree, s, guests)
    assert (
        "external-collector/receiver: needs memory_mb 384, host data (guest:data-1) has 383 "
        "(less headroom)"
    ) in got


def test_a_baseline_the_guest_does_not_carry_is_refused(tree, guests):
    """The receiver role requires baseline server; small-1 carries only base."""
    s = site()
    s["hosts"]["data"]["guest"] = "guest:small-1"
    got = site_problems(tree, s, guests)
    assert (
        "external-collector/receiver: needs baseline server; host data (guest:small-1) carries base"
    ) in got


def test_a_baseline_is_met_through_extends(tree, guests):
    """data-1 names server, which extends base: a role requiring base is met."""
    mods = copy.deepcopy(tree.mods)
    role = mods["external-collector"]["requires"]["hosts"][1]
    role["guest"] = {"baselines": ["base"]}
    t = ld.Tree(mods, tree.dirs, tree.origin)
    assert site_problems(t, site(), guests) == []
    # without the baseline set, extends is not followed, and the problem says so
    data = dataclasses.replace(guests.hosts["guest:data-1"], baselines=frozenset({"server"}))
    plain = gh.Guests({**guests.hosts, data.id: data}, {}, baselines_read=False)
    assert site_problems(t, site(), plain) == [
        "external-collector/receiver: needs baseline base; host data (guest:data-1) carries "
        "server (no baseline set read: extends not followed)"
    ]


def test_a_capability_the_guest_does_not_provide_is_refused(tree, guests):
    mods = copy.deepcopy(tree.mods)
    role = mods["external-collector"]["requires"]["hosts"][1]
    role["guest"] = {"capability": ["cap:lake-catalog", "cap:hot-index"]}
    t = ld.Tree(mods, tree.dirs, tree.origin)
    assert site_problems(t, site(), guests) == [
        "external-collector/receiver: needs a guest whose capability is cap:lake-catalog or "
        "cap:hot-index; host data (guest:data-1) provides cap:object-store"
    ]
    role["guest"] = {"capability": ["cap:object-store"]}
    assert site_problems(t, site(), guests) == []


def test_guest_requirements_on_a_stand_in_host_are_noted_not_judged(tree):
    report = check(tree, ld.load_yaml(SMALL_LAB), None)
    assert report.problems == []
    assert (
        "guest requirements not checked (the host is a stand-in, not a guest reference): "
        "external-collector/receiver on data"
    ) in report.notes


# ----------------------------------------------------------------------------- the overlay layout


def _overlay(tmp_path: Path, with_guests: bool) -> Path:
    lab = tmp_path / "overlay" / "lab"
    (lab / "mcp").mkdir(parents=True)
    (lab / "keyring").mkdir()
    (lab / "keyring" / "keyring.json").write_text('{"principals": []}')
    shutil.copy(SITE, lab / "modules.yml")
    if with_guests:
        shutil.copytree(GUESTS, lab / "guests")
    return lab.parent


def test_the_overlay_s_lab_guests_is_the_default(tmp_path, capsys):
    ov = _overlay(tmp_path, with_guests=True)
    code, doc = _cli(capsys, "--overlay", str(ov))
    assert (code, doc["problems"]) == (0, [])
    ov2 = _overlay(tmp_path / "b", with_guests=False)
    code, doc = _cli(capsys, "--overlay", str(ov2))
    missing = "references guest:data-1, but no guest records were read"
    assert any(missing in p for p in doc["problems"])


def test_a_guests_path_that_does_not_exist_is_a_usage_error(capsys, tmp_path):
    args = ["--examples", "--site", str(SITE), "--guests", str(tmp_path / "x")]
    code = mcli.main(["check", "--root", str(ROOT), *args])
    capsys.readouterr()
    assert code == 2


# ----------------------------------------------------------------------------- review findings


def _guest_dir(tmp_path: Path) -> Path:
    d = tmp_path / "guests"
    shutil.copytree(GUESTS, d)
    return d


def test_a_guest_address_that_is_public_is_refused(tree, tmp_path):
    """The egress policy lets a role reach a host's own addresses: a guest's public one would
    open a path out (a public address, built from an integer so no literal is in the test)."""
    import ipaddress

    public = str(ipaddress.ip_address(0x0808_0808))
    d = _guest_dir(tmp_path)
    doc = yaml.safe_load((d / "data-1.yml").read_text())
    doc["network"]["ip"] = public
    (d / "data-1.yml").write_text(yaml.safe_dump(doc))
    got = site_problems(tree, site(), gh.read(d))
    assert (
        f"hosts.data: address {public} (from guest:data-1) is neither private nor in "
        "scope.trusted.nets; a lab host's own address is never the internet"
    ) in got


def test_two_files_with_one_guest_id_are_refused(tree, tmp_path):
    d = _guest_dir(tmp_path)
    shutil.copy(d / "data-1.yml", d / "data-1.yaml")
    got = site_problems(tree, site(), gh.read(d))
    assert got == [
        "hosts.data: guest:data-1's guest file has problems (hnx guests validate): "
        "two guest files carry this id"
    ]


def test_a_symlinked_guest_file_is_unreadable(tmp_path):
    d = _guest_dir(tmp_path)
    (tmp_path / "outside.yml").write_text("secret: value\n")
    (d / "evil-1.yml").symlink_to(tmp_path / "outside.yml")
    with pytest.raises(gh.GuestsUnreadable, match=re.escape("symbolic links: evil-1.yml")):
        gh.read(d)


def test_a_guest_file_that_is_not_utf8_is_a_problem_not_a_crash(tree, tmp_path):
    d = _guest_dir(tmp_path)
    (d / "junk-1.yml").write_bytes(b"\xff\xfe\x00junk")
    g = gh.read(d)
    assert "guest:junk-1" in g.invalid
    assert site_problems(tree, site(), g) == []  # the selection does not reference it


def test_a_gpu_footprint_on_a_guest_host_is_named_once(tree, guests):
    mods = copy.deepcopy(tree.mods)
    role = mods["external-collector"]["requires"]["hosts"][1]
    role["footprint"] = {**role["footprint"], "gpu_memory_mb": 1024}
    t = ld.Tree(mods, tree.dirs, tree.origin)
    got = site_problems(t, site(), guests)
    assert got == [
        "external-collector/receiver: a GPU footprint cannot be judged against a guest record "
        "yet (host data (guest:data-1) declares no GPU memory); place it on a stand-in host"
    ]
