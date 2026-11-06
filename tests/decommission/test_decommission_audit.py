# SPDX-License-Identifier: Apache-2.0
"""Fixtures-based end-to-end: a live guest is flagged on every plane, a retired one is clean."""

from __future__ import annotations

import json

import pytest
from labdata import SNAPSHOT

from homelabnext.cli import COMMANDS
from homelabnext.decommission import (
    PLANES,
    Adapters,
    DirTree,
    MemTree,
    Status,
    Target,
    plan,
    positive_control,
    render,
    run,
)
from homelabnext.decommission.cli import main

LIVE = Target("app-core", vmid=180, ips=("192.0.2.50",))
RETIRED = Target("old-core", vmid=170, ips=("192.0.2.99",))


def by_plane(report):
    return {r.plane: r for r in report.results}


def test_live_guest_is_flagged_on_every_plane(adapters):
    rep = run(LIVE, adapters)
    got = by_plane(rep)
    assert set(got) == set(PLANES)
    for name, r in got.items():
        assert r.status is Status.REMNANT, (name, r)
    assert rep.verdict() == "REMNANTS" and rep.exit_code() == 1


def test_retired_guest_is_clean_on_every_measured_plane(adapters):
    rep = run(RETIRED, adapters)
    got = by_plane(rep)
    for name, r in got.items():
        assert r.status in (Status.CLEAN, Status.REVIEW, Status.INFO), (name, r)
    # the comment and the narrative doc are a human decision, not a failure
    assert got["live-refs"].status is Status.REVIEW
    assert rep.verdict() == "CLEAN" and rep.exit_code() == 0
    assert rep.verdict(strict=True) == "UNRESOLVED"


def test_positive_control_flags_the_live_guest(adapters):
    assert positive_control(LIVE, adapters).remnants


def test_broken_audit_is_caught_by_the_control():
    """An audit with nothing wired up returns no remnants for a live guest: the control fails."""
    ctl = positive_control(LIVE, Adapters())
    assert not ctl.remnants and ctl.verdict() == "UNMEASURED"


def test_unreachable_plane_is_skip_never_clean(files):
    snap = {"hypervisor": {"unreachable": "ssh timed out"}, "siem": {"unreachable": "503"}}
    rep = run(RETIRED, Adapters.from_snapshot(snap, MemTree(files)))
    got = by_plane(rep)
    for n in ("hv-config", "hv-firewall", "hv-volumes", "hv-backup", "hv-ha", "siem-roster"):
        assert got[n].status is Status.SKIP and "unreachable" in got[n].detail
    for n in ("monitoring", "secret-names", "dns", "proxy", "dhcp"):
        assert got[n].status is Status.SKIP and "no adapter" in got[n].detail


def test_nothing_measured_is_not_a_pass():
    rep = run(RETIRED, Adapters())
    # >= 100 is "could not measure" everywhere (docs/interfaces.md), never 1 ("remnants found")
    assert rep.measured == 0 and rep.verdict() == "UNMEASURED" and rep.exit_code() == 100


def test_probe_crash_becomes_skip(adapters, monkeypatch):
    def boom(t, a):
        raise RuntimeError("x")

    monkeypatch.setitem(PLANES, "dns", boom)
    assert by_plane(run(LIVE, adapters))["dns"].status is Status.SKIP


def test_no_vmid_skips_hypervisor_planes(adapters):
    rep = run(Target("app-core"), adapters, only=["hv-config"])
    assert rep.results[0].status is Status.SKIP


def test_vmid_reused_by_another_resource_is_info_not_delete(files, adapters):
    files["terraform/app.tf"] = 'resource "x_vm" "new" {\n  name = "fresh-core"\n  vmid = 180\n}\n'
    r = by_plane(run(RETIRED_WITH_180, adapters))["iac"]
    assert r.status is Status.INFO and "Do NOT delete by id" in r.detail


RETIRED_WITH_180 = Target("old-core", vmid=180)


def test_terraform_blocks_are_judged_separately(files, adapters):
    files["terraform/both.tf"] = (
        'resource "x_vm" "a" {\n  name = "app-core"\n  vmid = 180\n}\n'
        'resource "x_vm" "b" {\n  name = "web-core"\n  vmid = 190\n}\n'
    )
    r = by_plane(run(Target("web-core", vmid=190), adapters))["iac"]
    assert r.status is Status.REMNANT


def test_name_matching_is_word_bounded(files, adapters):
    files["config/x.conf"] = "host = app-core-2\nother = x.app-core\n"
    files.pop("config/proxy.conf")
    r = by_plane(run(Target("app-core"), adapters))["live-refs"]
    assert r.status is Status.CLEAN


def test_broken_import_naming_the_guest_is_a_remnant(files, adapters):
    files["playbooks/site.yml"] = "- import_playbook: old-core.yml\n"
    r = by_plane(run(RETIRED, adapters))["playbooks"]
    assert r.status is Status.REMNANT and "does not resolve" in r.items[0]


def test_unrelated_broken_import_is_info(adapters):
    r = by_plane(run(RETIRED, adapters))["playbooks"]
    assert r.status is Status.INFO and "gone-core.yml" in r.items[0]


def test_secret_plane_sees_names_only(adapters):
    r = by_plane(run(LIVE, adapters))["secret-names"]
    assert r.items == ["app_core_db_password"]


def test_secret_plane_is_word_bounded_and_reads_aliases(files):
    names = [
        "app_core_db_password",
        "APP_CORE",
        "app_core_2_db_password",
        "myapp_core_token",
        "app_core2_key",
        "legacy_app_token",
        "x_legacy_app_token",
    ]
    snap = {"secrets": {"names": names}}
    t = Target("app-core", aliases=("legacy-app",))
    r = by_plane(run(t, Adapters.from_snapshot(snap, MemTree(files)), ["secret-names"]))
    assert r["secret-names"].items == ["app_core_db_password", "APP_CORE", "legacy_app_token"]


def test_a_section_without_its_key_is_skip_not_clean(files):
    snap = {"dns": {"record": ["app-core.example.internal A 192.0.2.50"]}}  # mistyped key
    r = by_plane(run(LIVE, Adapters.from_snapshot(snap, MemTree(files)), ["dns"]))["dns"]
    assert r.status is Status.SKIP and "records" in r.detail


def test_two_roots_with_the_same_relative_path_are_both_scanned(tmp_path):
    for name, host in (("src", "app-core"), ("overlay", "web-core")):
        (tmp_path / name / "playbooks").mkdir(parents=True)
        (tmp_path / name / "playbooks" / "site.yml").write_text(f"- hosts: {host}\n  tasks: []\n")
    tree = DirTree(tmp_path / "src", tmp_path / "overlay")
    assert sorted(rel for rel, _ in tree.files()) == [
        "overlay/playbooks/site.yml",
        "src/playbooks/site.yml",
    ]
    r = by_plane(run(LIVE, Adapters(tree=tree), ["playbooks"]))["playbooks"]
    assert r.status is Status.REMNANT and r.items[0].startswith("src/playbooks/site.yml")


def test_claimed_paths_are_not_double_reported(adapters):
    rep = by_plane(run(LIVE, adapters))
    assert not any("terraform/app.tf" in i for i in rep["live-refs"].items)
    assert any("config/proxy.conf" in i for i in rep["live-refs"].items)


def test_render_and_plan_text(adapters):
    rep = run(LIVE, adapters)
    assert "verdict: REMNANTS" in render(rep)
    p = plan(rep)
    assert "read-only" in p and "hv-config" in p and "revoke its key" in p
    assert "nothing to do" in plan(run(RETIRED, adapters, only=["hv-config"]))


def test_unknown_plane_is_keyerror(adapters):
    with pytest.raises(KeyError):
        run(LIVE, adapters, only=["nope"])


# ------------------------------------------------------------------ CLI


@pytest.fixture
def lab(tmp_path, files):
    for rel, text in files.items():
        p = tmp_path / "src" / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    snap = tmp_path / "snap.json"
    snap.write_text(json.dumps(SNAPSHOT), encoding="utf-8")
    return tmp_path


def args(lab, name, *extra):
    return [name, "--root", str(lab / "src"), "--snapshot", str(lab / "snap.json"), *extra]


def test_cli_exit_codes(lab, capsys):
    assert main(["check", *args(lab, "app-core", "--vmid", "180")]) == 1
    assert main(["check", *args(lab, "old-core", "--vmid", "170")]) == 0
    assert main(["check", *args(lab, "old-core", "--vmid", "170", "--strict")]) == 1
    assert main(["check"]) == 2
    assert main(["bogus"]) == 2
    assert main(["check", "x", "--root", str(lab / "missing")]) == 2
    assert main(["planes"]) == 0
    assert main(["check", "app-core"]) == 100  # no tree, no snapshot: nothing measured
    capsys.readouterr()


def test_cli_json_and_plan(lab, capsys):
    assert main(["check", *args(lab, "old-core", "--vmid", "170", "--json")]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["verdict"] == "CLEAN" and len(doc["results"]) == len(PLANES)
    assert main(["plan", *args(lab, "app-core", "--vmid", "180")]) == 1
    assert "hv-ha" in capsys.readouterr().out


def test_cli_positive_control(lab, capsys):
    ok = args(lab, "old-core", "--vmid", "170", "--control", "app-core", "--control-vmid", "180")
    assert main(["check", *ok]) == 0
    bad = args(lab, "old-core", "--control", "ghost-core")
    assert main(["check", *bad]) == 1
    assert "POSITIVE CONTROL FAILED" in capsys.readouterr().err


def test_hnx_dispatch_registered():
    assert "decommission" in COMMANDS


def test_secret_plane_marks_a_known_sibling_guests_names_ambiguous(files):
    """Key `app` matches `app_core_*`; with app-core a known guest, those are not for deletion."""
    names = ["app_core_db_password", "app_token"]
    snap = {"secrets": {"names": names}, "guests": ["app-core"]}
    r = by_plane(run(Target("app"), Adapters.from_snapshot(snap, MemTree(files)), ["secret-names"]))
    res = r["secret-names"]
    assert res.status is Status.REMNANT
    assert res.items[0] == "app_token"
    assert res.items[1].startswith("AMBIGUOUS app_core_db_password")


def test_secret_plane_derives_known_guests_from_host_vars(files):
    snap = {"secrets": {"names": ["app_core_db_password"]}}
    r = by_plane(run(Target("app"), Adapters.from_snapshot(snap, MemTree(files)), ["secret-names"]))
    assert r["secret-names"].status is Status.REVIEW
