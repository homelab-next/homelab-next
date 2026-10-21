# SPDX-License-Identifier: Apache-2.0
"""Per-control settings (baseline set 1.2): a baseline's ``{id, with}`` entries, checked against
the bound role's ``meta/argument_specs.yml``, merged parent-first through ``extends``, refused on
a conflict between baselines neither of which extends the other, and passed to the role as its
prefixed variables (host variables for a per-guest control, ``settings`` in ``<role>_guests`` rows
for a central one)."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
import yaml

from homelabnext import cli as hnx
from homelabnext.compute import ComputeError, load_fleet, open_site, render, site_flows
from homelabnext.compute.baselines import coverage, coverage_text, resolve

HERE = Path(__file__).resolve().parent
FLEET = HERE / "fleet"
SITE = HERE / "site.yml"
REPO = HERE.parents[1]
EXAMPLE = REPO / "examples" / "minimal" / "guests"
EXAMPLE_SITE = REPO / "examples" / "minimal" / "site.yml"

SPECS = {
    "time_sync": {
        "time_sync_servers": {"type": "list", "elements": "str", "required": True},
        "time_sync_max_offset": {"type": "float", "default": 1.0},
        "time_sync_mode": {"type": "str", "choices": ["strict", "loose"], "default": "strict"},
        "time_sync_retries": {"type": "int", "default": 3},
    },
    "greenbone_target": {
        "greenbone_target_guests": {"type": "list", "elements": "dict", "required": True},
        "greenbone_target_port_range": {"type": "str", "default": "T:1-65535"},
    },
    "ssh_hardening": {"ssh_hardening_keep_user": {"type": "str", "required": True}},
}


@pytest.fixture(autouse=True)
def roles_dir(tmp_path, monkeypatch):
    d = tmp_path / "roles"
    for role, opts in SPECS.items():
        meta = d / role / "meta"
        meta.mkdir(parents=True)
        doc = {
            "argument_specs": {
                "main": {"options": {k: {**v, "description": k} for k, v in opts.items()}}
            }
        }
        (meta / "argument_specs.yml").write_text(yaml.safe_dump(doc))
    monkeypatch.setenv("HNX_ROLES_DIR", str(d))
    return d


def fleet_with(tmp_path, entries, guests=None, controls=None):
    """The test fleet with ``entries`` (baseline -> extra controls entries) appended."""
    d = tmp_path / "fleet"
    shutil.copytree(FLEET, d)
    p = d / "_baselines.yml"
    doc = yaml.safe_load(p.read_text())
    for b, extra in entries.items():
        doc["baselines"].setdefault(b, {"description": f"test baseline {b}"})
        doc["baselines"][b].setdefault("controls", [])
        doc["baselines"][b]["controls"] += extra
    for c, edit in (controls or {}).items():
        edit(doc["controls"][c])
    p.write_text(yaml.safe_dump(doc, sort_keys=False))
    for name, names in (guests or {}).items():
        g = d / f"{name}.yml"
        gd = yaml.safe_load(g.read_text())
        gd["baseline"] = {"names": names}
        g.write_text(yaml.safe_dump(gd, sort_keys=False))
    zones, domain = open_site(SITE)
    return load_fleet(d, zones, domain=domain, flows=site_flows(SITE))


def problems(tmp_path, entries, **kw) -> str:
    with pytest.raises(ComputeError) as ei:
        fleet_with(tmp_path, entries, **kw)
    return str(ei.value)


def ts(**w):
    return {"id": "time-sync", "with": w}


def guest(fleet, name):
    return next(g for g in fleet.guests if g.id == f"guest:{name}")


# ---------------------------------------------------------------- merge order
def test_a_child_baseline_overrides_its_parent_and_inherits_the_rest(tmp_path):
    f = fleet_with(tmp_path, {"base": [ts(servers=["time"], mode="loose")],
                              "sensitive": [ts(max_offset=0.5, mode="strict")]})  # fmt: skip
    assert resolve(guest(f, "bus-core"), f.baselines).settings["time-sync"] == {
        "servers": ["time"],
        "mode": "loose",
    }  # server: from base only
    assert resolve(guest(f, "secrets-core"), f.baselines).settings["time-sync"] == {
        "servers": ["time"],
        "mode": "strict",
        "max_offset": 0.5,
    }  # sensitive overrides base


def test_settings_reach_the_role_as_host_variables(tmp_path):
    f = fleet_with(tmp_path, {"base": [ts(servers=["time"])], "sensitive": [ts(max_offset=0.5)]})
    out = render(f, "inventory")
    hv = yaml.safe_load(out["host_vars/secrets-core.example.internal.yml"])
    assert hv["time_sync_servers"] == ["time"] and hv["time_sync_max_offset"] == 0.5
    plain = yaml.safe_load(out["host_vars/bus-core.example.internal.yml"])
    assert plain["time_sync_servers"] == ["time"] and "time_sync_max_offset" not in plain
    text = render(f, "baseline-playbook")["baseline.yml"]
    assert "# baseline settings (with:) are host variables (the inventory target)" in text


def test_a_central_control_gets_its_settings_per_guest_in_the_enrolled_rows(tmp_path):
    f = fleet_with(
        tmp_path, {"sensitive": [{"id": "vuln-scan", "with": {"port_range": "T:22,443"}}]}
    )
    plays = {p["name"]: p for p in yaml.safe_load(render(f, "baseline-playbook")["baseline.yml"])}
    rows = {
        r["name"]: r
        for r in plays["control vuln-scan (detection, central)"]["roles"][0][
            "greenbone_target_guests"
        ]
    }
    assert rows["secrets-core"]["settings"] == {"greenbone_target_port_range": "T:22,443"}
    assert "settings" not in rows["bus-core"]  # a server guest: nothing set, the row is unchanged
    hv = yaml.safe_load(render(f, "inventory")["host_vars/secrets-core.example.internal.yml"])
    assert "greenbone_target_port_range" not in hv  # central: never a host variable of the guest


# ---------------------------------------------------------------- refusals
@pytest.mark.parametrize(
    ("entries", "expect"),
    [
        ({"base": [ts(server=["time"])]},
         "baseline 'base', control 'time-sync': unknown setting 'server' (role 'time_sync' has no input time_sync_server)"),
        ({"base": [ts(max_offset="fast")]}, "setting 'max_offset' is str 'fast', not a float"),
        ({"base": [ts(retries=True)]}, "setting 'retries' is True, not a int"),
        ({"base": [ts(retries=2.5)]}, "setting 'retries' is float 2.5, not a int"),
        ({"base": [ts(mode="lax")]}, "setting 'mode' is 'lax', not one of ['strict', 'loose']"),
        ({"base": [ts(servers=["time", 7])]}, "setting 'servers' has an element that is int 7, not a str"),
        ({"base": [{"id": "patching", "with": {"window": "03:00"}}]},
         "baseline 'base', control 'patching': `with` needs a bound role"),
        ({"base": [{"id": "remote-access", "with": {"hostname": "x"}}]},
         "cannot read the meta/argument_specs.yml of role 'tailscale_node'"),
    ],
)  # fmt: skip
def test_bad_settings_are_refused(tmp_path, entries, expect):
    assert expect in problems(tmp_path, entries)


def test_a_control_can_narrow_what_a_baseline_may_set(tmp_path):
    narrow = {"time-sync": lambda c: c.update(settings=["servers"])}
    assert "setting 'mode' is not in the control's settings ['servers']" in problems(
        tmp_path, {"base": [ts(servers=["time"], mode="loose")]}, controls=narrow
    )
    other = tmp_path / "ok"
    other.mkdir()
    fleet_with(other, {"base": [ts(servers=["time"])]}, controls=narrow)
    bad = tmp_path / "bad"
    bad.mkdir()
    assert "setting 'moat' is not an input of role 'time_sync'" in problems(
        bad, {}, controls={"time-sync": lambda c: c.update(settings=["moat"])}
    )


def test_two_baselines_a_guest_names_may_not_disagree(tmp_path):
    """exposed and sensitive both extend server; neither extends the other."""
    expect = "setting time-sync.mode is 'loose' in 'exposed' and 'strict' in 'sensitive', and neither extends the other"
    entries = {"exposed": [ts(mode="loose")], "sensitive": [ts(mode="strict")]}
    assert expect in problems(tmp_path, entries, guests={"bus-core": ["exposed", "sensitive"]})
    same = tmp_path / "same"
    same.mkdir()
    f = fleet_with(same, {"exposed": [ts(mode="loose")], "sensitive": [ts(mode="loose")]},
                   guests={"bus-core": ["exposed", "sensitive"]})  # fmt: skip
    assert resolve(guest(f, "bus-core"), f.baselines).settings["time-sync"] == {"mode": "loose"}


def test_a_baseline_that_extends_both_settles_their_disagreement(tmp_path):
    entries = {"exposed": [ts(mode="loose")], "sensitive": [ts(mode="strict")]}
    both = {"both": {"description": "extends both", "extends": ["exposed", "sensitive"]}}

    def add_both(tmp, own):
        d = tmp / "fleet"
        shutil.copytree(FLEET, d)
        p = d / "_baselines.yml"
        doc = yaml.safe_load(p.read_text())
        for b, extra in entries.items():
            doc["baselines"][b]["controls"] += extra
        doc["baselines"].update(both)
        doc["baselines"]["both"]["controls"] = own
        p.write_text(yaml.safe_dump(doc, sort_keys=False))
        zones, domain = open_site(SITE)
        return lambda: load_fleet(d, zones, domain=domain, flows=site_flows(SITE))

    a = tmp_path / "a"
    a.mkdir()
    with pytest.raises(ComputeError, match=r"baseline 'both': setting time-sync\.mode"):
        add_both(a, ["time-sync"])()
    b = tmp_path / "b"
    b.mkdir()
    f = add_both(b, [ts(mode="strict")])()
    assert f.baselines.settings(["both"])[0]["time-sync"] == {"mode": "strict"}


# ---------------------------------------------------------------- report
def test_the_report_lists_the_settings_that_differ_from_the_role_defaults(tmp_path, capsys):
    f = fleet_with(tmp_path, {"base": [ts(servers=["time"], mode="strict", max_offset=0.5)]})
    rep = coverage(f.sorted(), f.baselines)
    assert rep["settings"] == [
        {
            "baseline": "base",
            "control": "time-sync",
            "setting": "max_offset",
            "value": 0.5,
            "default": 1.0,
        },
        {
            "baseline": "base",
            "control": "time-sync",
            "setting": "servers",
            "value": ["time"],
            "default": None,
        },
    ]  # mode=strict is the role's default: not listed
    row = next(r for r in rep["guests"] if r["id"] == "guest:bus-core")
    assert row["settings"]["time-sync"] == {
        "servers": ["time"],
        "mode": "strict",
        "max_offset": 0.5,
    }
    text = coverage_text(rep)
    assert '  base: time-sync servers=["time"]\n' in text and "mode=" not in text


# ---------------------------------------------------------------- the example lab
def test_the_example_lab_binds_every_needed_control_and_sets_its_inputs(capsys, monkeypatch):
    monkeypatch.delenv("HNX_ROLES_DIR")  # the repository's own roles
    args = ["guests", "baselines", str(EXAMPLE), "--site", str(EXAMPLE_SITE), "--require-bound"]
    assert hnx.main(args) == 0, capsys.readouterr()
    out = capsys.readouterr().out
    assert (
        "0 needed but not bound to a role" in out
        and '  server: package-scan severity="HIGH"' in out
    )
    zones, domain = open_site(EXAMPLE_SITE)
    f = load_fleet(EXAMPLE, zones, domain=domain, flows=site_flows(EXAMPLE_SITE))
    hv = yaml.safe_load(render(f, "inventory")["host_vars/bus-core.example.internal.yml"])
    assert hv["trivy_severity"] == "HIGH" and hv["chrony_server_ids"] == ["time"]
    assert hv["ssh_hardening_keep_user"] == "ansible" and hv["lynis_min_hardening_index"] == 60
    assert f.baselines.settings(["sensitive"])[0]["package-scan"] == {"severity": "MEDIUM"}
    assert f.baselines.settings(["container-host"])[0]["package-scan"] == {
        "severity": "HIGH",
        "scan_containers": True,
    }
