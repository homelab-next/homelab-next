# SPDX-License-Identifier: Apache-2.0
"""Guest baselines (ADR-0016): the set's rules, per-guest resolution, inventory, playbook, CLI."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
import yaml

from homelabnext import cli as hnx
from homelabnext.compute import ComputeError, MappingZones, ZoneInfo, load_fleet, render
from homelabnext.compute.baselines import (
    LAYERS,
    BaselineSet,
    coverage,
    resolve,
    set_problems,
)

HERE = Path(__file__).resolve().parent
FLEET = HERE / "fleet"
SITE = HERE / "site.yml"
REPO = HERE.parents[1]
STUB = MappingZones(
    [
        ZoneInfo("mgmt", "192.0.2.0/24", "192.0.2.1", None, 10),
        ZoneInfo(
            "data", "198.51.100.0/25", "198.51.100.1", ("198.51.100.100", "198.51.100.126"), 20
        ),
        ZoneInfo("compute", "198.51.100.128/25", "198.51.100.129", None, 30),
        ZoneInfo("edge", "203.0.113.0/24", "203.0.113.1", None, 40),
    ]
)
EXAMPLE = REPO / "examples" / "minimal" / "guests"
EXAMPLE_SITE = REPO / "examples" / "minimal" / "site.yml"


@pytest.fixture(scope="module")
def fleet():
    return load_fleet(FLEET, STUB)


def copy_fleet(tmp_path: Path, *, guests=None, baselines=None) -> Path:
    """The test fleet in ``tmp_path``; ``guests``: {name: edit(doc)}; ``baselines``: edit(doc)."""
    d = tmp_path / "fleet"
    shutil.copytree(FLEET, d)
    for name, edit in (guests or {}).items():
        p = d / f"{name}.yml"
        doc = yaml.safe_load(p.read_text())
        edit(doc)
        p.write_text(yaml.safe_dump(doc, sort_keys=False))
    if baselines is not None:
        p = d / "_baselines.yml"
        doc = yaml.safe_load(p.read_text())
        baselines(doc)
        p.write_text(yaml.safe_dump(doc, sort_keys=False))
    return d


def problems_of(d: Path) -> str:
    with pytest.raises(ComputeError) as ei:
        load_fleet(d, STUB)
    return str(ei.value)


# ---------------------------------------------------------------- the repository passes
def test_the_example_lab_gives_every_guest_a_baseline():
    from homelabnext.compute import open_site

    zones, _ = open_site(EXAMPLE_SITE)
    f = load_fleet(EXAMPLE, zones)
    assert f.baselines is not None
    report = coverage(f.sorted(), f.baselines)
    assert report["summary"]["missing"] == 0
    assert {f.baselines.layer(c) for c in f.baselines.controls} == set(LAYERS)
    assert set(f.baselines.baselines) >= {"base", "server", "exposed", "sensitive", "scratch"}


def test_the_test_fleet_loads_with_its_set(fleet):
    assert fleet.baselines is not None and len(fleet.guests) == 7


def test_no_set_means_no_requirement(tmp_path):
    d = tmp_path / "old"
    shutil.copytree(FLEET, d)
    (d / "_baselines.yml").unlink()
    for p in d.glob("[!_]*.yml"):
        doc = yaml.safe_load(p.read_text())
        doc.pop("baseline", None)
        p.write_text(yaml.safe_dump(doc, sort_keys=False))
    f = load_fleet(d, STUB)  # a pre-1.3 tree stays valid
    assert f.baselines is None
    assert "hnx_baselines" not in render(f, "inventory")["host_vars/edge-core.example.internal.yml"]


# ---------------------------------------------------------------- every rule fails on bad input
def _drop(doc):
    doc.pop("baseline")


GUEST_CASES = [
    ("vm-without-baseline", "edge-core", _drop, "guest:edge-core: no baseline"),
    ("lxc-without-baseline", "idp-core", _drop, "guest:idp-core: no baseline"),
    ("host-without-baseline", "hv-a", _drop, "guest:hv-a: no baseline"),
    (
        "unknown-baseline",
        "edge-core",
        lambda d: d["baseline"].update(names=["fortress"]),
        "baseline 'fortress' is not defined",
    ),
    (
        "exemption-with-names",
        "hv-a",
        lambda d: d["baseline"].update(names=["base"]),
        "exemption cannot be combined with names",
    ),
    (
        "add-unknown-control",
        "edge-core",
        lambda d: d["baseline"].update(add=["moat"]),
        "baseline.add: control 'moat' is not defined",
    ),
    (
        "add-already-included",
        "edge-core",
        lambda d: d["baseline"].update(add=["siem-agent"]),
        "'siem-agent' already comes from its baselines",
    ),
    (
        "remove-stale",
        "bus-core",
        lambda d: d["baseline"].update(
            remove=[{"control": "disk-encryption", "reason": "nothing to encrypt here at all"}]
        ),
        "'disk-encryption' is not in its baselines (stale)",
    ),
    (
        "remove-unknown",
        "bus-core",
        lambda d: d["baseline"].update(
            remove=[{"control": "moat", "reason": "nothing to encrypt here at all"}]
        ),
        "baseline.remove: control 'moat' is not defined",
    ),
    (
        "remove-twice",
        "infer-core",
        lambda d: d["baseline"]["remove"].append(dict(d["baseline"]["remove"][0])),
        "names a control twice",
    ),
    (
        "exemption-short-reason",
        "hv-a",
        lambda d: d["baseline"]["exemption"].update(reason="n/a"),
        "baseline/exemption/reason",
    ),
]


@pytest.mark.parametrize(
    ("label", "name", "edit", "expect"), GUEST_CASES, ids=[c[0] for c in GUEST_CASES]
)
def test_guest_rule_fails(tmp_path, label, name, edit, expect):
    msg = problems_of(copy_fleet(tmp_path, guests={name: edit}))
    assert expect in msg, msg


SET_CASES = [
    (
        "unknown-control-in-baseline",
        lambda d: d["baselines"]["base"]["controls"].append("moat"),
        "baseline 'base' names control 'moat', which is not defined",
    ),
    (
        "missing-extends-target",
        lambda d: d["baselines"]["server"].update(extends=["base", "core"]),
        "baseline 'server' extends 'core', which is not defined",
    ),
    (
        "extends-cycle",
        lambda d: d["baselines"]["base"].update(extends=["exposed"]),
        "extends cycle: base -> exposed -> server -> base",
    ),
    (
        "self-cycle",
        lambda d: d["baselines"]["sensitive"].update(extends=["sensitive"]),
        "extends cycle: sensitive -> sensitive",
    ),
    (
        "empty-baseline",
        lambda d: d["baselines"].update(empty={"description": "a baseline with no controls"}),
        "baseline 'empty' resolves to no controls",
    ),
    (
        "control-in-no-layer",
        lambda d: d["controls"]["patching"].pop("layer"),
        "schema: controls/patching: 'layer' is a required property",
    ),
    (
        "control-in-unknown-layer",
        lambda d: d["controls"]["patching"].update(layer="perimeter"),
        "controls/patching/layer",
    ),
    (
        "role-left-out",
        lambda d: d["controls"]["patching"].pop("role"),
        "'role' is a required property",
    ),
]


@pytest.mark.parametrize(("label", "edit", "expect"), SET_CASES, ids=[c[0] for c in SET_CASES])
def test_set_rule_fails(tmp_path, label, edit, expect):
    msg = problems_of(copy_fleet(tmp_path, baselines=edit))
    assert expect in msg, msg


def test_a_set_built_in_code_with_no_layer_is_refused():
    bs = BaselineSet(
        {"x": {"layer": "moat", "role": None, "verify": "v" * 10, "description": "d" * 10}},
        {"b": {"description": "d" * 10, "controls": ["x"]}},
    )
    assert any("in no known layer" in str(p) for p in set_problems(bs))


def test_a_baseline_without_a_set_is_an_error(tmp_path):
    d = copy_fleet(tmp_path)
    (d / "_baselines.yml").unlink()
    assert "there is no baseline set" in problems_of(d)


def test_an_explicit_set_path_that_is_missing_is_an_error(tmp_path):
    with pytest.raises(ComputeError, match="cannot read baseline set"):
        load_fleet(FLEET, STUB, baselines_path=tmp_path / "nope.yml")


def test_the_coverage_loader_tolerates_only_the_missing_baseline(tmp_path):
    d = copy_fleet(tmp_path, guests={"edge-core": _drop})
    f = load_fleet(d, STUB, require_baselines=False)
    assert resolve(next(g for g in f.guests if g.name == "edge-core"), f.baselines).missing
    bad = copy_fleet(
        tmp_path / "b", guests={"edge-core": lambda x: x["baseline"].update(names=["no"])}
    )
    with pytest.raises(ComputeError, match="'no' is not defined"):
        load_fleet(bad, STUB, require_baselines=False)


# ---------------------------------------------------------------- resolution
def guest(fleet, name):
    return next(g for g in fleet.guests if g.name == name)


def test_resolution_is_parents_first_listed_order_deduped(fleet):
    r = resolve(guest(fleet, "lake-core"), fleet.baselines)  # names: [server, sensitive]
    assert r.baselines == ("base", "server", "sensitive")
    assert r.controls == (
        "time-sync",
        "patching",
        "ssh-hardening",
        "host-firewall",
        "siem-agent",
        "vuln-scan",
        "backup-verify",
        "disk-encryption",
    )
    assert r.by_layer["detection"] == ("siem-agent", "vuln-scan")


def test_add_appends_and_remove_drops(fleet):
    sec = resolve(guest(fleet, "secrets-core"), fleet.baselines)
    assert sec.controls[-1] == "network-sensor"
    inf = resolve(guest(fleet, "infer-core"), fleet.baselines)
    assert "backup-verify" not in inf.controls and inf.removed == ("backup-verify",)


def test_exempt_guest_has_no_controls(fleet):
    r = resolve(guest(fleet, "hv-a"), fleet.baselines)
    assert r.exemption and r.controls == () and not r.missing


# ---------------------------------------------------------------- generators
def test_inventory_groups_and_vars(fleet):
    out = render(fleet, "inventory")
    hosts = yaml.safe_load(out["hosts.yml"])["all"]["children"]
    assert set(hosts["baseline_sensitive"]["hosts"]) == {
        "idp-core.example.internal",
        "lake-core.example.internal",
        "secrets-core.example.internal",
    }
    assert "hv-a.example.internal" not in hosts["baseline_base"]["hosts"]
    assert set(hosts["control_network_sensor"]["hosts"]) == {
        "edge-core.example.internal",
        "secrets-core.example.internal",
    }
    assert "infer-core.example.internal" not in hosts["control_backup_verify"]["hosts"]
    hv = yaml.safe_load(out["host_vars/infer-core.example.internal.yml"])
    assert hv["hnx_baselines"] == ["base", "server"]
    assert "backup-verify" not in hv["hnx_controls"]


def test_playbook_binds_roles_and_never_drops_an_unbound_control(fleet):
    text = render(fleet, "baseline-playbook")["baseline.yml"]
    plays = yaml.safe_load(text)
    assert [(p["hosts"], p["roles"][0]["role"]) for p in plays] == [
        ("control_remote_access", "tailscale_node"),
        ("control_ssh_hardening", "ssh_hardening"),
        ("control_time_sync", "time_sync"),
        ("cap_sensor", "suricata_enroll"),  # central (tests/compute/test_products.py)
        ("cap_scanner", "greenbone_target"),
    ]
    for c in fleet.baselines.controls:
        assert f"control {c} (" in text, c  # every control is named
    assert "# control siem-agent (detection): NOT BOUND to a product yet" in text


def test_playbook_without_a_set_or_bound_role_is_an_empty_list(tmp_path):
    d = copy_fleet(
        tmp_path, baselines=lambda x: [c.update(role=None) for c in x["controls"].values()]
    )
    assert yaml.safe_load(render(load_fleet(d, STUB), "baseline-playbook")["baseline.yml"]) == []
    plain = tmp_path / "plain"
    shutil.copytree(EXAMPLE, plain)
    (plain / "_baselines.yml").unlink()
    for p in plain.glob("[!_]*.yml"):
        doc = yaml.safe_load(p.read_text())
        doc.pop("baseline", None)
        p.write_text(yaml.safe_dump(doc, sort_keys=False))
    from homelabnext.compute import open_site

    f = load_fleet(plain, open_site(EXAMPLE_SITE)[0])
    assert yaml.safe_load(render(f, "baseline-playbook")["baseline.yml"]) == []


# ---------------------------------------------------------------- CLI
def run_cli(*args):
    return hnx.main(["guests", "baselines", *args])


BASE = [str(FLEET), "--site", str(SITE)]


def test_cli_matrix(capsys):
    assert run_cli(*BASE) == 0
    out = capsys.readouterr().out
    assert out.splitlines()[0].split() == ["guest", "baselines", *LAYERS]
    assert "hv-a" in out and "exempt" in out
    assert "7 guests: 6 with a baseline, 1 exempt, 0 missing" in out


def test_cli_json(capsys):
    assert run_cli(*BASE, "--json") == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["layers"] == list(LAYERS)
    assert doc["controls"]["ssh-hardening"]["role"] == "ssh_hardening"
    assert "siem-agent" in doc["unbound"]


def test_cli_check_passes_on_the_repository(capsys):
    assert run_cli(*BASE, "--check") == 0
    assert run_cli(str(EXAMPLE), "--site", str(EXAMPLE_SITE), "--check") == 0
    assert "baselines: ok" in capsys.readouterr().out


def test_cli_check_fails_on_a_guest_without_a_baseline(tmp_path, capsys):
    d = copy_fleet(tmp_path, guests={"edge-core": _drop})
    assert hnx.main(["guests", "validate", str(d), "--site", str(SITE)]) == 1
    assert run_cli(str(d), "--site", str(SITE)) == 0  # the report itself still prints
    assert "MISSING" in capsys.readouterr().out
    assert run_cli(str(d), "--site", str(SITE), "--check") == 1
    assert "no baseline or exemption: guest:edge-core" in capsys.readouterr().err


def test_cli_require_bound_fails_on_an_unbound_needed_control(capsys):
    assert run_cli(*BASE, "--require-bound") == 1
    assert "not bound to a role: patching" in capsys.readouterr().err


def test_cli_check_without_a_set_cannot_pass(tmp_path, capsys):
    d = tmp_path / "f"
    shutil.copytree(FLEET, d)
    (d / "_baselines.yml").unlink()
    for p in d.glob("[!_]*.yml"):
        doc = yaml.safe_load(p.read_text())
        doc.pop("baseline", None)
        p.write_text(yaml.safe_dump(doc, sort_keys=False))
    assert run_cli(str(d), "--site", str(SITE), "--check") == 1
    assert "no baseline set" in capsys.readouterr().err


# ---------------------------------------------------------------- status hub page
def _doc(baselines=True):
    from homelabnext.registry.model import load
    from homelabnext.status.model import sources_from_registry
    from homelabnext.status.views import build_status, load_views

    reg = load(REPO / "examples/services.yml")
    specs = sources_from_registry(reg)
    views = load_views(REPO / "examples/status/views.yml", reg, specs)
    snap = {"now": "2026-10-20T13:10:00Z", "observations": [], "sources": []}
    return build_status(snap, views, reg, [], baselines=baselines)


def test_the_page_is_on_the_menu_and_available_only_when_served():
    entry = next(m for m in _doc()["menu"] if m["id"] == "baselines")
    assert entry == {
        "id": "baselines", "title": "Baselines", "kind": "page", "panel": "baselines",
        "href": "/baselines", "available": True,
    }  # fmt: skip
    assert not next(m for m in _doc(False)["menu"] if m["id"] == "baselines")["available"]


def test_the_page_renders_the_matrix_escaped(tmp_path):
    from homelabnext.compute.pages import BaselineSite

    d = copy_fleet(
        tmp_path,
        guests={"edge-core": _drop},
        baselines=lambda x: x["controls"]["patching"].update(verify="<script>x</script> pending"),
    )
    site = BaselineSite(d, SITE)
    assert site.handle("/baselines/../etc", "", _doc()) is None
    code, ctype, body = site.handle("/baselines", "", _doc())
    html = body.decode()
    assert code == 200 and ctype.startswith("text/html")
    assert "<script>x" not in html and "&lt;script&gt;x&lt;/script&gt; pending" in html
    assert '<code>guest:edge-core</code></td><td>vm</td><td><span class="s fail">missing' in html
    assert "exempt</span> Hypervisor hardened" in html
    assert "<code>ssh_hardening</code>" in html and "not bound" in html


def test_the_page_reports_an_unloadable_tree(tmp_path):
    from homelabnext.compute.pages import BaselineSite

    d = copy_fleet(tmp_path, guests={"edge-core": lambda x: x["baseline"].update(names=["no"])})
    html = BaselineSite(d, SITE).handle("/baselines", "", _doc())[2].decode()
    assert "cannot load the guests" in html and "&#x27;no&#x27; is not defined" in html


def test_serve_routes_the_page():
    import threading
    import urllib.request

    from homelabnext.compute.pages import BaselineSite
    from homelabnext.status.serve import make_server

    srv = make_server(_doc, baselines=BaselineSite(EXAMPLE, EXAMPLE_SITE))
    threading.Thread(target=srv.serve_forever, args=(0.05,), daemon=True).start()
    host, port = srv.server_address[:2]
    try:
        with urllib.request.urlopen(f"http://{host}:{port}/baselines", timeout=5) as r:  # loopback
            body = r.read().decode()
        assert "<h2>Baselines</h2>" in body and "<code>guest:bus-core</code>" in body
    finally:
        srv.shutdown()
        srv.server_close()
