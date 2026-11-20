# SPDX-License-Identifier: Apache-2.0
"""The feed-reader provider module, ``modules/<id>`` (its README.md).

* The public tree loads clean and the module's ``roles/`` holds only its one contributed role.
* The manifest says what the README says: the administrator's secrets by reference, internet egress for
  the feeds, no public route, local accounts, an image pinned by tag and digest whose version is the
  product's.
* A fictional overlay that places it on a guest (an egress grant, no public route) passes
  ``hnx modules check --overlay`` and renders ``modules.yml`` on ``mod_<id>_server``; a registry row
  that differs, a missing egress grant and a guest without the ``base`` baseline are refused.
* The module's own probe reads the sign-in page and the refused feed-API call from the resolved
  endpoint only.
* role_lint passes the role and the lifecycle playbooks.
"""

from __future__ import annotations

import copy
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from homelabnext.conform.adapters._env import AdapterConfigError
from homelabnext.modules import cli as mcli
from homelabnext.modules import loader as ld
from tests.modules.feed_reader_front import Server
from tests.modules.feed_reader_module import MID, MODULE, P, ref
from tests.modules.play_vars import without_footprint

ROOT = Path(__file__).resolve().parents[2]

FIXTURES = Path(__file__).resolve().parent / "fixtures"
GUEST = ld.load_yaml(ROOT / "examples" / "services.yml")["hosts"]["dns-core"]["address"]
REQUIRED = sorted(
    s
    for s, d in ld.load_yaml(ROOT / "examples" / "modules" / "slots.yml")["slots"].items()
    if d.get("required_in_core")
)


class _NoAliases(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


def _dump(doc) -> str:
    return yaml.dump(doc, Dumper=_NoAliases, sort_keys=False)


def _args(ov: Path) -> list[str]:
    return [
        "--root", str(ROOT), "--overlay", str(ov),
        "--keyring", str(ROOT / "examples" / "keyring" / "keyring.json"),
        "--mcp-catalog", str(ROOT / "examples" / "mcp"),
    ]  # fmt: skip


def bound_row() -> dict:
    row = ld.load_yaml(MODULE / "registry" / "services.yml")["services"]["feed-reader"]
    version = str(ld.load_yaml(MODULE / "module.yml")["product"]["version"])
    return {**copy.deepcopy(row), "host": "feeds-1", "version": version}


def overlay(tmp: Path, grant: bool = True) -> Path:
    lab = tmp / "lab"
    (lab / "guests").mkdir(parents=True)
    reg = ld.load_yaml(ROOT / "examples" / "services.yml")
    reg["hosts"]["feeds-1"] = {"address": GUEST, "zone": "mgmt", "role": "feeds"}
    reg["services"]["feeds"] = bound_row()
    hosts = {"agent-runtime": "runtime-core", "backup": "secrets-core", "broker": "idp-core",
             "edge": "edge-core", "records": "lake-core"}  # fmt: skip
    for i, (slot, host) in enumerate(sorted(hosts.items())):
        reg["services"][f"{slot}-incumbent"] = {
            "capability": slot, "impl": "example", "host": host, "protocol": "tcp",
            "port": 7001 + i, "health": {"kind": "none"}, "owner": "platform-team",
            "version": "1.0", "tls": "none",
        }  # fmt: skip
    (lab / "services.yml").write_text(_dump(reg))
    shutil.copy(FIXTURES / "guests" / "_baselines.yml", lab / "guests" / "_baselines.yml")
    (lab / "guests" / "feeds-1.yml").write_text(
        "# SPDX-License-Identifier: Apache-2.0\n"
        "id: guest:feeds-1\nkind: vm\nprovisioning: terraform\nstatus: planned\n"
        "placement: {node: hv-01, vmid: 242, vmid_scheme: freeform}\n"
        "resources:\n  cpu: {cores: 2}\n  memory: {size_mb: 1024}\n"
        "  disks: [{name: rootfs, size_gb: 10, pool: fast}]\n"
        "image: {logical: debian-13-cloudinit, kind: template-clone, os_type: linux-6}\n"
        "cloudinit: {user: ansible, ssh_authorized_keys: [operator]}\n"
        f"network: {{zone: mgmt, ip: {GUEST}}}\n"
        "capability: cap:documents\nbackup: {policy: none}\n"
        "owners: {primary: platform-team}\nbaseline: {names: [base]}\n"
    )
    rows = {n: r["capability"] for n, r in reg["services"].items()}
    incumbents = {
        slot: {"service": next(n for n, c in rows.items() if c == slot), "why": "fictional"}
        for slot in REQUIRED
    }
    sel = {
        "profile": "feeds-pilot",
        "hosts": {"feeds": {"guest": "guest:feeds-1"}},
        "slots": {"feed-reader": [{"provider": MID, "instance": "feeds", "placement": {"server": "feeds"}}]},
        "incumbents": incumbents,
    }  # fmt: skip
    if grant:
        sel["grants"] = {"egress": {MID: {"server": ["internet"]}}}
    (lab / "modules.yml").write_text(_dump(sel))
    return tmp


def _check(ov: Path, capsys) -> tuple[int, str]:
    code = mcli.main(["check", *_args(ov)])
    return code, capsys.readouterr().out


# ----------------------------------------------------------------------------- the public tree


def test_the_public_tree_loads_clean(capsys):
    code = mcli.main(["check", "--root", str(ROOT)])
    out = capsys.readouterr().out
    assert code == 0, out
    public = sum(1 for p in (ROOT / "modules").iterdir() if (p / "module.yml").is_file())
    assert out.rstrip().endswith(f"{public} module(s), 0 problem(s)")


def test_roles_holds_only_the_contributed_role():
    assert sorted(p.name for p in (MODULE / "roles").iterdir()) == [MID]
    assert not any(p.is_symlink() for p in MODULE.rglob("*"))
    manifest = ld.load_yaml(MODULE / "module.yml")
    assert [c["file"] for c in manifest["contributes"]["roles"]] == [f"roles/{MID}"]


def test_the_manifest_names_the_administrators_secrets_and_internet_egress_and_no_public_route():
    manifest = ld.load_yaml(MODULE / "module.yml")
    assert [c["secret"] for c in manifest["credentials"]] == [
        ref("admin-password"),
        ref("admin-api-password"),
    ]
    assert manifest["egress"] == [
        {"host": "server", "to": ["internet"], "purpose": manifest["egress"][0]["purpose"]}
    ]
    assert list(manifest["provides"]["slots"]) == ["feed-reader"]
    row = ld.load_yaml(MODULE / "registry" / "services.yml")["services"]["feed-reader"]
    assert row["auth"] == "own" and row["port"] == 8084
    assert row["health"]["path"] == "/i/"
    assert "public_hostname" not in row  # private by default: the site adds a route if it wants one
    assert "version" not in row  # a provider's row takes product.version


def test_the_role_defaults_carry_the_administrators_references():
    d = ld.load_yaml(MODULE / "roles" / MID / "defaults" / "main.yml")
    manifest = ld.load_yaml(MODULE / "module.yml")
    assert d[P + "admin_login_ref"] in {c["secret"] for c in manifest["credentials"]}
    assert d[P + "admin_api_login_ref"] == ""  # no API for the administrator unless named
    assert d[P + "users"] == []  # no account the site did not name


def test_the_image_pin_is_the_product_version_and_a_digest():
    defaults = ld.load_yaml(MODULE / "roles" / MID / "defaults" / "main.yml")
    version = ld.load_yaml(MODULE / "module.yml")["product"]["version"]
    image = defaults[P + "image"]
    assert image.split("@")[1].startswith("sha256:") and len(image.split("@")[1]) == 71
    assert image.split("@")[0].endswith(":" + version)


def test_the_defaults_are_sqlite_the_schedule_in_the_container_and_a_private_reader():
    d = ld.load_yaml(MODULE / "roles" / MID / "defaults" / "main.yml")
    assert d[P + "cron_minutes"] == "7,37" and d[P + "port"] == 8084
    text = (MODULE / "roles" / MID / "tasks" / "app.yml").read_text()
    assert "--db-type sqlite" in text and "--api-enabled" in text and "CRON_MIN" in text
    assert "--db-host" not in text  # the one database file per account


# ----------------------------------------------------------------------------- an overlay


def test_an_overlay_placing_the_module_on_a_guest_checks_clean_and_renders(tmp_path, capsys):
    ov = overlay(tmp_path / "ov")
    code, out = _check(ov, capsys)
    assert code == 0, out
    dest = tmp_path / "out"
    code = mcli.main(["render", *_args(ov), "--out", str(dest)])
    out = capsys.readouterr().out
    assert code == 0, out
    books = yaml.safe_load((dest / "modules.yml").read_text())
    plays = [p for p in books if p["hosts"] == f"mod_{MID}_server"]
    assert len(plays) == 1 and plays[0]["become"] is True
    assert plays[0]["roles"][0]["role"].endswith(f"modules/{MID}/roles/{MID}")
    assert without_footprint(plays[0]["vars"]) == {"hnx_module_slice": f"hnx-{MID}-server.slice"}


def test_a_registry_row_that_differs_is_named(tmp_path, capsys):
    ov = overlay(tmp_path)
    reg = ld.load_yaml(ov / "lab" / "services.yml")
    reg["services"]["feeds"]["auth"] = "idp"
    (ov / "lab" / "services.yml").write_text(_dump(reg))
    code, out = _check(ov, capsys)
    assert code == 1 and "registry: services.feeds.auth" in out, out


def test_the_feed_fetching_egress_needs_the_sites_grant(tmp_path, capsys):
    code, out = _check(overlay(tmp_path, grant=False), capsys)
    assert code == 1 and "egress" in out, out


def test_a_guest_without_the_base_baseline_is_refused(tmp_path, capsys):
    ov = overlay(tmp_path)
    g = ov / "lab" / "guests" / "feeds-1.yml"
    g.write_text(g.read_text().replace("names: [base]", "names: []"))
    code, out = _check(ov, capsys)
    assert code == 1 and "base" in out, out


# ----------------------------------------------------------------------------- the probe


def test_the_probe_reads_the_sign_in_page_and_the_refused_key_from_the_resolved_endpoint(
    monkeypatch,
):
    from homelabnext.conform.adapters.feed_reader import make

    monkeypatch.delenv("HNX_ENDPOINT_FEED_READER", raising=False)
    with pytest.raises(AdapterConfigError, match="HNX_ENDPOINT_FEED_READER"):
        make()  # no default endpoint
    with Server() as srv:
        monkeypatch.setenv("HNX_ENDPOINT_FEED_READER", "http://{}:{}".format(*srv.addr))
        probe = make()
        assert probe.health() and probe.api_is_private()
        assert srv.paths == ["/i/", "/api/fever.php?api"]
        assert srv.bodies == [{"api_key": "0" * 32}]  # a key no account has: no credential is sent
    probe.close()


def test_the_probe_says_so_when_the_api_accepts_any_key(monkeypatch):
    from homelabnext.conform.adapters.feed_reader import make

    with Server(open_api=True) as srv:
        monkeypatch.setenv("HNX_ENDPOINT_FEED_READER", "http://{}:{}".format(*srv.addr))
        assert make().api_is_private() is False


def test_the_probe_says_so_when_the_sign_in_page_does_not_answer(monkeypatch):
    from homelabnext.conform.adapters.feed_reader import make

    with Server(login=500) as srv:
        monkeypatch.setenv("HNX_ENDPOINT_FEED_READER", "http://{}:{}".format(*srv.addr))
        assert make().health() is False


# ----------------------------------------------------------------------------- lint


def test_role_lint_passes_the_role_and_the_lifecycle_playbooks():
    lint = [sys.executable, str(ROOT / "tools" / "role_lint.py")]
    r = subprocess.run([*lint, str(MODULE / "roles" / MID)], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    books = sorted(str(p) for p in (MODULE / "playbooks").glob("*.yml"))
    inv = str(ROOT / "ansible" / "inventory" / "example" / "hosts.yml")
    r = subprocess.run(
        [*lint, "--playbook", *books, "--inventory", inv], capture_output=True, text=True
    )
    assert r.returncode == 0, r.stdout + r.stderr
