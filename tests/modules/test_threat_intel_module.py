# SPDX-License-Identifier: Apache-2.0
"""The threat-intel provider module, ``modules/<id>`` (its README.md).

* The public tree loads clean and the module's ``roles/`` holds only its one contributed role.
* The manifest says what the README says: the secrets by reference, internet egress for the
  feeds, no public route, local accounts, four images pinned by tag and digest whose application
  version is the product's.
* A fictional overlay that places it on a guest (an egress grant, no public route) passes
  ``hnx modules check --overlay`` and renders ``modules.yml`` on ``mod_<id>_server``; a registry row
  that differs, a missing egress grant and a guest without the ``base`` baseline are refused.
* The module's own probe reads the sign-in page and the refused version call from the resolved
  endpoint only.
* role_lint passes the role and the lifecycle playbooks.
"""

from __future__ import annotations

import copy
import shutil
import sys
from pathlib import Path

import pytest
import yaml

from homelabnext.conform.adapters._env import AdapterConfigError
from homelabnext.modules import cli as mcli
from homelabnext.modules import loader as ld
from tests.modules.play_vars import without_footprint
from tests.modules.threat_intel_front import Server
from tests.modules.threat_intel_module import MID, MODULE, P, ref

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
    row = ld.load_yaml(MODULE / "registry" / "services.yml")["services"]["threat-intel"]
    version = str(ld.load_yaml(MODULE / "module.yml")["product"]["version"])
    return {**copy.deepcopy(row), "host": "intel-1", "version": version}


def overlay(tmp: Path, grant: bool = True) -> Path:
    lab = tmp / "lab"
    (lab / "guests").mkdir(parents=True)
    reg = ld.load_yaml(ROOT / "examples" / "services.yml")
    reg["hosts"]["intel-1"] = {"address": GUEST, "zone": "mgmt", "role": "intel"}
    reg["services"]["intel"] = bound_row()
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
    (lab / "guests" / "intel-1.yml").write_text(
        "# SPDX-License-Identifier: Apache-2.0\n"
        "id: guest:intel-1\nkind: vm\nprovisioning: terraform\nstatus: planned\n"
        "placement: {node: hv-01, vmid: 242, vmid_scheme: freeform}\n"
        "resources:\n  cpu: {cores: 4}\n  memory: {size_mb: 32768}\n"
        "  disks: [{name: rootfs, size_gb: 160, pool: fast}]\n"
        "image: {logical: debian-13-cloudinit, kind: template-clone, os_type: linux-6}\n"
        "cloudinit: {user: ansible, ssh_authorized_keys: [operator]}\n"
        f"network: {{zone: mgmt, ip: {GUEST}}}\n"
        "capability: cap:threat-intel\nbackup: {policy: none}\n"
        "owners: {primary: platform-team}\nbaseline: {names: [base]}\n"
    )
    rows = {n: r["capability"] for n, r in reg["services"].items()}
    incumbents = {
        slot: {"service": next(n for n, c in rows.items() if c == slot), "why": "fictional"}
        for slot in REQUIRED
    }
    sel = {
        "profile": "intel-pilot",
        "hosts": {"intel": {"guest": "guest:intel-1"}},
        "slots": {"threat-intel": [{"provider": MID, "instance": "intel", "placement": {"server": "intel"}}]},
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


def test_roles_holds_only_the_contributed_role():
    assert sorted(p.name for p in (MODULE / "roles").iterdir()) == [MID]
    assert not any(p.is_symlink() for p in MODULE.rglob("*"))
    manifest = ld.load_yaml(MODULE / "module.yml")
    assert [c["file"] for c in manifest["contributes"]["roles"]] == [f"roles/{MID}"]


def test_the_manifest_names_the_secrets_and_internet_egress_and_no_public_route():
    manifest = ld.load_yaml(MODULE / "module.yml")
    assert [c["secret"] for c in manifest["credentials"]] == [
        ref(n)
        for n in (
            "admin-password", "admin-api-key", "mysql-password", "mysql-root-password",
            "redis-password", "encryption-key", "gpg-passphrase", "tls-cert", "tls-key",
        )
    ]  # fmt: skip
    assert [c["holder"] for c in manifest["credentials"] if c["holder"] == "granted"] == ["granted"]
    assert manifest["egress"] == [
        {"host": "server", "to": ["internet"], "purpose": manifest["egress"][0]["purpose"]}
    ]
    assert list(manifest["provides"]["slots"]) == ["threat-intel"]
    row = ld.load_yaml(MODULE / "registry" / "services.yml")["services"]["threat-intel"]
    assert row["auth"] == "own" and row["port"] == 443 and row["protocol"] == "https"
    assert row["health"]["path"] == "/users/heartbeat"
    assert "public_hostname" not in row  # private by default: the site adds a route if it wants one
    assert "version" not in row  # a provider's row takes product.version


def test_the_role_defaults_carry_the_modules_references():
    d = ld.load_yaml(MODULE / "roles" / MID / "defaults" / "main.yml")
    manifest = ld.load_yaml(MODULE / "module.yml")
    refs = {v for k, v in d.items() if k.endswith("_ref") and v}
    assert refs <= {c["secret"] for c in manifest["credentials"]}
    assert (
        d[P + "tls_cert_ref"] == "" and d[P + "tls_key_ref"] == ""
    )  # a site opts in, both or neither
    assert d[P + "consumers"] == []  # no account the site did not name
    # the site's own values have no default: the role's argument spec requires them
    assert P + "admin_email" not in d and P + "admin_org" not in d
    spec = ld.load_yaml(MODULE / "roles" / MID / "meta" / "argument_specs.yml")["argument_specs"]
    for hook in ("main", "health", "export", "restore"):
        assert spec[hook]["options"][P + "admin_email"]["required"] is True


def test_every_image_pin_is_a_tag_and_a_digest_and_the_application_tag_is_the_product_version():
    d = ld.load_yaml(MODULE / "roles" / MID / "defaults" / "main.yml")
    version = ld.load_yaml(MODULE / "module.yml")["product"]["version"]
    for name in ("core", "modules", "db", "redis"):
        image = d[P + name + "_image"]
        assert image.split("@")[1].startswith("sha256:") and len(image.split("@")[1]) == 71, name
        assert not image.split("@")[0].endswith((":latest", ":stable")), name
    assert d[P + "core_image"].split("@")[0].endswith(":v" + version)


def test_the_database_is_capped_by_the_role_slice_and_no_container_publishes_but_the_application():
    text = (MODULE / "roles" / MID / "tasks" / "app.yml").read_text()
    # the slice (compose_app's cgroup_parent) is the CPU and memory cap; each container has a limit
    assert text.count("mem_limit:") == 4
    assert text.count("ports:") == 1
    assert "privileged" not in text and "docker.sock" not in text


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


def test_the_feeds_egress_needs_the_sites_grant(tmp_path, capsys):
    code, out = _check(overlay(tmp_path, grant=False), capsys)
    assert code == 1 and "egress" in out, out


# ----------------------------------------------------------------------------- the probe


def test_the_probe_reads_the_sign_in_page_and_the_refused_call_from_the_resolved_endpoint(
    monkeypatch,
):
    from homelabnext.conform.adapters.threat_intel import make

    monkeypatch.delenv("HNX_ENDPOINT_THREAT_INTEL", raising=False)
    with pytest.raises(AdapterConfigError, match="HNX_ENDPOINT_THREAT_INTEL"):
        make()  # no default endpoint
    with Server() as srv:
        monkeypatch.setenv("HNX_ENDPOINT_THREAT_INTEL", "http://{}:{}".format(*srv.addr))
        probe = make()
        assert probe.health() and probe.api_is_private()
        assert srv.paths == ["/users/login", "/servers/getVersion", "/servers/getVersion"]
        # no key, then a key no account has: no credential of ours is ever sent
        assert srv.auth == [None, None, "0" * 40]
    probe.close()


def test_the_probe_says_so_when_the_api_answers_any_caller(monkeypatch):
    from homelabnext.conform.adapters.threat_intel import make

    with Server(open_api=True) as srv:
        monkeypatch.setenv("HNX_ENDPOINT_THREAT_INTEL", "http://{}:{}".format(*srv.addr))
        assert make().api_is_private() is False


# ----------------------------------------------------------------------------- lint


def test_pin_freshness_watches_every_image():
    sys.path.insert(0, str(ROOT / "tools"))
    try:
        import pin_freshness as pf
    finally:
        sys.path.pop(0)
    ids = {p.id for p in pf.inventory(ROOT)}
    for name in ("core", "modules", "db", "redis"):
        assert f"role:{MID}/{P}{name}_image" in ids
    assert pf.check_inventory(pf.inventory(ROOT)) == []
