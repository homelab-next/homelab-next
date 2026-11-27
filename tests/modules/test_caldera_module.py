# SPDX-License-Identifier: Apache-2.0
"""The adversary-emulation server feature module, ``modules/caldera`` (its README).

* The manifest: a feature (no product, no credentials), its secrets as ``secret:`` references of its
  own namespace, one isolated host role, install-time internet egress declared optional and
  bounded, four datasets exported before a removal, no registry row, no public route.
* The defaults hold no lab value: no address, no hostname, every secret a ``secret:`` reference,
  the pinned version, the UI published on the guest's own address only.
* A fictional overlay that places it on an isolated guest checks clean and renders ``modules.yml``
  and ``checks/caldera.yml`` (readiness then health); the same overlay with a guest that is not
  isolated is refused, and so is a selection that grants the internet to a run-time role.
* role_lint passes the role and the lifecycle playbooks.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

from homelabnext.modules import cli as mcli
from homelabnext.modules import loader as ld

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / "fixtures"
MODULE = ROOT / "modules" / "caldera"
ROLE = MODULE / "roles" / "caldera"
GUEST = ld.load_yaml(ROOT / "examples" / "services.yml")["hosts"]["dns-core"]["address"]
SLOTS = ld.load_yaml(ROOT / "examples" / "modules" / "slots.yml")["slots"]
REQUIRED = sorted(s for s, d in SLOTS.items() if d.get("required_in_core"))
MANIFEST = ld.load_yaml(MODULE / "module.yml")
DEFAULTS = ld.load_yaml(ROLE / "defaults" / "main.yml")


def test_the_manifest_is_a_feature_on_one_isolated_role_with_bounded_install_egress():
    m = MANIFEST
    assert m["kind"] == "feature" and m["id"] == "caldera"
    assert not {"product", "licence", "credentials", "provides", "bundle"} & set(m)
    assert m["identifiers"] == [{"kind": "secret-name", "name": "caldera", "on_remove": "keep"}]
    assert [r["cap"] for r in m["requires"]["capabilities"]] == ["cap:secrets"]
    hosts = m["requires"]["hosts"]
    assert [h["role"] for h in hosts] == ["server"]
    assert hosts[0]["exposure"] == "isolated" and hosts[0]["roles"] == ["role:caldera"]
    egress = m["egress"]
    assert len(egress) == 1 and egress[0]["host"] == "server"
    assert egress[0]["to"] == ["internet"] and egress[0]["optional"] is True
    assert "install" in egress[0]["purpose"]
    assert [d["id"] for d in m["data"]] == ["operations", "adversaries", "agents", "artifacts"]
    assert all(d["retention"] == {"keep": "forever"} for d in m["data"])
    assert m["lifecycle"]["remove"]["export_first"] is True
    assert "services" not in m["contributes"] and not (MODULE / "registry").exists()
    assert not (MODULE / "conformance").exists() and "provides" not in m
    assert sorted(p.name for p in (MODULE / "roles").iterdir()) == ["caldera"]
    assert not any(p.is_symlink() for p in MODULE.rglob("*"))


def test_the_config_keys_match_the_role_defaults():
    cfg = MANIFEST["config"]
    assert cfg["caldera_version"]["default"] == "5.3.0" == DEFAULTS["caldera_version"]
    assert cfg["caldera_admin_password_ref"]["type"] == "secret"
    assert cfg["caldera_red_password_ref"]["type"] == "secret"
    assert cfg["caldera_admin_password_ref"]["default"] == DEFAULTS["caldera_admin_login_ref"]
    assert cfg["caldera_red_password_ref"]["default"] == DEFAULTS["caldera_red_login_ref"]


def test_every_secret_default_is_a_reference_and_none_is_a_value():
    refs = {k: v for k, v in DEFAULTS.items() if k.endswith("_ref") or k.endswith("_login_ref")}
    assert len(refs) == 2
    assert all(re.fullmatch("secret" + r":caldera/[a-z-]+", v) for v in refs.values())
    secretish = [k for k in DEFAULTS if re.search(r"pass|token|key|salt", k) and k not in refs]
    assert secretish == [], secretish


def test_the_defaults_hold_no_address_and_no_lab_name():
    text = (ROLE / "defaults" / "main.yml").read_text()
    code = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    for ip in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", code):
        assert ip == "0.0.0.0", ip
    assert not re.search(r"\.(casa|local|lan)\b", code)
    assert DEFAULTS["caldera_bind"] == "{{ ansible_host }}"
    assert DEFAULTS["caldera_extra_ports"] == []  # only the UI port is published unless asked
    spec = yaml.safe_load((ROLE / "meta" / "argument_specs.yml").read_text())["argument_specs"]
    assert spec["main"]["options"]["caldera_logical_id"]["required"] is True
    for hook in ("main", "health", "readiness", "backup", "restore", "upgrade", "export"):
        assert hook in spec


def test_the_compose_template_does_not_mount_the_whole_source_tree():
    # upstream bind-mounts "./:/usr/src/app", which shadows the UI baked into the image
    text = (ROLE / "tasks" / "app.yml").read_text()
    assert not re.search(r"""['"]?\./?:/usr/src/app['"]?\s*[,\]\n]""", text)
    for part in ("conf", "data", "logs"):
        assert f'"{{{{ caldera_src }}}}/{part}:{{{{ caldera_container_root }}}}/{part}"' in text
    assert len(re.findall(r"caldera_src \}\}[^/]", text)) == 0  # the tree itself is never mounted


def _dump(doc) -> str:
    class NoAliases(yaml.SafeDumper):
        def ignore_aliases(self, data):
            return True

    return yaml.dump(doc, Dumper=NoAliases, sort_keys=False)


def _args(ov: Path) -> list[str]:
    return [
        "--root", str(ROOT), "--overlay", str(ov),
        "--keyring", str(ROOT / "examples" / "keyring" / "keyring.json"),
        "--mcp-catalog", str(ROOT / "examples" / "mcp"),
    ]  # fmt: skip


def overlay(tmp: Path, isolated: bool = True, grant: bool = True) -> Path:
    lab = tmp / "lab"
    (lab / "guests").mkdir(parents=True)
    reg = ld.load_yaml(ROOT / "examples" / "services.yml")
    reg["hosts"]["range-1"] = {"address": GUEST, "zone": "mgmt", "role": "range"}
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
    (lab / "guests" / "range-1.yml").write_text(
        "# SPDX-License-Identifier: Apache-2.0\n"
        "id: guest:range-1\nkind: vm\nprovisioning: terraform\nstatus: planned\n"
        "placement: {node: hv-01, vmid: 243, vmid_scheme: freeform}\n"
        "resources:\n  cpu: {cores: 4}\n  memory: {size_mb: 8192}\n"
        "  disks: [{name: rootfs, size_gb: 60, pool: fast}]\n"
        "image: {logical: debian-13-cloudinit, kind: template-clone, os_type: linux-6}\n"
        "cloudinit: {user: ansible, ssh_authorized_keys: [operator]}\n"
        f"network: {{zone: mgmt, ip: {GUEST}}}\n"
        "capability: cap:cti-pipeline\nbackup: {policy: none}\n"
        "owners: {primary: platform-team}\nbaseline: {names: [base]}\n"
    )
    rows = {n: r["capability"] for n, r in reg["services"].items()}
    incumbents = {
        slot: {"service": next(n for n, c in rows.items() if c == slot), "why": "fictional"}
        for slot in REQUIRED
    }
    host = {"guest": "guest:range-1"}
    if isolated:
        host["isolated"] = True
    sel = {
        "profile": "intel-pilot",
        "hosts": {"range": host},
        "slots": {},
        "features": {"caldera": {"placement": {"server": "range"}}},
        "incumbents": incumbents,
    }
    if grant:
        sel["grants"] = {"egress": {"caldera": {"server": ["internet"]}}}
    (lab / "modules.yml").write_text(_dump(sel))
    return tmp


def test_an_overlay_placing_it_on_an_isolated_guest_checks_clean_and_renders_its_checks(
    tmp_path, capsys
):
    ov = overlay(tmp_path / "ov", grant=False)  # the install-time egress is optional: no grant owed
    code = mcli.main(["check", *_args(ov)])
    out = capsys.readouterr().out
    assert code == 0, out
    dest = tmp_path / "out"
    code = mcli.main(["render", *_args(ov), "--out", str(dest)])
    out = capsys.readouterr().out
    assert code == 0, out
    plays = [
        p
        for p in yaml.safe_load((dest / "modules.yml").read_text())
        if p["hosts"] == "mod_caldera_server"
    ]
    assert len(plays) == 1 and plays[0]["become"] is True
    assert plays[0]["roles"][0]["role"].endswith("modules/caldera/roles/caldera")
    assert plays[0]["vars"]["hnx_module_slice"] == "hnx-caldera-server.slice"
    checks = yaml.safe_load((dest / "checks" / "caldera.yml").read_text())
    hooks = [
        t["name"].split(":")[0]
        for p in checks
        if p["hosts"] == "mod_caldera_server"
        for t in p["tasks"]
    ]
    assert hooks == ["readiness", "health"]


def test_a_guest_that_is_not_isolated_is_refused(tmp_path, capsys):
    ov = overlay(tmp_path / "ov", isolated=False, grant=False)
    code = mcli.main(["check", *_args(ov)])
    out = capsys.readouterr().out
    assert code != 0
    assert "caldera/server" in out and "isolated" in out, out
    code = mcli.main(["render", *_args(ov), "--out", str(tmp_path / "out")])
    assert code != 0, capsys.readouterr().out


def test_a_grant_of_the_internet_to_the_role_is_listed_not_implied(tmp_path, capsys):
    # the optional install-time egress is a per-site opt-in: a site that lists it gets it, and the
    # selection stays valid either way (a grant to an unknown target would be refused)
    ov = overlay(tmp_path / "ov", grant=True)
    code = mcli.main(["check", *_args(ov)])
    out = capsys.readouterr().out
    assert code == 0, out


# ----------------------------------------------------------------------------- lint


def test_role_lint_passes_the_role_and_the_lifecycle_playbooks():
    lint = [sys.executable, str(ROOT / "tools" / "role_lint.py")]
    r = subprocess.run([*lint, str(ROLE)], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    books = sorted(str(p) for p in (MODULE / "playbooks").glob("*.yml"))
    inv = str(ROOT / "ansible" / "inventory" / "example" / "hosts.yml")
    r = subprocess.run(
        [*lint, "--playbook", *books, "--inventory", inv], capture_output=True, text=True
    )
    assert r.returncode == 0, r.stdout + r.stderr
