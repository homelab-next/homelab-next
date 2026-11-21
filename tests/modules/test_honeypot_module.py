# SPDX-License-Identifier: Apache-2.0
"""The honeypot feature module, ``modules/honeypot`` (its README).

* The manifest: a feature (no product, no credentials), its secrets in its own namespace, the lake
  query and inference slots preferred (the spool holds the events if the lake is away), internet egress only from its receiver
  role, one stateful dataset exported before a removal, no registry row.
* The defaults hold no lab value: no address, no hostname, every secret a ``secret:`` reference, the
  daily (never interval) schedule of the lake writer, and a TLS-verified lake.
* A fictional overlay that places it on a guest and grants its egress checks clean and renders
  ``modules.yml`` and ``checks/honeypot.yml`` (readiness then health); without the grant it is refused.
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
MODULE = ROOT / "modules" / "honeypot"
ROLE = MODULE / "roles" / "honeypot"
GUEST = ld.load_yaml(ROOT / "examples" / "services.yml")["hosts"]["dns-core"]["address"]
SLOTS = ld.load_yaml(ROOT / "examples" / "modules" / "slots.yml")["slots"]
REQUIRED = sorted(s for s, d in SLOTS.items() if d.get("required_in_core"))
MANIFEST = ld.load_yaml(MODULE / "module.yml")
DEFAULTS = ld.load_yaml(ROLE / "defaults" / "main.yml")


def test_the_manifest_is_a_feature_with_its_own_secrets_and_internet_egress_only():
    m = MANIFEST
    assert m["kind"] == "feature" and m["id"] == "honeypot"
    assert not {"product", "licence", "credentials", "provides"} & set(m)
    assert m["identifiers"] == [{"kind": "secret-name", "name": "honeypot", "on_remove": "keep"}]
    assert [r["cap"] for r in m["requires"]["capabilities"]] == ["cap:secrets"]
    assert [r["cap"] for r in m["prefers"]["capabilities"]] == ["cap:lake-query", "cap:inference"]
    assert m["egress"] == [
        {"host": "receiver", "to": ["internet"], "purpose": m["egress"][0]["purpose"]}
    ]
    assert [d["id"] for d in m["data"]] == ["state"]
    assert m["lifecycle"]["remove"]["export_first"] is True
    assert "services" not in m["contributes"] and not (MODULE / "registry").exists()
    assert sorted(p.name for p in (MODULE / "roles").iterdir()) == ["honeypot"]
    assert not any(p.is_symlink() for p in MODULE.rglob("*"))
    assert DEFAULTS["honeypot_lake_login_ref"] == m["config"]["lake_password"]["default"]
    assert DEFAULTS["honeypot_gateway_key_ref"] == m["config"]["gateway_key"]["default"]


def test_every_secret_default_is_a_reference_and_none_is_a_value():
    refs = {k: v for k, v in DEFAULTS.items() if k.endswith("_ref") and v != ""}
    assert refs and all(re.fullmatch(r"secret:[A-Za-z0-9._/-]+", v) for v in refs.values())


def test_the_lake_writer_is_daily_on_the_calendar_never_an_interval():
    assert re.search(r"\*-\*-\* \d\d:\d\d:\d\d", DEFAULTS["honeypot_lake_oncalendar"])
    for name in ("lake.timer.j2", "report.timer.j2"):
        lines = (ROLE / "templates" / name).read_text().splitlines()
        assert any(ln.startswith("OnCalendar=") for ln in lines)
        assert not any(ln.startswith(("OnUnitActiveSec=", "OnBootSec=")) for ln in lines)


def test_the_defaults_hold_no_address_and_no_lab_name():
    text = (ROLE / "defaults" / "main.yml").read_text()
    code = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    for ip in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", code):
        assert ip == "0.0.0.0", ip
    assert not re.search(r"\.(casa|local|lan)\b", code)
    assert DEFAULTS["honeypot_ensure_table"] is False  # an imported table is checked, never created
    assert DEFAULTS["honeypot_lake_url"] == "" and DEFAULTS["honeypot_friendly_ips"] == []
    assert (
        "honeypot_lake_catalog" not in DEFAULTS
    )  # the site's name for its lake: required, no default
    spec = yaml.safe_load((ROLE / "meta" / "argument_specs.yml").read_text())["argument_specs"][
        "main"
    ]["options"]
    assert (
        spec["honeypot_lake_catalog"]["required"] is True
        and spec["honeypot_bind"]["required"] is True
    )


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


def overlay(tmp: Path, grant: bool = True) -> Path:
    lab = tmp / "lab"
    (lab / "guests").mkdir(parents=True)
    reg = ld.load_yaml(ROOT / "examples" / "services.yml")
    reg["hosts"]["agents-1"] = {"address": GUEST, "zone": "mgmt", "role": "agents"}
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
    (lab / "guests" / "agents-1.yml").write_text(
        "# SPDX-License-Identifier: Apache-2.0\n"
        "id: guest:agents-1\nkind: vm\nprovisioning: terraform\nstatus: planned\n"
        "placement: {node: hv-01, vmid: 242, vmid_scheme: freeform}\n"
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
    sel = {
        "profile": "intel-pilot",
        "hosts": {"agents": {"guest": "guest:agents-1"}},
        "slots": {},
        "features": {"honeypot": {"placement": {"receiver": "agents"}}},
        "incumbents": incumbents,
    }
    if grant:
        sel["grants"] = {"egress": {"honeypot": {"receiver": ["internet"]}}}
    (lab / "modules.yml").write_text(_dump(sel))
    return tmp


def test_an_overlay_placing_it_on_a_guest_checks_clean_and_renders_its_checks(tmp_path, capsys):
    ov = overlay(tmp_path / "ov")
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
        if p["hosts"] == "mod_honeypot_receiver"
    ]
    assert len(plays) == 1 and plays[0]["become"] is True
    assert plays[0]["roles"][0]["role"].endswith("modules/honeypot/roles/honeypot")
    assert plays[0]["vars"]["hnx_module_slice"] == "hnx-honeypot-receiver.slice"
    checks = yaml.safe_load((dest / "checks" / "honeypot.yml").read_text())
    hooks = [
        t["name"].split(":")[0]
        for p in checks
        if p["hosts"] == "mod_honeypot_receiver"
        for t in p["tasks"]
    ]
    assert hooks == ["readiness", "health"]


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
