# SPDX-License-Identifier: Apache-2.0
"""The threat-intelligence pipeline feature module, ``modules/cti-pipeline`` (its README).

* The manifest: a feature (no product, no credentials), its secrets in its own namespace, the
  orchestration and inference slots required, egress to the internet only from its worker role,
  one stateful dataset exported before a removal, no registry row (it serves no port).
* A fictional overlay that places it on a guest and grants its egress checks clean and renders
  ``modules.yml`` and ``checks/cti-pipeline.yml`` (readiness then health); without the grant it is
  refused.
* The units, the lanes and the data root: tests/modules/test_cti_pipeline_units.py.
* role_lint passes the role and the lifecycle playbooks.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import yaml

from homelabnext.modules import cli as mcli
from homelabnext.modules import loader as ld

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / "fixtures"
MODULE = ROOT / "modules" / "cti-pipeline"
ROLE = MODULE / "roles" / "cti_pipeline"
GUEST = ld.load_yaml(ROOT / "examples" / "services.yml")["hosts"]["dns-core"]["address"]
SLOTS = ld.load_yaml(ROOT / "examples" / "modules" / "slots.yml")["slots"]
REQUIRED = sorted(s for s, d in SLOTS.items() if d.get("required_in_core"))
MANIFEST = ld.load_yaml(MODULE / "module.yml")


# ----------------------------------------------------------------------------- the manifest


def test_the_manifest_is_a_feature_with_its_own_secrets_and_internet_egress_only():
    m = MANIFEST
    assert m["kind"] == "feature" and m["bundle"] == {"id": "soc", "group": "threat-intel"}
    assert not {"product", "licence", "credentials", "provides"} & set(m)
    assert m["identifiers"] == [
        {"kind": "secret-name", "name": "cti-pipeline", "on_remove": "keep"}
    ]
    assert [r["cap"] for r in m["requires"]["capabilities"]] == [
        "cap:secrets",
        "cap:orchestration",
        "cap:inference",
    ]
    assert m["egress"] == [
        {"host": "worker", "to": ["internet"], "purpose": m["egress"][0]["purpose"]},
        {
            "host": "worker",
            "to": ["svc:web-search"],
            "optional": True,
            "purpose": m["egress"][1]["purpose"],
        },
    ]
    assert [d["id"] for d in m["data"]] == ["store"] and m["lifecycle"]["remove"][
        "export_first"
    ] is True
    assert "services" not in m["contributes"] and not (MODULE / "registry").exists()
    assert sorted(p.name for p in (MODULE / "roles").iterdir()) == ["cti_pipeline"]
    assert not any(p.is_symlink() for p in MODULE.rglob("*"))
    defaults = ld.load_yaml(ROLE / "defaults" / "main.yml")
    assert defaults["cti_pipeline_jobs"] == {} and defaults["cti_pipeline_lane_refs"] == {
        "real": {},
        "shadow": {},
    }
    assert defaults["cti_pipeline_gateway_key_ref"] == m["config"]["gateway_key"]["default"]
    assert defaults["cti_pipeline_lake_schema"]["shadow"] == m["config"]["shadow_schema"]["default"]


# ----------------------------------------------------------------------------- an overlay


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


def _slot_provider(slot: str) -> tuple[str, Path]:
    """The one in-tree module that provides ``slot`` (its id and directory)."""
    found = [
        (m["id"], d)
        for d in sorted((ROOT / "modules").iterdir())
        if (d / "module.yml").is_file()
        for m in [ld.load_yaml(d / "module.yml")]
        if slot in (m.get("provides") or {}).get("slots", {})
    ]
    assert len(found) == 1, found
    return found[0]


def overlay(tmp: Path, grant: bool = True, web_search: bool = False) -> Path:
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
        "features": {"cti-pipeline": {"placement": {"worker": "agents"}}},
        "incumbents": incumbents,
    }
    if web_search:  # the lab's metasearch slot, filled by its provider module on the same guest
        pid, pdir = _slot_provider("web-search")
        row = ld.load_yaml(pdir / "registry" / "services.yml")["services"]["web-search"]
        version = ld.load_yaml(pdir / "module.yml")["product"]["version"]
        reg["services"]["web-search"] = dict(row, host="agents-1", version=version)
        (lab / "services.yml").write_text(_dump(reg))
        sel["slots"]["web-search"] = [
            {"provider": pid, "instance": "web-search", "placement": {"server": "agents"}}
        ]
    if grant:
        to = ["internet", "svc:web-search"] if web_search else ["internet"]
        sel["grants"] = {"egress": {"cti-pipeline": {"worker": to}}}
        if web_search:
            sel["grants"]["egress"][_slot_provider("web-search")[0]] = {"server": ["internet"]}
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
        if p["hosts"] == "mod_cti_pipeline_worker"
    ]
    assert len(plays) == 1 and plays[0]["become"] is True
    assert plays[0]["roles"][0]["role"].endswith("modules/cti-pipeline/roles/cti_pipeline")
    assert plays[0]["vars"]["hnx_module_slice"] == "hnx-cti_pipeline-worker.slice"
    checks = yaml.safe_load((dest / "checks" / "cti-pipeline.yml").read_text())
    hooks = [
        t["name"].split(":")[0]
        for p in checks
        if p["hosts"] == "mod_cti_pipeline_worker"
        for t in p["tasks"]
    ]
    assert hooks == ["readiness", "health"]


def test_its_internet_egress_needs_the_sites_grant(tmp_path, capsys):
    code = mcli.main(["check", *_args(overlay(tmp_path, grant=False))])
    out = capsys.readouterr().out
    assert code == 1 and "egress" in out, out


def test_the_metasearch_egress_is_optional_and_a_grant_of_it_is_accepted(tmp_path, capsys):
    # no grant of it is owed (the overlay above grants internet only and checks clean) ...
    code = mcli.main(["check", *_args(overlay(tmp_path / "a", web_search=True, grant=False))])
    out = capsys.readouterr().out
    assert code == 1 and "svc:web-search" not in out, out  # only the internet grant is owed
    # ... and a site that selects a metasearch service may grant it
    code = mcli.main(["check", *_args(overlay(tmp_path / "b", web_search=True))])
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
