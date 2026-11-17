# SPDX-License-Identifier: Apache-2.0
"""The context provider module, ``modules/context`` (modules/context/README.md).

* The public tree loads clean and the module's ``roles/`` holds only its one contributed role.
* The manifest says what the README says: the admin token and the gateway key in its own namespace,
  the slot with its contract (``semantic``, a conformance target, stateless: no data, nothing
  exported on removal), egress for the git sources only, a row authenticated per caller with no
  public route, the reindex timer, and the slot registry's ``context`` entry.
* The image pins its base by digest, installs hashed wheels only, fetches the model through the
  pinned fetcher, and runs offline.
* A fictional overlay that places it on a guest and grants its egress checks clean and renders
  ``modules.yml`` on ``mod_context_server``; a differing row and a missing egress grant are refused.
* role_lint passes the role and the lifecycle playbooks.
"""

from __future__ import annotations

import copy
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

from homelabnext.context import semantic_model
from homelabnext.modules import cli as mcli
from homelabnext.modules import loader as ld

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / "fixtures"
MODULE = ROOT / "modules" / "context"
GUEST = ld.load_yaml(ROOT / "examples" / "services.yml")["hosts"]["dns-core"]["address"]
SLOTS = ld.load_yaml(ROOT / "examples" / "modules" / "slots.yml")["slots"]
REQUIRED = sorted(s for s, d in SLOTS.items() if d.get("required_in_core"))
DEFAULTS = ld.load_yaml(MODULE / "roles" / "context" / "defaults" / "main.yml")


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
    row = ld.load_yaml(MODULE / "registry" / "services.yml")["services"]["context"]
    version = str(ld.load_yaml(MODULE / "module.yml")["product"]["version"])
    return {**copy.deepcopy(row), "host": "agents-1", "version": version}


def overlay(tmp: Path, grant: bool = True) -> Path:
    lab = tmp / "lab"
    (lab / "guests").mkdir(parents=True)
    reg = ld.load_yaml(ROOT / "examples" / "services.yml")
    reg["hosts"]["agents-1"] = {"address": GUEST, "zone": "mgmt", "role": "agents"}
    reg["services"]["context-instance"] = bound_row()
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
        "  disks: [{name: rootfs, size_gb: 40, pool: fast}]\n"
        "image: {logical: debian-13-cloudinit, kind: template-clone, os_type: linux-6}\n"
        "cloudinit: {user: ansible, ssh_authorized_keys: [operator]}\n"
        f"network: {{zone: mgmt, ip: {GUEST}}}\n"
        "capability: cap:context\nbackup: {policy: none}\n"
        "owners: {primary: platform-team}\nbaseline: {names: [server]}\n"
    )
    rows = {n: r["capability"] for n, r in reg["services"].items()}
    incumbents = {
        slot: {"service": next(n for n, c in rows.items() if c == slot), "why": "fictional"}
        for slot in REQUIRED
    }
    sel = {
        "profile": "context-pilot",
        "hosts": {"agents": {"guest": "guest:agents-1"}},
        "slots": {"context": [{"provider": "context", "instance": "context-instance",
                               "placement": {"server": "agents"}}]},
        "incumbents": incumbents,
    }  # fmt: skip
    if grant:
        sel["grants"] = {"egress": {"context": {"server": ["internet"]}}}
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
    assert sorted(p.name for p in (MODULE / "roles").iterdir()) == ["context"]
    assert not any(p.is_symlink() for p in MODULE.rglob("*"))
    manifest = ld.load_yaml(MODULE / "module.yml")
    assert [c["file"] for c in manifest["contributes"]["roles"]] == ["roles/context"]


def test_the_manifest_declares_the_slot_its_secrets_its_egress_and_no_data():
    m = ld.load_yaml(MODULE / "module.yml")
    assert [c["secret"] for c in m["credentials"]] == [
        "secret:context/admin-token", "secret:context/gateway-key"]  # fmt: skip
    slot = m["provides"]["slots"]["context"]
    assert slot["features"] == ["semantic"] and slot["conformance"]["target"]
    assert "provisional" not in slot and "migration" not in slot  # a contract; stateless
    assert "data" not in m and m["lifecycle"]["remove"]["export_first"] is False
    assert [e["to"] for e in m["egress"]] == [["internet"]]  # the git sources only
    assert m["contributes"]["scheduler_jobs"] == [{"timer": "timer:context/reindex"}]
    assert SLOTS["context"] == {"stage": None, "contract": "context.py", "stateful": False}
    row = ld.load_yaml(MODULE / "registry" / "services.yml")["services"]["context"]
    assert row["auth"] == "own" and row["port"] == DEFAULTS["context_port"] == 8094
    assert row["health"]["path"] == "/ready"
    assert "public_hostname" not in row and "version" not in row
    target = ld.load_yaml(MODULE / "conformance" / "target.yml")["capabilities"]["context"]
    assert target["adapter"] == slot["adapter"] and target["features"] == slot["features"]


def test_the_role_defaults_hold_no_lab_value():
    assert "context_image" not in DEFAULTS  # there is no published image to pin
    assert DEFAULTS["context_sources"] == [] and DEFAULTS["context_callers"] == []
    assert DEFAULTS["context_health_query"] == {}  # required: the site's own known item
    assert DEFAULTS["context_gateway_id"] == ""  # the judge is off until the site names a gateway
    assert DEFAULTS["context_judge_threshold"] == 0.10 and DEFAULTS["context_judge_workers"] == 2
    assert DEFAULTS["context_build_repositories"] == ["localhost/hnx-context"]


def test_the_dockerfile_pins_its_base_its_wheels_git_and_the_model():
    text = (MODULE / "image" / "Dockerfile").read_text()
    from_line = next(line for line in text.splitlines() if line.startswith("FROM "))
    assert "@sha256:" in from_line and len(from_line.split("@sha256:")[1]) == 64
    assert "--require-hashes" in text and "--no-deps" in text and "--only-binary=:all:" in text
    assert "git=1:" in text and "snapshot.debian.org/archive/debian/2026" in text
    assert "semantic_model.py /opt/hnx-context/model" in text  # the per-file sha256 fetcher
    assert "HF_HUB_OFFLINE=1" in text and "TRANSFORMERS_OFFLINE=1" in text
    req = (MODULE / "image" / "requirements.txt").read_text()
    pins = [x for x in req.splitlines() if "==" in x and not x.startswith((" ", "#"))]
    assert pins and all(x.rstrip().endswith("\\") for x in pins)
    assert req.count("--hash=sha256:") >= len(pins)
    assert len(pins) > 20  # the index library, torch and everything they import, each hashed
    assert semantic_model.REVISION and len(semantic_model.FILES) >= 5


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
    plays = [p for p in books if p["hosts"] == "mod_context_server"]
    assert len(plays) == 1 and plays[0]["become"] is True
    assert plays[0]["roles"][0]["role"].endswith("modules/context/roles/context")
    assert plays[0]["vars"] == {"hnx_module_slice": "hnx-context-server.slice"}


def test_a_registry_row_that_differs_is_named(tmp_path, capsys):
    ov = overlay(tmp_path)
    reg = ld.load_yaml(ov / "lab" / "services.yml")
    reg["services"]["context-instance"]["port"] = 8095
    (ov / "lab" / "services.yml").write_text(_dump(reg))
    code, out = _check(ov, capsys)
    assert code == 1 and "registry: services.context-instance.port" in out, out


def test_the_sources_egress_needs_the_sites_grant(tmp_path, capsys):
    code, out = _check(overlay(tmp_path, grant=False), capsys)
    assert code == 1 and "egress" in out, out


# ----------------------------------------------------------------------------- lint


def test_role_lint_passes_the_role_and_the_lifecycle_playbooks():
    lint = [sys.executable, str(ROOT / "tools" / "role_lint.py")]
    r = subprocess.run([*lint, str(MODULE / "roles" / "context")], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    books = sorted(str(p) for p in (MODULE / "playbooks").glob("*.yml"))
    inv = str(ROOT / "ansible" / "inventory" / "example" / "hosts.yml")
    r = subprocess.run(
        [*lint, "--playbook", *books, "--inventory", inv], capture_output=True, text=True
    )
    assert r.returncode == 0, r.stdout + r.stderr
