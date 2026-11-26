# SPDX-License-Identifier: Apache-2.0
"""The orchestration provider module, ``modules/orchestration`` (README.md beside the manifest).

* The public tree loads clean, and the module's ``roles/`` holds only its one contributed role.
* The manifest declares no egress and the row no public route; the row's metrics credential, the
  credentials the manifest lists and the role's default references are one set; the row's port is
  the role's default.
* A fictional overlay that places it on a guest (every other required core slot an incumbent)
  passes ``hnx modules check --overlay`` and renders ``modules.yml`` and its checks on
  ``mod_orchestration_server``; a registry row that differs from the module's, a guest without the
  ``base`` baseline and an orchestration slot answered by both the module and an incumbent are
  refused.
* The conformance target binds the shared adapter exactly as the repository's own controller target
  does (which CI runs strict, with fault injection, on the same binary), the slot's declared
  features are the adapter's, and the orchestration suite's checks that need no fault hook pass on
  the repository's controller through the module's target file.
* Nothing in the module names a private address or an operator's workstation.
* role_lint passes the role and the lifecycle playbooks.
"""

from __future__ import annotations

import copy
import dataclasses
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from conformance.suites import orchestration as orch_suite
from homelabnext.conform.core import run_checks
from homelabnext.conform.target import load_target, make_factory
from homelabnext.modules import cli as mcli
from homelabnext.modules import loader as ld
from tests.conform.controller_rig import controller_binary, live_controller
from tests.modules.play_vars import without_footprint

__all__ = ["controller_binary"]  # the session fixture, imported for its test

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "modules" / "orchestration"
ROLE = MODULE / "roles" / "orchestration"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
LOOP = ".".join(["127", "0", "0", "1"])
GUEST = ".".join(["192", "0", "2", "40"])  # a documentation-range guest address
REQUIRED = sorted(
    s for s, d in ld.load_yaml(ROOT / "examples" / "modules" / "slots.yml")["slots"].items()
    if d.get("required_in_core")
)  # fmt: skip


class _NoAliases(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


def _dump(doc) -> str:
    return yaml.dump(doc, Dumper=_NoAliases, sort_keys=False)


def bound_row() -> dict:
    """The module's row as the overlay copies it: the instance's name, the guest as host and the
    product's version."""
    row = ld.load_yaml(MODULE / "registry" / "services.yml")["services"]["orchestration"]
    version = str(ld.load_yaml(MODULE / "module.yml")["product"]["version"])
    return {**copy.deepcopy(row), "host": "agents-1", "version": version}


def overlay(tmp: Path) -> Path:
    """A fictional overlay adopting the module: the example registry with the example's own
    orchestration row replaced by the bound one (and a row for each required core slot it has none
    for), one guest, and a selection placing the module on it with every other required core slot
    an incumbent."""
    lab = tmp / "lab"
    (lab / "guests").mkdir(parents=True)
    reg = ld.load_yaml(ROOT / "examples" / "services.yml")
    reg["hosts"]["agents-1"] = {"address": GUEST, "zone": "mgmt", "role": "apps"}
    reg["services"].pop("orchestrator")
    reg["services"]["agent-jobs"] = bound_row()
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
        "placement: {node: hv-01, vmid: 241, vmid_scheme: freeform}\n"
        "resources:\n  cpu: {cores: 2}\n  memory: {size_mb: 4096}\n"
        "  disks: [{name: rootfs, size_gb: 32, pool: fast}]\n"
        "image: {logical: debian-13-cloudinit, kind: template-clone, os_type: linux-6}\n"
        "cloudinit: {user: ansible, ssh_authorized_keys: [operator]}\n"
        f"network: {{zone: mgmt, ip: {GUEST}}}\n"
        "capability: cap:orchestration\nbackup: {policy: none}\n"
        "owners: {primary: platform-team}\nbaseline: {names: [base]}\n"
    )
    rows = {n: r["capability"] for n, r in reg["services"].items()}
    incumbents = {
        slot: {"service": next(n for n, c in rows.items() if c == slot), "why": "fictional"}
        for slot in REQUIRED
        if slot != "orchestration"
    }
    sel = {
        "profile": "orchestration-pilot",
        "hosts": {"agents": {"guest": "guest:agents-1"}},
        "slots": {"orchestration": [{"provider": "orchestration", "instance": "agent-jobs",
                                     "placement": {"server": "agents"}}]},
        "incumbents": incumbents,
    }  # fmt: skip
    (lab / "modules.yml").write_text(_dump(sel))
    return tmp


def _args(ov: Path) -> list[str]:
    return ["--root", str(ROOT), "--overlay", str(ov),
            "--keyring", str(ROOT / "examples" / "keyring" / "keyring.json"),
            "--mcp-catalog", str(ROOT / "examples" / "mcp")]  # fmt: skip


def _check(ov: Path, capsys) -> tuple[int, str]:
    code = mcli.main(["check", *_args(ov)])
    return code, capsys.readouterr().out


# ----------------------------------------------------------------------------- the public tree


@pytest.mark.static
def test_the_public_tree_loads_clean(capsys):
    code = mcli.main(["check", "--root", str(ROOT)])
    out = capsys.readouterr().out
    assert code == 0, out
    public = sum(1 for p in (ROOT / "modules").iterdir() if (p / "module.yml").is_file())
    assert out.rstrip().endswith(f"{public} module(s), 0 problem(s)")


@pytest.mark.static
def test_roles_holds_only_the_contributed_role():
    assert sorted(p.name for p in (MODULE / "roles").iterdir()) == ["orchestration"]
    assert not any(p.is_symlink() for p in MODULE.rglob("*"))
    manifest = ld.load_yaml(MODULE / "module.yml")
    assert [c["file"] for c in manifest["contributes"]["roles"]] == ["roles/orchestration"]


def test_the_manifest_has_no_egress_and_the_row_no_public_route():
    manifest = ld.load_yaml(MODULE / "module.yml")
    assert manifest["egress"] == "none"
    row = ld.load_yaml(MODULE / "registry" / "services.yml")["services"]["orchestration"]
    assert "public_hostname" not in row and row["auth"] == "own"
    assert "version" not in row  # a provider's row takes product.version
    assert row["health"] == {"kind": "http", "path": "/healthz", "expect_status": 200}


def test_the_row_port_credentials_and_references_are_one_set():
    defaults = ld.load_yaml(ROLE / "defaults" / "main.yml")
    row = ld.load_yaml(MODULE / "registry" / "services.yml")["services"]["orchestration"]
    assert row["port"] == defaults["orchestration_port"]
    assert row["metrics"]["auth"] == {
        "kind": "bearer",
        "secret": defaults["orchestration_metrics_ref"],
    }
    listed = {c["secret"] for c in ld.load_yaml(MODULE / "module.yml")["credentials"]}
    refs = {v for k, v in defaults.items() if k.endswith("_ref") and isinstance(v, str)}
    assert refs == listed, refs ^ listed
    # the three a caller outside the module holds are granted, never the provider's alone
    holders = {c["secret"]: c["holder"] for c in ld.load_yaml(MODULE / "module.yml")["credentials"]}
    for ref in ("jobs", "status", "metrics"):
        assert holders[defaults[f"orchestration_{ref}_ref"]] == "granted"
    assert holders[defaults["orchestration_admin_ref"]] == "provider"


def test_the_slot_features_are_the_adapters_and_the_store_has_a_jsonl_export():
    manifest = ld.load_yaml(MODULE / "module.yml")
    slot = manifest["provides"]["slots"]["orchestration"]
    assert slot["adapter"] == "homelabnext.conform.adapters.orchestrator:make"
    assert slot["migration"] == {"formats": ["jsonl"], "export": "role:orchestration",
                                 "import": "role:orchestration"}  # fmt: skip
    (store,) = manifest["data"]
    assert (
        store["export"]["formats"] == ["jsonl"] and store["import"]["via"] == "role:orchestration"
    )


# ----------------------------------------------------------------------------- an overlay


def test_an_overlay_placing_the_module_on_a_guest_checks_clean_and_renders(tmp_path, capsys):
    ov = overlay(tmp_path / "ov")
    code, out = _check(ov, capsys)
    assert code == 0, out
    assert out.rstrip().endswith("0 problem(s), 0 warning(s)") or "0 problem(s)" in out
    dest = tmp_path / "out"
    code = mcli.main(["render", *_args(ov), "--out", str(dest)])
    out = capsys.readouterr().out
    assert code == 0, out
    books = yaml.safe_load((dest / "modules.yml").read_text())
    plays = [p for p in books if p["hosts"] == "mod_orchestration_server"]
    assert len(plays) == 1 and plays[0]["become"] is True
    assert plays[0]["roles"][0]["role"].endswith("modules/orchestration/roles/orchestration")
    assert plays[0]["pre_tasks"][0]["ansible.builtin.include_role"]["tasks_from"] == "readiness"
    # the unit joins the role's slice (the template reads the play variable)
    assert without_footprint(plays[0]["vars"]) == {
        "hnx_module_slice": "hnx-orchestration-server.slice"
    }
    assert (dest / "limits" / "agents" / "hnx-orchestration-server.slice").is_file()


def test_a_registry_row_that_differs_is_named(tmp_path, capsys):
    ov = overlay(tmp_path)
    reg = ld.load_yaml(ov / "lab" / "services.yml")
    reg["services"]["agent-jobs"]["port"] = 9000
    (ov / "lab" / "services.yml").write_text(_dump(reg))
    code, out = _check(ov, capsys)
    assert code == 1
    assert "registry: services.agent-jobs.port" in out and "contributes 8088" in out


def test_a_row_that_gains_a_public_route_is_refused(tmp_path, capsys):
    ov = overlay(tmp_path)
    reg = ld.load_yaml(ov / "lab" / "services.yml")
    reg["services"]["agent-jobs"]["public_hostname"] = "agents.example.org"
    (ov / "lab" / "services.yml").write_text(_dump(reg))
    code, out = _check(ov, capsys)
    assert code == 1 and "public_hostname" in out, out


def test_a_guest_without_the_base_baseline_is_refused(tmp_path, capsys):
    ov = overlay(tmp_path)
    g = ov / "lab" / "guests" / "agents-1.yml"
    g.write_text(g.read_text().replace("names: [base]", "names: []"))
    code, out = _check(ov, capsys)
    assert code == 1 and "base" in out, out


def test_orchestration_cannot_be_both_the_module_and_an_incumbent(tmp_path, capsys):
    ov = overlay(tmp_path)
    sel = ld.load_yaml(ov / "lab" / "modules.yml")
    sel["incumbents"]["orchestration"] = {"service": "agent-jobs", "why": "both"}
    (ov / "lab" / "modules.yml").write_text(_dump(sel))
    code, out = _check(ov, capsys)
    assert code == 1 and "incumbents.orchestration: the slot is also selected under slots" in out, (
        out
    )


# ----------------------------------------------------------------------------- conformance


@pytest.mark.static
def test_the_target_binds_the_adapter_as_the_repositorys_own_controller_target_does():
    mine = load_target(str(MODULE / "conformance" / "target.yml"), root=ROOT)
    ref = load_target(
        str(ROOT / "conformance" / "targets" / "orchestration-orchestrator.yml"), root=ROOT
    )
    a, b = mine.binding("orchestration"), ref.binding("orchestration")
    assert (a.adapter, a.config) == (b.adapter, b.config)
    assert a.adapter == "homelabnext.conform.adapters.orchestrator:make"


def test_the_suite_passes_through_the_modules_target_on_the_repositorys_controller(
    controller_binary, tmp_path, monkeypatch
):
    """Every check that needs no fault hook (the kill and restart checks are CI's strict run with
    process fault injection, tools/orchestration_conformance.py) passes through the module's own
    target file on a live controller."""
    target = load_target(str(MODULE / "conformance" / "target.yml"), root=ROOT)
    binding = target.binding("orchestration")
    config = {k: v for k, v in binding.config.items() if k != "fault_injection"}
    with live_controller(controller_binary, tmp_path / "work") as live:
        monkeypatch.setenv("HNX_ENDPOINT_ORCHESTRATION", live._url)  # the live subject's own URL
        monkeypatch.setenv("HNX_ORCHESTRATION_PROFILES_DIR", str(tmp_path / "work" / "profiles"))
        binding = dataclasses.replace(binding, config=config)
        make_subject = make_factory(binding, root=ROOT)

        def factory():
            # a cancel against this local controller is a process kill: three seconds is ample,
            # and the suite's watch that a hold outlives two graces shrinks with it (10 s default)
            subject = make_subject()
            subject.cancel_grace_s = 3.0
            return subject

        wanted = [
            s.id for s in orch_suite.SUITE.specs if "fault-injection" not in (s.requires or ())
        ]
        results = run_checks(orch_suite.SUITE, factory, only=wanted)
    failed = sorted(r.check for r in results if r.status not in ("pass", "skip", "waived"))
    assert failed == [], failed
    assert any(r.status == "pass" for r in results)


# ----------------------------------------------------------------------------- nothing on a workstation


PRIVATE = re.compile(
    r"(?<![0-9.])(10|127|169\.254|192\.168|172\.(1[6-9]|2[0-9]|3[01]))\.[0-9]{1,3}\.[0-9]{1,3}(?![0-9])"
)


@pytest.mark.static
def test_nothing_in_the_module_names_a_private_address_or_a_workstation():
    hits = []
    for p in sorted(MODULE.rglob("*")):
        if not p.is_file():
            continue
        text = p.read_text()
        for n, line in enumerate(text.splitlines(), 1):
            if (PRIVATE.search(line) and LOOP not in line) or re.search(
                r"(?i)\bwsl\b|/mnt/[a-z]/", line
            ):
                hits.append(f"{p.relative_to(MODULE)}:{n}: {line.strip()[:100]}")
    # the role's own refusal patterns name them in order to refuse them; nothing else may
    assert [
        h
        for h in hits
        if "orchestration_forbidden_value_pattern" not in h
        and "vars/main.yml" not in h
        and "README.md" not in h
        and "tasks/validate.yml" not in h
    ] == [], hits


# ----------------------------------------------------------------------------- lint


def test_role_lint_passes_the_role_and_the_lifecycle_playbooks():
    lint = [sys.executable, str(ROOT / "tools" / "role_lint.py")]
    r = subprocess.run([*lint, str(ROLE)], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    books = sorted(str(p) for p in (MODULE / "playbooks").glob("*.yml"))
    inv = str(ROOT / "ansible" / "inventory" / "example" / "hosts.yml")
    r = subprocess.run([*lint, "--playbook", *books, "--inventory", inv],
                       capture_output=True, text=True)  # fmt: skip
    assert r.returncode == 0, r.stdout + r.stderr
