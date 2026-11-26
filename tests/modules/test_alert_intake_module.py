# SPDX-License-Identifier: Apache-2.0
"""The ``alert-intake`` feature module's manifest and public tree: it names slots and its secrets by
reference, declares no egress and no lab value and no product, its vendored contract file equals the
repository's, and its role passes the role lint."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "modules" / "alert-intake"
ROLE = MODULE / "roles" / "alert_intake"


def _manifest() -> dict:
    return yaml.safe_load((MODULE / "module.yml").read_text())


def test_the_manifest_is_a_feature_that_requires_the_case_store_the_notifier_and_the_secret_store():
    m = _manifest()
    assert m["kind"] == "feature" and m["id"] == "alert-intake"
    assert {c["cap"] for c in m["requires"]["capabilities"]} == {
        "cap:secrets",
        "cap:case-management",
        "cap:notify",
    }
    assert m["egress"] == "none"
    assert [h["role"] for h in m["requires"]["hosts"]] == ["server"]


@pytest.mark.static
def test_every_secret_default_is_a_reference_and_the_state_is_exportable():
    m = _manifest()
    for cfg in m["config"].values():
        assert cfg["type"] == "secret" and cfg["default"].split("/")[0] == "secret:alert-intake"
    assert [d["id"] for d in m["data"]] == ["state"]
    defaults = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text())
    refs = {
        v
        for k, v in defaults.items()
        if (k.endswith("_ref") and v and "cases_ca" not in k) or k.endswith("cases_ca_ref")
    }
    assert refs == {c["default"] for c in m["config"].values()}


@pytest.mark.static
def test_the_defaults_hold_no_address_and_no_lab_name_and_the_policy_is_conservative():
    text = (ROLE / "defaults" / "main.yml").read_text()
    assert "192.168" not in text and "gluck" not in text
    d = yaml.safe_load(text)
    assert d["alert_intake_page_min"] == "high"  # the old lab paged only its top tier
    assert d["alert_intake_promote_min"] == ""  # alerts, not cases
    assert d["alert_intake_canary_prefix"].startswith("det:")


@pytest.mark.static
def test_the_unit_runs_as_its_own_user_with_the_secrets_in_a_root_only_file():
    unit = (ROLE / "templates" / "alert-intake.service.j2").read_text()
    assert "User={{ alert_intake_user }}" in unit and "NoNewPrivileges=yes" in unit
    assert "CapabilityBoundingSet=\n" in unit
    cfg = (ROLE / "tasks" / "config.yml").read_text()
    logins = cfg[cfg.index("Write the secrets for the unit") :]
    assert (
        'mode: "0600"' in logins.split("- name:")[0]
        and "no_log: true" in logins.split("- name:")[0]
    )
    assert "{{ lookup" not in (ROLE / "templates" / "alert-intake.env.j2").read_text()


@pytest.mark.static
def test_the_vendored_contract_file_equals_the_repositorys():
    assert (ROLE / "files" / "cases_contract.txt").read_text() == (
        ROOT / "conformance" / "protocols" / "cases.py"
    ).read_text()


def test_role_lint_passes_the_role():
    r = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "role_lint.py"), str(ROLE)],
        capture_output=True, text=True, check=False,
    )  # fmt: skip
    assert r.returncode == 0, r.stdout + r.stderr


def test_the_shared_library_set_the_role_installs_is_exactly_what_the_script_imports():
    """The guest has no homelabnext package: the role copies the files the script's imports load. A new
    import in the script (or in the shared helpers it uses) that is not in the list would fail on the guest."""
    code = (
        "import importlib.util, sys; sys.path.insert(0, sys.argv[1]);"
        "spec = importlib.util.spec_from_file_location('hnx_alert_intake', sys.argv[2]);"
        "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m);"
        "print('\\n'.join(f'{k} {int(hasattr(v, chr(95) * 2 + \"path\" + chr(95) * 2))}' "
        "for k, v in sorted(sys.modules.items()) if k.startswith('homelabnext')))"
    )
    out = subprocess.run(
        [sys.executable, "-I", "-c", code, str(ROOT), str(ROLE / "files" / "hnx_alert_intake.py")],
        capture_output=True, text=True, check=True,
    ).stdout.splitlines()  # fmt: skip
    loaded = set()
    for line in out:
        name, is_pkg = line.split()
        rel = name.removeprefix("homelabnext").lstrip(".").replace(".", "/")
        loaded.add(f"{rel}/__init__.py".lstrip("/") if is_pkg == "1" else f"{rel}.py")
    # the package's __init__ reads _version.py only when the package is not installed (the guest case);
    # a test environment that has it installed does not load it, so it is expected either way
    loaded.add("_version.py")
    listed = yaml.safe_load((ROLE / "vars" / "main.yml").read_text())["alert_intake_shared_files"]
    assert len(loaded) > 5 and sorted(listed) == sorted(loaded), (sorted(listed), sorted(loaded))


@pytest.mark.static
def test_the_readiness_hook_looks_for_systemd_as_a_directory():
    # /run/systemd/system is a directory on every systemd host: a check for a regular file refused every
    # real host at its first deploy (found 2026-11-23 on the lab's first placement)
    tasks = yaml.safe_load((ROLE / "tasks" / "readiness.yml").read_text())
    steps = tasks[0]["block"]
    look = next(
        i
        for i, s in enumerate(steps)
        if s.get("ansible.builtin.stat", {}).get("path") == "/run/systemd/system"
    )
    check = steps[look + 1]["ansible.builtin.assert"]["that"]
    assert "stat.isdir" in check and "stat.isreg" not in check
