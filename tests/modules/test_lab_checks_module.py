# SPDX-License-Identifier: Apache-2.0
"""The ``lab-checks`` feature module's manifest and public tree: it names the notify slot and one secret by
reference, declares no egress and no lab value, its timer is a calendar, and its role passes the role lint."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "modules" / "lab-checks"
ROLE = MODULE / "roles" / "lab_checks"


def _manifest() -> dict:
    return yaml.safe_load((MODULE / "module.yml").read_text())


def test_the_manifest_is_a_feature_that_requires_notify_and_the_secret_store():
    m = _manifest()
    assert m["kind"] == "feature" and m["id"] == "lab-checks"
    assert {c["cap"] for c in m["requires"]["capabilities"]} == {"cap:secrets", "cap:notify"}
    assert m["egress"] == "none"
    assert [h["role"] for h in m["requires"]["hosts"]] == ["runner"]
    pair = m["contributes"]["notify_pairs"][0]
    assert pair["problem"] == "Invariant newly broken" and pair["recovery"] == "Invariant recovered"


def test_the_one_secret_default_is_a_reference_the_role_defaults_agree_with():
    m = _manifest()
    (cfg,) = m["config"].values()
    assert cfg["type"] == "secret" and cfg["default"].split("/")[0] == "secret:lab-checks"
    defaults = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text())
    refs = {v for k, v in defaults.items() if k.endswith("_ref") and v}
    assert refs == {cfg["default"]}
    # the unit names the hnx path literally (the scripts catalog resolves the exec); the role checks the same one
    unit = (ROLE / "templates" / "lab-checks.service.j2").read_text()
    path = yaml.safe_load((ROLE / "vars" / "main.yml").read_text())["lab_checks_hnx_bin"]
    assert f"ExecStart={path} invariants run" in unit


def test_the_defaults_hold_no_address_and_the_timer_is_a_calendar_never_an_interval():
    text = (ROLE / "defaults" / "main.yml").read_text()
    assert "192.168" not in text and "gluck" not in text
    defaults = yaml.safe_load(text)
    assert defaults["lab_checks_oncalendar"].endswith(" UTC")
    timer = (ROLE / "templates" / "lab-checks.timer.j2").read_text()
    assert "OnCalendar=" in timer and "OnBootSec=" not in timer and "OnUnitActiveSec=" not in timer


def test_the_unit_accepts_a_red_run_and_a_run_that_could_not_measure():
    # the runner exits 1 (a criterion failed) or 100 (one could not be measured): the page is the signal
    service = (ROLE / "templates" / "lab-checks.service.j2").read_text()
    assert "SuccessExitStatus=1 100" in service
    assert "--state " in service and "--notify-cmd " in service and "--notify-ceiling " in service
    assert (
        "NoNewPrivileges=yes" in service and "CapabilityBoundingSet=CAP_DAC_READ_SEARCH" in service
    )


def test_role_lint_passes_the_role():
    r = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "role_lint.py"), str(ROLE)],
        capture_output=True, text=True, check=False,
    )  # fmt: skip
    assert r.returncode == 0, r.stdout + r.stderr


def test_the_role_installs_the_state_tool_beside_the_wrapper_for_the_sites_checks():
    role = ROOT / "modules" / "cti-pipeline" / "roles" / "cti_pipeline"
    config = (role / "tasks" / "config.yml").read_text()
    assert "src: cti_state.py" in config and 'dest: "{{ cti_pipeline_state_tool }}"' in config
    vars_ = (role / "vars" / "main.yml").read_text()
    assert 'cti_pipeline_state_tool: "{{ cti_pipeline_install_dir }}/bin/hnx-cti-state"' in vars_
