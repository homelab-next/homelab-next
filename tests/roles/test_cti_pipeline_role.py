# SPDX-License-Identifier: Apache-2.0
"""Role ``cti_pipeline`` hooks that need ansible (modules/cti-pipeline/roles/cti_pipeline), run on
localhost: the handoff and host-tool settings are refused by name before anything is written, and
the claude CLI the app's fallback calls is a readiness check that fails clearly (no module installs
it)."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import pytest
from rolerun import fake, run_role

ROOT = Path(__file__).resolve().parents[2]
ROLE = str(ROOT / "modules" / "cti-pipeline" / "roles" / "cti_pipeline")


@pytest.fixture
def outside_home():
    """A directory outside /home (the role refuses a claude CLI the units' ProtectHome would hide)."""
    d = Path(tempfile.mkdtemp(prefix="hnx-claude-"))
    yield d
    shutil.rmtree(d, ignore_errors=True)


def base_vars() -> dict:
    return {
        "cti_pipeline_logical_id": "intel",
        "cti_pipeline_artefact": "/srv/build/intel.tar.gz",
        "cti_pipeline_artefact_sha256": "a" * 64,
        "cti_pipeline_jobs": {
            "fresh": {"steps": [["{python}", "-m", "intel.run"]], "timeout_s": 600, "max_age_s": 0}
        },
    }


def test_validate_passes_for_the_handoff_defaults(tmp_path):
    r = run_role(tmp_path, ROLE, "validate", base_vars())
    assert r.returncode == 0, r.stdout + r.stderr


@pytest.mark.parametrize(
    "bad",
    [
        {"cti_pipeline_handoff_dir": "/var/lib/hnx-modules/intel/handoff"},  # inside the data root
        {"cti_pipeline_handoff_dir": "/opt/hnx/intel/out"},  # inside the install directory
        {"cti_pipeline_handoff_dir": "/var/lib"},  # too shallow, and above the data root
        {"cti_pipeline_handoff_dir": "relative/handoff"},
        {"cti_pipeline_handoff_enabled": "yes please"},
        {"cti_pipeline_handoff_group": {"real": "same", "shadow": "same"}},
        {
            "cti_pipeline_handoff_group": {"real": "hnx-intel", "shadow": "other"}
        },  # the module's group
        {"cti_pipeline_handoff_group": {"real": "root", "shadow": "other"}},
        {"cti_pipeline_handoff_group": {"real": "Bad Name", "shadow": "other"}},
        {"cti_pipeline_handoff_group": {"real": "only-one"}},
        {"cti_pipeline_handoff_keep": 0},
        {"cti_pipeline_claude_cli": "relative/claude"},
        {"cti_pipeline_claude_cli": "/home/ansible/.local/bin/claude"},  # the units hide /home
        {"cti_pipeline_claude_cli": "/root/bin/claude"},
    ],
)
def test_validate_refuses_an_unsafe_handoff_or_tool_setting(tmp_path, bad):
    r = run_role(tmp_path, ROLE, "validate", {**base_vars(), **bad})
    assert r.returncode != 0, r.stdout


def test_validate_accepts_a_site_chosen_handoff_and_claude_path(tmp_path):
    v = {
        **base_vars(),
        "cti_pipeline_handoff_dir": "/srv/handoff/intel",
        "cti_pipeline_handoff_group": {"real": "intel-r", "shadow": "intel-s"},
        "cti_pipeline_handoff_keep": 5,
        "cti_pipeline_claude_cli": "/usr/local/bin/claude",
    }
    r = run_role(tmp_path, ROLE, "validate", v)
    assert r.returncode == 0, r.stdout + r.stderr


def test_readiness_names_a_missing_claude_cli_and_how_to_supply_it(tmp_path, outside_home):
    v = {**base_vars(), "cti_pipeline_claude_cli": str(outside_home / "bin" / "claude")}
    r = run_role(tmp_path, ROLE, "readiness", v)
    out = " ".join((r.stdout + r.stderr).split())  # ansible wraps long messages
    assert r.returncode != 0
    assert (
        "claude CLI" in out and "no module installs it" in out and "outside /home and /root" in out
    )


def test_readiness_refuses_a_claude_cli_that_does_not_run(tmp_path, outside_home):
    b = outside_home / "bin"
    b.mkdir()
    fake(b / "claude", "import sys\nsys.exit(7)\n")
    v = {**base_vars(), "cti_pipeline_claude_cli": str(b / "claude")}
    r = run_role(tmp_path, ROLE, "readiness", v)
    assert r.returncode != 0
    assert "missing or does not run (exit 7)" in " ".join((r.stdout + r.stderr).split())


def test_a_working_claude_cli_passes_that_check_and_an_unset_one_is_not_checked(
    tmp_path, outside_home
):
    b = outside_home / "bin"
    b.mkdir()
    fake(b / "claude", "print('2.1.0 (Claude Code)')\n")
    v = {**base_vars(), "cti_pipeline_claude_cli": str(b / "claude")}
    got = run_role(
        tmp_path, ROLE, "readiness", v
    )  # it fails later (no dispatcher user here), not at the CLI
    assert "missing or does not run" not in " ".join((got.stdout + got.stderr).split())
    unset = run_role(tmp_path, ROLE, "readiness", base_vars())
    assert "missing or does not run" not in " ".join((unset.stdout + unset.stderr).split())
