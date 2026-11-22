# SPDX-License-Identifier: Apache-2.0
"""The ``intel-ingest`` feature module's manifest and public tree: it names its two slots and its
secrets by reference, declares no egress and no lab value, and its role passes the role lint."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "modules" / "intel-ingest"
ROLE = MODULE / "roles" / "intel_ingest"


def _manifest() -> dict:
    return yaml.safe_load((MODULE / "module.yml").read_text())


def test_the_manifest_is_a_feature_that_requires_the_two_slots_and_the_secret_store():
    m = _manifest()
    assert m["kind"] == "feature" and m["id"] == "intel-ingest"
    caps = {c["cap"] for c in m["requires"]["capabilities"]}
    assert caps == {"cap:secrets", "cap:threat-intel", "cap:graph-store"}
    assert m["egress"] == "none"
    assert [h["role"] for h in m["requires"]["hosts"]] == ["job"]


def test_every_secret_default_is_a_reference_and_the_state_is_exportable():
    m = _manifest()
    for cfg in m["config"].values():
        assert cfg["type"] == "secret" and cfg["default"].startswith("secret:") and "/" in cfg["default"]
    assert [d["id"] for d in m["data"]] == ["state"]
    defaults = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text())
    refs = {v for k, v in defaults.items() if k.endswith("_ref") and v}
    assert refs == {c["default"] for c in m["config"].values()}


def test_the_defaults_hold_no_address_and_the_timer_is_a_calendar_never_an_interval():
    text = (ROLE / "defaults" / "main.yml").read_text()
    assert "192.168" not in text and "gluck" not in text
    defaults = yaml.safe_load(text)
    assert defaults["intel_ingest_oncalendar"].startswith("*-*-*")
    timer = (ROLE / "templates" / "intel-ingest.timer.j2").read_text()
    assert "OnCalendar=" in timer and "OnBootSec=" not in timer and "OnUnitActiveSec=" not in timer


def test_role_lint_passes_the_role():
    r = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "role_lint.py"), str(ROLE)],
        capture_output=True, text=True, check=False,
    )  # fmt: skip
    assert r.returncode == 0, r.stdout + r.stderr
