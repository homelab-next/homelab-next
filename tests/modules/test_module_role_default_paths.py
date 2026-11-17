# SPDX-License-Identifier: Apache-2.0
"""A module role's own defaults must pass the path rule its own validation applies.

``orchestration_install_dir`` and ``orchestration_config_dir`` once defaulted to two-component
paths, so the role refused its own defaults on the first deploy that did not override them.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
ROLES = sorted(p for p in (ROOT / "modules").glob("*/roles/*") if p.is_dir())


def _load(p: Path) -> dict:
    return yaml.safe_load(p.read_text()) or {} if p.is_file() else {}


def _vars(role: Path) -> dict:
    return {**_load(role / "defaults" / "main.yml"), **_load(role / "vars" / "main.yml")}


def _path_rules(role: Path) -> list[tuple[str, re.Pattern[str]]]:
    v = _vars(role)
    return [(k[: -len("_path_pattern")], re.compile(val)) for k, val in v.items()
            if k.endswith("_path_pattern") and isinstance(val, str)]  # fmt: skip


@pytest.mark.parametrize("role", ROLES, ids=lambda p: f"{p.parent.parent.name}/{p.name}")
def test_role_defaults_pass_its_own_path_pattern(role: Path) -> None:
    v = _vars(role)
    for prefix, pattern in _path_rules(role):
        for key, val in v.items():
            if not key.startswith(prefix + "_") or not isinstance(val, str):
                continue
            if key.endswith(("_dir", "_root")) and val.startswith("/") and "{{" not in val:
                assert pattern.match(val), f"{key}={val!r} fails {prefix}_path_pattern"


def test_orchestration_defaults_are_canonical_hnx_paths() -> None:
    v = _vars(ROOT / "modules" / "orchestration" / "roles" / "orchestration")
    assert v["orchestration_install_dir"] == "/opt/hnx/orchestration"
    assert v["orchestration_config_dir"] == "/etc/hnx/orchestration"
    pattern = re.compile(v["orchestration_path_pattern"])
    for key in ("install_dir", "config_dir", "data_root", "systemd_dir"):
        assert pattern.match(v[f"orchestration_{key}"]), key
    # the argument spec states the same defaults
    spec = _load(
        ROOT
        / "modules"
        / "orchestration"
        / "roles"
        / "orchestration"
        / "meta"
        / "argument_specs.yml"
    )["argument_specs"]["main"]["options"]
    assert spec["orchestration_install_dir"]["default"] == v["orchestration_install_dir"]
    assert spec["orchestration_config_dir"]["default"] == v["orchestration_config_dir"]
