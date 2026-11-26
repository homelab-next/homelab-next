# SPDX-License-Identifier: Apache-2.0
"""The serving allowlist names only flags the pinned engine release has."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from homelabnext.models import serving as sv

ROOT = Path(__file__).resolve().parents[2]
VLLM_HELP_SNAPSHOT = ROOT / "tests" / "models" / "fixtures" / "vllm_serve_help_0.32.0.json"


@pytest.mark.static
def test_allowlisted_args_exist_in_the_pinned_vllm_serve_help():
    snapshot = json.loads(VLLM_HELP_SNAPSHOT.read_text())
    pin = yaml.safe_load((ROOT / "ansible/roles/vllm_server/defaults/main.yml").read_text())[
        "vllm_server_version"
    ]
    assert snapshot["version"] == pin, "verify and refresh the help snapshot when moving the pin"
    assert set(sv.ALLOWED_ARGS) <= set(snapshot["options"])
