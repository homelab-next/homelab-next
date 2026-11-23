# SPDX-License-Identifier: Apache-2.0
"""Where the signature-based network-sensor provider module is, found by the slot it fills and by the
rule-feed setting its role has (the tests name the slot, not the product): its directory, its id
(also its role's name and its variables' prefix) and the helpers that spell those."""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
SLOT = "network-sensor"


def _find() -> Path:
    found = []
    for manifest in sorted((ROOT / "modules").glob("*/module.yml")):
        doc = yaml.safe_load(manifest.read_text())
        if SLOT not in doc.get("provides", {}).get("slots", {}):
            continue
        defaults = manifest.parent / "roles" / manifest.parent.name / "defaults" / "main.yml"
        if defaults.is_file() and f"{manifest.parent.name}_rule_sources" in yaml.safe_load(
            defaults.read_text()
        ):
            found.append(manifest.parent)
    assert len(found) == 1, f"exactly one signature sensor fills {SLOT}: {found}"
    return found[0]


MODULE = _find()
MID = MODULE.name
P = MID + "_"
ROLE_DIR = MODULE / "roles" / MID


def var(name: str) -> str:
    """The role's variable ``<id>_<name>``."""
    return P + name


def prefixed(**kw) -> dict:
    """``name=value`` pairs as the role's variables, ``<id>_<name>: value``."""
    return {P + k: v for k, v in kw.items()}
