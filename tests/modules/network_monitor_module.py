# SPDX-License-Identifier: Apache-2.0
"""Where the flow-monitor network-sensor provider module is, found by the slot it fills and by the
package-pin list its role has (the tests name the slot, not the product): its directory, its id
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
        mid = manifest.parent.name
        defaults = manifest.parent / "roles" / mid / "defaults" / "main.yml"
        if defaults.is_file() and f"{mid}_script_packages" in yaml.safe_load(defaults.read_text()):
            found.append(manifest.parent)
    assert len(found) == 1, f"exactly one flow monitor fills {SLOT}: {found}"
    return found[0]


MODULE = _find()
MID = MODULE.name
P = MID + "_"
ROLE_DIR = MODULE / "roles" / MID
