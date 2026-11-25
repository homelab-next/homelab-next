# SPDX-License-Identifier: Apache-2.0
"""Where the web-search provider module is, by the slot it fills (the tests name the slot, not the
product): its directory, its id (which is also its role's name and its variables' and secrets'
prefix) and the helpers that spell those."""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
SLOT = "web-search"


def _find() -> Path:
    found = []
    for manifest in sorted((ROOT / "modules").glob("*/module.yml")):
        doc = yaml.safe_load(manifest.read_text())
        if SLOT in doc.get("provides", {}).get("slots", {}):
            found.append(manifest.parent)
    assert len(found) == 1, f"exactly one module fills {SLOT}: {found}"
    return found[0]


MODULE = _find()
MID = MODULE.name  # the module id: its role, its variables' prefix and its secret namespace
P = MID + "_"
ROLE_DIR = MODULE / "roles" / MID


def var(name: str) -> str:
    """The role's variable ``<id>_<name>``."""
    return P + name


def ref(name: str) -> str:
    """The module's own secret reference ``secret:<id>/<name>``."""
    return f"secret:{MID}/{name}"


def env_for(secret_ref: str) -> str:
    """The environment variable the secret lookup reads a reference from."""
    return "HNX_SECRET_" + "".join(c if c.isalnum() else "_" for c in secret_ref[7:]).upper()


def defaults() -> dict:
    return yaml.safe_load((ROLE_DIR / "defaults" / "main.yml").read_text())
