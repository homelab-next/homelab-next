# SPDX-License-Identifier: Apache-2.0
"""Where the endpoint-forensics provider module is, by the slot it fills (the tests name the slot,
not the product): its directory, its id (which is also its roles' name prefix and its variables'
and secrets' prefix) and the helpers that spell those."""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
SLOT = "endpoint-forensics"


def _find() -> Path:
    found = []
    for manifest in sorted((ROOT / "modules").glob("*/module.yml")):
        doc = yaml.safe_load(manifest.read_text())
        if SLOT in doc.get("provides", {}).get("slots", {}):
            found.append(manifest.parent)
    assert len(found) == 1, f"exactly one module fills {SLOT}: {found}"
    return found[0]


MODULE = _find()
MID = MODULE.name  # the module id
SERVER = MODULE / "roles" / f"{MID}_server"
CLIENT = MODULE / "roles" / f"{MID}_client"
SP = f"{MID}_server_"  # the server role's variables' prefix
CP = f"{MID}_client_"  # the client role's variables' prefix


def ref(name: str) -> str:
    """The module's own secret reference ``secret:<id>/<name>``."""
    return f"secret:{MID}/{name}"


def env_for(secret_ref: str) -> str:
    """The environment variable the secret lookup reads a reference from."""
    return "HNX_SECRET_" + "".join(c if c.isalnum() else "_" for c in secret_ref[7:]).upper()


def server_defaults() -> dict:
    return yaml.safe_load((SERVER / "defaults" / "main.yml").read_text())
