# SPDX-License-Identifier: Apache-2.0
"""Load the endpoint-forensics role's two host scripts by path (they are files a role installs, not
package modules), and build the catalog and the stand-in server the script tests share."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import yaml

from tests.modules.endpoint_forensics_module import MID, SERVER

FILES = SERVER / "files"
CATALOG = FILES / "baseline-artifacts.yml"
CYCLE = FILES / f"hnx_{MID}.py"
CHECK = FILES / f"hnx_{MID}_check.py"


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def catalog_doc() -> dict:
    return yaml.safe_load(CATALOG.read_text())


class FakeServer:
    """A stand-in for ``docker compose exec ... query``: the script hands it the
    command line, it answers from tables. ``calls`` keeps every VQL the script sent."""

    def __init__(self, clients=(), definitions=None, hunt_rows=None, fail=False):
        self.clients = list(clients)
        self.definitions = definitions
        self.hunt_rows = hunt_rows or {}
        self.fail = fail
        self.calls: list[str] = []
        self.hunts = 0

    def __call__(self, argv):
        vql = argv[argv.index("query") + 1]
        self.calls.append(vql)
        if self.fail:
            return 1, "", "boom"
        if "FROM clients()" in vql:
            return 0, "\n".join(json.dumps(c) for c in self.clients) + "\n", ""
        if "FROM artifact_definitions" in vql:
            rows = self.definitions
            if rows is None:
                rows = [{"name": n, "required_permissions": [], "implied_permissions": []}
                        for n in catalog_names()]  # fmt: skip
            return 0, "\n".join(json.dumps(r) for r in rows) + "\n", ""
        if "hunt(description" in vql:
            self.hunts += 1
            return 0, json.dumps({"r": {"HuntId": f"H.TEST{self.hunts}"}}) + "\n", ""
        if "FROM hunt_results" in vql:
            key = next((k for k in self.hunt_rows if k in vql), None)
            rows = self.hunt_rows.get(key, [])
            return 0, "\n".join(json.dumps(r) for r in rows) + "\n", ""
        return 0, "", ""


def catalog_names() -> list[str]:
    return [a["name"] for a in catalog_doc()["artifacts"]]
