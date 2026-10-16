# SPDX-License-Identifier: Apache-2.0
"""Builders shared by the customization tests (a plain module so tests can import it)."""

from __future__ import annotations

import copy
import json
from datetime import date
from pathlib import Path

from homelabnext.customization import load_tree

TODAY = date(2026, 10, 15)


def make_doc(**over):
    """A valid override customization (overrides applied last; a value of None drops the key)."""
    doc = {
        "id": "custom:test-port",
        "title": "Test port override",
        "kind": "override",
        "scope": {"capabilities": ["cap:monitoring"]},
        "contract": "cap:monitoring",
        "reason": "A synthetic deviation used by the tests, long enough to be a real reason.",
        "owner": "test-team",
        "created": "2026-09-01",
        "review_by": "2026-12-01",
        "upstream": "none",
        "action": {"role": "example_service", "vars": {"example_service_listen_port": 9090}},
    }
    doc = copy.deepcopy(doc)
    for k, v in over.items():
        if v is None:
            doc.pop(k, None)
        else:
            doc[k] = v
    return doc


def write_custom(directory: Path, name: str, doc: dict, files: dict[str, str] | None = None):
    d = directory / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "customization.json").write_text(json.dumps(doc))
    for rel, text in (files or {}).items():
        (d / rel).parent.mkdir(parents=True, exist_ok=True)
        (d / rel).write_text(text)
    return d / "customization.json"


def load_one(directory: Path):
    items, problems = load_tree(directory, "local")
    assert not problems, problems
    return items
