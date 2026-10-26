# SPDX-License-Identifier: Apache-2.0
"""A manifest name holding a control character is refused by ``validate_manifest``.

The schemas' patterns end in ``$``, which ``re.search`` also matches before a trailing newline,
so ``profile:reader\\n`` passes the manifest schema; the broker refuses it after the schema, and
never repeats the value in the problem.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from homelabnext.agent.schemas import schema_errors
from homelabnext.broker.service import load_manifest, validate_manifest

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "examples" / "broker"


def test_the_broker_refuses_a_name_with_a_control_character(tmp_path):
    manifest, _ = load_manifest(EXAMPLE / "manifest.yml")
    manifest["grants"][1]["profile"] = "profile:reader\n"
    manifest["manifest_id"] = "example-lab-broker\n"
    assert schema_errors("broker", "manifest", manifest) == []  # the schema lets both through
    _, problems = validate_manifest(manifest, EXAMPLE)
    assert "manifest: grants[1].profile holds a control character" in problems
    assert "manifest: manifest_id holds a control character" in problems
    assert not any("reader\n" in p for p in problems)  # the value is never repeated
    # and a handler document's action
    shutil.copytree(EXAMPLE, tmp_path / "broker")
    path = tmp_path / "broker" / "handlers" / "service-status.handler.json"
    doc = json.loads(path.read_text())
    path.write_text(json.dumps(dict(doc, action="service.status\n")))
    manifest, _ = load_manifest(EXAMPLE / "manifest.yml")
    _, problems = validate_manifest(manifest, tmp_path / "broker")
    assert any("service-status.handler.json: handler: action holds" in p for p in problems)
    assert validate_manifest(load_manifest(EXAMPLE / "manifest.yml")[0], EXAMPLE)[1] == []
