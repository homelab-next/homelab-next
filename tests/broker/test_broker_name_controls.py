# SPDX-License-Identifier: Apache-2.0
"""A manifest name holding a control character is refused by ``validate_manifest``.

Python's ``$`` also matches before a trailing newline; the shared ``ids/`` patterns now end in
``$(?!\\n)``, so the manifest schema refuses ``profile:reader\\n`` too.  The broker's own refusal
after the schema stays (a pattern in another schema may still lack the guard), and it never
repeats the value in the problem.
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
    named = dict(manifest, grants=[dict(g) for g in manifest["grants"]])
    named["grants"][1]["profile"] = "profile:reader\n"
    named["manifest_id"] = "example-lab-broker\n"
    # an id or slug from ids/ carries the newline guard: the schema itself refuses both
    refused = schema_errors("broker", "manifest", named)
    assert [e.split(":", 1)[0] for e in refused] == ["grants/1/profile", "manifest_id"]
    assert not any("reader\n" in p for p in validate_manifest(named, EXAMPLE)[1])
    # a name whose pattern has no guard yet (a grant's action) passes the schema: the broker
    # refuses it after the schema
    manifest["grants"][1]["actions"] = [manifest["grants"][1]["actions"][0] + "\n"]
    assert schema_errors("broker", "manifest", manifest) == []
    _, problems = validate_manifest(manifest, EXAMPLE)
    assert "manifest: grants[1].actions holds a control character" in problems
    assert not any("status\n" in p for p in problems)  # the value is never repeated
    # and a handler document's action
    shutil.copytree(EXAMPLE, tmp_path / "broker")
    path = tmp_path / "broker" / "handlers" / "service-status.handler.json"
    doc = json.loads(path.read_text())
    path.write_text(json.dumps(dict(doc, action="service.status\n")))
    manifest, _ = load_manifest(EXAMPLE / "manifest.yml")
    _, problems = validate_manifest(manifest, tmp_path / "broker")
    assert any("service-status.handler.json: handler: action holds" in p for p in problems)
    assert validate_manifest(load_manifest(EXAMPLE / "manifest.yml")[0], EXAMPLE)[1] == []
