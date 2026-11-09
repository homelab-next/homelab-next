# SPDX-License-Identifier: Apache-2.0
"""The agent-runner contract's drafts (schemas/runner, ADR-0051): every example validates and
every negative is refused for the reason its name states, not merely refused."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import schema_check as sc

ROOT = Path(__file__).resolve().parents[2]
DIR = ROOT / "schemas" / "runner"
REGISTRY = sc.build_registry(ROOT)
SCHEMAS = sorted(DIR.glob("*.schema.json"))

#: negative file stem -> (JSON path of the error, a fragment of its message)
WHY = {
    "session.key-value": ("$", "'gateway_key' was unexpected"),
    "session.engine-url": ("target", "'engine_url' was unexpected"),
    "session.inline-prompt": ("prompt", "is not of type 'object'"),
    "session.server-command": ("servers/0", "is not of type 'string'"),
    "session.unknown-key": ("$", "'home' was unexpected"),
    "session.credential-value": ("credentials/gateway_key", "'gateway-key' was expected"),
    "session.zero-trace": ("trace", "does not match"),
    "usage_record.call-carries-prompt": ("$", "'prompt' was unexpected"),
    "usage_record.unsized-with-tokens": ("$", "'input_tokens' was unexpected"),
    "usage_record.tool-call-carries-arguments": ("$", "'arguments' was unexpected"),
    "usage_record.unknown-type": ("type", "is not one of"),
    "usage_record.end-with-unknown-class": ("class", "is not one of"),
    "usage_record.answer-in-end": ("$", "'answer' was unexpected"),
    "usage_record.call-sized-is-a-string": ("sized", "is not of type 'boolean'"),
    "usage_record.call-sized-is-null": ("sized", "is not of type 'boolean'"),
    "usage_record.call-sized-is-a-number": ("sized", "is not of type 'boolean'"),
    "grants.stdio-without-command": ("servers/notes", "'command' is a required property"),
    "grants.http-with-command": ("servers/lake", "should not be valid"),
    "grants.unknown-transport": ("servers/lake/transport", "is not one of"),
    "grants.relative-command": ("servers/notes/command", "does not match"),
    "grants.no-profile-digest": ("$", "'profile_digest' is a required property"),
    "grants.unknown-key": ("$", "'secret' was unexpected"),
    "grants.environment-sets-the-loader": ("servers/notes/env", "should not be valid"),
}


def _validator(stem: str):
    from jsonschema import Draft202012Validator

    schema = json.loads((DIR / f"{stem}.schema.json").read_text())
    return Draft202012Validator(schema, registry=REGISTRY)


@pytest.mark.parametrize("schema", SCHEMAS, ids=lambda p: p.name)
def test_every_example_validates(schema):
    stem = schema.name.removesuffix(".schema.json")
    examples = sorted((DIR / "examples").glob(f"{stem}.*.json"))
    assert examples
    for ex in examples:
        assert list(_validator(stem).iter_errors(json.loads(ex.read_text()))) == [], ex.name


@pytest.mark.parametrize("name", sorted(WHY))
def test_each_negative_is_refused_for_its_reason(name):
    stem = name.split(".", 1)[0]
    errors = list(
        _validator(stem).iter_errors(json.loads((DIR / "negative" / f"{name}.json").read_text()))
    )
    path, fragment = WHY[name]
    hits = [e for e in errors if ("/".join(map(str, e.absolute_path)) or "$") == path]
    assert any(fragment in e.message for e in hits), [
        ("/".join(map(str, e.absolute_path)) or "$", e.message[:120]) for e in errors
    ]


def test_every_negative_has_its_reason():
    assert {p.name.removesuffix(".json") for p in (DIR / "negative").glob("*.json")} == set(WHY)


def test_the_drafts_name_their_adr():
    for schema in SCHEMAS:
        assert "ADR-0051" in json.loads(schema.read_text())["x-draft"], schema.name


@pytest.mark.parametrize(
    "name", ["call-sized-is-a-string", "call-sized-is-null", "call-sized-is-a-number"]
)
def test_the_launcher_refuses_a_call_record_that_is_neither_sized_nor_unsized(name):
    """A call whose ``sized`` is not exactly true or false matched no closed shape and took any
    key, a prompt or model text included; the launcher's stream reader refuses it."""
    from conformance.fakes.agent_runner_launcher import parse_stream

    line = (DIR / "negative" / f"usage_record.{name}.json").read_text().replace("\n", "")
    records, why = parse_stream(line.encode() + b"\n")
    assert records == [] and "not a usage record" in why, (records, why)


def test_the_grants_env_deny_list_is_the_catalogs():
    """A stdio server's env in the grants file refuses exactly what the MCP catalog refuses."""
    from homelabnext.mcp.servers import DENIED_ENV

    schema = json.loads((DIR / "grants.schema.json").read_text())
    env = schema["properties"]["servers"]["additionalProperties"]["properties"]["env"]
    assert env["propertyNames"]["not"]["pattern"] == f"^(?:{DENIED_ENV.pattern})$"
