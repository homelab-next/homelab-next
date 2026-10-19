# SPDX-License-Identifier: Apache-2.0
"""Every owned schema: valid 2020-12, >=1 example accepted, >=1 negative rejected."""

import json
from pathlib import Path

import pytest
import schema_check as sc

ROOT = Path(__file__).resolve().parents[2]
OWNED_DIRS = ["ids", "events", "records", "registers", "platform", "ocsf"]
EXCLUDED = {"platform/service.json"}  # owned by the registry task
REGISTRY = sc.build_registry(ROOT)
SCHEMAS = [
    p
    for p in sc.schema_files(ROOT, OWNED_DIRS)
    if p.relative_to(ROOT / "schemas").as_posix() not in EXCLUDED
]
IDS = [p.relative_to(ROOT / "schemas").as_posix() for p in SCHEMAS]

EXPECTED = {
    "ids/logical-id.schema.json",
    "ids/common.schema.json",
    "events/envelope.schema.json",
    "events/alert.created.schema.json",
    "events/case.opened.schema.json",
    "events/proposal.created.schema.json",
    "events/proposal.decided.schema.json",
    "events/task.queued.schema.json",
    "events/decision.requested.schema.json",
    "events/decision.returned.schema.json",
    "events/swap.step.schema.json",
    "events/scope.denied.schema.json",
    "events/deploy.changed.schema.json",
    "records/note.schema.json",
    "registers/lesson.schema.json",
    "registers/runbook.schema.json",
    "registers/invariant.schema.json",
    "registers/kanban_item.schema.json",
    "registers/decision_spec.json",
    "platform/model_roles.json",
    "platform/capability.schema.json",
    "platform/guest.schema.json",
    "platform/role_interface.schema.json",
    "platform/agent_profile.schema.json",
    "platform/broker_action.schema.json",
    "platform/site.schema.json",
    "platform/customization.schema.json",
    "platform/swap_record.schema.json",
    "ocsf/authentication.v1.json",
    "ocsf/detection_finding.v1.json",
    "ocsf/dns_activity.v1.json",
    "ocsf/network_activity.v1.json",
    "ocsf/vulnerability_finding.v1.json",
}


def test_expected_schema_set_is_present():
    assert set(IDS) == EXPECTED


def test_readme_per_schema_dir():
    for d in OWNED_DIRS:
        assert (ROOT / "schemas" / d / "README.md").is_file(), d


@pytest.mark.parametrize("path", SCHEMAS, ids=IDS)
def test_schema_has_examples_and_negatives_and_they_behave(path):
    schema = json.loads(path.read_text())
    problems = sc.check_schema(ROOT, path, REGISTRY, strict=True)
    assert problems == [], "\n".join(map(str, problems))
    exs, negs = sc.instances_for(path, "examples"), sc.instances_for(path, "negative")
    if not schema.get("x-defs-only"):
        assert exs and negs


@pytest.mark.parametrize("path", SCHEMAS, ids=IDS)
def test_id_convention(path):
    schema = json.loads(path.read_text())
    name, major, minor = sc.parse_id(schema)
    d = path.parent.name
    assert name.startswith(d + "/")
    # minor bumps are additive (see _frozen), so any minor of major 1 is allowed
    assert major == 1
    assert minor >= 0


def test_event_schemas_cover_reaction_seam_types():
    types = {
        json.loads(p.read_text())["allOf"][1]["properties"]["type"]["const"]
        for p in SCHEMAS
        if p.parent.name == "events" and p.stem != "envelope.schema"
    }
    assert types == {
        "homelabnext." + t
        for t in (
            "alert.created",
            "case.opened",
            "proposal.created",
            "proposal.decided",
            "task.queued",
            "decision.requested",
            "decision.returned",
            "swap.step",
            "scope.denied",
            "deploy.changed",
        )
    }


def test_event_examples_use_documentation_ips_only():
    assert [p for p in sc.check_repo(ROOT, ["events"], strict=True) if "lint" in p.message] == []


def test_envelope_example_of_each_type_is_accepted_by_envelope_too():
    env = json.loads((ROOT / "schemas/events/envelope.schema.json").read_text())
    for f in (ROOT / "schemas/events/examples").glob("*.valid.json"):
        assert sc.errors_for(env, json.loads(f.read_text()), REGISTRY) == [], f.name


def test_a_negative_that_is_accepted_would_be_reported(tmp_path):
    """The checker itself: copy one schema, plant a negative the schema accepts."""
    import shutil

    shutil.copytree(ROOT / "schemas", tmp_path / "schemas")
    (tmp_path / "schemas/registers/negative/lesson.planted.json").write_text(
        (tmp_path / "schemas/registers/examples/lesson.open-new-id.json").read_text()
    )
    probs = sc.check_repo(tmp_path, ["registers"])
    assert any("ACCEPTED" in p.message for p in probs)


def test_missing_example_is_reported(tmp_path):
    import shutil

    shutil.copytree(ROOT / "schemas", tmp_path / "schemas")
    for f in (tmp_path / "schemas/registers/examples").glob("runbook.*"):
        f.unlink()
    assert any("no example" in p.message for p in sc.check_repo(tmp_path, ["registers"]))


def test_lint_catches_product_locator_in_example(tmp_path):
    import shutil

    shutil.copytree(ROOT / "schemas", tmp_path / "schemas")
    f = tmp_path / "schemas/platform/examples/capability.valid.json"
    d = json.loads(f.read_text())
    d["summary"] = "reads viking://resources/x and " + ".".join(["10", "1", "2", "3"])
    f.write_text(json.dumps(d))
    msgs = [p.message for p in sc.check_repo(tmp_path, ["platform"])]
    assert any("PRODUCT_URI" in m for m in msgs) and any("IP_LITERAL" in m for m in msgs)
