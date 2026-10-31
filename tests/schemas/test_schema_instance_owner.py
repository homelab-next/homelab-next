# SPDX-License-Identifier: Apache-2.0
"""Which schema an example or negative belongs to: a label may hold dots, the longest sibling
stem wins, and a file no schema owns is an error rather than a file nobody validates."""

import json
import shutil
from pathlib import Path

import schema_check as sc

ROOT = Path(__file__).resolve().parents[2]


def test_a_label_with_a_dot_belongs_to_its_schema():
    assert sc.instance_owner("customization.full.maintained.json", ["customization"]) == (
        "customization"
    )
    found = sc.instances_for(ROOT / "schemas/platform/customization.schema.json", "examples")
    assert ROOT / "schemas/platform/examples/customization.full.maintained.json" in found


def test_the_longest_stem_owns_a_file_when_stems_nest():
    stems = ["agent.job", "agent.job.failed"]
    assert sc.instance_owner("agent.job.failed.auto-retried.json", stems) == "agent.job.failed"
    assert sc.instance_owner("agent.job.started.json", stems) == "agent.job"
    assert sc.instance_owner("agent.job.json", stems) is None  # no label


def test_no_file_in_the_repository_is_owned_by_no_schema():
    assert sc.orphan_instances(ROOT) == []


def test_a_dotted_negative_the_schema_accepts_is_reported(tmp_path):
    """The defect: a negative named ``<stem>.<a>.<b>.json`` was skipped, so a schema could lose
    the rejection it pinned with every check green."""
    shutil.copytree(ROOT / "schemas", tmp_path / "schemas")
    good = tmp_path / "schemas/platform/examples/customization.full.maintained.json"
    neg = tmp_path / "schemas/platform/negative/customization.still.accepted.json"
    neg.write_text(good.read_text())
    probs = sc.check_repo(tmp_path, ["platform"], only=["platform/customization.schema.json"])
    assert any(
        p.where.endswith("customization.still.accepted.json") and "ACCEPTED" in p.message
        for p in probs
    )


def test_a_file_no_schema_owns_is_an_error(tmp_path):
    shutil.copytree(ROOT / "schemas", tmp_path / "schemas")
    (tmp_path / "schemas/platform/examples/nosuchschema.case.json").write_text(json.dumps({}))
    (tmp_path / "schemas/platform/negative/guest.case.txt").write_text("x")
    where = {p.where for p in sc.orphan_instances(tmp_path)}
    assert where == {
        "schemas/platform/examples/nosuchschema.case.json",
        "schemas/platform/negative/guest.case.txt",
    }
