# SPDX-License-Identifier: Apache-2.0
"""schemas/agent and schemas/broker: registered with the schema check, examples accepted,
negatives rejected, and the existing golden suite format still validates."""

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import schema_check as sc

from homelabnext.golden.tasks import parse_suite

DIRS = ["agent", "broker"]
REGISTRY = sc.build_registry(ROOT)
SCHEMAS = sc.schema_files(ROOT, DIRS)
IDS = [p.relative_to(ROOT / "schemas").as_posix() for p in SCHEMAS]


def test_expected_schema_set():
    assert set(IDS) == {
        *(
            f"agent/{n}.schema.json"
            for n in (
                "profile",
                "report_result",
                "context_manifest",
                "pregate_output",
                "golden_task",
            )
        ),
        *(
            f"broker/{n}.schema.json"
            for n in ("request", "decision", "handler", "manifest", "approval")
        ),
    }


@pytest.mark.parametrize("d", DIRS)
def test_readme_per_dir(d):
    assert (ROOT / "schemas" / d / "README.md").is_file()


@pytest.mark.parametrize("path", SCHEMAS, ids=IDS)
def test_schema_contract(path):
    problems = sc.check_schema(ROOT, path, REGISTRY, strict=True)
    assert problems == [], "\n".join(map(str, problems))
    assert len(sc.instances_for(path, "examples")) >= 1
    assert len(sc.instances_for(path, "negative")) >= 3, "each schema needs several negatives"
    name, major, _ = sc.parse_id(json.loads(path.read_text()))
    assert name == f"{path.parent.name}/{sc.stem_of(path)}" and major == 1


@pytest.mark.parametrize("path", SCHEMAS, ids=IDS)
def test_every_negative_fails_for_a_reason_of_its_own(path):
    """A negative must be rejected by the schema, not merely differ from the example."""
    schema = json.loads(path.read_text())
    for neg in sc.instances_for(path, "negative"):
        assert sc.errors_for(schema, sc.load_instance(neg), REGISTRY), neg.name


def test_check_repo_clean_for_new_dirs():
    assert sc.check_repo(ROOT, DIRS, strict=True) == []


def test_existing_golden_suite_format_unchanged_and_valid():
    path = ROOT / "homelabnext" / "golden" / "examples" / "classifier_smoke.yml"
    doc = sc.load_instance(path)
    schema = json.loads((ROOT / "schemas/agent/golden_task.schema.json").read_text())
    assert sc.errors_for(schema, doc, REGISTRY) == []
    assert parse_suite(doc).name == "classifier-smoke"  # the real loader agrees


def test_golden_schema_and_loader_agree_on_rejects():
    schema = json.loads((ROOT / "schemas/agent/golden_task.schema.json").read_text())
    for neg in sc.instances_for(ROOT / "schemas/agent/golden_task.schema.json", "negative"):
        doc = sc.load_instance(neg)
        if neg.name.startswith("golden_task.task-id-uppercase"):
            continue  # loader and schema both reject; covered below
        assert sc.errors_for(schema, doc, REGISTRY), neg.name
    from homelabnext.golden.tasks import TaskError

    for neg in sc.instances_for(ROOT / "schemas/agent/golden_task.schema.json", "negative"):
        with pytest.raises(TaskError):
            parse_suite(sc.load_instance(neg))


def test_examples_have_no_lab_identifiers():
    """Generic shapes from the leak scanner, plus the run-time deny-list when HNX_DENYLIST is set."""
    import os

    import leak_scan

    deny = leak_scan.load_denylist(os.environ.get("HNX_DENYLIST"))
    for d in DIRS:
        for f in (ROOT / "schemas" / d).rglob("*"):
            if f.is_file() and f.suffix in {".json", ".yml", ".md"}:
                hits = leak_scan.scan_text(f.read_text(), str(f), leak_scan.PATTERNS, deny)
                assert hits == [], hits
