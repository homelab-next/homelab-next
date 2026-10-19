# SPDX-License-Identifier: Apache-2.0
"""``hnx decide lint`` (K-02, K-03, K-04): every rule fails its fixture, the repo's specs pass."""

import shutil
import subprocess
from pathlib import Path

import pytest

from homelabnext.decide import parse_spec
from homelabnext.decide.cli import main
from homelabnext.decide.lint import MAX_LABELS, lint_doc, lint_paths, load

ROOT = Path(__file__).resolve().parents[2]
FIX = Path(__file__).parent / "fixtures" / "spec_lint"

#: each failing fixture -> the one lint rule it exists to trip (``schema`` may also fire)
NEGATIVE = {
    "incomplete": "complete",
    "audit-sample-zero": "audit-sample",
    "compound-and": "single-axis",
    "compound-or": "single-axis",
    "two-questions": "single-axis",
    "asked-twice": "single-axis",
    "too-many-labels": "labels",
    "one-label": "labels",
    "pairwise-one-order": "pairwise",
    "pairwise-undeclared": "pairwise",
    "inline-large-tier": "inline",
    "inline-slow-budget": "inline",
    "inline-no-timeout": "inline",
}


def _rules(path: Path) -> set[str]:
    return {rule for rule, _ in lint_doc(load(path))}


def test_every_negative_fixture_is_listed():
    assert {p.stem for p in (FIX / "negative").glob("*.yml")} == set(NEGATIVE)


@pytest.mark.parametrize(("name", "rule"), sorted(NEGATIVE.items()))
def test_negative_fixture_fails_its_rule(name, rule):
    got = _rules(FIX / "negative" / f"{name}.yml")
    assert rule in got
    assert got <= {rule, "schema"}, f"{name} trips more than its own rule: {got}"


@pytest.mark.parametrize("path", sorted((FIX / "good").glob("*.yml")), ids=lambda p: p.stem)
def test_good_fixture_passes(path):
    assert lint_doc(load(path)) == []


def test_each_rule_has_a_failing_fixture():
    assert set(NEGATIVE.values()) == {
        "complete",
        "audit-sample",
        "single-axis",
        "labels",
        "pairwise",
        "inline",
    }
    assert MAX_LABELS == 5


def test_the_repository_specs_pass():
    if shutil.which("git") is None or not (ROOT / ".git").exists():
        pytest.skip("needs a git checkout")
    n, problems = lint_paths([], root=ROOT)
    assert problems == [], "\n".join(map(str, problems))
    assert n >= 5  # the decide example, two schema examples, the good fixtures


def test_schema_negatives_fail_the_lint():
    n, problems = lint_paths([ROOT / "schemas" / "registers" / "negative"])
    assert n >= 4
    assert len({p.path for p in problems}) == n


def test_untracked_spec_fails_in_git(tmp_path):
    if shutil.which("git") is None:
        pytest.skip("needs git")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    shutil.copy(FIX / "good" / "batch-all-tiers.yml", tmp_path / "spec.yml")
    (tmp_path / "notes.yml").write_text("question_set: is mentioned, but this is no spec\n")
    n, problems = lint_paths([], root=tmp_path)
    assert n == 1
    assert [(p.path, p.rule) for p in problems] == [("spec.yml", "in-git")]
    subprocess.run(["git", "-C", str(tmp_path), "add", "spec.yml"], check=True)
    assert lint_paths([], root=tmp_path) == (1, [])


def test_frozen_and_negative_dirs_are_not_discovered(tmp_path):
    if shutil.which("git") is None:
        pytest.skip("needs git")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    for d in ("negative", "_frozen/1.0"):
        (tmp_path / d).mkdir(parents=True)
        shutil.copy(FIX / "negative" / "incomplete.yml", tmp_path / d / "spec.yml")
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    assert lint_paths([], root=tmp_path) == (0, [])


def test_cli_exit_codes(capsys):
    assert main(["lint", str(FIX / "good")]) == 0
    assert main(["lint", str(FIX / "negative" / "compound-and.yml")]) == 1
    assert "single-axis" in capsys.readouterr().out
    assert main(["lint", str(FIX / "nope.yml")]) == 2


def test_not_a_git_tree_cannot_be_measured(tmp_path, capsys, monkeypatch):
    if shutil.which("git") is None:
        pytest.skip("needs git")
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path.parent))
    assert main(["lint", "--root", str(tmp_path)]) == 100
    assert "cannot list" in capsys.readouterr().err


def test_single_axis_words_are_whole_words_only():
    doc = load(FIX / "good" / "batch-all-tiers.yml")
    doc["question_set"] = ["Does the Android build pin an orchestrator version?"]
    assert lint_doc(doc) == []
    doc["question_set"] = ["Is the host a server and/or a laptop?"]
    assert {r for r, _ in lint_doc(doc)} == {"single-axis"}


def test_pairwise_mirror_must_match_text_and_labels():
    doc = load(FIX / "good" / "inline-pairwise.yml")
    doc["question_set"][3]["labels"] = ["no", "yes"]
    assert "pairwise" in {r for r, _ in lint_doc(doc)}
    doc = load(FIX / "good" / "inline-pairwise.yml")
    doc["question_set"][3]["text"] = "Is {right} safer than {left}?"
    assert "pairwise" in {r for r, _ in lint_doc(doc)}


def test_question_objects_parse_to_texts_and_callers():
    spec = parse_spec(load(FIX / "good" / "inline-pairwise.yml"))
    assert spec.question_set[1] == "How severe is the alert?"
    assert spec.questions[2].compare == ("left", "right")
    assert spec.inline and spec.callers == ("inline", "batch")
    batch = parse_spec(load(FIX / "good" / "batch-all-tiers.yml"))
    assert not batch.inline
