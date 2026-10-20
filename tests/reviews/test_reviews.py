# SPDX-License-Identifier: Apache-2.0
"""The shared review model: identity rules, policy, digest staleness, the digest command."""

import copy
import pathlib

import pytest
import yaml

from homelabnext import reviews
from homelabnext.reviews import ReviewError, evaluate, load_policy, policy_from

REPO = pathlib.Path(__file__).resolve().parents[2]
POLICY = REPO / "examples" / "review-policy.yml"
DIGEST = "sha256:" + "ab" * 32


@pytest.fixture
def policy_data():
    return yaml.safe_load(POLICY.read_text())


@pytest.fixture
def policy(policy_data):
    return policy_from(policy_data)


def rv(by, kind, role, digest=DIGEST[:19], verdict="pass"):
    return {
        "by": by,
        "kind": kind,
        "role": role,
        "date": "2026-10-19",
        "verdict": verdict,
        "digest": digest,
    }


CHECK = rv("agent:example-checker", "agent", "check")
ADV = rv("agent:example-challenger", "agent", "challenge")
APPROVE = rv("human:example-operator", "human", "approve")


def ev(rs, policy, state="retired", artefact="lesson.pitfall", author="unknown", digest=DIGEST):
    return evaluate(
        rs, author=author, digest=digest, artefact=artefact, state=state, policy=policy, who="X"
    )


def test_the_example_policy_validates():
    p = load_policy(POLICY)
    assert [q.label() for q in p.required("lesson.pitfall", "retired")] == [
        "agent check",
        "agent challenge",
        "human approve",
    ]
    assert p.required("lesson.pitfall", "open") == ()


def test_a_complete_set_passes_and_derives_last_reviewed(policy):
    e = ev([CHECK, ADV, APPROVE], policy)
    assert e.problems == [] and e.missing == []
    assert str(e.last_reviewed) == "2026-10-19"


@pytest.mark.parametrize(
    "author, by",
    [
        ("agent:example-checker", "agent:example-checker"),
        ("agent:Example_Checker", "agent:example.checker"),
    ],
)
def test_self_review_fails_in_any_spelling(policy, author, by):
    e = ev([rv(by, "agent", "check"), ADV, APPROVE], policy, author=author)
    assert any("is the author" in p for p in e.problems)


def test_challenge_by_the_check_agent_fails_and_does_not_count(policy):
    e = ev([CHECK, rv("agent:Example-Checker", "agent", "challenge"), APPROVE], policy)
    assert any("must be a different agent" in p for p in e.problems)
    assert "agent challenge" in e.missing


def test_agent_identity_in_a_human_slot_fails(policy):
    e = ev([CHECK, ADV, rv("agent:example-challenger", "human", "approve")], policy)
    assert any("agent identity in a human review" in p for p in e.problems)
    # the broker's other agent signal: an allowlist entry of kind agent, whatever the issuer
    data = {
        **policy_data_copy(),
        "reviewers": [{"issuer": "ops", "subject": "bot", "kind": "agent"}],
    }
    e = ev([rv("ops:bot", "human", "approve")], policy_from(data))
    assert any("agent identity in a human review" in p for p in e.problems)


def policy_data_copy():
    return yaml.safe_load(POLICY.read_text())


def test_a_human_review_needs_an_allowlisted_human(policy):
    e = ev([CHECK, ADV, rv("human:somebody-else", "human", "approve")], policy)
    assert any("not a `kind: human` reviewer" in p for p in e.problems)
    assert "human approve" in e.missing


def test_retire_without_a_human_approve_fails(policy):
    assert ev([CHECK, ADV], policy).missing == ["human approve"]


def test_a_review_of_an_earlier_content_is_ignored(policy):
    old = [rv(r["by"], r["kind"], r["role"], digest="sha256:" + "cd" * 6) for r in (CHECK, ADV)]
    e = ev([*old, APPROVE], policy)
    assert len(e.stale) == 2 and e.missing == ["agent check", "agent challenge"]


def test_only_a_passing_verdict_counts(policy):
    e = ev([CHECK, {**ADV, "verdict": "reject"}, APPROVE], policy)
    assert e.missing == ["agent challenge"]


@pytest.mark.parametrize(
    "bad, needle",
    [
        ({"by": "nobody"}, "issuer-qualified"),
        ({"role": "rubber-stamp"}, "`role`"),
        ({"verdict": "lgtm"}, "`verdict`"),
        ({"digest": "md5:abc"}, "`digest`"),
        ({"date": "soon"}, "`date`"),
        ({"extra": 1}, "unknown field"),
    ],
)
def test_malformed_review_entries_fail(policy, bad, needle):
    e = ev([{**CHECK, **bad}], policy)
    assert any(needle in p for p in e.problems), e.problems


def test_author_is_required():
    e = evaluate([], author=None, digest=DIGEST, artefact="runbook", state="active")
    assert any("`author` is required" in p for p in e.problems)


def test_a_policy_change_changes_what_is_required(policy_data):
    data = copy.deepcopy(policy_data)
    data["requirements"]["lesson.pitfall"]["retired"] = [
        {"role": "approve", "kind": "human", "min": 2}
    ]
    p = policy_from(data)
    assert ev([CHECK, ADV, APPROVE], p).missing == ["human approve x2"]
    data["requirements"]["lesson.pitfall"]["retired"] = []
    assert ev([], policy_from(data)).missing == []


def test_min_counts_distinct_reviewers_not_reviews(policy_data):
    data = copy.deepcopy(policy_data)
    data["requirements"]["lesson.pitfall"]["controlled"] = [
        {"role": "check", "kind": "agent", "min": 2}
    ]
    p = policy_from(data)
    twice = [
        rv("agent:example-checker", "agent", "check"),
        rv("agent:Example_Checker", "agent", "check"),
    ]
    assert ev(twice, p, state="controlled").missing == ["agent check x2"]
    two = [rv("agent:example-checker", "agent", "check"), rv("agent:fake-second", "agent", "check")]
    assert ev(two, p, state="controlled").missing == []


@pytest.mark.parametrize(
    "mutate, needle",
    [
        (lambda d: d.pop("version"), "`version` must be 1"),
        (lambda d: d["requirements"]["lesson.pitfall"].pop("retired"), "retired: missing"),
        (lambda d: d["requirements"]["runbook"].update(draft=[]), "unknown state 'draft'"),
        (lambda d: d["requirements"].update(kanban={}), "unknown artefact kind"),
        (
            lambda d: d["requirements"]["runbook"]["active"].append(
                {"role": "vibe", "kind": "agent"}
            ),
            "`role`",
        ),
        (
            lambda d: d["requirements"]["runbook"]["active"].append(
                {"role": "check", "kind": "agent", "min": 0}
            ),
            "`min`",
        ),
        (
            lambda d: d["reviewers"].append({"issuer": "agent", "subject": "x", "kind": "human"}),
            "cannot be kind human",
        ),
        (lambda d: d["reviewers"].append(dict(d["reviewers"][0])), "listed twice"),
    ],
)
def test_bad_policies_fail(policy_data, mutate, needle, tmp_path):
    mutate(policy_data)
    f = tmp_path / "p.yml"
    f.write_text(yaml.safe_dump(policy_data))
    with pytest.raises(ReviewError) as ex:
        load_policy(f)
    assert any(needle in p for p in ex.value.problems), ex.value.problems


def test_digest_command_is_stable(capsys):
    files = [str(REPO / "examples/registers/lessons/LL-002.md"), str(REPO / "docs/systems/dns.md")]
    assert reviews.main(["digest", *files]) == 0
    first = capsys.readouterr().out
    assert reviews.main(["digest", *files]) == 0
    assert capsys.readouterr().out == first
    lines = first.splitlines()
    assert len(lines) == 2 and all(
        ln.startswith("sha256:") and len(ln.split()[0]) == 71 for ln in lines
    )
    # the committed example review was stamped with this very digest
    events = sorted((REPO / "examples/registers/lessons/LL-002.events").glob("*-review-*.yml"))
    stamped = yaml.safe_load(events[0].read_text())["digest"]
    assert lines[0].startswith(stamped)
