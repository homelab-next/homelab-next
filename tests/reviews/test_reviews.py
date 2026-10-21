# SPDX-License-Identifier: Apache-2.0
"""The shared review model: identity rules, policy, digest staleness, the digest command."""

import copy
import pathlib
import re

import pytest
import yaml

from homelabnext import reviews
from homelabnext.identity.aliases import load_aliases
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
AUDIT = rv("agent:example-auditor", "agent", "audit")
APPROVE = rv("human:example-operator", "human", "approve")


def ev(rs, policy, state="retired", artefact="lesson.pitfall", author="unknown", digest=DIGEST):
    return evaluate(
        rs, author=author, digest=digest, artefact=artefact, state=state, policy=policy, who="X"
    )


def test_the_example_policy_validates():
    p = load_policy(POLICY)
    assert [q.label() for q in p.required("lesson.pitfall", "retired")] == [
        "agent check",
        "agent audit",
        "human approve",
    ]
    assert p.required("lesson.pitfall", "open") == ()


def test_a_complete_set_passes_and_derives_last_reviewed(policy):
    e = ev([CHECK, AUDIT, APPROVE], policy)
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
    e = ev([rv(by, "agent", "check"), AUDIT, APPROVE], policy, author=author)
    assert any("is the author" in p for p in e.problems)


def test_audit_by_the_check_agent_fails_and_does_not_count(policy):
    e = ev([CHECK, rv("agent:Example-Checker", "agent", "audit"), APPROVE], policy)
    assert any("must be a different agent" in p for p in e.problems)
    assert "agent audit" in e.missing


def test_agent_identity_in_a_human_slot_fails(policy):
    e = ev([CHECK, AUDIT, rv("agent:example-auditor", "human", "approve")], policy)
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
    e = ev([CHECK, AUDIT, rv("human:somebody-else", "human", "approve")], policy)
    assert any("not a `kind: human` reviewer" in p for p in e.problems)
    assert "human approve" in e.missing


def test_retire_without_a_human_approve_fails(policy):
    assert ev([CHECK, AUDIT], policy).missing == ["human approve"]


def test_a_review_of_an_earlier_content_is_ignored(policy):
    old = [rv(r["by"], r["kind"], r["role"], digest="sha256:" + "cd" * 6) for r in (CHECK, AUDIT)]
    e = ev([*old, APPROVE], policy)
    assert len(e.stale) == 2 and e.missing == ["agent check", "agent audit"]


def test_only_a_passing_verdict_counts(policy):
    e = ev([CHECK, {**AUDIT, "verdict": "reject"}, APPROVE], policy)
    assert e.missing == ["agent audit"]


# ----- `challenge`: the deprecated spelling of `audit` (read, warned about, never written) -----


def test_normalize_role_maps_the_deprecated_alias_with_a_warning():
    with pytest.warns(
        reviews.DeprecatedReviewRole, match="'challenge' is deprecated; write 'audit'"
    ):
        assert reviews.normalize_role("challenge", "X") == "audit"


@pytest.mark.parametrize("role", ["check", "audit", "approve", "rubber-stamp", None])
def test_normalize_role_leaves_everything_else_alone(recwarn, role):
    assert reviews.normalize_role(role) == role
    assert not [w for w in recwarn if issubclass(w.category, reviews.DeprecatedReviewRole)]


def test_a_challenge_review_counts_as_an_audit_and_warns(policy):
    with pytest.warns(reviews.DeprecatedReviewRole):
        e = ev([CHECK, {**AUDIT, "role": "challenge"}, APPROVE], policy)
    assert e.problems == [] and e.missing == []
    assert [r["role"] for r in e.current] == ["check", "audit", "approve"]


def test_a_challenge_review_by_the_checker_still_fails_independence(policy):
    with pytest.warns(reviews.DeprecatedReviewRole):
        e = ev([CHECK, rv("agent:example-checker", "agent", "challenge"), APPROVE], policy)
    assert any("must be a different agent" in p for p in e.problems)
    assert "agent audit" in e.missing


def test_a_policy_that_still_says_challenge_loads_as_audit_and_warns(policy_data):
    data = copy.deepcopy(policy_data)
    data["requirements"]["lesson.pitfall"]["retired"][1]["role"] = "challenge"
    with pytest.warns(reviews.DeprecatedReviewRole, match="lesson.pitfall.retired #2"):
        p = policy_from(data)
    assert [q.label() for q in p.required("lesson.pitfall", "retired")][1] == "agent audit"


def test_a_challenge_event_is_still_schema_valid():
    from homelabnext.registers.events import check_event

    old = {"event": "review", **rv("agent:example-auditor", "agent", "challenge")}
    assert check_event(old) == []
    assert check_event({**old, "role": "audit"}) == []


# No file in examples/ or docs/ uses the old name.  Allowed: a line documenting the deprecated
# alias, and ACME's own protocol term (a "DNS challenge" in a lesson about certificate renewal).
_OLD_NAME = re.compile(r"challeng", re.I)
_ALLOWED = re.compile(r"deprecated|DNS challenge", re.I)


def old_name_hits(rel: str, text: str) -> list[str]:
    hits = [rel] if _OLD_NAME.search(rel) else []
    return hits + [
        f"{rel}:{n}: {ln.strip()}"
        for n, ln in enumerate(text.splitlines(), 1)
        if _OLD_NAME.search(ln) and not _ALLOWED.search(ln)
    ]


def test_the_old_name_scan_flags_the_role_the_reviewer_and_the_file_name():
    assert old_name_hits("x.yml", "role: challenge\n") == ["x.yml:1: role: challenge"]
    assert old_name_hits("x.yml", "by: agent:example-challenger") != []
    assert old_name_hits("a-review-agent-example-challenger.yml", "") != []
    assert old_name_hits("x.md", "`challenge` is the deprecated spelling of `audit`") == []
    assert old_name_hits("x.md", "role: audit\n") == []


def test_examples_and_docs_no_longer_say_challenge():
    hits = []
    for base in ("examples", "docs"):
        for f in sorted((REPO / base).rglob("*")):
            rel = f.relative_to(REPO).as_posix()
            if not f.is_file() or rel.startswith("docs/graph/"):  # docs/graph/: a local build
                continue
            try:
                text = f.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                text = ""
            hits += old_name_hits(rel, text)
    assert hits == [], "say audit, not challenge:\n" + "\n".join(hits)


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
    assert ev([CHECK, AUDIT, APPROVE], p).missing == ["human approve x2"]
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
    ll2 = load_aliases(REPO / "examples/registers").codes["LL-002"]
    files = [str(REPO / f"examples/registers/lessons/{ll2}.md"), str(REPO / "docs/systems/dns.md")]
    assert reviews.main(["digest", *files]) == 0
    first = capsys.readouterr().out
    assert reviews.main(["digest", *files]) == 0
    assert capsys.readouterr().out == first
    lines = first.splitlines()
    assert len(lines) == 2 and all(
        ln.startswith("sha256:") and len(ln.split()[0]) == 71 for ln in lines
    )
    # the latest committed example review was stamped with this very digest
    events = sorted((REPO / f"examples/registers/lessons/{ll2}.events").glob("*-review-*.yml"))
    stamped = yaml.safe_load(events[-1].read_text())["digest"]
    assert lines[0].startswith(stamped)
