# SPDX-License-Identifier: Apache-2.0
import copy
import random

import pytest
from agent_support import library, spec

from homelabnext.agent import (
    BudgetError,
    CeilingViolation,
    MissingPartError,
    SpecError,
    check_ceiling,
    compile_profile,
    digest_of,
    profile_digest,
    verify_profile,
)
from homelabnext.agent.schemas import schema_errors


def test_compiles_and_validates():
    p = compile_profile(spec(), library())
    assert schema_errors("agent", "profile", p) == []
    assert verify_profile(p) == []
    assert p["parts"]["skills"] == ["skill:summarise", "skill:triage"]  # sorted
    assert p["grants"] == {"mcp": ["lake"], "capabilities": ["cap:lake-query"], "tier": "read"}


def test_digest_is_deterministic_and_content_bound():
    a, b = compile_profile(spec(), library()), compile_profile(spec(), library())
    assert a == b and a["digest"] == b["digest"] == profile_digest(a)
    changed = spec()
    changed["budgets"]["max_tool_calls"] = 21
    assert compile_profile(changed, library())["digest"] != a["digest"]


def test_digest_changes_when_a_part_changes():
    from agent_support import PARTS

    other = dict(PARTS, **{"skill:triage": "Rank by blast radius."})
    assert (
        compile_profile(spec(), library(other))["digest"]
        != compile_profile(spec(), library())["digest"]
    )


def test_input_order_and_duplicates_do_not_matter():
    base = compile_profile(spec(), library())
    for seed in range(20):
        s = spec()
        rng = random.Random(seed)
        s["skills"] = rng.sample(s["skills"] * 2, 4)
        s["mcp"] = ["lake", "lake"]
        s["memory_scopes"] = ["analyst", "analyst"]
        s["ceiling"]["mcp"] = rng.sample(s["ceiling"]["mcp"], 2)
        items = list(s.items())
        rng.shuffle(items)
        assert compile_profile(dict(items), library())["digest"] == base["digest"]


def test_provenance_lists_every_part_and_the_spec():
    p = compile_profile(spec(), library())
    ids = [e["id"] for e in p["provenance"]]
    assert set(ids) == {
        "persona:analyst",
        "skill:summarise",
        "skill:triage",
        "cap:lake-query",
        "profile:reader",
    }
    part = next(e for e in p["provenance"] if e["id"] == "skill:triage")
    assert part["source"] == "fake-library"
    assert part["digest"].startswith("sha256:")
    assert next(e for e in p["provenance"] if e["id"] == "profile:reader")["source"] == "spec"


def test_missing_logical_id_is_rejected_with_every_missing_id_named():
    from agent_support import PARTS

    parts = {k: v for k, v in PARTS.items() if k not in ("skill:triage", "persona:analyst")}
    with pytest.raises(MissingPartError) as exc:
        compile_profile(spec(), library(parts))
    msg = str(exc.value)
    assert "skill:triage" in msg and "persona:analyst" in msg
    assert "parts library has no entry for" in msg
    assert exc.value.missing == ["persona:analyst", "skill:triage"]


def test_wrong_kind_and_bad_ids_are_spec_errors():
    s = spec()
    s["skills"] = ["cap:lake-query"]
    with pytest.raises(SpecError, match="expected skill:"):
        compile_profile(s, library())
    s = spec()
    s["persona"] = "persona:Not A Slug"
    with pytest.raises(SpecError):
        compile_profile(s, library())
    s = spec()
    del s["budgets"]
    with pytest.raises(SpecError, match="budgets"):
        compile_profile(s, library())


@pytest.mark.parametrize(
    "mutate, fragment",
    [
        (lambda s: s["mcp"].append("shell"), "mcp outside ceiling: ['shell']"),
        (lambda s: s["capabilities"].append("cap:records-propose-more"), "capabilities outside"),
        (lambda s: s.update(tier="execute"), "above the ceiling tier"),
        (lambda s: s.update(tier="root"), "tier must be one of"),
    ],
)
def test_ceiling_violation_rejected(mutate, fragment):
    s = spec()
    mutate(s)
    with pytest.raises(CeilingViolation) as exc:
        compile_profile(s, library_with_extra())
    assert fragment in str(exc.value)


def library_with_extra():
    from agent_support import PARTS

    return library(dict(PARTS, **{"cap:records-propose-more": "x"}))


def test_every_violation_is_reported_together():
    s = spec()
    s["mcp"].append("shell")
    s["tier"] = "execute"
    with pytest.raises(CeilingViolation) as exc:
        compile_profile(s, library())
    assert len(exc.value.problems) == 2


def test_budget_above_ceiling_budget_rejected():
    s = spec()
    s["budgets"]["max_runtime_s"] = 901
    with pytest.raises(BudgetError, match="max_runtime_s=901 exceeds the ceiling budget 900"):
        compile_profile(s, library())


@pytest.mark.parametrize("key", ["max_input_tokens", "max_output_tokens", "max_runtime_s"])
@pytest.mark.parametrize("bad", [0, -1, 1.5, True, "10"])
def test_malformed_budgets_rejected(key, bad):
    s = spec()
    s["budgets"][key] = bad
    with pytest.raises(BudgetError):
        compile_profile(s, library())


def test_zero_tool_calls_is_a_valid_budget():
    s = spec()
    s["budgets"]["max_tool_calls"] = 0
    assert compile_profile(s, library())["budgets"]["max_tool_calls"] == 0


def test_check_ceiling_property_subset_never_flagged():
    rng = random.Random(7)
    universe = [f"srv-{i}" for i in range(8)]
    for _ in range(200):
        ceiling = {
            "mcp": rng.sample(universe, rng.randint(0, 8)),
            "capabilities": [],
            "tier": "write",
        }
        grant = {
            "mcp": rng.sample(ceiling["mcp"], rng.randint(0, len(ceiling["mcp"]))),
            "capabilities": [],
            "tier": "read",
        }
        assert check_ceiling(grant, ceiling) == []
        extra = {"mcp": [*grant["mcp"], "outside"], "capabilities": [], "tier": "read"}
        assert check_ceiling(extra, ceiling)


def test_verify_profile_catches_tampering():
    p = compile_profile(spec(), library())
    t = copy.deepcopy(p)
    t["grants"]["mcp"].append("shell")
    assert any("outside ceiling" in x for x in verify_profile(t))
    t = copy.deepcopy(p)
    t["budgets"]["max_tool_calls"] = 999
    assert any("digest" in x for x in verify_profile(t))
    t = copy.deepcopy(p)
    t["digest"] = digest_of({"x": 1})
    assert any("digest" in x for x in verify_profile(t))
    t = copy.deepcopy(p)
    del t["provenance"]
    assert verify_profile(t)


# ---- ceilings from a separately owned policy (security review: a self-declared ceiling is no bound)
POLICY = {
    "ceilings": {
        "profile:reader": {
            "mcp": ["lake"],
            "capabilities": ["cap:lake-query"],
            "tier": "read",
            "budgets": {
                "max_input_tokens": 64000,
                "max_output_tokens": 4000,
                "max_runtime_s": 900,
                "max_tool_calls": 40,
            },
        }
    }
}


def _policy():
    from homelabnext.agent import CeilingPolicy

    return CeilingPolicy.from_mapping(copy.deepcopy(POLICY))


def test_spec_cannot_raise_its_own_ceiling_past_the_policy():
    s = spec()
    s["mcp"].append("records")  # within the spec's own ceiling, outside the policy
    compile_profile(s, library())  # self-declared ceiling: accepted
    with pytest.raises(CeilingViolation) as exc:
        compile_profile(s, library(), policy=_policy())
    assert any("mcp outside ceiling: ['records']" in p for p in exc.value.problems)


def test_policy_needs_an_entry_and_spec_ceiling_is_optional():
    s = spec()
    del s["ceiling"]
    s["ceiling"] = POLICY["ceilings"]["profile:reader"]
    p = compile_profile(s, library(), policy=_policy())
    assert verify_profile(p, policy=_policy()) == []
    del s["ceiling"]
    assert compile_profile(s, library(), policy=_policy())["ceiling"]["tier"] == "read"
    s["id"] = "profile:other"
    with pytest.raises(CeilingViolation, match="no ceiling for profile:other"):
        compile_profile(s, library(), policy=_policy())


def test_verify_uses_the_policy_not_the_profiles_own_ceiling():
    from homelabnext.agent import profile_digest

    p = compile_profile(spec(), library())  # spec ceiling is wider than the policy
    forged = copy.deepcopy(p)
    forged["grants"]["mcp"] = ["lake", "records"]
    forged["digest"] = profile_digest(forged)  # recomputed: internally consistent
    assert verify_profile(forged) == []
    probs = verify_profile(forged, policy=_policy())
    assert any("mcp outside ceiling" in x for x in probs)
    assert any(x.startswith("ceiling wider than the policy") for x in probs)  # stored ceiling wider than policy


def test_lock_pins_the_reviewed_digest():
    from homelabnext.agent import profile_digest

    s = spec()
    del s["ceiling"]
    p = compile_profile(s, library(), policy=_policy())
    lock = {p["id"]: p["digest"]}
    assert verify_profile(p, policy=_policy(), lock=lock) == []
    edited = copy.deepcopy(p)
    edited["budgets"]["max_runtime_s"] = 10
    edited["digest"] = profile_digest(edited)
    assert any("not the reviewed" in x for x in verify_profile(edited, policy=_policy(), lock=lock))
    assert any("not in the lock" in x for x in verify_profile(p, policy=_policy(), lock={}))
