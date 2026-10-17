# SPDX-License-Identifier: Apache-2.0
"""The scope guard: policy as data, canonical resolution first, fail closed, loggable denials."""

from __future__ import annotations

from pathlib import Path

import pytest

from homelabnext.compute import MappingZones, ZoneInfo, load_fleet
from homelabnext.events import event_problems
from homelabnext.ids import MappingResolver
from homelabnext.scope import (
    PolicyError,
    ScopeDenied,
    ScopeGuard,
    ScopePolicy,
    Target,
    guarded,
    targets_from_fleet,
    targets_from_services,
)

FLEET = Path(__file__).resolve().parents[1] / "compute" / "fleet"
ZONES = MappingZones(
    [
        ZoneInfo("mgmt", "192.0.2.0/24", "192.0.2.1", None, 10),
        ZoneInfo(
            "data", "198.51.100.0/25", "198.51.100.1", ("198.51.100.100", "198.51.100.126"), 20
        ),
        ZoneInfo("compute", "198.51.100.128/25", "198.51.100.129", None, 30),
        ZoneInfo("edge", "203.0.113.0/24", "203.0.113.1", None, 40),
    ]
)

TARGETS = [
    Target("guest:prod-a", aliases=("198.51.100.10", "prod-a.example.invalid"), vmid=120),
    Target("guest:edge-limit", vmid=9000),
    Target("guest:above-limit", vmid=9001),
    Target("guest:scratch-a", scope="out", vmid=130),
    Target("guest:pinned-in", scope="in", vmid=9500),
    Target("guest:tagged", tags=("lab", "prod"), vmid=140),
    Target("guest:novmid"),
]
POLICY = ScopePolicy(vmid_threshold=9000, out_tags=frozenset({"lab"}))


@pytest.fixture
def guard():
    return ScopeGuard(TARGETS, POLICY)


# ---------------------------------------------------------------- the decision table
@pytest.mark.parametrize(
    "ref,allow,code",
    [
        ("guest:prod-a", True, "allowed"),
        ("guest:edge-limit", True, "allowed"),  # vmid == threshold is IN: the bound is exclusive
        ("guest:above-limit", False, "vmid-threshold"),  # threshold + 1 is OUT
        ("guest:scratch-a", False, "explicit-out"),
        ("guest:pinned-in", True, "explicit-in"),  # explicit `in` beats the threshold
        ("guest:tagged", False, "out-tag"),
        ("guest:novmid", True, "allowed"),  # no vmid, no tags: the threshold cannot apply
    ],
)
def test_decision_table(guard, ref, allow, code):
    d = guard.in_scope(ref)
    assert (d.allow, d.code, d.verdict) == (allow, code, "allow" if allow else "deny")
    assert d.canonical == ref and d.reason


def test_threshold_boundary_is_exclusive_both_sides():
    g = ScopeGuard(
        [Target("guest:a", vmid=99), Target("guest:b", vmid=100), Target("guest:c", vmid=101)],
        ScopePolicy(vmid_threshold=100),
    )
    assert [g.in_scope(f"guest:{x}").allow for x in "abc"] == [True, True, False]


def test_no_threshold_configured_means_no_vmid_rule():
    g = ScopeGuard([Target("guest:a", vmid=999999)], ScopePolicy())
    assert g.in_scope("guest:a").allow


def test_override_beats_everything():
    p = ScopePolicy(
        vmid_threshold=9000,
        overrides={"guest:above-limit": "in", "guest:pinned-in": "out", "guest:prod-a": "out"},
    )
    g = ScopeGuard(TARGETS, p)
    assert g.in_scope("guest:above-limit").code == "override-in"
    assert g.in_scope("guest:pinned-in").code == "override-out"
    assert not g.in_scope("guest:prod-a").allow


# ---------------------------------------------------------------- unknown targets
def test_unknown_target_fails_closed_by_default(guard):
    d = guard.in_scope("guest:does-not-exist")
    assert (d.allow, d.code, d.canonical) == (False, "unknown-target", None)


@pytest.mark.parametrize("ref", ["", "   ", None, 7])
def test_empty_or_non_string_reference_is_denied(guard, ref):
    assert not guard.in_scope(ref).allow


def test_unknown_allow_is_an_explicit_policy_choice():
    g = ScopeGuard(TARGETS, ScopePolicy(unknown="allow"))
    d = g.in_scope("guest:does-not-exist")
    assert d.allow and d.code == "unknown-allowed"


def test_ambiguous_reference_is_denied_even_when_unknown_is_allow():
    t = [Target("guest:a", aliases=("shared",)), Target("guest:b", aliases=("shared",))]
    d = ScopeGuard(t, ScopePolicy(unknown="allow")).in_scope("shared")
    assert (d.allow, d.code) == (False, "ambiguous-target")


# ---------------------------------------------------------------- bypass attempts
@pytest.mark.parametrize(
    "ref",
    [
        "scratch-a",  # bare hostname
        "SCRATCH-A",  # case
        " guest:scratch-a ",  # whitespace
        "Guest:Scratch-A",
        "scratch-a.",  # trailing dot (FQDN form)
    ],
)
def test_alternate_spellings_cannot_bypass(guard, ref):
    d = guard.in_scope(ref)
    assert not d.allow and d.canonical == "guest:scratch-a" and d.target == ref


def test_address_and_fqdn_aliases_resolve_to_the_same_decision():
    t = [
        Target(
            "guest:scratch-a", aliases=("198.51.100.99", "scratch-a.example.invalid"), scope="out"
        )
    ]
    g = ScopeGuard(t, ScopePolicy())
    for ref in ("198.51.100.99", "scratch-a.example.invalid"):
        assert g.in_scope(ref).code == "explicit-out"


def test_logical_id_resolver_alias_cannot_bypass():
    # an old name the registry still resolves (rename, capability alias, ...)
    r = MappingResolver("canon", {"svc:old-name": "guest:scratch-a"})
    g = ScopeGuard(TARGETS, POLICY, resolver=r)
    d = g.in_scope("svc:old-name")
    assert (d.allow, d.canonical, d.code) == (False, "guest:scratch-a", "explicit-out")
    assert g.in_scope("svc:never-registered").code == "unknown-target"


def test_resolver_pointing_at_nothing_is_unknown_not_allowed():
    r = MappingResolver("canon", {"svc:ghost": "guest:not-a-target"})
    assert ScopeGuard(TARGETS, POLICY, resolver=r).in_scope("svc:ghost").code == "unknown-target"


def test_resolver_cannot_launder_an_out_of_scope_target_into_an_allowed_one():
    r = MappingResolver("canon", {"svc:nice-name": "guest:scratch-a"})
    g = ScopeGuard(TARGETS, POLICY, resolver=r)
    with pytest.raises(ScopeDenied):
        g.require("svc:nice-name")


def test_duplicate_target_ids_are_a_construction_error():
    with pytest.raises(ValueError):
        ScopeGuard([Target("guest:a"), Target("guest:a")])


# ---------------------------------------------------------------- policy as data
def test_policy_from_mapping_and_validation():
    p = ScopePolicy.from_mapping(
        {"vmid_threshold": 100, "out_tags": ["lab"], "overrides": {"guest:a": "out"}}
    )
    assert p.vmid_threshold == 100 and p.out_tags == {"lab"} and p.unknown == "deny"
    for bad in (
        {"vmid_threshold": 0},
        {"vmid_threshold": True},
        {"unknown": "maybe"},
        {"out_tags": ["Lab Tag"]},
        {"overrides": {"guest:a": "perhaps"}},
        {"overrides": {"not an id": "out"}},
        {"surprise": 1},
    ):
        with pytest.raises(PolicyError):
            ScopePolicy.from_mapping(bad)


def test_policy_from_file(tmp_path):
    f = tmp_path / "scope.yml"
    f.write_text("scope_policy:\n  vmid_threshold: 9000\n  out_tags: [lab]\n")
    p = ScopePolicy.from_file(str(f))
    assert p.vmid_threshold == 9000 and "lab" in p.out_tags


# ---------------------------------------------------------------- the decorator + event
def test_denied_tool_body_never_runs_and_returns_structured_reason(guard):
    written = []
    events = []

    @guarded(guard, target_arg="host", tool="task-writer", sink=events.append)
    def write_task(host, title):
        written.append((host, title))
        return {"ok": True}

    assert write_task("guest:prod-a", "patch it") == {"ok": True}
    out = write_task("scratch-a", "patch it")
    assert out["ok"] is False and out["denied"]["code"] == "explicit-out"
    assert (
        out["denied"]["canonical"] == "guest:scratch-a" and out["denied"]["target"] == "scratch-a"
    )
    assert written == [("guest:prod-a", "patch it")]
    assert len(events) == 1


def test_denial_event_is_schema_valid_and_deterministic(guard):
    d = guard.in_scope("guest:above-limit")
    ev = d.as_event(tool="note-writer", time="2026-01-01T00:00:00Z")
    assert event_problems(ev) == []
    assert ev["type"] == "homelabnext.scope.denied" and ev["subject"] == "guest:above-limit"
    assert ev["data"]["code"] == "vmid-threshold"
    assert ev == d.as_event(tool="note-writer", time="2026-01-01T00:00:00Z")
    other = d.as_event(tool="note-writer", time="2026-01-01T00:00:01Z")
    assert other["id"] != ev["id"]  # a later denial is a new event


def test_unresolved_denial_event_is_valid_with_null_canonical(guard):
    ev = guard.in_scope("guest:ghost").as_event(time="2026-01-01T00:00:00Z")
    assert ev["data"]["canonical"] is None and event_problems(ev) == []
    assert "subject" not in ev


def test_allow_has_no_event(guard):
    with pytest.raises(ValueError):
        guard.in_scope("guest:prod-a").as_event()


def test_raise_mode_and_failing_sink(guard):
    def boom(_ev):
        raise RuntimeError("sink down")

    @guarded(guard, on_deny="raise", sink=boom)
    def write_note(target):
        raise AssertionError("must not run")

    with pytest.raises(ScopeDenied) as ei:
        write_note("guest:scratch-a")
    assert ei.value.decision.code == "explicit-out"


def test_failing_sink_never_turns_a_denial_into_a_write(guard):
    @guarded(guard, sink=lambda e: 1 / 0)
    def write(target):
        raise AssertionError("must not run")

    assert write("guest:scratch-a")["ok"] is False


def test_decorator_finds_target_by_keyword_and_default(guard):
    @guarded(guard)
    def w(title, target="guest:scratch-a"):
        raise AssertionError("must not run")

    assert w("t")["ok"] is False
    assert w("t", target="guest:scratch-a")["ok"] is False
    assert w(title="t", target="scratch-a")["ok"] is False


def test_decorator_checks_its_arguments(guard):
    with pytest.raises(TypeError):

        @guarded(guard, target_arg="nope")
        def w(target):
            pass

    with pytest.raises(ValueError):
        guarded(guard, on_deny="explode")


def test_non_string_target_to_a_guarded_tool_is_denied(guard):
    @guarded(guard)
    def w(target):
        raise AssertionError("must not run")

    assert w(["guest:prod-a"])["denied"]["code"] == "unknown-target"


# ---------------------------------------------------------------- built from the real models
def test_targets_from_fleet_reads_scope_vmid_tags_and_aliases(tmp_path):
    import shutil

    import yaml

    d = tmp_path / "fleet"
    shutil.copytree(FLEET, d)
    p = d / "infer-core.yml"
    doc = yaml.safe_load(p.read_text())
    doc["scope"] = "out"
    p.write_text(yaml.safe_dump(doc, sort_keys=False))
    fleet = load_fleet(d, ZONES)
    g = ScopeGuard(targets_from_fleet(fleet), ScopePolicy(vmid_threshold=200))
    for ref in ("guest:infer-core", "infer-core", "infer-core.example.internal", "198.51.100.130"):
        assert g.in_scope(ref).code == "explicit-out", ref
    assert g.in_scope("lake-core").allow
    by_vmid = next(t for t in targets_from_fleet(fleet) if t.vmid == 140)
    assert f"vmid:{by_vmid.vmid}" in by_vmid.aliases
    assert g.in_scope(f"vmid:{by_vmid.vmid}").canonical == by_vmid.id


def test_service_inherits_scope_from_its_host_guest():
    guests = [Target("guest:scratch-a", scope="out", vmid=9001), Target("guest:prod-a")]
    reg = {
        "services": {
            "worker": {"capability": "orchestration", "host": "scratch-a"},
            "api": {"capability": "lake-query", "host": "prod-a"},
            "pinned": {"capability": "notify", "host": "scratch-a", "scope": "in"},
        }
    }
    g = ScopeGuard([*guests, *targets_from_services(reg, guests)], ScopePolicy())
    assert g.in_scope("svc:worker").code == "explicit-out"
    assert g.in_scope("orchestration").canonical == "svc:worker"  # capability alias resolves first
    assert g.in_scope("svc:api").allow
    assert g.in_scope("svc:pinned").code == "explicit-in"


def test_hostname_shared_by_guest_and_service_does_not_become_ambiguous():
    guests = [Target("guest:store", scope="out")]
    reg = {"services": {"store": {"capability": "object-store", "host": "store"}}}
    g = ScopeGuard([*guests, *targets_from_services(reg, guests)], ScopePolicy())
    assert g.in_scope("store").canonical == "guest:store"  # a bare name is a hostname
    assert g.in_scope("svc:store").canonical == "svc:store"
