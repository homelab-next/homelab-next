# SPDX-License-Identifier: Apache-2.0
"""``hnx workflows st2``: the rendered StackStorm pack, its checks, and the runtime it calls.

Hermetic: no StackStorm.  Rendered documents are checked against the fields st2 3.8 requires
(``st2.SHAPES``); rule criteria are evaluated by :func:`st2_matches`, a transcription of
``st2reactor/rules/filter.py`` and ``st2common/operators.py`` for the four operators the renderer
emits, against every event example and fixture in the repository.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import re
import sys
import types
from datetime import UTC, datetime

import pytest
import yaml
from wf_support import PACKS, ROOT, manifest, pack, universe

from conformance.protocols.broker import Denied
from homelabnext.broker.service import BrokerService
from homelabnext.events.envelope import event_problems
from homelabnext.workflows import (
    cli,
    load_doc,
    pack_digest,
    run_fixture,
    st2,
    st2_runtime,
    triggered,
)
from homelabnext.workflows.st2 import render, render_repo

BINDING = ROOT / "workflows" / "stackstorm.yml"
OUT = ROOT / "workflows" / "stackstorm"
T0 = datetime(2026, 1, 15, 10, 0, tzinfo=UTC)


# ---------------------------------------------------------------- helpers
def binding() -> dict:
    return copy.deepcopy(load_doc(BINDING))


def all_packs() -> dict[str, dict]:
    return {load_doc(p)["pack"]: load_doc(p) for p in sorted(PACKS.glob("*.yml"))}


def go(b: dict, packs: dict | None = None, tracked=lambda _p: True):
    packs = packs if packs is not None else all_packs()
    return render(
        b,
        packs,
        pins={n: pack_digest(d) for n, d in packs.items()},
        manifests=lambda rel: universe().manifest(rel)[0],
        clean=set(packs),
        tracked=tracked,
    )


def rules_of(b: dict | None = None, packs: dict | None = None) -> dict[str, dict]:
    res = go(b or binding(), packs)
    assert res.problems == [], [str(p) for p in res.problems]
    return {
        p: yaml.safe_load(t)
        for p, t in res.files.items()
        if "/rules/" in p  # rule name -> document
    }


def lookup(payload, key: str):
    """st2's PayloadLookup for the key shapes the renderer emits (``a.b[0].c``)."""
    cur = {"trigger": payload}
    for part in re.findall(r"[^.\[\]]+|\[\d+\]", key.split("#", 1)[0]):
        if part.startswith("["):
            i = int(part[1:-1])
            if not isinstance(cur, list) or i >= len(cur):
                return None
            cur = cur[i]
        elif isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def st2_matches(rule: dict, body: dict) -> bool:
    """Would StackStorm fire ``rule`` for a webhook POST of ``body``? (all criteria must hold)."""
    payload = {"headers": {}, "body": body}
    for key, crit in (rule.get("criteria") or {}).items():
        value, op, pat = lookup(payload, key), crit["type"], crit.get("pattern")
        ok = {
            "equals": lambda v, p: p is not None and v == p,
            "inside": lambda v, p: p is not None and v in p,
            "exists": lambda v, _p: v is not None,
            "nexists": lambda v, _p: v is None,
        }[op](value, pat)
        if not ok:
            return False
    return True


def corpus() -> list[dict]:
    """Every event example, every fixture event, and A02's reason x resubmits grid."""
    evs = [json.loads(p.read_text()) for p in sorted((ROOT / "schemas/events/examples").glob("*"))]
    for doc in all_packs().values():
        evs += [fx["event"] for fx in doc["fixtures"]]
    base = load_doc(PACKS / "agent-job-retry.yml")["fixtures"][0]["event"]
    for reason in ("capacity", "stall", "timeout", "backend-down", "deadline", "budget", "unknown"):
        for n in range(4):
            ev = copy.deepcopy(base)
            ev["id"] = f"evt-grid-{reason}-{n}"
            ev["data"] |= {"reason": reason, "resubmits": n}
            evs.append(ev)
    return evs


class KV:
    """The StackStorm datastore with TTLs, on a fake clock."""

    def __init__(self):
        self.now, self.items = 0.0, {}

    def get(self, name):
        v = self.items.get(name)
        return v[0] if v and v[1] > self.now else None

    def set(self, name, value, ttl):
        self.items[name] = (value, self.now + ttl)


class FakeBroker:
    def __init__(self, deny: str | None = None):
        self.calls, self.submits, self.deny = [], [], deny

    def call(self, action, params=None, *, target=None):
        if self.deny:
            raise Denied("no", reason=self.deny)
        self.calls.append((action, params, target))
        return {"ok": True}

    def submit(self, action, params=None, *, target=None):
        self.submits.append((action, params, target))
        return {"request_id": "req-1", "state": "pending", "awaiting_approval": True}


class NoBroker:
    def __getattr__(self, name):
        raise AssertionError(f"shadow mode used the broker ({name})")


class ServiceAsClient:
    """A real BrokerService behind the BrokerClient surface, as one caller."""

    def __init__(self, svc: BrokerService, caller: str):
        self.svc, self.caller = svc, caller

    def call(self, action, params=None, *, target=None):
        return self.svc.call(self.caller, action, dict(params or {}), target=target)

    def submit(self, action, params=None, *, target=None):
        rid = self.svc.submit(self.caller, action, dict(params or {}), target=target)
        state = self.svc.status(self.caller, rid).state
        return {"request_id": rid, "state": state, "awaiting_approval": state == "pending"}


def broker_service(tmp_path) -> BrokerService:
    return BrokerService.from_manifest(
        ROOT / "examples" / "broker" / "manifest.yml",
        tmp_path / "state",
        data_root=tmp_path / "data",
        clock=lambda: T0,
        resolve_secret={"DEMO_API_TOKEN": "fake-demo-token-4b1d"}.__getitem__,
    )


def workflow_steps(name: str, b: dict | None = None) -> list[dict]:
    res = go(b or binding())
    wf = yaml.safe_load(res.files[f"homelabnext/actions/workflows/{st2.st2_name(name)}.yaml"])
    return [t["input"]["step"] for n, t in wf["tasks"].items() if n != "admit"]


# ---------------------------------------------------------------- the committed tree
def test_committed_tree_is_the_rendered_one():
    res, _b = render_repo(ROOT)
    assert res.problems == [], [str(p) for p in res.problems]
    assert st2.drift(res.files, OUT, "workflows/stackstorm") == []
    assert cli.main(["st2", "check"]) == 0


def test_drift_is_reported_file_by_file(tmp_path):
    res, _b = render_repo(ROOT)
    st2.write(res.files, tmp_path)
    assert st2.drift(res.files, tmp_path, "x") == []
    (tmp_path / "bridge.json").write_text("{}\n")
    (tmp_path / "homelabnext/rules/on_proposal_validate.yaml").unlink()
    (tmp_path / "homelabnext/rules/on_extra.yaml").write_text("name: extra\n")
    got = {(p.path, p.detail.split(":")[0]) for p in st2.drift(res.files, tmp_path, "x")}
    assert got == {
        ("x/bridge.json", "differs from the rendered file"),
        ("x/homelabnext/rules/on_proposal_validate.yaml", "missing"),
        ("x/homelabnext/rules/on_extra.yaml", "not rendered"),
    }
    st2.write(res.files, tmp_path)  # write removes what it no longer renders
    assert st2.drift(res.files, tmp_path, "x") == []


def test_rendered_documents_have_the_fields_stackstorm_requires():
    res = go(binding())
    kinds = {}
    for path, text in res.files.items():
        if path.endswith(".yaml"):
            assert text.startswith("# SPDX-License-Identifier: Apache-2.0\n"), path
            kinds[path] = yaml.safe_load(text)
    assert st2.tree_problems(res.files, "homelabnext") == []
    meta = kinds["homelabnext/actions/agent_job_retry.yaml"]
    assert meta["runner_type"] == "orquesta" and meta["parameters"]["mode"]["default"] == "shadow"
    for broken in (
        {k: v for k, v in meta.items() if k != "entry_point"},
        meta | {"runner_type": "local-shell-cmd"},
        meta | {"parameters": {"bad-name": {"type": "string"}}},
    ):
        assert st2.shape_errors("action", broken)
    assert st2.shape_errors("pack", {"ref": "homelabnext", "name": "x", "version": "1"})


def test_the_tree_check_catches_a_task_that_is_not_a_shim():
    res = go(binding())
    path = "homelabnext/actions/workflows/agent_job_retry.yaml"
    wf = yaml.safe_load(res.files[path])
    wf["tasks"]["step_resubmit"]["action"] = "core.http"
    bad = dict(res.files) | {path: yaml.safe_dump(wf)}
    assert [p.detail for p in st2.tree_problems(bad, "homelabnext")] == [
        "tasks/step_resubmit: action core.http is not a shim"
    ]


# ---------------------------------------------------------------- criteria conformance
def test_rule_criteria_match_exactly_the_events_the_pack_triggers_on():
    packs = all_packs()
    events = corpus()
    for path, rule in rules_of().items():
        name = rule["action"]["ref"].split(".", 1)[1].replace("_", "-")
        doc = packs[name]
        hits = [e for e in events if st2_matches(rule, e)]
        assert hits, f"{path} matches nothing in the corpus"
        for ev in events:
            assert st2_matches(rule, ev) == triggered(doc, ev), (path, ev["id"], ev["type"])


def test_a02_criteria_retry_only_environment_failures_of_original_submits():
    rule = rules_of()["homelabnext/rules/on_agent_job_retry.yaml"]
    grid = [e for e in corpus() if e["id"].startswith("evt-grid-")]
    fired = {(e["data"]["reason"], e["data"]["resubmits"]) for e in grid if st2_matches(rule, e)}
    assert fired == {("capacity", 0), ("stall", 0), ("timeout", 0), ("backend-down", 0)}


def test_a_rule_without_a_type_criterion_matches_everything_and_is_refused():
    rule = rules_of()["homelabnext/rules/on_proposal_validate.yaml"]
    assert st2.criteria_problems(rule) == []
    loose = copy.deepcopy(rule)
    del loose["criteria"]["trigger.body.type"]
    assert all(st2_matches(loose, e) for e in corpus())  # the failure the check exists for
    assert st2.criteria_problems(loose)
    wild = copy.deepcopy(rule)
    wild["criteria"]["trigger.body.type"] = {"type": "equals", "pattern": "homelabnext"}
    assert st2.criteria_problems(wild)
    res = go(binding())
    path = "homelabnext/rules/on_proposal_validate.yaml"
    bad = dict(res.files) | {path: yaml.safe_dump(loose)}
    assert {p.rule for p in st2.tree_problems(bad, "homelabnext")} == {"st2-criteria"}


def test_criteria_keys_and_repeated_fields():
    assert st2.criteria_key("$event.data.entities.0.kind") == "trigger.body.data.entities[0].kind"
    crit = st2.rule_criteria(
        {
            "event": "homelabnext.alert.created",
            "where": [
                {"ref": "$event.data.severity", "exists": True},
                {"ref": "$event.data.severity", "in": ["high", "critical"]},
                {"ref": "$event.data.title", "exists": False},
            ],
        }
    )
    assert crit == {
        "trigger.body.type": {"type": "equals", "pattern": "homelabnext.alert.created"},
        "trigger.body.data.severity": {"type": "exists"},
        "trigger.body.data.severity#2": {"type": "inside", "pattern": ["high", "critical"]},
        "trigger.body.data.title": {"type": "nexists"},
    }


# ---------------------------------------------------------------- the binding's rules
def _a02(b: dict) -> dict:
    return next(r for r in b["rules"] if r["pack"] == "agent-job-retry")


def _problems(b: dict, packs: dict | None = None, **kw) -> set[tuple[str, str]]:
    return {(p.rule, p.detail.split(":")[0]) for p in go(b, packs, **kw).problems}


def test_the_shipped_binding_passes_and_starts_in_shadow():
    assert go(binding()).problems == []
    assert {r["mode"] for r in binding()["rules"]} == {"shadow"}
    for rule in rules_of().values():
        assert rule["action"]["parameters"]["mode"] == "shadow"


def test_live_needs_a_week_of_shadow_and_tracked_evidence():
    b = binding()
    _a02(b)["mode"] = "live"
    assert ("st2-live", "agent-job-retry") in _problems(b)
    _a02(b)["promotion"] = {
        "shadow_from": "2026-01-01",
        "live_from": "2026-01-05",
        "evidence": "docs/parity/a02.md",
    }
    assert ("st2-live", "agent-job-retry") in _problems(b)
    _a02(b)["promotion"]["live_from"] = "2026-01-08"
    assert ("st2-live", "agent-job-retry") in _problems(b, tracked=lambda _p: False)
    assert go(b).problems == []
    assert "mode: live" in go(b).files["homelabnext/rules/on_agent_job_retry.yaml"]


def test_agent_dispatch_must_coalesce_and_retries_must_be_bounded():
    b = binding()
    del _a02(b)["coalesce"]
    assert _problems(b) == {("st2-coalesce", "agent-job-retry")}
    packs = all_packs()
    a02 = packs["agent-job-retry"]
    a02["trigger"]["where"] = a02["trigger"]["where"][:1]  # drop the resubmits bound
    assert ("st2-bound", "agent-job-retry") in _problems(binding(), packs)
    a02["trigger"]["where"].append({"ref": "$event.data.resubmits", "in": [0, 5]})
    assert ("st2-bound", "agent-job-retry") in _problems(binding(), packs)
    a02["trigger"]["where"][-1] = {"ref": "$event.data.resubmits", "equals": 0}
    del a02["steps"][0]["params"]["retry_of_run_id"]
    assert _problems(binding(), packs) == {("st2-bound", "agent-job-retry")}


def test_steps_actor_pins_and_templates():
    b = binding()
    b["rules"].append({"pack": "new-critical-alert", "mode": "shadow"})
    got = _problems(b)
    assert ("st2-step", "new-critical-alert") in got  # lookup and decide do not run on st2 yet
    assert ("st2-actor", "new-critical-alert") in got
    packs = all_packs()
    packs["proposal-validate"]["steps"][0]["params"]["note"] = "{{ st2kv.system.leak }}"
    res = render(
        binding(),
        packs,
        pins={n: pack_digest(d) for n, d in all_packs().items()},  # the old digest is pinned
        manifests=lambda rel: universe().manifest(rel)[0],
        clean=set(packs),
    )
    assert {(p.rule, p.detail.split(":")[0]) for p in res.problems} == {
        ("st2-pin", "proposal-validate")
    }
    assert ("st2-template", "proposal-validate") in _problems(binding(), packs)
    b = binding()
    b["rules"].append(copy.deepcopy(b["rules"][0]))
    assert ("st2-duplicate", "proposal-validate") in _problems(b)


def test_secrets_are_datastore_references_never_values():
    b = binding()
    b["config"] = {"notify_token": {"value": "fake-token-value"}}
    assert _problems(b) == {("st2-secret", "config notify_token")}
    b["config"] = {"notify_token": {"st2kv": "homelabnext.notify_token"}, "site": {"value": "lab"}}
    res = go(b)
    cfg = yaml.safe_load(res.files["configs/homelabnext.yaml"])
    schema = yaml.safe_load(res.files["homelabnext/config.schema.yaml"])
    assert cfg["notify_token"] == "{{ st2kv.system.homelabnext.notify_token | decrypt_kv }}"
    assert schema["notify_token"]["secret"] is True and cfg["site"] == "lab"
    bridge = json.loads(res.files["bridge.json"])
    assert bridge["api_key"].startswith("secret:")  # a secret-store name, not a key


# ---------------------------------------------------------------- schedules
SCHED_PACK = {
    "pack": "nightly-digest",
    "version": 1,
    "description": "Post the nightly digest.",
    "trigger": {
        "event": "homelabnext.schedule.fired",
        "where": [{"ref": "$event.data.schedule", "equals": "nightly-digest"}],
    },
    "actor": "profile:workflow-agents",
    "broker_manifest": "workflows/broker.manifest.json",
    "steps": [
        {
            "id": "dispatch",
            "kind": "action",
            "action": "agent.job.submit",
            "target": "svc:orchestration",
            "params": {"agent_key": "digest", "idempotency_key": "$event.id", "priority": 70},
        }
    ],
    "fixtures": [],
}


def _sched(cron: str = "5 6 * * 1-5", sid: str = "nightly-digest"):
    b = binding()
    b["rules"].append(
        {
            "pack": "nightly-digest",
            "mode": "shadow",
            "schedule": {"id": sid, "cron": cron},
            "coalesce": {"key": "$event.data.schedule", "window_s": 3600},
        }
    )
    return b, all_packs() | {"nightly-digest": copy.deepcopy(SCHED_PACK)}


def test_a_scheduled_pack_becomes_a_crontimer_rule():
    b, packs = _sched()
    res = go(b, packs)
    assert res.problems == []
    rule = yaml.safe_load(res.files["homelabnext/rules/on_nightly_digest.yaml"])
    assert rule["trigger"] == {
        "type": "core.st2.CronTimer",
        "parameters": {"timezone": "UTC", "minute": 5, "hour": 6, "day_of_week": "mon-fri"},
    }
    assert "criteria" not in rule and rule["action"]["parameters"]["fired_at"]
    subjects = [s["subject"] for s in json.loads(res.files["bridge.json"])["subscriptions"]]
    assert "homelabnext.schedule.fired" not in subjects  # the clock is StackStorm's own
    assert ("st2-cron", "nightly-digest") in _problems(*_sched("61 6 * * *"))
    assert ("st2-trigger", "nightly-digest") in _problems(*_sched(sid="other"))


@pytest.mark.parametrize(
    ("cron", "params"),
    [
        ("*/15 * * * *", {"minute": "*/15"}),
        ("0 2 1 * 0", {"minute": 0, "hour": 2, "day": 1, "day_of_week": "sun"}),
        ("30 23 * 1-6 6,7", {"minute": 30, "hour": 23, "month": "1-6", "day_of_week": "sat,sun"}),
    ],
)
def test_cron_fields(cron, params):
    assert st2.cron_params(cron) == {"timezone": "UTC", **params}


@pytest.mark.parametrize(
    "cron", ["* * * *", "60 * * * *", "* * * * */2", "* * * * 5-1", "a * * * *"]
)
def test_bad_cron_fields(cron):
    with pytest.raises(ValueError):
        st2.cron_params(cron)


def test_a_firing_is_one_stable_event():
    a = st2_runtime.schedule_event("nightly-digest", "2026-01-15 06:05:00.123456", "5 6 * * *")
    b = st2_runtime.schedule_event("nightly-digest", "2026-01-15T06:05:00Z")
    assert event_problems(a) == [] and a["id"] == b["id"] and a["time"] == "2026-01-15T06:05:00Z"
    got = st2_runtime.admit(
        pack="nightly-digest",
        trigger=SCHED_PACK["trigger"],
        schedule={"id": "nightly-digest", "fired_at": "2026-01-15 06:05:00"},
    )
    assert got["admitted"] and got["event"]["id"] == a["id"]


# ---------------------------------------------------------------- admit and coalesce
def _failure(i: int, agent: str = "triage", **data) -> dict:
    ev = copy.deepcopy(load_doc(PACKS / "agent-job-retry.yml")["fixtures"][0]["event"])
    ev["id"], ev["subject"] = f"evt-burst-{i}", f"run-{i}"
    ev["data"] |= {"run_id": f"run-{i}", "agent_key": agent, **data}
    return ev


def test_a02_coalesces_a_burst_of_failures_of_one_agent():
    a02 = pack("agent-job-retry")
    co = _a02(binding())["coalesce"]
    kv = KV()
    got = [
        st2_runtime.admit(
            pack=a02["pack"], trigger=a02["trigger"], event=_failure(i), coalesce=co, kv=kv
        )
        for i in range(5)
    ]
    assert [g["reason"] for g in got] == ["admitted"] + ["coalesced"] * 4
    assert {g.get("coalesced_into") for g in got[1:]} == {"evt-burst-0"}
    other = st2_runtime.admit(
        pack=a02["pack"], trigger=a02["trigger"], event=_failure(9, "reader"), coalesce=co, kv=kv
    )
    assert other["reason"] == "admitted"  # coalescing is per agent
    kv.now += co["window_s"]
    again = st2_runtime.admit(
        pack=a02["pack"], trigger=a02["trigger"], event=_failure(10), coalesce=co, kv=kv
    )
    assert again["reason"] == "admitted"  # a new window
    capped = st2_runtime.admit(
        pack=a02["pack"],
        trigger=a02["trigger"],
        event=_failure(11, resubmits=1),
        coalesce=co,
        kv=kv,
    )
    assert capped["reason"] == "not-triggered"  # the attempt cap, before the datastore is touched
    bad = st2_runtime.admit(pack=a02["pack"], trigger=a02["trigger"], event={"type": "x"})
    assert bad["reason"] == "invalid-event"


# ---------------------------------------------------------------- steps: shadow, live, broker
def test_shadow_logs_the_offline_request_and_submits_nothing():
    a01 = pack("proposal-validate")
    fx = a01["fixtures"][0]
    [offline] = run_fixture(a01, fx, manifest=manifest()).calls
    [st] = workflow_steps("proposal-validate")
    got = st2_runtime.step(
        {"broker_socket": "/nonexistent"},
        broker_factory=lambda _s: NoBroker(),
        pack=a01["pack"],
        actor=a01["actor"],
        step=st,
        event=fx["event"],
        mode="shadow",
        risky=False,
    )
    [rec] = got["calls"]
    assert rec["result"] == "shadow" and rec["reason"] == "st2-shadow"
    assert (rec["request_id"], rec["request_digest"]) == (
        offline.request_id,
        offline.request_digest,
    )
    assert rec["params"] == offline.params


def test_live_calls_or_submits_through_the_broker_only():
    a02 = pack("agent-job-retry")
    ev = a02["fixtures"][0]["event"]
    [st] = workflow_steps("agent-job-retry")
    kw = {"pack": a02["pack"], "actor": a02["actor"], "step": st, "event": ev, "mode": "live"}
    fb = FakeBroker()
    out = st2_runtime.step({"broker_socket": "/s"}, broker_factory=lambda _s: fb, risky=False, **kw)
    assert out["calls"][0]["result"] == "executed" and fb.calls == [
        ("agent.job.submit", out["calls"][0]["params"], "svc:orchestration")
    ]
    assert out["calls"][0]["params"]["retry_of_run_id"] == "run-0001"
    fb = FakeBroker()
    out = st2_runtime.step({"broker_socket": "/s"}, broker_factory=lambda _s: fb, risky=True, **kw)
    assert (out["calls"][0]["result"], fb.calls, len(fb.submits)) == ("held", [], 1)
    out = st2_runtime.step(
        {"broker_socket": "/s"},
        broker_factory=lambda _s: FakeBroker("not-granted"),
        risky=False,
        **kw,
    )
    assert (out["calls"][0]["result"], out["calls"][0]["reason"]) == ("denied", "not-granted")
    with pytest.raises(ValueError, match="mode"):
        st2_runtime.run_step(**(kw | {"mode": "dry-run"}))
    with pytest.raises(st2_runtime.UnsupportedStep):
        st2_runtime.run_step(**(kw | {"step": {"id": "d", "kind": "decide"}}))


def test_skipped_and_enrich_steps_match_the_offline_runner():
    ev = pack("phishing-report")["fixtures"][0]["event"]
    step = {"id": "iocs", "kind": "enrich", "op": "extract-iocs", "from": "$event.data"}
    got = st2_runtime.run_step(pack="p", actor="profile:x", step=step, event=ev)
    assert got["steps"]["iocs"]["count"] >= 0 and got["calls"] == []
    when = dict(step, when=[{"ref": "$event.data.nope", "exists": True}])
    got = st2_runtime.run_step(pack="p", actor="profile:x", step=when, event=ev)
    assert got["skipped"] and got["steps"] == {"iocs": None}


def test_proposal_lane_to_a01_end_to_end_through_a_real_broker(tmp_path):
    svc = broker_service(tmp_path)
    note = {"title": "Raise the drain timeout", "risk": "low", "rollback": "set it back"}
    svc.call("profile:triage", "proposal.file", {"note": note, "body": "Seen twice."})
    [event] = svc.state.outbox()
    assert event["type"] == "homelabnext.proposal.created"
    rule = rules_of()["homelabnext/rules/on_proposal_validate.yaml"]
    assert st2_matches(rule, event)
    a01 = pack("proposal-validate")
    admitted = st2_runtime.admit(
        pack=a01["pack"],
        trigger=a01["trigger"],
        event=event,
        coalesce=next(r for r in binding()["rules"] if r["pack"] == a01["pack"])["coalesce"],
        kv=KV(),
    )
    assert admitted["admitted"]
    [st] = workflow_steps("proposal-validate")
    fb = FakeBroker()
    st2_runtime.run_step(
        pack=a01["pack"],
        actor=a01["actor"],
        step=st,
        event=admitted["event"],
        mode="live",
        risky=False,
        broker=fb,
    )
    [(action, params, target)] = fb.calls
    assert (action, target) == ("agent.job.submit", "svc:orchestration")
    assert params["input"]["note"] == event["data"]["note"]
    assert params["idempotency_key"] == event["id"]


def test_a_risky_action_is_held_and_the_broker_emits_decision_requested(tmp_path):
    svc = broker_service(tmp_path)
    step = {
        "id": "restart",
        "kind": "action",
        "action": "service.restart",
        "target": "svc:queue",
        "params": {"grace_s": 30},
    }
    ev = pack("agent-job-retry")["fixtures"][0]["event"]
    out = st2_runtime.run_step(
        pack="restart-queue",
        actor="profile:triage",
        step=step,
        event=ev,
        mode="live",
        risky=True,
        broker=ServiceAsClient(svc, "profile:triage"),
    )
    [rec] = out["calls"]
    assert (rec["result"], rec["reason"]) == ("held", "awaiting-approval")
    [requested] = svc.state.outbox()
    assert requested["type"] == "homelabnext.decision.requested"
    assert requested["data"]["decision_id"] == rec["broker_request_id"]
    assert requested["data"]["action"] == "service.restart"
    with pytest.raises(Denied):  # calling it instead of submitting is refused by the broker
        ServiceAsClient(svc, "profile:triage").call(
            "service.restart", {"grace_s": 30}, target="svc:queue"
        )


# ---------------------------------------------------------------- the shims
def _load_shim(name: str, monkeypatch):
    base = types.ModuleType("st2common.runners.base_action")

    class Action:
        def __init__(self, config=None, action_service=None):
            self.config, self.action_service = config, action_service

    base.Action = Action
    for mod in ("st2common", "st2common.runners"):
        monkeypatch.setitem(sys.modules, mod, types.ModuleType(mod))
    monkeypatch.setitem(sys.modules, "st2common.runners.base_action", base)
    path = OUT / "homelabnext" / "actions" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"st2shim_{name}", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return getattr(mod, name.title())


def test_the_rendered_shims_delegate_to_the_runtime(monkeypatch):
    class Service:
        def __init__(self):
            self.kv = {}

        def get_value(self, name, local=True):
            assert local is False
            return self.kv.get(name)

        def set_value(self, name, value, ttl=None, local=True):
            assert local is False and ttl == 600
            self.kv[name] = value

    a02 = pack("agent-job-retry")
    co = _a02(binding())["coalesce"]
    admit = _load_shim("admit", monkeypatch)(action_service=Service())
    ev = a02["fixtures"][0]["event"]
    first = admit.run(pack=a02["pack"], trigger=a02["trigger"], event=ev, coalesce=co)
    second = admit.run(pack=a02["pack"], trigger=a02["trigger"], event=ev, coalesce=co)
    assert (first["reason"], second["reason"]) == ("admitted", "coalesced")
    step = _load_shim("step", monkeypatch)(config={"broker_socket": "/nonexistent"})
    [st] = workflow_steps("agent-job-retry")
    out = step.run(pack=a02["pack"], actor=a02["actor"], step=st, event=ev, mode="shadow")
    assert out["calls"][0]["result"] == "shadow"
