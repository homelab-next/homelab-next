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
import urllib.parse
from datetime import UTC, datetime

import pytest
import yaml
from wf_support import PACKS, ROOT, manifest, pack, universe

from conformance.fakes.event_bus import FakeEventBus
from conformance.protocols.broker import Denied
from homelabnext.broker.service import BrokerService
from homelabnext.events.envelope import event_problems
from homelabnext.workflows import (
    cli,
    load_doc,
    pack_digest,
    run_fixture,
    st2,
    st2_bridge,
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
        handlers=lambda m, h: st2.handler_problem(ROOT, m, h),
    )


def pinned_dir(tmp_path, b: dict | None = None, packs: dict | None = None):
    """The ``pinned/`` directory of a tree rendered from ``b`` and ``packs``, written out."""
    res = go(b or binding(), packs)
    assert res.problems == [], [str(p) for p in res.problems]
    st2.write(res.files, tmp_path / "st2")
    return tmp_path / "st2" / "homelabnext" / "pinned"


def calls_of(out: dict) -> list[dict]:
    return st2_runtime.decode(out["state"])["calls"]


#: what a reviewer filed as a proposal title: st2 would render it, unsandboxed, as Jinja
HOSTILE = (
    "{{ st2kv.system.leak | decrypt_kv }}{% for c in ''.__class__.__mro__ %}x{% endfor %}<% 1 %>"
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
    # the broker's own decision.returned, an approval and a denial (A03)
    for verdict in ("accept", "reject"):
        evs.append(
            {
                "specversion": "1.0",
                "id": f"evt-broker-{verdict}",
                "source": "svc:broker",
                "type": "homelabnext.decision.returned",
                "time": "2026-01-01T00:00:00Z",
                "subject": "restart-0001",
                "data": {
                    "decision_id": "restart-0001",
                    "verdict": verdict,
                    "confidence": 1.0,
                    "tier_used": "human",
                },
            }
        )
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

    def status(self, request_id):
        return self.svc.detail(self.caller, request_id)

    def run(self, request_id):
        self.runs = getattr(self, "runs", 0) + 1
        return self.svc.run(self.caller, request_id)


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
    pin = json.loads(res.files[f"homelabnext/pinned/{st2.st2_name(name)}.json"])
    ids = [t["input"]["step"] for n, t in wf["tasks"].items() if n != "admit"]
    return [next(s for s in pin["pack"]["steps"] if s["id"] == i) for i in ids]


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
    assert meta["runner_type"] == "orquesta" and set(meta["parameters"]) == {"event"}
    assert meta["parameters"]["event"]["type"] == "string"  # the encoded body, never an object
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
    packs["approved-run"] = st2_runtime.approved_run_pack(binding()["actor"])
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
    del loose["criteria"]["trigger.body.source"]
    assert all(st2_matches(loose, e) for e in corpus())  # the failure the check exists for
    assert st2.criteria_problems(loose)
    wild = copy.deepcopy(rule)
    wild["criteria"]["trigger.body.type"] = {"type": "equals", "pattern": "homelabnext"}
    assert st2.criteria_problems(wild)
    res = go(binding())
    path = "homelabnext/rules/on_proposal_validate.yaml"
    bad = dict(res.files) | {path: yaml.safe_dump(loose)}
    assert {p.rule for p in st2.tree_problems(bad, "homelabnext")} == {"st2-criteria", "st2-source"}


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
    res = go(binding())
    assert res.problems == []
    assert {r["mode"] for r in binding()["rules"]} == {"shadow"}
    pins = [json.loads(t) for p, t in res.files.items() if "/pinned/" in p]
    assert len(pins) == 3 and {p["mode"] for p in pins} == {"shadow"}
    assert binding()["approved_run"]["mode"] == "shadow"
    for rule in rules_of().values():
        assert "mode" not in rule["action"]["parameters"]  # never a parameter


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
    assert json.loads(go(b).files["homelabnext/pinned/agent_job_retry.json"])["mode"] == "live"


def test_agent_dispatch_must_coalesce_and_retries_must_be_bounded():
    b = binding()
    del _a02(b)["coalesce"]
    assert _problems(b) == {("st2-coalesce", "agent-job-retry")}
    packs = all_packs()
    a02 = packs["agent-job-retry"]
    a02["trigger"]["where"] = a02["trigger"]["where"][:2]  # drop the resubmits bound
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
        ("0 2 1 * *", {"minute": 0, "hour": 2, "day": 1}),
        ("0 2 * * 0", {"minute": 0, "hour": 2, "day_of_week": "sun"}),
        ("30 23 * 1-6 6,7", {"minute": 30, "hour": 23, "month": "1-6", "day_of_week": "sat,sun"}),
    ],
)
def test_cron_fields(cron, params):
    assert st2.cron_params(cron) == {"timezone": "UTC", **params}


@pytest.mark.parametrize(
    "cron", ["* * * *", "60 * * * *", "* * * * */2", "* * * * 5-1", "a * * * *", "0 2 1 * 0"]
)
def test_bad_cron_fields(cron):
    with pytest.raises(ValueError):
        st2.cron_params(cron)


def test_day_of_month_and_day_of_week_together_are_refused():
    # cron fires on the 1st OR on Sundays; the CronTimer (APScheduler) only on a Sunday the 1st
    with pytest.raises(ValueError, match="day of month and day of week"):
        st2.cron_params("0 2 1 * 0")
    assert ("st2-cron", "nightly-digest") in _problems(*_sched("0 6 1 * 1"))


def test_a_firing_is_one_stable_event():
    a = st2_runtime.schedule_event("nightly-digest", "2026-01-15 06:05:00.123456", "5 6 * * *")
    b = st2_runtime.schedule_event("nightly-digest", "2026-01-15T06:05:00Z")
    assert event_problems(a) == [] and a["id"] == b["id"] and a["time"] == "2026-01-15T06:05:00Z"
    got = st2_runtime.admit_event(
        pack="nightly-digest",
        trigger=SCHED_PACK["trigger"],
        schedule={"id": "nightly-digest", "fired_at": "2026-01-15 06:05:00"},
    )
    assert got["admitted"] and got["event"]["id"] == a["id"]


def test_a_scheduled_run_takes_its_schedule_from_the_pinned_pack(tmp_path):
    b, packs = _sched()
    pdir = pinned_dir(tmp_path, b, packs)
    got = st2_runtime.admit(
        pack="nightly-digest", pinned_dir=pdir, fired_at="2026-01-15 06:05:00", kv=KV()
    )
    assert got["admitted"]
    ev = st2_runtime.decode(got["event"])
    assert ev["data"] == {
        "schedule": "nightly-digest",
        "fired_at": "2026-01-15T06:05:00Z",
        "cron": "5 6 * * 1-5",
    }
    forged = st2_runtime.admit(pack="nightly-digest", pinned_dir=pdir, event=got["event"])
    assert forged["reason"] == "invalid-event"  # a scheduled pack takes no event


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
        st2_runtime.admit_event(
            pack=a02["pack"], trigger=a02["trigger"], event=_failure(i), coalesce=co, kv=kv
        )
        for i in range(5)
    ]
    assert [g["reason"] for g in got] == ["admitted"] + ["coalesced"] * 4
    assert {g.get("coalesced_into") for g in got[1:]} == {"evt-burst-0"}
    other = st2_runtime.admit_event(
        pack=a02["pack"], trigger=a02["trigger"], event=_failure(9, "reader"), coalesce=co, kv=kv
    )
    assert other["reason"] == "admitted"  # coalescing is per agent
    kv.now += co["window_s"]
    again = st2_runtime.admit_event(
        pack=a02["pack"], trigger=a02["trigger"], event=_failure(10), coalesce=co, kv=kv
    )
    assert again["reason"] == "admitted"  # a new window
    capped = st2_runtime.admit_event(
        pack=a02["pack"],
        trigger=a02["trigger"],
        event=_failure(11, resubmits=1),
        coalesce=co,
        kv=kv,
    )
    assert capped["reason"] == "not-triggered"  # the attempt cap, before the datastore is touched
    bad = st2_runtime.admit_event(pack=a02["pack"], trigger=a02["trigger"], event={"type": "x"})
    assert bad["reason"] == "invalid-event"
    forged = _failure(12)
    forged["source"] = "profile:triage"  # anyone who may post to the bus, but not the controller
    got = st2_runtime.admit_event(
        pack=a02["pack"], trigger=a02["trigger"], event=forged, coalesce=co, kv=kv
    )
    assert got["reason"] == "not-triggered"  # before the datastore: it opens no window


def test_a_redelivered_event_is_admitted_once_without_a_coalesce_window():
    """A StackStorm webhook starts one run per POST (it ignores Idempotency-Key) and the bridge
    delivers at least once, so admit itself drops an event id it already took."""
    a02 = pack("agent-job-retry")
    kv = KV()
    got = [
        st2_runtime.admit_event(pack=a02["pack"], trigger=a02["trigger"], event=_failure(1), kv=kv)
        for _ in range(3)
    ]
    assert [g["reason"] for g in got] == ["admitted", "duplicate", "duplicate"]
    other = st2_runtime.admit_event(
        pack="another-pack", trigger=a02["trigger"], event=_failure(1), kv=kv
    )
    assert other["reason"] == "admitted"  # remembered per pack
    kv.now += st2_runtime.DEDUPE_WINDOW_S
    again = st2_runtime.admit_event(
        pack=a02["pack"], trigger=a02["trigger"], event=_failure(1), kv=kv
    )
    assert again["reason"] == "admitted"  # forgotten after the window
    # a CronTimer that fires twice for the same time is one event, so one run
    firing = {"id": "nightly-digest", "fired_at": "2026-01-15 06:05:00"}
    twice = [
        st2_runtime.admit_event(
            pack="nightly-digest", trigger=SCHED_PACK["trigger"], schedule=firing, kv=kv
        )["reason"]
        for _ in range(2)
    ]
    assert twice == ["admitted", "duplicate"]


def test_every_event_triggered_pack_pins_its_producer():
    rules = rules_of()
    a01 = rules["homelabnext/rules/on_proposal_validate.yaml"]
    a02 = rules["homelabnext/rules/on_agent_job_retry.yaml"]
    assert a01["criteria"]["trigger.body.source"] == {"type": "equals", "pattern": "svc:broker"}
    assert a02["criteria"]["trigger.body.source"]["pattern"] == st2.ORCHESTRATOR_SOURCE
    ev = pack("proposal-validate")["fixtures"][0]["event"]
    assert st2_matches(a01, ev)
    assert not st2_matches(a01, ev | {"source": "profile:triage"})
    packs = all_packs()
    packs["proposal-validate"]["trigger"].pop("where")
    assert ("st2-source", "proposal-validate") in _problems(binding(), packs)
    # the window is keyed by producer too: an event of another source never shares one
    assert st2_runtime.coalesce_name("p", "svc:a", "k") != st2_runtime.coalesce_name(
        "p", "svc:b", "k"
    )


# ---------------------------------------------------------------- steps: shadow, live, broker
def test_shadow_logs_the_offline_request_and_submits_nothing(tmp_path):
    a01 = pack("proposal-validate")
    fx = a01["fixtures"][0]
    [offline] = run_fixture(a01, fx, manifest=manifest()).calls
    got = st2_runtime.step(
        {"broker_socket": "/nonexistent"},
        pinned_dir=pinned_dir(tmp_path),
        broker_factory=lambda _s: NoBroker(),
        pack=a01["pack"],
        step="submit",
        event=st2_runtime.encode(fx["event"]),
    )
    assert got["result"] == "shadow"
    [rec] = calls_of(got)
    assert rec["result"] == "shadow" and rec["reason"] == "st2-shadow"
    assert (rec["request_id"], rec["request_digest"]) == (
        offline.request_id,
        offline.request_digest,
    )
    assert rec["params"] == offline.params


def _live_a02() -> dict:
    b = binding()
    _a02(b)["mode"] = "live"
    _a02(b)["promotion"] = {
        "shadow_from": "2026-01-01",
        "live_from": "2026-01-08",
        "evidence": "docs/parity/a02.md",
    }
    return b


def test_live_calls_or_submits_through_the_broker_only(tmp_path):
    a02 = pack("agent-job-retry")
    ev = a02["fixtures"][0]["event"]
    [st] = workflow_steps("agent-job-retry")
    pdir = pinned_dir(tmp_path, _live_a02())
    enc = st2_runtime.encode(ev)
    fb = FakeBroker()
    out = st2_runtime.step(
        {"broker_socket": "/s"},
        pinned_dir=pdir,
        broker_factory=lambda _s: fb,
        pack=a02["pack"],
        step="resubmit",
        event=enc,
    )
    [rec] = calls_of(out)
    assert rec["result"] == "executed" and fb.calls == [
        ("agent.job.submit", rec["params"], "svc:orchestration")
    ]
    assert rec["params"]["retry_of_run_id"] == "run-0001"
    out = st2_runtime.step(
        {"broker_socket": "/s"},
        pinned_dir=pdir,
        broker_factory=lambda _s: FakeBroker("not-granted"),
        pack=a02["pack"],
        step="resubmit",
        event=enc,
    )
    assert (calls_of(out)[0]["result"], calls_of(out)[0]["reason"]) == ("denied", "not-granted")
    kw = {"pack": a02["pack"], "actor": a02["actor"], "step": st, "event": ev, "mode": "live"}
    fb = FakeBroker()
    out = st2_runtime.run_step(broker=fb, risky=True, **kw)
    assert (out["calls"][0]["result"], fb.calls, len(fb.submits)) == ("held", [], 1)
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
    admitted = st2_runtime.admit_event(
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
    assert params["task_description"] == event["data"]["note"]  # the controller takes no input
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
            assert local is False
            assert ttl == (600 if name.startswith("homelabnext.coalesce.") else 86400)
            self.kv[name] = value

    a02 = pack("agent-job-retry")
    co = _a02(binding())["coalesce"]
    admit = _load_shim("admit", monkeypatch)(action_service=Service())
    ev = a02["fixtures"][0]["event"]
    assert co["window_s"] == 600
    enc = st2_runtime.encode(ev)
    first = admit.run(pack=a02["pack"], event=enc)  # the committed pack's pinned/ directory
    second = admit.run(pack=a02["pack"], event=enc)  # a redelivery: the same id
    third = admit.run(pack=a02["pack"], event=st2_runtime.encode(ev | {"id": "evt-other"}))
    assert (first["reason"], second["reason"], third["reason"]) == (
        "admitted",
        "duplicate",
        "coalesced",
    )
    step = _load_shim("step", monkeypatch)(config={"broker_socket": "/nonexistent"})
    out = step.run(pack=a02["pack"], step="resubmit", event=first["event"], state="")
    assert calls_of(out)[0]["result"] == "shadow"
    with pytest.raises(TypeError):  # the mode is the pinned rule's, never a parameter
        step.run(pack=a02["pack"], step="resubmit", event=first["event"], mode="live")


# ---------------------------------------------------------------- what crosses StackStorm
def _hostile_proposal() -> dict:
    ev = copy.deepcopy(pack("proposal-validate")["fixtures"][0]["event"])
    ev["data"]["summary"] = HOSTILE  # the one free-text field (the note path is a pattern)
    return ev


def st2_jinja_body(body: dict) -> str:
    """What st2 hands the rule's action for ``ENCODED_BODY``: ``to_json_string`` is st2's own
    (``json.dumps`` with its default separators), ``urlencode`` Jinja's (``quote``, ``/`` safe)."""
    text = json.dumps(body, indent=None, sort_keys=False, separators=(",", ": "))
    return urllib.parse.quote(text.encode("utf-8"), safe="/")


def test_rules_pass_the_trigger_encoded_and_never_raw():
    for rule in rules_of().values():
        params = rule["action"]["parameters"]
        assert params == {"event": st2.ENCODED_BODY}, rule["name"]
    passed = st2_jinja_body(_hostile_proposal())
    assert not st2._TEMPLATE.search(passed) and "%>" not in passed
    assert st2_runtime.decode(passed) == _hostile_proposal()


def test_hostile_event_text_never_reaches_an_action_parameter_unencoded(tmp_path):
    pdir = pinned_dir(tmp_path)
    got = st2_runtime.admit(
        pack="proposal-validate",
        pinned_dir=pdir,
        event=st2_jinja_body(_hostile_proposal()),
        kv=KV(),
    )
    assert got["admitted"]
    out = st2_runtime.step(
        {"broker_socket": "/nonexistent"},
        pinned_dir=pdir,
        broker_factory=lambda _s: NoBroker(),
        pack="proposal-validate",
        step="submit",
        event=got["event"],
    )
    for text in (got["event"], out["state"]):  # what the workflow publishes and passes on
        assert isinstance(text, str) and not st2._TEMPLATE.search(text) and "%>" not in text
    assert st2_runtime.decode(got["event"])["data"]["summary"] == HOSTILE
    assert calls_of(out)[0]["result"] == "shadow"
    raw = st2_runtime.admit(pack="proposal-validate", pinned_dir=pdir, event=_hostile_proposal())
    assert raw["reason"] == "invalid-event"  # an object is refused: st2 would have rendered it


def test_stackstorm_jinja_sees_no_marker_in_any_parameter(tmp_path):
    jinja2 = pytest.importorskip("jinja2")
    env = jinja2.Environment()
    env.filters["to_json_string"] = lambda v: json.dumps(v, separators=(",", ": "))
    rule = rules_of()["homelabnext/rules/on_proposal_validate.yaml"]
    body = _hostile_proposal()
    rendered = env.from_string(rule["action"]["parameters"]["event"]).render(trigger={"body": body})
    assert not st2._TEMPLATE.search(rendered)
    assert env.from_string(rendered).render() == rendered  # rendering it again is inert
    got = st2_runtime.admit(
        pack="proposal-validate", pinned_dir=pinned_dir(tmp_path), event=rendered, kv=KV()
    )
    assert st2_runtime.decode(got["event"]) == body


def test_the_tree_check_refuses_raw_trigger_data_and_raw_task_expressions():
    res = go(binding())
    path = "homelabnext/rules/on_proposal_validate.yaml"
    rule = yaml.safe_load(res.files[path])
    rule["action"]["parameters"] = {"event": "{{ trigger.body }}", "mode": "live"}
    bad = dict(res.files) | {path: yaml.safe_dump(rule)}
    assert {(p.path, p.rule) for p in st2.tree_problems(bad, "homelabnext")} == {
        (path, "st2-template")
    }
    wpath = "homelabnext/actions/workflows/proposal_validate.yaml"
    wf = yaml.safe_load(res.files[wpath])
    wf["tasks"]["step_submit"]["input"]["event"] = "<% ctx(event).data %>"
    wf["tasks"]["step_submit"]["input"]["step"] = {"id": "x", "note": "{{ st2kv.system.leak }}"}
    bad = dict(res.files) | {wpath: yaml.safe_dump(wf)}
    got = [p.detail.split(":")[0] for p in st2.tree_problems(bad, "homelabnext")]
    assert got == ["tasks/step_submit/input/event", "tasks/step_submit/input/step"]


def test_the_step_action_runs_only_a_pinned_step_in_its_pinned_mode(tmp_path):
    pdir = pinned_dir(tmp_path)  # shipped: shadow
    ev = st2_runtime.encode(pack("agent-job-retry")["fixtures"][0]["event"])
    kw = {"pack": "agent-job-retry", "pinned_dir": pdir, "broker_factory": lambda _s: NoBroker()}
    assert st2_runtime.step({}, step="resubmit", event=ev, **kw)["result"] == "shadow"
    with pytest.raises(TypeError):
        st2_runtime.step({}, step="resubmit", event=ev, mode="live", **kw)
    with pytest.raises(TypeError):  # no step document from a parameter either
        st2_runtime.step({}, step={"id": "x", "kind": "action", "action": "host.isolate"}, **kw)
    with pytest.raises(st2_runtime.PinError):
        st2_runtime.step({}, step="isolate", event=ev, **kw)
    with pytest.raises(st2_runtime.PinError):
        st2_runtime.step({}, step="resubmit", event=ev, **(kw | {"pack": "../../etc"}))
    other = st2_runtime.encode(pack("agent-job-retry")["fixtures"][1]["event"])  # resubmits: 1
    with pytest.raises(ValueError, match="triggers on"):
        st2_runtime.step({}, step="resubmit", event=other, **kw)
    f = pdir / "agent_job_retry.json"
    doc = json.loads(f.read_text())
    doc["pack"]["steps"][0]["action"] = "host.isolate"  # edited after rendering
    f.write_text(json.dumps(doc))
    with pytest.raises(st2_runtime.PinError, match="digest"):
        st2_runtime.step({}, step="resubmit", event=ev, **kw)


def test_every_called_action_has_its_handler_pinned_in_the_tree(tmp_path):
    assert (
        st2.handler_problem(ROOT, "workflows/broker.manifest.json", "handlers/agent-job-submit.sh")
        is None
    )
    root = tmp_path / "repo"
    (root / "workflows" / "handlers").mkdir(parents=True)
    rel = "workflows/broker.manifest.json"
    assert "not in the tree" in st2.handler_problem(root, rel, "handlers/agent-job-submit.sh")
    sh = root / "workflows" / "handlers" / "agent-job-submit.sh"
    sh.write_text((ROOT / "workflows/handlers/agent-job-submit.sh").read_text() + "# edited\n")
    (root / "workflows/handlers/agent-job-submit.handler.json").write_text(
        (ROOT / "workflows/handlers/agent-job-submit.handler.json").read_text()
    )
    assert "handler_digest" in st2.handler_problem(root, rel, "handlers/agent-job-submit.sh")
    assert "not in the tree" in st2.handler_problem(root, rel, "../../outside.sh")
    res = render(
        binding(),
        all_packs(),
        pins={n: pack_digest(d) for n, d in all_packs().items()},
        manifests=lambda r: universe().manifest(r)[0],
        clean=set(all_packs()),
        handlers=lambda m, h: st2.handler_problem(root, m, h),
    )
    assert {(p.rule, p.detail.split(":")[0]) for p in res.problems} == {
        ("st2-handler", "agent-job-retry"),
        ("st2-handler", "proposal-validate"),
    }


# ---------------------------------------------------------------- the approved-run rule (A03)
RESTART = {
    "pack": "restart-queue",
    "version": 1,
    "description": "restart the queue service (a risky action, held for approval)",
    "actor": "profile:triage",
    "trigger": {
        "event": "homelabnext.agent.job.failed",
        "where": [{"ref": "$event.source", "equals": st2.ORCHESTRATOR_SOURCE}],
    },
    "steps": [
        {
            "id": "restart",
            "kind": "action",
            "action": "service.restart",
            "target": "svc:queue",
            "params": {"grace_s": 30},
        }
    ],
}


def _pin(pdir, doc: dict, mode: str, risky: dict) -> None:
    pin = {"pack": doc, "digest": pack_digest(doc), "mode": mode, "risky": risky}
    (pdir / (st2.st2_name(doc["pack"]) + ".json")).write_text(json.dumps(pin))


def approved_run_dir(tmp_path, run_mode="live", pack_mode="live", actor="profile:triage"):
    """A ``pinned/`` directory as the renderer writes it: a live pack with one risky step, and
    the built-in approved-run pack (both for ``actor``)."""
    pdir = tmp_path / "pinned"
    pdir.mkdir(parents=True, exist_ok=True)
    _pin(pdir, dict(RESTART, actor=actor), pack_mode, {"restart": True})
    _pin(pdir, st2_runtime.approved_run_pack(actor), run_mode, {"run": False})
    return pdir


def _job_failed(i: int) -> dict:
    ev = copy.deepcopy(pack("agent-job-retry")["fixtures"][0]["event"])
    ev["id"] = f"evt-restart-{i}"
    return ev


def _held(svc, pdir, kv, i: int) -> str:
    """Run the risky step live: the broker holds it; returns the broker's request id."""
    out = st2_runtime.step(
        {"broker_socket": "/s"},
        pinned_dir=pdir,
        kv=kv,
        broker_factory=lambda _s: ServiceAsClient(svc, "profile:triage"),
        pack="restart-queue",
        step="restart",
        event=st2_runtime.encode(_job_failed(i)),
    )
    [rec] = calls_of(out)
    assert (rec["result"], rec["recorded"]) == ("held", True)
    return rec["broker_request_id"]


def _returned(rid: str, **over) -> dict:
    """A decision.returned as the broker builds it (svc:broker, accept, human)."""
    from homelabnext.events.envelope import build_event

    data = {"decision_id": rid, "verdict": "accept", "confidence": 1.0, "tier_used": "human"}
    return build_event(
        "homelabnext.decision.returned", "svc:broker", data | over, dedupe_key=f"forged:{rid}"
    )


def _run(pdir, kv, ev: dict, broker) -> dict:
    out = st2_runtime.step(
        {"broker_socket": "/s"},
        pinned_dir=pdir,
        kv=kv,
        broker_factory=lambda _s: broker,
        pack="approved-run",
        step="run",
        event=st2_runtime.encode(ev),
    )
    [rec] = calls_of(out)
    assert out["result"] == rec["result"]
    return rec


def test_the_approved_run_rule_is_rendered_shadow_and_bound_to_the_broker():
    rules = rules_of()
    rule = rules["homelabnext/rules/on_approved_run.yaml"]
    assert rule["action"]["parameters"] == {"event": st2.ENCODED_BODY}
    ev = _returned("restart-0001")
    assert st2_matches(rule, ev)
    assert not st2_matches(rule, _returned("restart-0001", verdict="reject"))
    assert not st2_matches(rule, _returned("restart-0001", tier_used="small"))
    assert not st2_matches(rule, ev | {"source": "svc:decide"})
    res = go(binding())
    pin = json.loads(res.files["homelabnext/pinned/approved_run.json"])
    assert pin["mode"] == "shadow" and pin["pack"] == st2_runtime.approved_run_pack(
        binding()["actor"]
    )
    bridge = json.loads(res.files["bridge.json"])
    [sub] = [x for x in bridge["subscriptions"] if x["subject"] == st2_runtime.DECISION_EVENT]
    assert sub["sources"] == ["svc:broker"] and sub["rules"] == ["homelabnext.on_approved_run"]


def test_the_approved_run_rule_takes_the_promotion_gate_and_its_name():
    b = binding()
    b["approved_run"]["mode"] = "live"
    assert ("st2-live", "approved-run") in _problems(b)
    b["approved_run"]["promotion"] = {
        "shadow_from": "2026-01-01",
        "live_from": "2026-01-03",
        "evidence": "docs/parity/a03.md",
    }
    assert ("st2-live", "approved-run") in _problems(b)  # a two-day window
    b["approved_run"]["promotion"]["live_from"] = "2026-01-08"
    assert ("st2-live", "approved-run") in _problems(b, tracked=lambda _p: False)
    assert _problems(b) == set()
    packs = all_packs()
    packs["approved-run"] = dict(copy.deepcopy(packs["proposal-validate"]), pack="approved-run")
    b = binding()
    b["rules"].append({"pack": "approved-run", "mode": "shadow", "coalesce": _a02(b)["coalesce"]})
    assert ("st2-duplicate", "approved-run") in _problems(b, packs)


def test_an_approved_request_st2_submitted_runs_exactly_once(tmp_path):
    """Live step -> held -> a person approves -> the broker's decision.returned on the bus ->
    the bridge -> the rule -> admit -> the approved-run step -> the broker runs it, once."""
    bus = FakeEventBus()
    svc = BrokerService.from_manifest(
        ROOT / "examples" / "broker" / "manifest.yml",
        tmp_path / "state",
        data_root=tmp_path / "data",
        clock=lambda: T0,
        resolve_secret={"DEMO_API_TOKEN": "fake-demo-token-4b1d"}.__getitem__,
        bus=bus,
    )

    class Capture:
        def __init__(self):
            self.events = []

        def post(self, ev):
            self.events.append(ev)
            return 202

    hook = Capture()
    bridge = st2_bridge.Bridge(
        bus, st2_bridge.load_bridge(json.loads(go(binding()).files["bridge.json"])), hook
    )
    bridge.open()
    pdir, kv = approved_run_dir(tmp_path), KV()
    rid = _held(svc, pdir, kv, 1)
    svc.approve(rid, "sso:operator-one")
    bridge.poll()
    [returned] = hook.events
    assert (returned["type"], returned["data"]["decision_id"]) == (st2_runtime.DECISION_EVENT, rid)
    assert st2_matches(rules_of()["homelabnext/rules/on_approved_run.yaml"], returned)
    admitted = st2_runtime.admit(
        pack="approved-run", pinned_dir=pdir, event=st2_runtime.encode(returned), kv=kv
    )
    assert admitted["admitted"]
    client = ServiceAsClient(svc, "profile:triage")
    rec = _run(pdir, kv, st2_runtime.decode(admitted["event"]), client)
    assert (rec["result"], rec["reason"], rec["pack"]) == ("executed", "approved", "restart-queue")
    assert svc.state.state_of(rid) == "done" and client.runs == 1
    # the same event again: admit drops it; a forged copy past admit runs nothing either
    again = st2_runtime.admit(
        pack="approved-run", pinned_dir=pdir, event=st2_runtime.encode(returned), kv=kv
    )
    assert again["reason"] == "duplicate"
    rec = _run(pdir, kv, returned, client)
    assert (rec["result"], rec["reason"], client.runs) == ("refused", "not-pending", 1)


def test_a_forged_accept_runs_nothing_and_is_refused_with_a_reason(tmp_path, caplog):
    svc = broker_service(tmp_path)
    pdir, kv = approved_run_dir(tmp_path), KV()
    client = ServiceAsClient(svc, "profile:triage")
    pending = _held(svc, pdir, kv, 1)  # held, never approved
    denied = _held(svc, pdir, kv, 2)
    svc.deny(denied, "sso:operator-one")
    other = svc.submit("profile:triage", "service.restart", {"grace_s": 5}, target="svc:queue")
    cases = {
        pending: "not-approved",
        denied: "not-pending",
        other: "not-st2-submitted",  # the agent's own request, not one StackStorm submitted
        "req-nonexistent": "not-st2-submitted",  # an arbitrary id
        "Restart..0001": "invalid-request-id",  # the event schema allows it, a broker id not
    }
    for rid, reason in cases.items():
        rec = _run(pdir, kv, _returned(rid), client)
        assert (rec["result"], rec["reason"]) == ("refused", reason), rid
    assert getattr(client, "runs", 0) == 0
    assert svc.state.state_of(pending) == "pending" and svc.state.state_of(other) == "pending"
    assert "not running" in caplog.text and "not-approved" in caplog.text
    # StackStorm's identity is not the owner: the broker answers not-owner, nothing runs
    svc.approve(pending, "sso:operator-one")
    stranger = ServiceAsClient(svc, "profile:reader")
    rec = _run(pdir, kv, _returned(pending), stranger)
    assert (rec["result"], rec["reason"]) == ("refused", "not-request-owner")
    # a record whose request was changed since (not what was submitted) is refused
    rec_name = st2_runtime.submitted_name(pending)
    sub = st2_runtime.decode(kv.get(rec_name))
    kv.set(rec_name, st2_runtime.encode(sub | {"fingerprint": "sha256:" + "0" * 64}), 60)
    rec = _run(pdir, kv, _returned(pending), client)
    assert (rec["result"], rec["reason"]) == ("refused", "request-mismatch")
    kv.set(rec_name, st2_runtime.encode(sub), 60)
    assert _run(pdir, kv, _returned(pending), client)["result"] == "executed"


def test_the_approved_run_needs_a_live_bound_pack_and_shadow_never_opens_the_socket(tmp_path):
    svc = broker_service(tmp_path)
    kv = KV()
    pdir = approved_run_dir(tmp_path)
    rid = _held(svc, pdir, kv, 1)
    svc.approve(rid, "sso:operator-one")
    shadow = approved_run_dir(tmp_path / "s", run_mode="shadow")
    rec = _run(shadow, kv, _returned(rid), NoBroker())
    assert (rec["result"], rec["reason"], rec["pack"]) == ("shadow", "st2-shadow", "restart-queue")
    not_live = approved_run_dir(tmp_path / "n", pack_mode="shadow")
    rec = _run(not_live, kv, _returned(rid), NoBroker())
    assert (rec["result"], rec["reason"]) == ("refused", "pack-not-live")
    unbound = tmp_path / "u" / "pinned"
    unbound.mkdir(parents=True)
    _pin(unbound, st2_runtime.approved_run_pack("profile:triage"), "live", {"run": False})
    rec = _run(unbound, kv, _returned(rid), NoBroker())
    assert (rec["result"], rec["reason"]) == ("refused", "pack-not-bound")
    # a reject, or another producer, does not even reach the step
    for ev in (_returned(rid, verdict="reject"), _returned(rid) | {"source": "svc:decide"}):
        got = st2_runtime.admit(
            pack="approved-run", pinned_dir=pdir, event=st2_runtime.encode(ev), kv=kv
        )
        assert got["reason"] == "not-triggered"
    assert svc.state.state_of(rid) == "pending"


def test_a_broker_run_step_runs_only_as_the_built_in_pack(tmp_path):
    pdir = approved_run_dir(tmp_path)
    sneaky = dict(st2_runtime.approved_run_pack("profile:triage"), pack="sneaky")
    _pin(pdir, sneaky, "live", {"run": False})
    with pytest.raises(st2_runtime.PinError, match="approved-run"):
        st2_runtime.step(
            {"broker_socket": "/s"},
            pinned_dir=pdir,
            kv=KV(),
            broker_factory=lambda _s: NoBroker(),
            pack="sneaky",
            step="run",
            event=st2_runtime.encode(_returned("restart-0001")),
        )


def test_the_tree_check_refuses_a_rule_that_lost_its_producer_or_its_accept():
    res = go(binding())
    assert st2.tree_problems(res.files, "homelabnext") == []
    path = "homelabnext/rules/on_approved_run.yaml"
    for key, check in (
        ("trigger.body.source", "st2-source"),
        ("trigger.body.data.verdict", "st2-criteria"),
        ("trigger.body.data.tier_used", "st2-criteria"),
    ):
        rule = yaml.safe_load(res.files[path])
        del rule["criteria"][key]
        bad = dict(res.files) | {path: yaml.safe_dump(rule)}
        assert [(p.path, p.rule) for p in st2.tree_problems(bad, "homelabnext")] == [
            (path, check)
        ], key
    rule = yaml.safe_load(res.files["homelabnext/rules/on_agent_job_retry.yaml"])
    rule["criteria"]["trigger.body.source"]["type"] = "exists"
    bad = dict(res.files) | {"homelabnext/rules/on_agent_job_retry.yaml": yaml.safe_dump(rule)}
    assert {p.rule for p in st2.tree_problems(bad, "homelabnext")} >= {"st2-source"}


# ---------------------------------------------------------------- the controller's job contract
HANDLER = ROOT / "workflows" / "handlers" / "agent-job-submit.sh"


def _bound_problems(mutate) -> set[tuple[str, str]]:
    packs = all_packs()
    mutate(packs)
    return {p for p in _problems(binding(), packs) if p[0] == "st2-bound"}


def test_dispatch_sends_only_what_the_controller_takes():
    a01, a02 = ("st2-bound", "proposal-validate"), ("st2-bound", "agent-job-retry")
    assert _bound_problems(lambda p: None) == set()

    def a02_source(p):
        p["agent-job-retry"]["trigger"]["where"][0]["equals"] = "svc:orchestration"

    def a01_input(p):
        p["proposal-validate"]["steps"][0]["params"]["input"] = {"note": "$event.data.note"}

    def a02_payload(p):
        p["agent-job-retry"]["steps"][0]["params"]["task_description"] = "$event.data.run_id"

    def a02_resubmits(p):
        p["agent-job-retry"]["steps"][0]["params"]["resubmits"] = 1

    def a01_reason(p):
        p["proposal-validate"]["steps"][0]["params"]["reason"] = "capacity"

    assert _bound_problems(a02_source) == {a02}  # not the controller's own source id
    assert _bound_problems(a01_input) == {a01}  # 400 input_unsupported
    assert _bound_problems(a02_payload) == {a02}  # 422 payload_override
    assert _bound_problems(a02_resubmits) == {a02}  # the controller counts the lineage
    assert _bound_problems(a01_reason) == {a01}  # reason only with retry_of_run_id


def test_every_fixture_request_is_one_the_handler_schema_accepts():
    from homelabnext.broker.validation import inline_errors

    schema = json.loads(HANDLER.with_name("agent-job-submit.handler.json").read_text())
    schema = schema["params_schema"]
    seen = 0
    for doc in all_packs().values():
        for fx in doc["fixtures"]:
            for call in fx.get("expect", {}).get("calls", []):
                if call["action"] == "agent.job.submit":
                    assert inline_errors(schema, call["params"]) == [], (doc["pack"], fx["name"])
                    seen += 1
    assert seen >= 2
    base = {"agent_key": "triage", "idempotency_key": "k", "priority": 40}
    for bad in (
        base | {"input": {"note": "x"}},
        base | {"resubmits": 0},
        base | {"reason": "capacity"},
        base | {"retry_of_run_id": "run-1", "task_description": "x"},
        base | {"task_description": "{{ st2kv.system.leak }}"},
    ):
        assert inline_errors(schema, bad), bad


@pytest.mark.parametrize(
    ("code", "body", "exit_code", "refused"),
    [
        (202, '{"run_id": "run-9"}', 0, None),
        (200, '{"run_id": "run-1", "replayed": true}', 0, None),  # an idempotent replay
        (409, '{"reason": "already_retried", "retried_by_run_id": "run-2"}', 0, None),
        (409, '{"reason": "retry_chain_spent"}', 0, "retry_chain_spent"),
        (422, '{"reason": "not_retryable", "failure_class": "deadline"}', 0, "not_retryable"),
        (422, '{"reason": "idempotency_key_mismatch"}', 0, "idempotency_key_mismatch"),
        (404, '{"reason": "unknown_run"}', 0, "unknown_run"),
        (400, '{"reason": "input_unsupported"}', 1, None),
        (503, "", 1, None),
        (None, "", 1, None),  # no answer
    ],
)
def test_the_submit_handler_maps_the_controllers_answers(tmp_path, code, body, exit_code, refused):
    import os
    import subprocess

    fake = tmp_path / "bin" / "curl"
    fake.parent.mkdir()
    if code is None:
        script = "#!/bin/sh\ncat >/dev/null\necho 'curl: (7) refused' >&2\nexit 7\n"
    else:
        script = (
            f'#!/bin/sh\nprintf "%s\\n" "$@" > "{tmp_path}/args"\ncat > "{tmp_path}/stdin"\n'
            f"printf '%s\\n%s' '{body}' '{code}'\n"
        )
    fake.write_text(script)
    fake.chmod(0o755)
    env = {
        "PATH": f"{fake.parent}{os.pathsep}/usr/bin{os.pathsep}/bin",
        "ORCHESTRATOR_JOBS_URL": "https://controller.example.invalid/jobs",
    }
    params = (
        b'{"agent_key": "triage", "idempotency_key": "run-0001", "retry_of_run_id": "run-0001"}'
    )
    got = subprocess.run(["/bin/sh", str(HANDLER)], input=params, env=env, capture_output=True)
    assert got.returncode == exit_code, got.stderr
    if code is not None:
        assert "Idempotency-Key: run-0001" in (tmp_path / "args").read_text().splitlines()
        assert (tmp_path / "stdin").read_bytes() == params  # the body goes on unchanged
    if exit_code == 0:
        out = json.loads(got.stdout)
        if refused:
            assert out == {"refused": True, "status": code, "reason": refused}
            assert b"refused by the controller" in got.stderr
        else:
            assert out == json.loads(body)


def test_the_submit_handler_refuses_params_without_a_key(tmp_path):
    import subprocess

    env = {"PATH": "/usr/bin:/bin", "ORCHESTRATOR_JOBS_URL": "https://controller.example.invalid/j"}
    got = subprocess.run(
        ["/bin/sh", str(HANDLER)], input=b'{"agent_key": "x"}', env=env, capture_output=True
    )
    assert got.returncode == 1 and b"no idempotency_key" in got.stderr


def test_a02_skips_a_run_already_retried_and_keys_on_the_run():
    a02 = ("st2-bound", "agent-job-retry")

    def no_auto_skip(p):
        where = p["agent-job-retry"]["trigger"]["where"]
        where[:] = [c for c in where if c["ref"] != "$event.data.auto_retry_scheduled"]

    def event_key(p):
        p["agent-job-retry"]["steps"][0]["params"]["idempotency_key"] = "$event.id"

    assert _bound_problems(no_auto_skip) == {a02}
    assert _bound_problems(event_key) == {a02}  # 422 idempotency_key_mismatch territory
    doc = pack("agent-job-retry")
    ev = _job_failed(9)
    ev["data"] |= {"auto_retry_scheduled": True}
    assert not triggered(doc, ev)
    rule = rules_of()["homelabnext/rules/on_agent_job_retry.yaml"]
    assert not st2_matches(rule, ev)
    got = st2_runtime.admit_event(pack=doc["pack"], trigger=doc["trigger"], event=ev, kv=KV())
    assert got["reason"] == "not-triggered"
