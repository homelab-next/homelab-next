# SPDX-License-Identifier: Apache-2.0
"""``codemode-runner``: the handler of ``codemode.execute`` (ADR-0031 decisions 2, 6, 7 and 10;
``docs/codemode.md`` CM-5b).

Every check asks the subject's broker, as an agent, to run a real program through
``codemode.execute`` and judges what comes back: the execution result, the broker's own state
(a request still pending, which handlers ran) and the runner's journal.  The rules are those of
:mod:`conformance.protocols.codemode_runner`, one check each.  Commands are registered on the
broker through its contract (``register``, ``allow``), so a target is a runner over any broker
that declares ``codemode-tokens``.  Each check holds its programs per language: a language the
runner declares and a check has no program for fails the check as untested.  The programs are
Python only, as the executor suite's are."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from conformance.fakes.codemode_runner import (
    CapHiddenRunner,
    DenialAsErrorRunner,
    DeniedWaitsRunner,
    HiddenPauseRunner,
    RawLogsRunner,
    ReferenceRunner,
    ResendingRunner,
    StepOnlyReplayRunner,
    UnjournalledRefusalRunner,
)
from conformance.protocols.broker import CODEMODE_EXECUTE, TOKEN_REFUSALS, ArgSpec, code_digest
from homelabnext.broker.validation import named_errors
from homelabnext.conform.core import Mutant, Suite

from ._util import uniq

SUITE = Suite(
    "codemode-runner",
    "the codemode.execute handler: schema results, denials as values, a journal of every call, "
    "pause on submit, resume without replay, the broker's cap",
    "conformance.protocols.codemode_runner:CodemodeRunner",
)

TOKENS = ["codemode-tokens"]
ARGS = {"name": ArgSpec("str")}
_REASON = re.compile(r"^[a-z][a-z0-9-]{0,63}$")


class _Lab:
    """An agent granted ``codemode.execute`` and a few commands, each counting its runs."""

    def __init__(self, r: Any, n: int = 3) -> None:
        self.r, self.b = r, r.broker
        self.agent = f"profile:{uniq('agent')}"
        self.cmds = [f"cm.{uniq('cmd')}" for _ in range(n)]
        self.ran: dict[str, list[str]] = {c: [] for c in self.cmds}
        for cmd in self.cmds:
            self.b.register(cmd, self._handler(cmd), ARGS)
        self.b.allow(self.agent, [CODEMODE_EXECUTE, *self.cmds])
        # another agent's command: granted to someone else, never in this agent's token
        self.other = f"cm.{uniq('cmd')}"
        self.b.register(self.other, self._handler(self.other), ARGS)
        self.ran[self.other] = []
        self.b.allow(f"profile:{uniq('admin')}", [self.other])

    def _handler(self, cmd: str):
        def handler(**kw):
            self.ran[cmd].append(kw["name"])
            return {"ok": kw["name"]}

        return handler

    def execute(self, code: str, language: str, *, eid: str | None = None, resume=False, **budget):
        params: dict[str, Any] = {
            "execution_id": eid or uniq("exec"),
            "language": language,
            "code": code,
        }
        if budget:
            params["budget"] = budget
        if resume:
            params["resume"] = True
        return dict(self.b.call(self.agent, CODEMODE_EXECUTE, params)), params


def _languages(r: Any, *programs: Mapping[str, str]) -> list[str]:
    """The languages the runner declares, each with a program in every table: a declared
    language a table lacks fails the check as untested."""
    langs = sorted(r.languages)
    assert langs, "the runner declares no language"
    missing = sorted({lang for lang in langs for p in programs if lang not in p})
    assert not missing, f"untested: this check has no program in {', '.join(missing)}"
    return langs


def _ids(call: Mapping[str, Any]) -> bool:
    return "request_id" in call or "request_digest" in call


def _schema(name: str, doc: Any) -> list[str]:
    return named_errors(f"codemode/{name}", doc)


@SUITE.check(
    "result-matches-the-schema",
    "an execution result is a schemas/codemode/execution_result: the execution, the actor, the "
    "program's code digest, the status and value, every call with its request ids, and printed "
    "output as single lines whatever the program printed",
    requires=TOKENS,
)
def _(r):
    lab = _Lab(r)
    cmd = lab.cmds[0]
    programs = {
        "python": (
            f"a = broker.call({cmd!r}, {{'name': 'one'}})\n"
            "print('a plain line')\n"
            "print('an \\x1b[31mescaped\\x1b[0m line\\u2028with a separator')\n"
            "result = {'a': a}\n"
        )
    }
    for lang in _languages(r, programs):
        res, params = lab.execute(programs[lang], lang)
        problems = _schema("execution_result", res)
        assert problems == [], f"{lang}: the result is not the schema's: {problems[:3]}"
        want = {
            "execution_id": params["execution_id"],
            "actor": lab.agent,
            "code_digest": code_digest(lang, programs[lang]),
            "status": "ok",
            "value": {"a": {"ok": "one"}},
        }
        got = {k: res.get(k) for k in want}
        assert got == want, f"{lang}: the result says {got}, not {want}"
        calls = res["calls"]
        assert [(c["step"], c["action"], c["outcome"]) for c in calls] == [(0, cmd, "ok")], calls
        assert _ids(calls[0]), f"{lang}: a call the broker answered names no request: {calls[0]}"
        assert any("escaped" in line for line in res.get("logs", [])), (
            f"{lang}: printed output is not in logs: {res.get('logs')}"
        )


@SUITE.check(
    "denied-call-is-a-value",
    "a broker refusal reaches the program as broker.Denied with the broker's reason, which it can "
    "catch and go on, and is a denied call with that reason (with request ids once the broker "
    "built the request, none for a token refusal); an uncaught one ends the run denied",
    requires=TOKENS,
)
def _(r):
    lab = _Lab(r)
    cmd, other = lab.cmds[0], lab.other
    caught = {
        "python": (
            "out = []\n"
            f"for action, args in [({other!r}, {{'name': 'x'}}), ({cmd!r}, {{'wrong': 1}})]:\n"
            "    try:\n"
            "        broker.call(action, args)\n"
            "        out.append('ran')\n"
            "    except broker.Denied as exc:\n"
            "        out.append(exc.reason)\n"
            f"out.append(broker.call({cmd!r}, {{'name': 'after'}}))\n"
            "result = out\n"
        )
    }
    escaped = {"python": f"broker.call({cmd!r}, {{'wrong': 1}})\nresult = 'went on'\n"}
    for lang in _languages(r, caught, escaped):
        res, _ = lab.execute(caught[lang], lang)
        assert res["status"] == "ok", f"{lang}: a program that caught its denials ended {res}"
        value, calls = res.get("value"), res["calls"]
        assert isinstance(value, list) and len(value) == 3, f"{lang}: the program saw {value}"
        assert value[0] == "token-action-not-allowed", (
            f"{lang}: an action outside the token reached the program as {value[0]!r}"
        )
        assert isinstance(value[1], str) and _REASON.match(value[1]), (
            f"{lang}: invalid arguments reached the program as {value[1]!r}"
        )
        assert value[1] not in (*TOKEN_REFUSALS, "ran", "approved", "allowed"), (
            f"{lang}: the broker's refusal of invalid arguments reached the program as "
            f"{value[1]!r}, not the broker's own reason"
        )
        assert value[2] == {"ok": "after"}, f"{lang}: the call after the denials got {value[2]}"
        shape = [(c["step"], c["outcome"], c.get("reason")) for c in calls]
        assert shape == [
            (0, "denied", "token-action-not-allowed"),
            (1, "denied", value[1]),
            (2, "ok", None),
        ], f"{lang}: the calls were recorded {shape}"
        assert not _ids(calls[0]), f"{lang}: a token refusal names a request: {calls[0]}"
        assert _ids(calls[1]), f"{lang}: a refusal of a built request names none: {calls[1]}"
        assert lab.ran[other] == [], f"{lang}: another agent's command ran"
        res, _ = lab.execute(escaped[lang], lang)
        assert res["status"] == "denied", f"{lang}: an uncaught denial ended {res['status']}"
        assert [c["outcome"] for c in res["calls"]] == ["denied"], res["calls"]
        assert "value" not in res, f"{lang}: a denied run returned a value"
    assert lab.ran[cmd] == ["after"] * len(_languages(r, caught)), lab.ran[cmd]


@SUITE.check(
    "every-call-is-journalled",
    "every call the broker answered with a request id has a journal_step record bound to the "
    "actor and the code digest, with its step, action, request id and digest, outcome and "
    "reason or result; a token refusal is not journalled",
    requires=TOKENS,
)
def _(r):
    lab = _Lab(r)
    cmd, other = lab.cmds[0], lab.other
    programs = {
        "python": (
            f"seen = [broker.call({cmd!r}, {{'name': 'one'}})]\n"
            f"for action, args in [({cmd!r}, {{'wrong': 1}}), ({other!r}, {{'name': 'x'}})]:\n"
            "    try:\n"
            "        broker.call(action, args)\n"
            "    except (broker.Denied, broker.Error) as exc:\n"
            "        seen.append(exc.reason)\n"
            f"broker.submit({cmd!r}, {{'name': 'later'}})\n"
        )
    }
    for lang in _languages(r, programs):
        res, params = lab.execute(programs[lang], lang)
        eid, digest = params["execution_id"], code_digest(lang, programs[lang])
        records = list(r.journal(lab.agent, eid))
        for rec in records:
            problems = _schema("journal_step", rec)
            assert problems == [], f"{lang}: a journal record is not the schema's: {problems[:3]}"
            got = (rec.get("execution_id"), rec.get("actor"), rec.get("code_digest"))
            assert got == (eid, lab.agent, digest), f"{lang}: a record is bound to {got}"
        latest = {rec["step"]: rec for rec in records}
        brokered = [c for c in res["calls"] if _ids(c)]
        assert [c["step"] for c in brokered] == [0, 1, 3], f"{lang}: the calls were {res['calls']}"
        assert sorted(latest) == [0, 1, 3], (
            f"{lang}: the journal holds steps {sorted(latest)}, not the three the broker answered"
        )
        for call in brokered:
            rec = latest[call["step"]]
            keys = ("action", "request_id", "request_digest", "outcome", "reason")
            assert {k: rec.get(k) for k in keys} == {k: call.get(k) for k in keys}, (
                f"{lang}: step {call['step']} is journalled as {rec}, recorded as {call}"
            )
        assert latest[0].get("result") == {"ok": "one"} and latest[0].get("result_digest"), (
            f"{lang}: the ok step keeps no result: {latest[0]}"
        )
        assert latest[1]["outcome"] == "denied" and latest[1].get("reason"), latest[1]
        assert latest[3]["outcome"] == "pending", latest[3]


@SUITE.check(
    "submit-pauses-the-run",
    "a submit leaves its request pending at the broker and ends the run paused, pending naming "
    "the step, action and request; the program makes no call after it",
    requires=TOKENS,
)
def _(r):
    lab = _Lab(r)
    first, held, after = lab.cmds
    programs = {
        "python": (
            f"one = broker.call({first!r}, {{'name': 'one'}})\n"
            f"broker.submit({held!r}, {{'name': 'approve-me'}})\n"
            f"broker.call({after!r}, {{'name': 'after'}})\n"
            "result = 'went on'\n"
        )
    }
    for lang in _languages(r, programs):
        res, _ = lab.execute(programs[lang], lang)
        assert res["status"] == "paused", f"{lang}: a run that submitted ended {res['status']}"
        calls = res["calls"]
        assert [(c["step"], c["action"], c["outcome"]) for c in calls] == [
            (0, first, "ok"),
            (1, held, "pending"),
        ], f"{lang}: a paused run's calls were {calls}"
        want = [
            {
                "step": 1,
                "action": held,
                "request_id": calls[1].get("request_id"),
                "request_digest": calls[1].get("request_digest"),
            }
        ]
        assert res.get("pending") == want and _ids(calls[1]), (
            f"{lang}: pending is {res.get('pending')}, not the submitted call"
        )
        state = lab.b.status(lab.agent, calls[1]["request_id"]).state
        assert state == "pending", f"{lang}: the submitted request is {state}, not pending"
        assert "value" not in res, f"{lang}: a paused run returned a value"
    assert lab.ran[held] == [] and lab.ran[after] == [], (
        f"after the submit, {held} ran {lab.ran[held]} and {after} ran {lab.ran[after]}"
    )


@SUITE.check(
    "resume-without-replay",
    "a resume of a paused execution answers its journalled steps from the journal (replayed), "
    "runs the paused request by its id and sends only the calls after it; a finished execution "
    "never resumes",
    requires=TOKENS,
)
def _(r):
    lab = _Lab(r)
    a, b, c = lab.cmds
    programs = {
        "python": (
            f"x = broker.call({a!r}, {{'name': 'one'}})\n"
            f"y = broker.submit({b!r}, {{'name': 'two'}})\n"
            f"z = broker.call({c!r}, {{'name': 'three'}}) if y else None\n"
            "result = [x, y, z]\n"
        )
    }
    langs = _languages(r, programs)
    for lang in langs:
        code, eid = programs[lang], uniq("exec")
        first, _ = lab.execute(code, lang, eid=eid)
        assert first["status"] == "paused", f"{lang}: the first run ended {first['status']}"
        paused = first["calls"]
        res, _ = lab.execute(code, lang, eid=eid, resume=True)
        assert res["status"] == "ok", f"{lang}: the resumed run ended {res}"
        assert res.get("value") == [{"ok": "one"}, {"ok": "two"}, {"ok": "three"}], (
            f"{lang}: the resumed program computed {res.get('value')}"
        )
        calls = res["calls"]
        shape = [(x["step"], x["outcome"], x.get("replayed", False)) for x in calls]
        assert shape == [(0, "ok", True), (1, "ok", False), (2, "ok", False)], (
            f"{lang}: the resumed run's calls were {shape}"
        )
        for step in (0, 1):
            assert calls[step].get("request_id") == paused[step].get("request_id"), (
                f"{lang}: step {step} of the resume is request {calls[step].get('request_id')}, "
                f"not the journalled {paused[step].get('request_id')}"
            )
        again, _ = lab.execute(code, lang, eid=eid, resume=True)
        assert again["status"] == "error" and again["calls"] == [], (
            f"{lang}: a finished execution resumed: {again}"
        )
    n = len(langs)
    ran = {k: lab.ran[k] for k in (a, b, c)}
    assert ran == {a: ["one"] * n, b: ["two"] * n, c: ["three"] * n}, (
        f"over a run and its resume each command ran {ran}: a journalled step was sent again"
    )


@SUITE.check(
    "resume-refuses-a-different-call",
    "a resume whose program makes another call than the journal holds at a step never replays "
    "the journal into it: the call is refused replay-mismatch, nothing after it is sent, and the "
    "run ends error",
    requires=TOKENS,
)
def _(r):
    lab = _Lab(r)
    a, b = lab.cmds[:2]
    programs = {
        "python": (
            "import time\n"
            f"broker.call({a!r}, {{'name': str(time.time_ns())}})\n"
            f"broker.submit({b!r}, {{'name': 'held'}})\n"
            "result = 'went on'\n"
        )
    }
    langs = _languages(r, programs)
    for lang in langs:
        eid = uniq("exec")
        first, _ = lab.execute(programs[lang], lang, eid=eid)
        assert first["status"] == "paused", f"{lang}: the first run ended {first['status']}"
        res, _ = lab.execute(programs[lang], lang, eid=eid, resume=True)
        assert res["status"] == "error", f"{lang}: a resume with a different call ended {res}"
        assert not any(c.get("replayed") for c in res["calls"]), (
            f"{lang}: a different call was answered from the journal: {res['calls']}"
        )
    assert lab.ran[a], f"{a} never ran"
    assert lab.ran[b] == [], f"the held request ran after a replay mismatch: {lab.ran[b]}"


@SUITE.check(
    "denied-pause-is-a-value",
    "a resume of a run paused on a request its approver denied tells the program the reason "
    "with reason request-denied, a denied call naming that request",
    requires=[*TOKENS, "approval-control"],
)
def _(r):
    lab = _Lab(r)
    held = lab.cmds[0]
    programs = {
        "python": (
            "try:\n"
            f"    broker.submit({held!r}, {{'name': 'risky'}})\n"
            "    result = 'ran'\n"
            "except (broker.Denied, broker.Error) as exc:\n"
            "    result = exc.reason\n"
        )
    }
    for lang in _languages(r, programs):
        eid = uniq("exec")
        first, _ = lab.execute(programs[lang], lang, eid=eid)
        assert first["status"] == "paused", f"{lang}: the submit ended {first['status']}"
        rid = first["pending"][0]["request_id"]
        lab.b.decide_request(rid, "denied")
        res, _ = lab.execute(programs[lang], lang, eid=eid, resume=True)
        assert (res["status"], res.get("value")) == ("ok", "request-denied"), (
            f"{lang}: the program saw a denied pause as {res.get('status')} {res.get('value')!r}"
        )
        (call,) = res["calls"]
        assert (call["outcome"], call.get("reason"), call.get("request_id")) == (
            "denied",
            "request-denied",
            rid,
        ), f"{lang}: the denied pause was recorded {call}"
        assert call.get("request_digest") == first["pending"][0]["request_digest"], call
    assert lab.ran[held] == [], f"a denied request ran: {lab.ran[held]}"


@SUITE.check(
    "call-cap-ends-the-run",
    "a call the broker refuses call-cap-reached is a denied call without request ids, and the run "
    "ends limit (calls) however the program handled the refusal",
    requires=TOKENS,
)
def _(r):
    lab = _Lab(r)
    cmd = lab.cmds[0]
    programs = {
        "python": (
            "got = []\n"
            "for i in range(3):\n"
            "    try:\n"
            f"        got.append(broker.call({cmd!r}, {{'name': str(i)}}))\n"
            "    except (broker.Denied, broker.Error) as exc:\n"
            "        got.append(exc.reason)\n"
            "result = got\n"
        )
    }
    for lang in _languages(r, programs):
        res, _ = lab.execute(programs[lang], lang, max_calls=2)
        assert (res["status"], res.get("limit")) == ("limit", "calls"), (
            f"{lang}: a run past the broker's cap ended {res['status']} ({res.get('limit')})"
        )
        last = res["calls"][-1]
        assert (len(res["calls"]), last["outcome"], last.get("reason")) == (
            3,
            "denied",
            "call-cap-reached",
        ), f"{lang}: the calls were {res['calls']}"
        assert last.get("reason") in TOKEN_REFUSALS and not _ids(last), last
    assert len(lab.ran[cmd]) == 2 * len(_languages(r, programs)), lab.ran[cmd]


def make_fake():
    return ReferenceRunner()


def _m(factory, check, description):
    return Mutant(factory, check, description, features=frozenset(TOKENS))


MUTANTS = {
    "raw-logs-unchecked-result": _m(
        RawLogsRunner,
        "result-matches-the-schema",
        "printed output reaches logs with its control characters and the result is not held to "
        "its schema",
    ),
    "denial-as-error": _m(
        DenialAsErrorRunner,
        "denied-call-is-a-value",
        "a broker refusal reaches the program as broker.Error, so it cannot tell a denial apart",
    ),
    "refusals-unjournalled": _m(
        UnjournalledRefusalRunner,
        "every-call-is-journalled",
        "a refusal the broker answered with a request id is not journalled",
    ),
    "pause-hidden": _m(
        HiddenPauseRunner,
        "submit-pauses-the-run",
        "a pending answer is told to the program as ok, so it runs on past the pause",
    ),
    "resume-resends": _m(
        ResendingRunner,
        "resume-without-replay",
        "a resume sends every journalled step to the broker again",
    ),
    "replay-by-step-only": _m(
        StepOnlyReplayRunner,
        "resume-refuses-a-different-call",
        "a resume replays a journalled step by its number whatever the call at that step now is",
    ),
    "denied-pause-waits": Mutant(
        DeniedWaitsRunner,
        "denied-pause-is-a-value",
        "a pause whose request was denied reads as still waiting: the resume pauses for ever",
        features=frozenset([*TOKENS, "approval-control"]),
    ),
    "cap-hidden": _m(
        CapHiddenRunner,
        "call-cap-ends-the-run",
        "a call refused call-cap-reached leaves the run with the program's own status",
    ),
}
