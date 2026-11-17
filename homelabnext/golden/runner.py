# SPDX-License-Identifier: Apache-2.0
"""Run a golden suite against any model-role alias: a chat suite through a completer, a decision
suite (``kind: decision``) through a decider, which asks the role noul questions on
``POST /v1/systemone`` (:meth:`homelabnext.registry.models.ModelClient.decide`)."""

from __future__ import annotations

import math
import time
from collections.abc import Callable, Mapping

from homelabnext.registry.models import ModelClient, ModelResolver

from .report import Report, TaskResult
from .scorers import score
from .tasks import Suite

#: ``completer(messages, params) -> output text``
Completer = Callable[[list[dict], dict], str]
#: ``decider(questions, state) -> {question id: probability}``: noul questions (``{id:
#: instructions}``) about ``state``, answered by a decision role
Decider = Callable[[Mapping[str, str], "str | None"], Mapping[str, float]]


def client_completer(resolver: ModelResolver, role: str, **client_kwargs) -> tuple[Completer, str]:
    """Build a completer for ``mdl:<role>`` through the resolver; returns it with the model id."""
    rm = resolver.resolve(role)
    client = ModelClient(rm, **client_kwargs)

    def complete(messages: list[dict], params: dict) -> str:
        return client.chat(messages, **params).text

    return complete, rm.model_id


def client_decider(resolver: ModelResolver, role: str, **client_kwargs) -> tuple[Decider, str]:
    """Build a decider for the decision role ``mdl:<role>`` through the resolver (the same
    :class:`ModelClient` a completer uses, on ``POST /v1/systemone``); returns it with the model
    id."""
    rm = resolver.resolve(role)
    client = ModelClient(rm, **client_kwargs)

    def decide(questions: Mapping[str, str], state: str | None) -> Mapping[str, float]:
        return client.decide(questions, state=state).probabilities

    return decide, rm.model_id


def one_probability(answers: object, qid: str) -> float:
    """The probability a decider answered for question ``qid``: the answers must be a mapping
    holding exactly that question, with a number in [0, 1]; anything else is a ValueError."""
    if not isinstance(answers, Mapping) or set(answers) != {qid}:
        raise ValueError(f"the answers do not hold exactly question {qid!r}")
    p = answers[qid]
    if isinstance(p, bool) or not isinstance(p, (int, float)):
        raise ValueError(f"question {qid!r}: the answer is not a number")
    if not (math.isfinite(p) and 0.0 <= p <= 1.0):
        raise ValueError(f"question {qid!r}: {p} is not a probability in [0, 1]")
    return float(p)


def run_decision_suite(
    suite: Suite,
    decider: Decider,
    *,
    role: str | None = None,
    model_id: str = "",
    clock: Callable[[], float] = time.monotonic,
) -> Report:
    """A decision suite against a decider: one noul question per task (id = the task id,
    instructions = its ``question``, state = its ``prompt``), scored by the task's probability
    band.  The report is a chat suite's, the answer kept as text."""
    if suite.kind != "decision":
        raise ValueError(f"suite {suite.name}: not a decision suite (kind {suite.kind!r})")
    role_name = (role or suite.role or "").removeprefix("mdl:")
    rep = Report(suite.name, role_name, model_id, suite.pass_score)
    for t in suite.tasks:
        t0 = clock()
        out, err = "", ""
        s, detail = 0.0, "no output"
        try:
            p = one_probability(decider({t.id: t.question}, t.prompt), t.id)
            out = f"{p:.4f}"
            s, detail = score(repr(p), t.expect)
        except Exception as exc:  # a backend failure or a malformed answer fails the task
            err = f"{type(exc).__name__}: {exc}"
        ms = (clock() - t0) * 1000
        if err:
            rep.results.append(TaskResult(t.id, 0.0, False, detail, out, err, ms, t.weight))
            continue
        rep.results.append(
            TaskResult(t.id, s, s >= suite.pass_score, detail, out, "", ms, t.weight)
        )
    return rep


def run_suite(
    suite: Suite,
    completer: Completer,
    *,
    role: str | None = None,
    model_id: str = "",
    clock: Callable[[], float] = time.monotonic,
) -> Report:
    if suite.kind == "decision":
        raise ValueError(
            f"suite {suite.name}: a decision suite runs through a decider (run_decision_suite)"
        )
    role_name = (role or suite.role or "").removeprefix("mdl:")
    rep = Report(suite.name, role_name, model_id, suite.pass_score)
    for t in suite.tasks:
        t0 = clock()
        out, err = "", ""
        s, detail = 0.0, "no output"
        try:
            out = completer(t.messages(), dict(t.params))
            try:
                s, detail = score(out, t.expect)
            except Exception as exc:
                s, detail, err = 0.0, "scorer error", f"{type(exc).__name__}: {exc}"
        except Exception as exc:  # a backend or scorer failure is a failed task, not a crashed run
            err = f"{type(exc).__name__}: {exc}"
        ms = (clock() - t0) * 1000
        if err:
            rep.results.append(TaskResult(t.id, 0.0, False, detail, out, err, ms, t.weight))
            continue
        rep.results.append(
            TaskResult(t.id, s, s >= suite.pass_score, detail, out, "", ms, t.weight)
        )
    return rep
