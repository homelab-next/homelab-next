# SPDX-License-Identifier: Apache-2.0
"""Run a golden suite against any model-role alias."""

from __future__ import annotations

import time
from collections.abc import Callable

from homelabnext.registry.models import ModelClient, ModelResolver

from .report import Report, TaskResult
from .scorers import score
from .tasks import Suite

#: ``completer(messages, params) -> output text``
Completer = Callable[[list[dict], dict], str]


def client_completer(resolver: ModelResolver, role: str, **client_kwargs) -> tuple[Completer, str]:
    """Build a completer for ``mdl:<role>`` through the resolver; returns it with the model id."""
    rm = resolver.resolve(role)
    client = ModelClient(rm, **client_kwargs)

    def complete(messages: list[dict], params: dict) -> str:
        return client.chat(messages, **params).text

    return complete, rm.model_id


def run_suite(
    suite: Suite,
    completer: Completer,
    *,
    role: str | None = None,
    model_id: str = "",
    clock: Callable[[], float] = time.monotonic,
) -> Report:
    role_name = (role or suite.role or "").removeprefix("mdl:")
    rep = Report(suite.name, role_name, model_id, suite.pass_score)
    for t in suite.tasks:
        t0 = clock()
        out, err = "", ""
        try:
            out = completer(t.messages(), dict(t.params))
        except Exception as exc:  # a backend failure is a failed task, not a crashed run
            err = f"{type(exc).__name__}: {exc}"
        ms = (clock() - t0) * 1000
        if err:
            rep.results.append(
                TaskResult(t.id, 0.0, False, "no output", error=err, latency_ms=ms, weight=t.weight)
            )
            continue
        s, detail = score(out, t.expect)
        rep.results.append(
            TaskResult(t.id, s, s >= suite.pass_score, detail, out, "", ms, t.weight)
        )
    return rep
