# SPDX-License-Identifier: Apache-2.0
"""Serving-config health check (K-14): probe every model role and alert on a mismatch.

:func:`check_serving` runs :func:`~homelabnext.registry.models.probe_all` (the model id each
backend really serves and its loaded context length) and reports each role's status through a
:class:`homelabnext.notify.Notifier` under the key ``model-serving/<role>``.  The notifier is
state-diffed, so a mismatch pages once when it appears and once more (the registered recovery)
when it clears, never on every run.  Every problem title is registered with its recovery here.
"""

from __future__ import annotations

from homelabnext.notify import Message, Notifier
from homelabnext.notify.core_pairs import SERVING_ERROR, SERVING_MISMATCH, SERVING_UNREACHABLE

from .models import ModelResolver, ProbeResult, Transport, probe_all

KEY_PREFIX = "model-serving/"
#: probe status -> (problem title, recovery title, level)
PAIRS: dict[str, tuple[str, str, str]] = {
    "mismatch": (*SERVING_MISMATCH, "crit"),
    "unreachable": (*SERVING_UNREACHABLE, "warn"),
    "error": (*SERVING_ERROR, "warn"),
}


def register(notifier: Notifier) -> None:
    for problem, recovery, _ in PAIRS.values():
        notifier.register_pair(problem, recovery)


def report(results: list[ProbeResult], notifier: Notifier, *, topic: str | None = None) -> int:
    """Report each result (``ok`` clears); returns the number of messages sent."""
    register(notifier)
    sent = 0
    for r in results:
        key = KEY_PREFIX + r.role
        if r.ok:
            msg = Message(key, SERVING_MISMATCH[1], f"mdl:{r.role} ok", topic=topic)
            sent += notifier.report(key, "ok", msg)
            continue
        title, _, level = PAIRS.get(r.status, PAIRS["error"])
        body = f"mdl:{r.role} ({r.model_id or 'unresolved'}): {r.detail or r.status}"
        msg = Message(key, title, body, level=level, tags=("model", r.status), topic=topic)
        sent += notifier.report(key, r.status, msg)
    return sent


def check_serving(
    resolver: ModelResolver,
    notifier: Notifier,
    *,
    timeout: float = 5.0,
    transport: Transport | None = None,
    topic: str | None = None,
) -> list[ProbeResult]:
    """Probe every role, alert on what changed, and return the results."""
    results = probe_all(resolver, timeout=timeout, transport=transport)
    report(results, notifier, topic=topic)
    return results
