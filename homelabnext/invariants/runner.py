# SPDX-License-Identifier: Apache-2.0
"""Run criteria, merge results, and page on NEWLY red criteria only.

Exit semantics for an ``observable`` command:
    0        pass (and, if ``expect_regex`` is set, the output matches it)
    1..99    fail
    >=100    could not measure (``error``): the check itself is broken or its target unreachable.
             This is neither a pass nor a fail; collapsing it into either is how a control
             turns decorative.
    timeout  error

Overall runner exit: 1 if anything failed, else 100 if anything could not be measured, else 0.

An observable is a command line that is executed: the register file it comes from is trusted
input (SECURITY.md, "Trusted inputs").
"""

from __future__ import annotations

import datetime as dt
import json
import pathlib
import re
import subprocess
import time
from collections.abc import Callable

from .api import ERROR, FAIL, PASS, SKIP, Context, Registry

__all__ = [
    "EXIT_COULD_NOT_MEASURE",
    "EXIT_FAIL",
    "EXIT_PASS",
    "RESULTS_SCHEMA",
    "diff_state",
    "load_state",
    "overall_exit",
    "page_changes",
    "run_criteria",
    "save_state",
]

EXIT_PASS, EXIT_FAIL, EXIT_COULD_NOT_MEASURE = 0, 1, 100
RESULTS_SCHEMA = "homelabnext.invariants.results/1"
EVIDENCE_MAX = 700
DEFAULT_TIMEOUT = 120
RED = (FAIL, ERROR)


def _command_result(c: dict, ctx: Context):
    tmo = int(c.get("timeout") or DEFAULT_TIMEOUT)
    try:
        p = subprocess.run(
            ["bash", "-o", "pipefail", "-c", c["observable"]],
            capture_output=True,
            text=True,
            timeout=tmo,
            cwd=ctx.root,
        )
    except subprocess.TimeoutExpired:
        return ERROR, f"timeout after {tmo}s"
    out = (p.stdout or "").strip() or (p.stderr or "").strip()
    if p.returncode >= 100:
        return ERROR, f"[exit {p.returncode}] " + (out or "check could not measure")
    if p.returncode != 0:
        return FAIL, f"[exit {p.returncode}] {out}".strip()
    rx = c.get("expect_regex")
    if rx and not re.search(rx, out):
        return FAIL, f"exit 0 but output does not match /{rx}/: {out}"
    return PASS, out


def _plugin_result(c: dict, ctx: Context, registry: Registry):
    chk = registry.get(c["plugin"])
    if chk is None:
        return ERROR, f"no plugin registered for {c['plugin']}"
    try:
        r = chk.fn(ctx)
        return r.status, r.evidence
    except Exception as ex:
        return ERROR, f"{type(ex).__name__}: {ex}"


def run_criteria(
    criteria: list[dict],
    ctx: Context,
    registry: Registry | None = None,
    *,
    only: set[str] | None = None,
    fast: bool = False,
    clock: Callable[[], dt.datetime] | None = None,
    timer: Callable[[], float] = time.monotonic,
    previous: dict | None = None,
) -> dict:
    """Execute runnable criteria and return a results document.

    ``previous`` (an earlier results doc) is merged for criteria not run (``only``) and supplies
    ``checked_at`` stability: a criterion's ``checked_at`` only advances when its status or
    evidence changes, so an unchanged re-run produces an identical document.
    """
    registry = registry or Registry()
    clock = clock or (lambda: dt.datetime.now(dt.UTC))
    now = clock().replace(microsecond=0).isoformat()
    prev = dict((previous or {}).get("results", {}))
    results = dict(prev) if only else {}
    for c in criteria:
        if only and c["id"] not in only:
            continue
        ev = c.get("evidence")
        if ev not in ("auto", "plugin"):
            continue
        slow = c.get("slow") or (
            registry.get(c.get("plugin", "")) and registry.get(c["plugin"]).slow
        )
        if fast and slow:
            continue
        t0 = timer()
        status, text = _command_result(c, ctx) if ev == "auto" else _plugin_result(c, ctx, registry)
        text = text[-EVIDENCE_MAX:]
        old = prev.get(c["id"], {})
        same = old.get("status") == status and old.get("evidence") == text
        results[c["id"]] = {
            "status": status,
            "evidence": text,
            "duration_s": round(timer() - t0, 1),
            "checked_at": old["checked_at"] if same else now,
        }
    return {"schema": RESULTS_SCHEMA, "last_run": now[:10], "results": results}


def overall_exit(results_doc: dict) -> int:
    sts = [r["status"] for r in results_doc["results"].values()]
    if FAIL in sts:
        return EXIT_FAIL
    return EXIT_COULD_NOT_MEASURE if ERROR in sts else EXIT_PASS


def diff_state(prev: dict[str, str], results_doc: dict) -> tuple[list[str], list[str]]:
    """(newly_red, recovered) comparing the last-seen status per id with the current one.

    Newly red = red now, and not red before (absent counts as not red, so a brand-new failing
    criterion pages once). Recovered = red before, passing now. fail<->error is neither: the
    criterion was already red, so the standing set is never re-paged.
    """
    cur = {i: r["status"] for i, r in results_doc["results"].items()}
    newly = sorted(i for i, s in cur.items() if s in RED and prev.get(i) not in RED)
    rec = sorted(i for i, s in cur.items() if s == PASS and prev.get(i) in RED)
    return newly, rec


def load_state(path) -> dict[str, str]:
    p = pathlib.Path(path)
    try:
        return json.loads(p.read_text())
    except (OSError, ValueError):
        return {}


def save_state(path, prev: dict[str, str], results_doc: dict) -> None:
    """Persist statuses (atomically). Skip results do not overwrite a known status."""
    merged = dict(prev)
    for i, r in results_doc["results"].items():
        if r["status"] != SKIP:
            merged[i] = r["status"]
    p = pathlib.Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(merged, indent=2, sort_keys=True) + "\n")
    tmp.replace(p)


def page_changes(
    results_doc: dict, state_path, sender: Callable[[str, str], None], *, baseline: bool = False
) -> tuple[list[str], list[str]]:
    """Send at most one 'newly broken' and one 'recovered' message, then persist state.

    ``sender(title, body)`` is injected (a fake in tests, an ntfy/webhook/mail adapter live).
    State is saved only AFTER a successful send, so a failed page is retried next run rather
    than lost. ``baseline=True`` records the current state without paging (first adoption).
    """
    prev = load_state(state_path)
    newly, rec = diff_state(prev, results_doc)
    if not baseline:
        res = results_doc["results"]
        if newly:
            sender(
                "Invariant newly broken",
                "\n".join(f"{i} {res[i]['status']}: {res[i]['evidence'][:200]}" for i in newly),
            )
        if rec:
            sender("Invariant recovered", "\n".join(f"{i} recovered" for i in rec))
    save_state(state_path, prev, results_doc)
    return newly, rec
