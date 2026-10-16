# SPDX-License-Identifier: Apache-2.0
"""Invariant X-10: every capability has a *passing* conformance test.

X-04 asks whether a conformance test file exists.  X-10 asks whether it passes and could fail:
it runs ``hnx conform report --json`` and reads ``capabilities_without_passing_test``.  A
capability counts only if its suite ran enough checks, no MUST check failed, and every
deliberately broken fake of it was caught.

Loadable the same three ways as every plugin (``homelabnext.invariants.api``): the entry-point
group ``homelabnext.invariants.checks`` (``x10_conformance = homelabnext.conform.plugins.
x10_conformance:register``), ``--plugins-dir`` pointing at this directory, or ``register``.

Pass: the report lists no capability without a passing test.  Fail: it lists some (evidence
names each with its reason).  Skip: this tree has no ``conformance/suites``.  Error: the
report could not be produced or parsed (could not measure).

The target is ``HNX_CONFORM_TARGET`` (default ``fake``), so a deployment can run the same
invariant against its real services.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any

from homelabnext.invariants.api import ERROR, FAIL, PASS, SKIP, Check, CheckResult, Context

CHECK_ID = "X-10"
STATEMENT = "every capability has a passing conformance test"


def _parse(out: str) -> dict[str, Any] | None:
    start = out.find("{")
    if start < 0:
        return None
    try:
        doc, _ = json.JSONDecoder().raw_decode(out[start:])
    except ValueError:
        return None
    return doc if isinstance(doc, dict) and "capabilities_without_passing_test" in doc else None


def x10(ctx: Context) -> CheckResult:
    if not (ctx.root / "conformance" / "suites").is_dir():
        return CheckResult(SKIP, "no conformance/suites in this tree")
    target = os.environ.get("HNX_CONFORM_TARGET", "fake")
    argv = [
        sys.executable,
        "-m",
        "homelabnext.cli",
        "conform",
        "--root",
        str(ctx.root),
        "report",
        "--json",
        "--target",
        target,
    ]
    rc, out = ctx.run(argv, 600)
    doc = _parse(out)
    if rc >= 100:
        return CheckResult(ERROR, f"[exit {rc}] conformance run could not measure: {out[-300:]}")
    if rc == 2 or doc is None:
        return CheckResult(ERROR, f"[exit {rc}] no usable conformance report: {out[-300:]}")
    missing = doc["capabilities_without_passing_test"]
    caps = doc.get("capabilities", {})
    if missing:
        why = "; ".join(f"{c}: {caps.get(c, {}).get('reason', 'no passing test')}" for c in missing)
        return CheckResult(FAIL, f"capabilities without a passing test: {why}"[:700])
    return CheckResult(PASS, f"{len(caps)} capabilities, each with a passing conformance test")


def make_check() -> Check:
    return Check(CHECK_ID, STATEMENT, x10)


def register(registry) -> None:
    registry.register(make_check())
