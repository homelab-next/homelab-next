# SPDX-License-Identifier: Apache-2.0
"""Invariant X-10: every capability has a *passing* conformance test.

X-04 asks whether a conformance test file exists.  X-10 asks whether it passes and could fail:
it runs ``hnx conform report --out FILE`` and reads ``capabilities_without_passing_test`` from
that file.  The report is never scraped from the process output: an adapter imported during the
run can print anything to stdout or stderr, including a JSON document that looks like a clean
report.  The file must carry the report schema, and its verdict must agree with the exit code.  A
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
import tempfile
from pathlib import Path
from typing import Any

from homelabnext.conform.report import SCHEMA
from homelabnext.invariants.api import ERROR, FAIL, PASS, SKIP, Check, CheckResult, Context

CHECK_ID = "X-10"
STATEMENT = "every capability has a passing conformance test"


def _parse(text: str) -> dict[str, Any] | None:
    """The report document, or None unless ``text`` is exactly one well-formed report."""
    try:
        doc = json.loads(text)
    except ValueError:
        return None
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA:
        return None
    missing = doc.get("capabilities_without_passing_test")
    if not isinstance(missing, list) or not isinstance(doc.get("capabilities"), dict):
        return None
    return doc


def x10(ctx: Context) -> CheckResult:
    if not (ctx.root / "conformance" / "suites").is_dir():
        return CheckResult(SKIP, "no conformance/suites in this tree")
    target = os.environ.get("HNX_CONFORM_TARGET", "fake")
    with tempfile.TemporaryDirectory(prefix="hnx-x10-") as tmp:
        out_file = Path(tmp) / "report.json"
        argv = [
            sys.executable,
            "-m",
            "homelabnext.cli",
            "conform",
            "--root",
            str(ctx.root),
            "report",
            "--out",
            str(out_file),
            "--target",
            target,
        ]
        rc, out = ctx.run(argv, 600)
        text = out_file.read_text(encoding="utf-8") if out_file.is_file() else ""
    if rc >= 100:
        return CheckResult(ERROR, f"[exit {rc}] conformance run could not measure: {out[-300:]}")
    doc = _parse(text)
    if rc == 2 or doc is None:
        return CheckResult(ERROR, f"[exit {rc}] no usable conformance report: {out[-300:]}")
    missing = doc["capabilities_without_passing_test"]
    caps = doc["capabilities"]
    if bool(missing) != (rc == 1) or rc not in (0, 1):
        return CheckResult(
            ERROR,
            f"[exit {rc}] the report and the exit code disagree "
            f"({len(missing)} capabilities without a passing test)",
        )
    if missing:
        why = "; ".join(f"{c}: {caps.get(c, {}).get('reason', 'no passing test')}" for c in missing)
        return CheckResult(FAIL, f"capabilities without a passing test: {why}"[:700])
    return CheckResult(PASS, f"{len(caps)} capabilities, each with a passing conformance test")


def make_check() -> Check:
    return Check(CHECK_ID, STATEMENT, x10)


def register(registry) -> None:
    registry.register(make_check())
