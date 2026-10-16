# SPDX-License-Identifier: Apache-2.0
"""Invariant X-09: customizations are owned and not expired.

Loadable three ways (see ``homelabnext.invariants.api``): ``--plugins-dir`` pointing at this
directory, the entry-point group ``homelabnext.invariants.checks``, or ``register(registry)``.

Pass: every customization found has a valid schema (so reason, owner and review_by exist),
the dates are coherent, none is expired, and none conflicts. Fail: any of those is violated;
the evidence lists the offenders. Skip: no customization exists in this tree. Error: the
loader itself broke (could not measure).

Customizations marked ``maintained_upstream: true`` that are loaded from the shipped
``profiles/`` directory are exempt from expiry (they never expire); the same flag in any other
directory fails with CU015, and those customizations still expire.

Where it looks, relative to ``ctx.root``: ``profiles/`` (shipped), ``customizations/`` (the
deployment's own), plus anything named by ``HNX_CUSTOMIZATIONS_DIR``.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from datetime import date
from pathlib import Path

from homelabnext.customization.lint import lint
from homelabnext.customization.loader import load_tree
from homelabnext.customization.universe import discover
from homelabnext.invariants.api import ERROR, FAIL, PASS, SKIP, Check, CheckResult, Context

CHECK_ID = "X-09"
STATEMENT = "every customization is owned (reason, owner, review_by) and none is expired"
#: findings that make this invariant fail; warnings and scope/path details are `hnx custom check`
GATING = {"CU001", "CU002", "CU007", "CU008", "CU011", "CU012", "CU015"}


def make_check(today_fn: Callable[[], date] = date.today) -> Check:
    def x09(ctx: Context) -> CheckResult:
        try:
            items, problems = load_tree(ctx.root / "profiles", "public")
            i2, p2 = load_tree(ctx.root / "customizations", "local")
            items += i2
            problems += p2
            for d in filter(None, os.environ.get("HNX_CUSTOMIZATIONS_DIR", "").split(os.pathsep)):
                i3, p3 = load_tree(Path(d), "local")
                items += i3
                problems += p3
            if not items and not problems:
                return CheckResult(SKIP, "no customizations in this tree")
            findings = [*problems, *lint(items, discover(ctx.root), today_fn())]
        except Exception as exc:  # could not measure is its own verdict
            return CheckResult(ERROR, f"customization loader failed: {exc}")
        bad = [f for f in findings if f.severity == "error" and f.code in GATING]
        if bad:
            return CheckResult(
                FAIL, "; ".join(f"{f.code} {f.customization}: {f.message}" for f in bad)[:600]
            )
        return CheckResult(PASS, f"{len(items)} customization(s) owned and in date")

    return Check(CHECK_ID, STATEMENT, x09)


def register(registry) -> None:
    """Entry for ``load_directory`` / entry points (the module deliberately defines no CHECKS, so
    the check is not registered twice)."""
    registry.register(make_check())
