# SPDX-License-Identifier: Apache-2.0
"""``report_result`` validation: the cross-checks JSON Schema cannot express."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .pack import PREGATE_PREFIX
from .schemas import schema_errors


def validate_report(
    report: Mapping[str, Any],
    pack: Mapping[str, Any],
    pack_hash: str,
    manifest: Mapping[str, Any] | None = None,
) -> list[str]:
    """Problems with ``report`` against the pack it claims to have run on (empty = valid).

    * schema (``schemas/agent/report_result``);
    * ``pack_id`` equals the pack hash, so a report cannot be attached to the wrong context;
    * a deferred pack can only produce a ``deferred`` report (no work on guessed context);
    * every cite names a source present in the pack;
    * for an ``ok`` report, every ``must_cite`` source of the manifest is cited.
    """
    problems = schema_errors("agent", "report_result", report)
    if problems:
        return problems
    if report["pack_id"] != pack_hash:
        problems.append("pack_id does not equal the hash of the pack the agent was given")
    if pack.get("status") == "deferred" and report["status"] != "deferred":
        problems.append("pack was deferred; the report must have status 'deferred'")
    known = {s["name"] for s in pack.get("sections", [])}
    known |= {n[len(PREGATE_PREFIX) :] for n in known if n.startswith(PREGATE_PREFIX)}
    cited = {c["source"] for c in report["cites"]}
    unknown = sorted(cited - known)
    if unknown:
        problems.append(f"cites sources that are not in the pack: {unknown}")
    if manifest and report["status"] == "ok":
        missing = sorted(set(manifest.get("must_cite", [])) - cited)
        if missing:
            problems.append(f"must_cite sources not cited: {missing}")
    return problems
