# SPDX-License-Identifier: Apache-2.0
"""M-04's declared exception (docs/scripts.md, "Declared exception: host scans that alert on a
change"): every timer-run script that alerts on its own is a ``kind: job`` named in that list,
and every name in the list is still such a script, so a self-paging check cannot pass M-04 by
being called a job without a reviewer seeing it."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TIMER_PREFIXES = ("timer:", "fleet-unit:")


def declared() -> set[str]:
    text = (ROOT / "docs" / "scripts.md").read_text()
    m = re.search(r"<!-- host-scan-alerts -->\n(.*?)<!-- /host-scan-alerts -->", text, re.S)
    assert m, "docs/scripts.md lost its host-scan-alerts list"
    return set(re.findall(r"^- `([a-z0-9-]+)`", m.group(1), re.M))


def self_alerting(scripts: list[dict]) -> dict[str, str]:
    """``{id: kind}`` of every script a timer or fleet unit runs whose outputs name an alert."""
    out = {}
    for s in scripts:
        if not any(str(t).startswith(TIMER_PREFIXES) for t in s.get("trigger") or []):
            continue
        if re.search(r"\balert", json.dumps(s.get("outputs")), re.I):
            out[s["id"]] = s["kind"]
    return out


def _catalog() -> list[dict]:
    return json.loads((ROOT / "docs" / "scripts" / "catalog.json").read_text())["scripts"]


def test_every_self_alerting_timer_script_is_a_declared_job():
    found = self_alerting(_catalog())
    assert set(found) == declared(), (
        f"timer-run scripts that alert: {sorted(found)}; declared: {sorted(declared())}"
    )
    assert set(found.values()) == {"job"}, "a self-alerting check belongs in the runner (M-04)"


def test_the_scan_finds_an_undeclared_one():
    planted = [
        {"id": "x-scan", "kind": "job", "trigger": ["timer:x/scan"], "outputs": "on a change, one alert"},
        {"id": "y-scan", "kind": "job", "trigger": ["timer:y/scan"], "outputs": "the report"},
        {"id": "z-tool", "kind": "tool", "trigger": ["make:z"], "outputs": "an alert line"},
    ]  # fmt: skip
    assert self_alerting(planted) == {"x-scan": "job"}
