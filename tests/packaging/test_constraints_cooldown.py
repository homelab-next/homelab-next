# SPDX-License-Identifier: Apache-2.0
"""`make constraints` keeps a 14-day cooldown; its per-package exemptions are dated and lapse.

An exemption `pkg=YYYY-MM-DD` admits releases up to that date only.  One older than the cooldown is
redundant (the global cutoff already covers it) and left in place it reads as a standing waiver, so
it fails here until removed.  The 14 days must also equal dependabot's cooldown."""

from __future__ import annotations

import datetime as dt
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
MAKEFILE = (ROOT / "Makefile").read_text()
COOLDOWN_DAYS = 14


def _fresh(text: str) -> list[str]:
    m = re.search(r"^CONSTRAINTS_FRESH \?=[ \t]*(.*)$", text, re.M)
    assert m, "Makefile has no CONSTRAINTS_FRESH"
    return m.group(1).split()


def _stale(entries: list[str], today: dt.date) -> list[str]:
    out = []
    for e in entries:
        m = re.fullmatch(r"([A-Za-z0-9_.-]+)=(\d{4}-\d{2}-\d{2})", e)
        assert m, f"CONSTRAINTS_FRESH entry {e!r} is not pkg=YYYY-MM-DD"
        if (today - dt.date.fromisoformat(m.group(2))).days > COOLDOWN_DAYS:
            out.append(e)
    return out


def test_exemptions_are_dated_and_none_is_older_than_the_cooldown():
    stale = _stale(_fresh(MAKEFILE), dt.datetime.now(dt.UTC).date())
    assert not stale, (
        f"drop exemptions older than {COOLDOWN_DAYS} days (the cutoff covers them): {stale}"
    )


def test_staleness_check_catches_an_old_and_an_undated_entry():
    today = dt.date(2026, 11, 6)
    assert _stale(["a=2026-10-01", "b=2026-10-30"], today) == ["a=2026-10-01"]
    with pytest.raises(AssertionError):
        _stale(["certifi"], today)  # the old undated form


def test_makefile_cutoff_and_dependabot_cooldown_agree():
    m = re.search(r"CONSTRAINTS_CUTOFF \?= .*date -u -d '(\d+) days ago'", MAKEFILE)
    assert m, "cannot find the cutoff in the Makefile"
    deps = yaml.safe_load((ROOT / ".github" / "dependabot.yml").read_text())["updates"]
    days = {u["cooldown"]["default-days"] for u in deps}
    assert days == {int(m.group(1))} == {COOLDOWN_DAYS}


@pytest.mark.skipif(shutil.which("make") is None, reason="make not installed")
def test_empty_cutoff_fails_loudly():
    r = subprocess.run(
        ["make", "-n", "constraints", "CONSTRAINTS_CUTOFF="],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert r.returncode != 0
    assert "CONSTRAINTS_CUTOFF is empty" in r.stderr


@pytest.mark.skipif(shutil.which("make") is None, reason="make not installed")
def test_recipe_passes_each_entrys_own_date_not_today():
    r = subprocess.run(
        [
            "make",
            "-n",
            "constraints",
            "CONSTRAINTS_CUTOFF=2026-01-01",
            "CONSTRAINTS_FRESH=foo=2026-01-02",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    assert "--exclude-newer 2026-01-01" in r.stdout
    assert "--exclude-newer-package foo=2026-01-02" in r.stdout
