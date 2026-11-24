# SPDX-License-Identifier: Apache-2.0
"""Ages are judged against the controller's clock as an epoch: ``now().timestamp()``. Ansible's
``now(utc=true)`` is a naive UTC datetime, and ``.timestamp()`` reads a naive datetime as LOCAL time,
so on a controller that is not on UTC every age is off by the zone's offset (6 h on a US Central
workstation: every freshness check failed, or passed, by hours). CI runs on UTC and cannot see it."""

from __future__ import annotations

import os
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest

ROOT = Path(__file__).resolve().parents[2]
SKEWED = re.compile(r"now\(\s*utc\s*=\s*[Tt]rue\s*\)\s*\.timestamp\(\)")


def test_no_template_reads_a_naive_utc_now_as_an_epoch():
    hits = []
    for base in ("ansible", "modules"):
        for p in sorted((ROOT / base).rglob("*")):
            if p.suffix in {".yml", ".yaml", ".j2"} and p.is_file():
                for n, line in enumerate(p.read_text(errors="replace").splitlines(), 1):
                    if SKEWED.search(line):
                        hits.append(f"{p.relative_to(ROOT)}:{n}")
    assert hits == [], "use now().timestamp(): " + ", ".join(hits)


@pytest.mark.requires_tool("ansible-playbook")
def test_a_naive_datetime_is_read_as_local_time_so_only_a_local_now_gives_the_epoch(tmp_path):
    """A fixed naive datetime, as now() (local) and now(utc=true) (UTC) both return one: under a
    non-UTC zone its .timestamp() is the epoch of that wall time IN THAT ZONE. So a local now gives
    the epoch and a UTC now is off by the zone's offset. No clock is read."""
    wall = "2026-11-24 07:00:00"
    out = tmp_path / "epoch.txt"
    play = tmp_path / "p.yml"
    play.write_text(
        "- hosts: localhost\n  connection: local\n  gather_facts: false\n  tasks:\n"
        "    - ansible.builtin.copy:\n"
        f"        dest: {out}\n"
        f"        content: \"{{{{ ('{wall}' | to_datetime).timestamp() | int }}}}\"\n"
    )
    env = {**os.environ, "TZ": "America/Chicago"}
    r = subprocess.run(
        ["ansible-playbook", "-i", "localhost,", str(play)],
        capture_output=True,
        text=True,
        env=env,
        cwd=tmp_path,
    )
    assert r.returncode == 0, r.stdout + r.stderr
    got = int(out.read_text())
    naive = datetime.strptime(wall, "%Y-%m-%d %H:%M:%S")
    as_local = int(naive.replace(tzinfo=ZoneInfo("America/Chicago")).timestamp())
    as_utc = int(naive.replace(tzinfo=UTC).timestamp())
    assert got == as_local  # read as local wall time: correct for now(), which returns local time
    assert got - as_utc == 6 * 3600  # the skew now(utc=true).timestamp() carries in that zone
