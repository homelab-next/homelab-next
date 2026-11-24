# SPDX-License-Identifier: Apache-2.0
"""Ages are judged against the controller's clock as an epoch: ``now().timestamp()``. Ansible's
``now(utc=true)`` is a naive UTC datetime, and ``.timestamp()`` reads a naive datetime as LOCAL time,
so on a controller that is not on UTC every age is off by the zone's offset (6 h on a US Central
workstation: every freshness check failed, or passed, by hours). CI runs on UTC and cannot see it."""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
from pathlib import Path

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
def test_now_timestamp_is_the_epoch_on_a_controller_that_is_not_on_utc(tmp_path):
    play = tmp_path / "p.yml"
    play.write_text(
        "- hosts: localhost\n  connection: local\n  gather_facts: false\n  tasks:\n"
        '    - ansible.builtin.debug:\n        msg: "{{ now().timestamp() | int }}"\n'
    )
    env = {**os.environ, "TZ": "America/Chicago", "ANSIBLE_STDOUT_CALLBACK": "json"}
    r = subprocess.run(
        ["ansible-playbook", "-i", "localhost,", str(play)],
        capture_output=True,
        text=True,
        env=env,
        cwd=tmp_path,
    )
    assert r.returncode == 0, r.stdout + r.stderr
    got = int(json.loads(r.stdout)["plays"][0]["tasks"][0]["hosts"]["localhost"]["msg"])
    assert abs(got - time.time()) < 120
