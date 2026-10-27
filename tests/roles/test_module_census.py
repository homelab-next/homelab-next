# SPDX-License-Identifier: Apache-2.0
"""Role module_census (docs/modules.md, "What the loader checks"): each host's enabled fleet units,
read-only, written on the controller, where ``hnx modules gather`` reads them.  systemctl is a
stand-in here; the play runs on localhost, which is then both the host and the controller."""

from __future__ import annotations

import json
import shutil

import pytest
from rolerun import calls, fake, first_run, logging_fake, run_cases

from homelabnext.modules import census

needs_ansible = pytest.mark.skipif(
    shutil.which("ansible-playbook") is None, reason="ansible-playbook not installed"
)

ENABLED = (
    "hnx-external-collector-pull.service enabled enabled\n"
    "hnx-external-collector-pull.timer enabled -\n"
    "hnx-lake-compact.timer enabled\n"
    "hnx-page@.service enabled disabled\n"
)


def _first(tmp_path):
    out = tmp_path / "census"
    out.mkdir()
    v = {
        "module_census_dir": str(out),
        "module_census_systemctl_cli": logging_fake(tmp_path, "systemctl", ENABLED),
    }
    return {"role": "module_census", "tasks_from": "main", "extra_vars": v, "setup": {"v": v}}


@needs_ansible
@first_run(_first)
def test_module_census_writes_each_hosts_answer_and_gather_reads_it(first):
    r, tmp_path = first
    v = first.setup["v"]
    assert r.returncode == 0, r.stdout + r.stderr
    # one read-only query, by argument vector: the pattern reaches systemctl unexpanded
    assert calls(tmp_path) == [
        "systemctl list-unit-files --no-legend --plain --no-pager --type=service,timer "
        "--state=enabled hnx-*"
    ]
    out = tmp_path / "census"
    assert json.loads((out / "_hosts.json").read_text()) == ["localhost"]
    answer = json.loads((out / "localhost.json").read_text())
    assert answer == {"host": "localhost", "systemctl": ENABLED.splitlines()}
    inventory, notes = census.gather(out)
    assert inventory == {
        "schema_version": "1.0",
        "units": ["external-collector-pull", "lake-compact"],
        "not_gathered": ["rows", "mcp_servers", "agents", "tables"],
    }
    assert any("template unit" in n for n in notes)

    # refused before anything is listed: a relative or missing directory; and a systemctl that
    # fails, or exits 1 while printing (only an empty "nothing matched" may exit 1)
    failing = fake(tmp_path / "systemctl-fails", "import sys\nsys.exit(2)\n")
    noisy = fake(
        tmp_path / "systemctl-noisy",
        "import sys\nprint('hnx-x.service enabled')\nsys.exit(1)\n",
    )
    empty = fake(tmp_path / "systemctl-empty", "import sys\nsys.exit(1)\n")
    results = run_cases(
        tmp_path,
        "module_census",
        "main",
        v,
        [
            {"module_census_dir": "relative/census"},
            {"module_census_dir": str(tmp_path / "absent")},
            {"module_census_systemctl_cli": failing},
            {"module_census_systemctl_cli": noisy},
            {"module_census_systemctl_cli": empty},
        ],
    )
    assert results[0][0] and "module_census: the census directory is an absolute" in results[0][1]
    assert results[1][0] and "is not a directory on the controller" in results[1][1]
    assert results[2][0] and results[3][0], results
    assert results[4] == (False, ""), results
