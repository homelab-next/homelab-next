# SPDX-License-Identifier: Apache-2.0
"""Role module_census (docs/modules.md, "What the loader checks"): each host's enabled and active
fleet units, read-only, written on the controller, where ``hnx modules gather`` reads them.  systemctl is a
stand-in here; the play runs on localhost, which is then both the host and the controller."""

from __future__ import annotations

import json
import os
import shutil

import pytest
from rolerun import LOGGER, calls, fake, first_run, run_cases

from homelabnext.modules import census
from homelabnext.notify import record as nr
from homelabnext.notify.record import PairsRecord

needs_ansible = pytest.mark.skipif(
    shutil.which("ansible-playbook") is None, reason="ansible-playbook not installed"
)

ENABLED = (
    "hnx-external-collector-pull.service enabled enabled\n"
    "hnx-external-collector-pull.timer enabled -\n"
    "hnx-lake-compact.timer enabled\n"
    "hnx-page@.service enabled disabled\n"
)
ACTIVE = (
    "hnx-external-collector-pull.timer loaded active waiting Pull the collector\n"
    "hnx-stray.service loaded active running Started outside any unit file\n"
)


def _systemctl(tmp_path) -> str:
    """A stand-in systemctl that logs its arguments and answers each query in its own shape."""
    out = f"sys.stdout.write({ENABLED!r} if sys.argv[1] == 'list-unit-files' else {ACTIVE!r})"
    body = (
        LOGGER.replace("LOG", repr(str(tmp_path / "calls.log")))
        .replace("NAME", repr("systemctl"))
        .replace("FAIL", repr(str(tmp_path / "systemctl.fails")))
        .replace("OUT", out)
    )
    return fake(tmp_path / "systemctl", body)


PAIR = {"problem": "UPS on battery", "recovery": "UPS back on line power"}


def _first(tmp_path):
    out = tmp_path / "census"
    out.mkdir()
    pairs = tmp_path / "pairs"
    pairs.mkdir(mode=0o700)
    os.chmod(pairs, 0o700)
    # this process writes it, so the record's process is running while the role reads it
    PairsRecord(pairs, "broker").write({PAIR["problem"]: (PAIR["recovery"], None)})
    v = {
        "module_census_dir": str(out),
        "module_census_systemctl_cli": _systemctl(tmp_path),
        "module_census_pairs_dir": str(pairs),  # broker's record present, status's absent
    }
    return {"role": "module_census", "tasks_from": "main", "extra_vars": v, "setup": {"v": v}}


@needs_ansible
@first_run(_first)
def test_module_census_writes_each_hosts_answer_and_gather_reads_it(first):
    r, tmp_path = first
    v = first.setup["v"]
    assert r.returncode == 0, r.stdout + r.stderr
    # two read-only queries, by argument vector: the pattern reaches systemctl unexpanded
    assert calls(tmp_path) == [
        "systemctl list-unit-files --no-legend --plain --no-pager --type=service,timer "
        "--state=enabled hnx-*",
        "systemctl list-units --no-legend --plain --no-pager --type=service,timer "
        "--state=active hnx-*",
    ]
    out = tmp_path / "census"
    assert json.loads((out / "_hosts.json").read_text()) == ["localhost"]
    answer = json.loads((out / "localhost.json").read_text())
    text = (tmp_path / "pairs" / "broker" / "pairs.json").read_text()
    started = nr.parse_record(text, "broker").started
    assert answer == {
        "host": "localhost",
        "enabled": ENABLED.splitlines(),
        "active": ACTIVE.splitlines(),
        "pairs": {
            "boot_id": nr.boot_id(),
            "now": answer["pairs"]["now"],
            "records": {"broker": {"text": text, "pid_started": started}, "status": None},
        },
    }
    inventory, notes = census.gather(out)
    assert inventory == {
        "schema_version": "1.0",
        "units": ["external-collector-pull", "lake-compact", "stray"],
        "not_gathered": ["rows", "mcp_servers", "agents", "tables"],
        "notify_pairs": [PAIR],
    }
    assert any("template unit" in n for n in notes)

    # refused before anything is listed: a relative or missing directory; and a systemctl that
    # fails, or exits 1 while printing (only an empty "nothing matched" may exit 1)
    failing = fake(tmp_path / "systemctl-fails", "import sys\nsys.exit(2)\n")
    noisy = fake(
        tmp_path / "systemctl-noisy",
        "import sys\nprint('hnx-x.service enabled')\nsys.exit(1)\n",
    )
    # nothing matches: list-unit-files exits 1 and list-units 0, both printing nothing
    empty = fake(
        tmp_path / "systemctl-empty",
        "import sys\nsys.exit(1 if sys.argv[1] == 'list-unit-files' else 0)\n",
    )
    # list-units has no "nothing matched" exit: a failure there fails the census
    active_fails = fake(
        tmp_path / "systemctl-active-fails",
        "import sys\nsys.exit(1 if sys.argv[1] == 'list-units' else 0)\n",
    )

    # a record is read only as a small regular file, never through a link, in a directory no
    # one else may write; a FIFO never blocks the read
    def plain(name, owner, mode=0o700):
        d = tmp_path / name
        (d / owner).mkdir(parents=True)
        for x in (d, d / owner):
            os.chmod(x, mode)
        return d

    linked = plain("linked-pairs", "broker")
    (linked / "broker" / "pairs.json").symlink_to(tmp_path / "pairs" / "broker" / "pairs.json")
    big = plain("big-pairs", "status")
    (big / "status" / "pairs.json").write_text(" " * (256 * 1024 + 1))
    fifo = plain("fifo-pairs", "status")
    os.mkfifo(fifo / "status" / "pairs.json")
    loose = plain("loose-pairs", "broker", 0o770)
    via = tmp_path / "via"
    via.symlink_to(tmp_path / "pairs")
    results = run_cases(
        tmp_path,
        "module_census",
        "main",
        v,
        [
            {"module_census_pairs_dir": "relative/pairs"},
            {"module_census_pairs_dir": str(linked)},
            {"module_census_pairs_dir": str(big)},
            {"module_census_pairs_dir": str(fifo)},
            {"module_census_pairs_dir": str(loose)},
            {"module_census_pairs_dir": str(via)},
            {"module_census_dir": "relative/census"},
            {"module_census_dir": str(tmp_path / "absent")},
            {"module_census_systemctl_cli": failing},
            {"module_census_systemctl_cli": noisy},
            {"module_census_systemctl_cli": empty},
            {"module_census_systemctl_cli": active_fails},
            # a host name names the host's answer file: never a path
            {"inventory_hostname": "../x"},
            {"inventory_hostname": "a/b"},
            {"inventory_hostname": ".hidden"},
        ],
    )
    assert results[0][0] and "the notify pairs directory an absolute" in results[0][1]
    for failed, said in results[1:4]:
        assert failed and "is not a regular file of at most 262144 bytes" in said, results
    assert results[4][0] and "is writable by its group or others" in results[4][1], results
    assert results[5][0] and "reached without a link" in results[5][1], results
    results = results[6:]
    assert results[0][0] and "module_census: the census directory is an absolute" in results[0][1]
    assert results[1][0] and "is not a directory on the controller" in results[1][1]
    assert results[2][0] and results[3][0], results
    assert results[4] == (False, ""), results
    assert results[5][0], results
    for failed, said in results[6:]:
        assert failed and "the host name a plain name" in said, results
