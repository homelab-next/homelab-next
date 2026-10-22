# SPDX-License-Identifier: Apache-2.0
"""Role timers report their runs (docs/role-interface.md section 8): every timer's service runs
the shared writer of role ``last_run`` on start and on stop, and the record it leaves is what the
status hub's ``job-last-run`` mapping reads.  The writer runs here unprivileged, exactly as the
rendered unit would run it, with systemd's ExecStopPost environment faked."""

from __future__ import annotations

import grp
import json
import os
import shlex
import shutil
import stat
import subprocess
import sys

import pytest
from rolerun import ROOT, last_run_vars, logging_fake, run_cases, run_role

from homelabnext.scripts.catalog import tracked_files
from homelabnext.status import apply_mapping
from homelabnext.status.maps import schedule
from homelabnext.status.model import parse_iso, schema_problems

needs_ansible = pytest.mark.skipif(
    shutil.which("ansible-playbook") is None, reason="ansible-playbook not installed"
)
GROUP = grp.getgrgid(os.getgid()).gr_name


def test_every_role_timer_writes_a_last_run_record():
    """The repository's own timers: each passes the check that fails a timer without the writer
    (tests/maps/test_directory.py shows it failing on one)."""
    timers = schedule.gather_timers(ROOT, tracked_files(ROOT))
    assert len(timers) >= 6
    assert {t["id"]: t["problems"] for t in timers if t["problems"]} == {}


def _lr_vars(tmp_path):
    return {"last_run_dir": str(tmp_path / "records"), "last_run_group": GROUP,
            "last_run_writer": str(tmp_path / "bin" / "hnx-last-run")}  # fmt: skip


@needs_ansible
def test_last_run_installs_the_writer_and_a_group_readable_directory(tmp_path):
    v = _lr_vars(tmp_path)
    assert run_role(tmp_path, "last_run", "health", v).returncode != 0  # nothing installed yet
    r = run_role(tmp_path, "last_run", "main", v)
    assert r.returncode == 0, r.stdout + r.stderr
    d = (tmp_path / "records").stat()
    assert stat.S_IMODE(d.st_mode) == 0o750 and d.st_gid == os.getgid()
    assert os.access(tmp_path / "bin" / "hnx-last-run", os.X_OK)
    assert run_role(tmp_path, "last_run", "health", v).returncode == 0
    results = run_cases(tmp_path, "last_run", "main", v, [
        {"last_run_dir": "relative/dir"}, {"last_run_dir": "/srv/a b"},
        {"last_run_writer": "/x/../y"}, {"last_run_group": "root\nExecStart=/bin/sh"}])  # fmt: skip
    assert all(f and "last_run: the record directory" in m for f, m in results), results


def _writer_lines(service: str, unit: str) -> dict[str, list[str]]:
    out = {}
    for key in ("ExecStartPre", "ExecStopPost"):
        (line,) = [x for x in service.splitlines() if x.startswith(key + "=")]
        assert line.startswith(f"{key}=-{schedule.WRITER} ")
        argv = shlex.split(line.split("=", 1)[1].lstrip("-"))
        out[key] = [a.replace("%n", unit) for a in argv[1:]]  # systemd expands %n
    return out


def _run(tmp_path, argv, **env):
    writer = tmp_path / "bin" / "hnx-last-run"
    clean = {k: v for k, v in os.environ.items() if k not in ("SERVICE_RESULT", "EXIT_CODE",
                                                              "EXIT_STATUS")}  # fmt: skip
    return subprocess.run([sys.executable, str(writer), *argv], capture_output=True, text=True,
                          env={**clean, **env}, check=False)  # fmt: skip


@needs_ansible
def test_the_rendered_unit_writes_its_record_on_start_and_on_a_failed_stop(tmp_path):
    (tmp_path / "units").mkdir()
    v = {
        "lynis_min_hardening_index": 60,
        "lynis_dpkg_verify": False,
        "lynis_unit_dir": str(tmp_path / "units"),
        "lynis_script": str(tmp_path / "bin" / "scan"),
        "lynis_state_dir": str(tmp_path / "state"),
        "lynis_systemctl_cli": logging_fake(tmp_path, "systemctl"),
        "lynis_schedule": "*-*-* 03:30:00 UTC",
        **last_run_vars(tmp_path, "lynis"),
    }
    r = run_role(tmp_path, "lynis", "config", v)
    assert r.returncode == 0, r.stdout + r.stderr
    lines = _writer_lines(
        (tmp_path / "units" / "hnx-lynis.service").read_text(), "hnx-lynis.service"
    )
    record = tmp_path / "last-run" / "timer%3Alynis%2Fscan.json"

    assert _run(tmp_path, lines["ExecStartPre"]).returncode == 0
    started = json.loads(record.read_text())
    assert started["running"] is True and started["finished_at"] is None
    assert (started["job"], started["unit"], started["on_calendar"], started["randomized_delay_s"]) == (
        "timer:lynis/scan", "hnx-lynis.service", "*-*-* 03:30:00 UTC", 900)  # fmt: skip

    stop = _run(tmp_path, lines["ExecStopPost"], SERVICE_RESULT="exit-code", EXIT_CODE="exited",
                EXIT_STATUS="1")  # fmt: skip
    assert stop.returncode == 0, stop.stderr
    done = json.loads(record.read_text())
    assert schema_problems("last_run.schema.json", done) == []
    assert done["started_at"] == started["started_at"] and done["running"] is False
    assert (done["result"], done["exit_code"], done["exit_status"]) == ("exit-code", "exited", "1")
    st = record.stat()
    assert stat.S_IMODE(st.st_mode) == 0o640 and st.st_gid == os.getgid()
    assert sorted(p.name for p in record.parent.iterdir()) == [record.name]  # no temporary left
    (d,) = apply_mapping(done, {"builtin": "job-last-run"}, now=parse_iso(done["finished_at"]),
                         fallback_item="x")  # fmt: skip
    assert d.item.startswith("timer:lynis/scan@") and d.state == "fail"

    # a stop with no start before it (ExecStartPre never ran) is dated by its end; success is ok
    record.unlink()
    assert _run(tmp_path, lines["ExecStopPost"], SERVICE_RESULT="success").returncode == 0
    only = json.loads(record.read_text())
    assert only["started_at"] == only["finished_at"] and only["result"] == "success"
    # a value systemd would never send is not recorded as given
    _run(tmp_path, lines["ExecStopPost"], SERVICE_RESULT="ok\nforged", EXIT_STATUS="0; x")
    odd = json.loads(record.read_text())
    assert (odd["result"], odd["exit_status"]) == ("unknown", None)
    # bad arguments are refused before anything is written
    bad = _run(tmp_path, [*lines["ExecStopPost"][:-4], "--calendar", "daily\nX=1", "--delay", "1"])
    assert bad.returncode == 2 and json.loads(record.read_text()) == odd


def test_record_file_names_are_injective_in_the_job_id(tmp_path):
    """``timer:lynis/scan`` and ``timer:lynis-scan`` used to share ``timer-lynis-scan.json``."""
    import importlib.util

    path = ROOT / "ansible" / "roles" / "last_run" / "files" / "hnx-last-run.py"
    spec = importlib.util.spec_from_file_location("hnx_last_run", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    jobs = ["timer:lynis/scan", "timer:lynis-scan", "timer:lynis.scan", "fleet-unit:lynis/scan"]
    assert all(mod.JOB.match(j) for j in jobs)
    names = [os.path.basename(mod.record_path(str(tmp_path), j)) for j in jobs]
    assert len(set(names)) == len(jobs) and all("/" not in n for n in names)
    assert names[0] == "timer%3Alynis%2Fscan.json"
