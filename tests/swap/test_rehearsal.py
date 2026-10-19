# SPDX-License-Identifier: Apache-2.0
"""P9.2 rehearsal driver: two in-memory lakes, a defective candidate, and the shell wrapper
against the loopback Trino/REST fake."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from homelabnext.lake import FakeLake
from homelabnext.swap import record as rec
from homelabnext.swap.flip import load_doc
from homelabnext.swap.rehearsal import (
    CANDIDATE,
    INCUMBENT,
    SWAP_ID,
    Router,
    main,
    rehearsal_registry,
    run,
    seed_rows,
)

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "compose" / "lab-in-a-box" / "rehearsals" / "swap-lake-query.sh"
CLOCK = datetime(2026, 4, 1, 9, 0, tzinfo=UTC)


def _checks(summary):
    return {c["check"]: c["ok"] for c in summary["checks"]}


def test_rehearsal_swaps_flips_and_rolls_back(tmp_path):
    s = run(tmp_path, FakeLake(), FakeLake(), clock=lambda: CLOCK)
    assert s["ok"], [c for c in s["checks"] if not c["ok"]]
    got = _checks(s)
    for name in (
        "step:cutover",
        "route-answers-from-candidate",
        "candidate-answers-like-incumbent",
        "rollback-restored-route",
        "registry-restored-byte-for-byte",
        "incumbent-serves-after-rollback",
        "record-validates",
    ):
        assert got[name], name
    doc = rec.load(tmp_path / f"{SWAP_ID}.swap.json")
    assert doc["status"] == "rolled_back" and doc["route"]["flipped"] is False
    assert [t["event"] for t in doc["transitions"]][-1] == "rolled-back"
    assert json.loads((tmp_path / "rehearsal.json").read_text())["ok"] is True


class _LossyLake(FakeLake):
    """Defect: the candidate silently drops the last row of every batch."""

    def write_batch(self, table, rows, **kw):
        return super().write_batch(table, list(rows)[:-1], **kw)


def test_a_lossy_candidate_is_refused_and_rollback_still_restores(tmp_path):
    s = run(tmp_path, FakeLake(), _LossyLake(), clock=lambda: CLOCK)
    got = _checks(s)
    assert not s["ok"]
    assert got["step:shadow-start"] is False  # the backfill wrote an unexpected row count
    assert "step:cutover" not in got  # never reached
    assert got["rollback-restored-route"] and got["registry-restored-byte-for-byte"]
    assert got["route-answers-from-incumbent"] and got["record-validates"]
    assert rec.load(tmp_path / f"{SWAP_ID}.swap.json")["status"] == "rolled_back"


def test_a_candidate_that_answers_differently_fails_the_parity_gate(tmp_path):
    class Skewed(FakeLake):
        def query(self, sql, params=None):
            rows = super().query(sql, params)
            return [dict(r, user_name="mallory") if "user_name" in r else r for r in rows]

    s = run(tmp_path, FakeLake(), Skewed(), clock=lambda: CLOCK)
    got = _checks(s)
    assert got["step:parity-compare"] is False and not s["ok"]
    assert got["registry-restored-byte-for-byte"]


def test_rehearsal_refuses_to_overwrite_a_record(tmp_path):
    run(tmp_path, FakeLake(), FakeLake(), clock=lambda: CLOCK)
    with pytest.raises(Exception, match="exists"):
        run(tmp_path, FakeLake(), FakeLake(), clock=lambda: CLOCK)


def test_registry_points_at_the_incumbent_and_knows_the_candidate(tmp_path):
    text = rehearsal_registry()
    doc = load_doc(text)
    row = doc["services"]["lake-query"]
    assert (row["host"], row["impl"]) == (INCUMBENT["host"], INCUMBENT["impl"])
    assert CANDIDATE["host"] in doc["hosts"] and INCUMBENT["host"] in doc["hosts"]
    reg = tmp_path / "services.yml"
    reg.write_text(text)
    a, b = object(), object()
    assert Router(reg, {INCUMBENT["host"]: a, CANDIDATE["host"]: b}).client() is a


def test_seed_is_deterministic_and_valid():
    lake = FakeLake()
    for table, rows in seed_rows().items():
        res = lake.write_batch(table, rows, idempotency_key=table)
        assert res.rows_written == len(rows)
    assert seed_rows() == seed_rows()


def test_main_reports_an_unreachable_candidate_as_exit_2(tmp_path, monkeypatch):
    for v in ("HNX_ENDPOINT_LAKE_QUERY", "HNX_ENDPOINT_LAKE_CATALOG"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setenv("LAB_WAREHOUSE", "lab")
    assert main(["--report-dir", str(tmp_path), "--domain", ""]) == 2


def _script_env(**extra):
    env = {k: v for k, v in os.environ.items() if not k.startswith(("HNX_ENDPOINT_", "LAB_"))}
    env.update(HNX_PYTHON=sys.executable, PYTHONPATH=str(ROOT), **extra)
    return env


def test_the_shell_wrapper_against_the_loopback_lab(tmp_path):
    sys.path.insert(0, str(ROOT / "tests" / "lake"))
    from fake_lab import FakeLab

    with FakeLab(page_size=50) as lab:
        env = _script_env(
            HNX_ENDPOINT_LAKE_QUERY=lab.url, HNX_ENDPOINT_LAKE_CATALOG=lab.url, LAB_WAREHOUSE="lab"
        )
        p = subprocess.run(
            ["bash", str(SCRIPT), str(tmp_path)],
            env=env,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
    assert p.returncode == 0, p.stdout[-3000:] + p.stderr[-3000:]
    out = tmp_path / "swap-lake-query"
    assert json.loads((out / "rehearsal.json").read_text())["ok"] is True
    assert "valid (" in p.stdout and "rehearsal: PASS" in p.stdout
    assert "lab-fake-lake:8443 -> lab-lake-query:8443" in (out / "flip-plan.txt").read_text()


def test_the_shell_wrapper_needs_the_endpoints(tmp_path):
    p = subprocess.run(
        ["bash", str(SCRIPT), str(tmp_path)],
        env=_script_env(),
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert p.returncode == 2, p.stdout + p.stderr
    p = subprocess.run(["bash", str(SCRIPT)], env=_script_env(), capture_output=True, check=False)
    assert p.returncode == 2
