# SPDX-License-Identifier: Apache-2.0
import datetime as dt
import json

import pytest

from homelabnext.invariants import (
    Check,
    CheckResult,
    Context,
    Registry,
    default_registry,
    diff_state,
    load_directory,
    load_entry_points,
    overall_exit,
    page_changes,
    run_criteria,
)
from homelabnext.invariants.__main__ import main as inv_main

T0 = dt.datetime(2026, 1, 1, 12, 0, tzinfo=dt.UTC)


def crit(id_, cmd, **kw):
    return {
        "id": id_,
        "statement": "s" * 12,
        "evidence": "auto",
        "observable": cmd,
        "expected": "exit 0",
        "remediation": "fix it properly",
        **kw,
    }


def run(criteria, tmp_path, **kw):
    return run_criteria(
        criteria, Context(tmp_path), kw.pop("registry", None), clock=lambda: T0, **kw
    )


@pytest.mark.parametrize(
    "cmd, status",
    [
        ("exit 0", "pass"),
        ("exit 1", "fail"),
        ("exit 2", "fail"),
        ("exit 99", "fail"),
        ("exit 100", "error"),
        ("exit 127", "error"),
        ("echo boom; exit 101", "error"),
    ],
)
def test_exit_code_semantics(tmp_path, cmd, status):
    doc = run([crit("F-01", cmd)], tmp_path)
    assert doc["results"]["F-01"]["status"] == status


def test_timeout_is_error_not_fail(tmp_path):
    doc = run([crit("F-01", "sleep 5", timeout=1)], tmp_path)
    assert doc["results"]["F-01"]["status"] == "error"
    assert "timeout" in doc["results"]["F-01"]["evidence"]


def test_expect_regex_must_match_output(tmp_path):
    ok = run([crit("F-01", "echo count=3", expect_regex=r"count=\d")], tmp_path)
    bad = run([crit("F-01", "echo nothing", expect_regex=r"count=\d")], tmp_path)
    assert ok["results"]["F-01"]["status"] == "pass"
    assert bad["results"]["F-01"]["status"] == "fail"


def test_overall_exit_precedence(tmp_path):
    p = run([crit("F-01", "exit 0")], tmp_path)
    e = run([crit("F-01", "exit 0"), crit("F-02", "exit 100")], tmp_path)
    f = run([crit("F-01", "exit 100"), crit("F-02", "exit 1")], tmp_path)
    assert (overall_exit(p), overall_exit(e), overall_exit(f)) == (0, 100, 1)


def test_only_merges_and_fast_skips_slow(tmp_path):
    cs = [crit("F-01", "exit 0"), crit("F-02", "exit 1", slow=True)]
    first = run(cs, tmp_path)
    assert set(first["results"]) == {"F-01", "F-02"}
    fast = run(cs, tmp_path, fast=True)
    assert set(fast["results"]) == {"F-01"}
    only = run(cs, tmp_path, only={"F-01"}, previous=first)
    assert set(only["results"]) == {"F-01", "F-02"}  # F-02 carried over


def test_checked_at_only_advances_on_change(tmp_path):
    cs = [crit("F-01", "echo same")]
    a = run_criteria(cs, Context(tmp_path), clock=lambda: T0)
    later = T0 + dt.timedelta(hours=3)
    b = run_criteria(cs, Context(tmp_path), clock=lambda: later, previous=a, only={"F-01"})
    assert b["results"]["F-01"]["checked_at"] == a["results"]["F-01"]["checked_at"]
    c = run_criteria(
        [crit("F-01", "echo different")],
        Context(tmp_path),
        clock=lambda: later,
        previous=b,
        only={"F-01"},
    )
    assert c["results"]["F-01"]["checked_at"] != a["results"]["F-01"]["checked_at"]


# ---- paging ---------------------------------------------------------------------------------


class Sender:
    def __init__(self):
        self.sent = []

    def __call__(self, title, body):
        self.sent.append((title, body))


def doc_of(**statuses):
    return {
        "results": {
            k.replace("_", "-"): {"status": v, "evidence": f"ev {k}"} for k, v in statuses.items()
        }
    }


def test_newly_red_pages_once_standing_set_never_repages(tmp_path):
    st, s = tmp_path / "state.json", Sender()
    page_changes(doc_of(F_01="pass", F_02="pass"), st, s)
    assert s.sent == []
    page_changes(doc_of(F_01="fail", F_02="pass"), st, s)
    assert len(s.sent) == 1 and "F-01" in s.sent[0][1] and "F-02" not in s.sent[0][1]
    for _ in range(3):  # still red: silence
        page_changes(doc_of(F_01="fail", F_02="pass"), st, s)
    assert len(s.sent) == 1
    page_changes(
        doc_of(F_01="error", F_02="pass"), st, s
    )  # fail -> error is still the standing set
    assert len(s.sent) == 1
    page_changes(doc_of(F_01="pass", F_02="pass"), st, s)  # recovery announced once
    assert [t for t, _ in s.sent] == ["Invariant newly broken", "Invariant recovered"]
    page_changes(doc_of(F_01="pass", F_02="pass"), st, s)
    assert len(s.sent) == 2


def test_two_new_reds_are_one_message(tmp_path):
    s = Sender()
    page_changes(doc_of(F_01="fail", F_02="error"), tmp_path / "s.json", s)
    assert len(s.sent) == 1 and "F-01" in s.sent[0][1] and "F-02" in s.sent[0][1]


def test_baseline_records_without_paging(tmp_path):
    st, s = tmp_path / "s.json", Sender()
    page_changes(doc_of(F_01="fail"), st, s, baseline=True)
    page_changes(doc_of(F_01="fail"), st, s)
    assert s.sent == []  # adopted red is standing, not new


def test_skip_does_not_clear_a_known_red(tmp_path):
    st, s = tmp_path / "s.json", Sender()
    page_changes(doc_of(F_01="fail"), st, s)
    page_changes(doc_of(F_01="skip"), st, s)
    page_changes(doc_of(F_01="fail"), st, s)
    assert len(s.sent) == 1


def test_failed_send_is_retried_not_lost(tmp_path):
    st = tmp_path / "s.json"

    def boom(*_):
        raise RuntimeError("sender down")

    with pytest.raises(RuntimeError):
        page_changes(doc_of(F_01="fail"), st, boom)
    s = Sender()
    page_changes(doc_of(F_01="fail"), st, s)
    assert len(s.sent) == 1


def test_diff_state_pure():
    assert diff_state({}, doc_of(F_01="fail")) == (["F-01"], [])
    assert diff_state({"F-01": "fail"}, doc_of(F_01="pass")) == ([], ["F-01"])


# ---- plugin API -----------------------------------------------------------------------------


def test_registered_plugin_runs_and_crash_is_error(tmp_path):
    reg = Registry()
    reg.register(Check("Z-01", "ok", lambda ctx: CheckResult("pass", "fine")))

    @reg.check("Z-02", "crashes")
    def _boom(ctx):
        raise ValueError("kaput")

    cs = [
        {"id": c, "statement": "s" * 12, "evidence": "plugin", "plugin": c, "remediation": "x" * 12}
        for c in ("Z-01", "Z-02", "Z-03")
    ]
    doc = run(cs, tmp_path, registry=reg)
    assert doc["results"]["Z-01"]["status"] == "pass"
    assert (
        doc["results"]["Z-02"]["status"] == "error"
        and "kaput" in doc["results"]["Z-02"]["evidence"]
    )
    assert doc["results"]["Z-03"]["status"] == "error"  # unknown plugin = cannot measure


def test_duplicate_plugin_id_rejected():
    reg = default_registry()
    with pytest.raises(ValueError):
        reg.register(Check("X-01", "again", lambda c: CheckResult("pass")))


def test_directory_plugins_load(tmp_path):
    d = tmp_path / "checks"
    d.mkdir()
    (d / "mine.py").write_text(
        "from homelabnext.invariants import Check, CheckResult\n"
        "CHECKS=[Check('Z-10','ten',lambda c: CheckResult('pass','dir'))]\n"
    )
    (d / "other.py").write_text(
        "from homelabnext.invariants import Check, CheckResult\n"
        "def register(r): r.register(Check('Z-11','eleven',lambda c: CheckResult('fail','dir2')))\n"
    )
    (d / "_ignored.py").write_text("raise SystemExit('must not be imported')\n")
    reg = Registry()
    assert load_directory(reg, d) == ["mine", "other"]
    assert set(reg.checks) == {"Z-10", "Z-11"}


def test_entry_point_plugins_load():
    class EP:
        def __init__(self, name, obj):
            self.name, self._o = name, obj

        def load(self):
            return self._o

    one = Check("Z-20", "one", lambda c: CheckResult("pass"))
    reg = Registry()
    names = load_entry_points(
        reg,
        [
            EP("a", one),
            EP("b", lambda r: r.register(Check("Z-21", "two", lambda c: CheckResult("pass")))),
            EP("c", [Check("Z-22", "three", lambda c: CheckResult("pass"))]),
        ],
    )
    assert names == ["a", "b", "c"] and set(reg.checks) == {"Z-20", "Z-21", "Z-22"}


def test_bad_status_rejected():
    with pytest.raises(ValueError):
        CheckResult("green")


# ---- CLI ------------------------------------------------------------------------------------

REGISTER = """\
pillars:
- {letter: F, title: Foundation}
criteria:
- id: F-01
  statement: A thing that must hold now.
  evidence: auto
  observable: "{cmd}"
  expected: exit 0
  remediation: Fix the thing properly.
"""


def test_cli_end_to_end_with_paging(tmp_path, capsys):
    reg = tmp_path / "invariants.yml"
    out = tmp_path / "res.json"
    state = tmp_path / "state.json"

    def args():
        return [
            "run",
            str(reg),
            "--root",
            str(tmp_path),
            "--out",
            str(out),
            "--state",
            str(state),
        ]

    reg.write_text(REGISTER.replace("{cmd}", "exit 0"))
    assert inv_main(args()) == 0
    reg.write_text(REGISTER.replace("{cmd}", "exit 1"))
    assert inv_main(args()) == 1
    assert "[page] Invariant newly broken" in capsys.readouterr().out
    assert inv_main(args()) == 1
    assert "[page]" not in capsys.readouterr().out  # standing red: quiet
    reg.write_text(REGISTER.replace("{cmd}", "exit 100"))
    assert inv_main(args()) == 100
    assert json.loads(out.read_text())["results"]["F-01"]["status"] == "error"


def test_cli_invalid_register_is_exit_2(tmp_path):
    reg = tmp_path / "invariants.yml"
    reg.write_text("criteria:\n- id: F-01\n")
    assert inv_main(["run", str(reg), "--root", str(tmp_path)]) == 2


def test_cli_skip_leaves_a_criterion_out_and_out_dir_is_created(tmp_path, capsys):
    reg = tmp_path / "invariants.yml"
    out = tmp_path / "build" / "inv" / "res.json"
    reg.write_text(REGISTER.replace("{cmd}", "exit 1"))
    argv = ["run", str(reg), "--root", str(tmp_path), "--out", str(out), "--no-notify"]
    assert inv_main(argv) == 1
    assert inv_main([*argv, "--skip", "F-01"]) == 0
    assert "F-01" not in json.loads(out.read_text())["results"]
