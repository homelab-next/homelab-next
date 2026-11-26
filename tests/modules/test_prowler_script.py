# SPDX-License-Identifier: Apache-2.0
"""The prowler module's findings exporter (modules/prowler/roles/prowler/files), run in process:
standard library only, no network, the scanner itself replaced by a stand-in.

* ``parse_findings``: a failing check becomes one flat ``pw_``-prefixed row; passes are only counted;
  a muted finding (status ``Suppressed`` with its status code left at FAIL) is counted as muted and
  never emitted; a non-fail verdict counts in the total only; a wrapped report parses; junk
  elements are skipped; a report with no findings at all is an error, not a clean account.
* the summary carries the score over the verdicts acted on, the muted count and the version.
* the findings file is replaced whole and atomically; a failed scan leaves the last one untouched.
* the scanner's exit code 3 (a check failed) is success, any other non-zero is a failure.
* credentials come from the environment only and never appear in an error; the output directory
  is cleaned only for the scanner's own files and a shallow path is refused.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
import stat
from datetime import UTC, datetime
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
FILES = ROOT / "modules" / "prowler" / "roles" / "prowler" / "files"


def _load(name: str, path: Path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


px = _load("hnx_prowler_export", FILES / "hnx_prowler_export.py")

T0 = datetime(2026, 11, 25, 3, 0, 0, tzinfo=UTC)
ACCOUNT = "1" * 12


def finding(status="FAIL", sev="High", check="iam_example_check", suppressed=False, **kw):
    f = {
        "status_code": status,
        "status": "Suppressed" if suppressed else status.title(),
        "severity": sev,
        "risk_details": kw.get("risk", "a risk\nover two lines"),
        "remediation": {"desc": kw.get("fix", "do the thing")},
        "metadata": {"event_code": check},
        "finding_info": {"title": kw.get("title", f"title of {check}"), "uid": f"uid-{check}"},
        "cloud": {"account": {"uid": ACCOUNT}, "region": "us-east-1"},
        "resources": [
            {
                "uid": kw.get("uid", "arn:aws:iam::res"),
                "type": "AwsIamUser",
                "region": kw.get("region", "us-east-1"),
                "group": {"name": "iam"},
            }
        ],
    }
    return f


def report(tmp_path: Path, items, wrap=False) -> Path:
    p = tmp_path / "prowler-run.ocsf.json"
    p.write_text(json.dumps({"findings": items} if wrap else items))
    return p


def test_a_failing_check_is_one_flat_prefixed_row_and_passes_are_only_counted(tmp_path):
    res = px.parse_findings(
        report(tmp_path, [finding("FAIL"), finding("PASS", check="b"), finding("PASS", check="c")])
    )
    assert (res.passed, res.failed, res.muted, res.total) == (2, 1, 0, 3)
    (row,) = res.rows
    assert row["pw_kind"] == "check" and row["pw_status"] == "fail" and row["pw_finding"] is True
    assert row["pw_severity"] == "high" and row["pw_service"] == "iam"
    assert row["pw_check_id"] == "iam_example_check" and row["pw_account"] == ACCOUNT
    assert row["pw_resource_type"] == "AwsIamUser" and row["pw_region"] == "us-east-1"
    assert "\n" not in row["pw_risk"]
    assert all(k.startswith("pw_") for k in row)
    assert all(not isinstance(v, (dict, list)) for v in row.values())  # flat: no nested decode


def test_a_muted_finding_is_counted_as_muted_even_though_its_status_code_stays_fail(tmp_path):
    res = px.parse_findings(report(tmp_path, [finding(suppressed=True), finding("PASS", check="b")]))
    assert (res.passed, res.failed, res.muted, res.total) == (1, 0, 1, 2)
    assert res.rows == []


def test_a_manual_or_unknown_verdict_counts_in_the_total_only(tmp_path):
    res = px.parse_findings(report(tmp_path, [finding("MANUAL"), finding("PASS", check="b")]))
    assert (res.passed, res.failed, res.muted, res.total) == (1, 0, 0, 2)


def test_a_wrapped_report_parses_and_junk_elements_are_skipped(tmp_path):
    res = px.parse_findings(report(tmp_path, [finding(), "junk", 3, None], wrap=True))
    assert res.failed == 1 and res.total == 1


def test_long_prose_is_truncated(tmp_path):
    res = px.parse_findings(report(tmp_path, [finding(risk="x" * 5000)]))
    assert len(res.rows[0]["pw_risk"]) == px.MAX_TEXT


@pytest.mark.parametrize("body", ["[]", "{}", '{"findings": []}', ""])
def test_a_report_with_no_findings_is_an_error_not_a_clean_account(tmp_path, body):
    p = tmp_path / "prowler-run.ocsf.json"
    p.write_text(body)
    with pytest.raises(px.ReportError):
        px.parse_findings(p)


def test_a_report_that_is_not_json_is_an_error(tmp_path):
    p = tmp_path / "prowler-run.ocsf.json"
    p.write_text("{not json")
    with pytest.raises(px.ReportError):
        px.parse_findings(p)


def test_the_summary_scores_over_the_verdicts_acted_on_and_never_divides_by_zero(tmp_path):
    res = px.parse_findings(
        report(tmp_path, [finding(), finding("PASS", check="b"), finding(suppressed=True, check="c")])
    )
    s = px.summary_event(res, "5.36.0", T0)
    assert s["pw_kind"] == "summary" and s["pw_score"] == 50.0
    assert (s["pw_passed"], s["pw_failed"], s["pw_muted"], s["pw_total"]) == (1, 1, 1, 3)
    assert s["pw_version"] == "5.36.0" and s["pw_account"] == ACCOUNT
    assert s["pw_scanned_at"] == "2026-11-25T03:00:00+00:00"
    only_muted = px.parse_findings(report(tmp_path, [finding(suppressed=True)]))
    assert px.summary_event(only_muted, "5.36.0", T0)["pw_score"] == 0.0
    # the account is known even when nothing failed
    assert px.summary_event(only_muted, "5.36.0", T0)["pw_account"] == ACCOUNT


def test_the_version_is_the_number_only():
    assert px.version_number("Prowler 5.36.0 (You are running the latest version, yay!)") == "5.36.0"
    assert px.version_number("") == "unknown"


def test_the_findings_file_is_replaced_whole_with_the_summary_first(tmp_path):
    out = tmp_path / "findings.json"
    out.write_text("old\n")
    res = px.parse_findings(report(tmp_path, [finding(), finding(check="b")]))
    px.write_findings(out, px.summary_event(res, "5.36.0", T0), res.rows, mode=0o640)
    lines = [json.loads(x) for x in out.read_text().splitlines()]
    assert [x["pw_kind"] for x in lines] == ["summary", "check", "check"]
    assert stat.S_IMODE(out.stat().st_mode) == 0o640
    assert not list(tmp_path.glob("*.tmp"))


class Stand:
    """A stand-in for the scanner: writes a report and exits with a code."""

    def __init__(self, tmp_path, code, items=None):
        self.code, self.items, self.dir = code, items, tmp_path / "out"
        self.argv = None

    def __call__(self, argv, **kw):
        self.argv = argv
        self.dir.mkdir(parents=True, exist_ok=True)
        if self.items is not None:
            (self.dir / "prowler-run.ocsf.json").write_text(json.dumps(self.items))

        class R:
            returncode = self.code
            stdout = "Prowler 5.36.0"
            stderr = "boom " + "z" * 3000

        return R()


def cfg(tmp_path, **over):
    base = {
        "prowler_bin": "/opt/x/bin/prowler",
        "output_dir": tmp_path / "var" / "lib" / "output",
        "findings": tmp_path / "findings.json",
        "mutelist": None,
        "regions": [],
        "state_dir": tmp_path / "state",
        "mode": 0o640,
        "timeout": 60,
    }
    base.update(over)
    return px.Config(**base)


def test_exit_code_three_is_a_successful_scan_with_findings(tmp_path):
    c = cfg(tmp_path)
    stand = Stand(tmp_path, 3, [finding()])
    stand.dir = c.output_dir
    code = px.run(c, {"AWS_ACCESS_KEY_ID": "a" * 5, "AWS_SECRET_ACCESS_KEY": "b" * 5}, runner=stand, now=T0)
    assert code == 0
    assert c.findings.exists() and json.loads((c.state_dir / "last-run.json").read_text())["ok"] is True


def test_any_other_exit_code_fails_and_leaves_the_last_findings_untouched(tmp_path):
    c = cfg(tmp_path)
    c.findings.write_text("previous\n")
    stand = Stand(tmp_path, 1, [finding()])
    stand.dir = c.output_dir
    code = px.run(c, {"AWS_ACCESS_KEY_ID": "a" * 5, "AWS_SECRET_ACCESS_KEY": "b" * 5}, runner=stand, now=T0)
    assert code == 1 and c.findings.read_text() == "previous\n"
    assert json.loads((c.state_dir / "last-run.json").read_text())["ok"] is False


def test_a_scan_with_no_report_fails_and_leaves_the_last_findings_untouched(tmp_path):
    c = cfg(tmp_path)
    c.findings.write_text("previous\n")
    stand = Stand(tmp_path, 0, None)
    stand.dir = c.output_dir
    code = px.run(c, {"AWS_ACCESS_KEY_ID": "a" * 5, "AWS_SECRET_ACCESS_KEY": "b" * 5}, runner=stand, now=T0)
    assert code == 1 and c.findings.read_text() == "previous\n"


def test_the_command_scans_every_region_unless_told_and_names_the_mutelist(tmp_path):
    mute = tmp_path / "mutelist.yaml"
    mute.write_text("Mutelist: {}\n")
    c = cfg(tmp_path, mutelist=mute)
    stand = Stand(tmp_path, 0, [finding("PASS")])
    stand.dir = c.output_dir
    px.run(c, {"AWS_ACCESS_KEY_ID": "a" * 5, "AWS_SECRET_ACCESS_KEY": "b" * 5}, runner=stand, now=T0)
    assert "--region" not in stand.argv and "--mutelist-file" in stand.argv
    assert stand.argv[1] == "aws" and "json-ocsf" in stand.argv
    c2 = cfg(tmp_path, regions=["eu-west-1", "us-east-1"])
    stand2 = Stand(tmp_path, 0, [finding("PASS")])
    stand2.dir = c2.output_dir
    px.run(c2, {"AWS_ACCESS_KEY_ID": "a" * 5, "AWS_SECRET_ACCESS_KEY": "b" * 5}, runner=stand2, now=T0)
    i = stand2.argv.index("--region")
    assert stand2.argv[i + 1 : i + 3] == ["eu-west-1", "us-east-1"]


def test_missing_credentials_are_refused_before_the_scanner_runs_and_never_echoed(tmp_path, capsys):
    c = cfg(tmp_path)
    called = []
    code = px.run(c, {"AWS_ACCESS_KEY_ID": "a" * 5}, runner=lambda *a, **k: called.append(1), now=T0)
    assert code == 2 and not called


def test_an_error_never_carries_the_scanners_stderr_past_its_cap_or_the_credentials(tmp_path, capsys):
    secret_value = "s" * 12
    c = cfg(tmp_path)
    stand = Stand(tmp_path, 1, None)
    stand.dir = c.output_dir
    px.run(c, {"AWS_ACCESS_KEY_ID": "a" * 5, "AWS_SECRET_ACCESS_KEY": secret_value}, runner=stand, now=T0)
    err = capsys.readouterr().err
    assert len(err) < 1500 and secret_value not in err
    assert secret_value not in (c.state_dir / "last-run.json").read_text()


def test_cleaning_the_output_directory_removes_only_the_scanners_own_files(tmp_path):
    d = tmp_path / "var" / "lib" / "output"
    d.mkdir(parents=True)
    (d / "prowler-run.ocsf.json").write_text("[]")
    (d / "prowler-run.json").write_text("[]")
    (d / "keep.txt").write_text("mine")
    (d / "sub").mkdir()
    px.clean_output(d)
    assert sorted(p.name for p in d.iterdir()) == ["keep.txt", "sub"]


@pytest.mark.parametrize("bad", ["/", "/var", "/var/lib", "relative/dir", "/a/../b/c"])
def test_a_shallow_or_relative_output_directory_is_refused(bad):
    with pytest.raises(px.ConfigError):
        px.clean_output(Path(bad))


def test_the_output_directory_may_not_be_a_symlink_out_of_the_tree(tmp_path):
    real = tmp_path / "real" / "deep" / "dir"
    real.mkdir(parents=True)
    link = tmp_path / "a" / "b" / "link"
    link.parent.mkdir(parents=True)
    os.symlink(real, link)
    with pytest.raises(px.ConfigError):
        px.clean_output(link)


def test_config_is_read_from_the_environment_with_safe_defaults(tmp_path):
    c = px.config_from_env({"PROWLER_BIN": "/opt/p/bin/prowler", "PROWLER_OUTPUT_DIR": "/var/lib/x/out",
                            "PROWLER_FINDINGS": "/var/log/f.json", "PROWLER_STATE_DIR": "/var/lib/x/state",
                            "PROWLER_REGIONS": "eu-west-1  us-east-1"})
    assert c.regions == ["eu-west-1", "us-east-1"] and c.mutelist is None
    assert c.mode == 0o640 and c.timeout == 3600
    with pytest.raises(px.ConfigError):
        px.config_from_env({})


def test_no_lab_value_and_no_credential_shaped_literal_is_in_the_script():
    import re

    text = (FILES / "hnx_prowler_export.py").read_text()
    assert not re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text)
    assert not re.search(r"\.(casa|local|lan)\b", text)
    assert not re.search(r"\b\d{12}\b", text)
    assert not re.search(r"AKIA[0-9A-Z]{8,}", text)
