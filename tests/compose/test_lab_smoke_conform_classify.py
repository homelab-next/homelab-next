# SPDX-License-Identifier: Apache-2.0
"""The lab smoke tells a capability with no suite from a real conformance failure by the CLI's
exit code and its own message, never by words a product put in a failing check's evidence."""

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

SMOKE = Path(__file__).resolve().parents[2] / "compose" / "lab-in-a-box" / "smoke.sh"

pytestmark = pytest.mark.requires_tool("bash")


def _function() -> str:
    m = re.search(r"^conform_missing_suite\(\) \{\n.*?^\}\n", SMOKE.read_text(), re.M | re.S)
    assert m, "smoke.sh defines conform_missing_suite"
    return m.group(0)


def _missing(tmp_path, rc: int, log: str, cap: str = "object-store") -> bool:
    f = tmp_path / "conform.log"
    f.write_text(log)
    script = _function() + 'conform_missing_suite "$1" "$2" "$3"\n'
    p = subprocess.run(
        [shutil.which("bash"), "-c", script, "smoke", str(rc), str(f), cap], check=False
    )
    return p.returncode == 0


FAILED_CHECK = (
    "FAIL  object-store  target=lab  9 executed\n"
    "  [FAIL] get-missing-raises: HTTP Error 404: Not Found\n"
    "  [FAIL] list-paginates: table not found; feature not available\n"
)


@pytest.mark.parametrize("rc", [1, 2, 100])
def test_product_text_in_a_failing_check_is_a_failure(tmp_path, rc):
    assert not _missing(tmp_path, rc, FAILED_CHECK)


def test_a_misconfigured_adapter_is_a_failure(tmp_path):
    log = "MISCONFIGURED  object-store  target=lab  0 executed\n  ERROR adapter misconfigured\n"
    assert not _missing(tmp_path, 2, log)


@pytest.mark.parametrize(
    "line",
    [
        "hnx conform: suite for 'object-store' not found: hnx conform needs a source checkout",
        "hnx conform: unknown capability 'object-store'; known: lake-query",
    ],
)
def test_the_clis_own_missing_suite_message_is_a_skip(tmp_path, line):
    assert _missing(tmp_path, 2, line + "\n")
    assert not _missing(tmp_path, 1, line + "\n"), "only exit 2 is the missing-suite case"
    assert not _missing(tmp_path, 2, line + "\n", cap="secrets"), "it names this capability"


def test_the_report_says_which_capabilities_ran_against_a_real_container(tmp_path):
    m = re.search(r"<<'PY'\n(.*?)^PY$", SMOKE.read_text(), re.M | re.S)
    assert m, "smoke.sh writes its report with an inline python program"
    (tmp_path / "conform-caps.txt").write_text(
        "object-store real pass\ninference fake pass\ncases fake no-suite\nsecrets real fail\n"
    )
    prog = tmp_path / "write_report.py"
    prog.write_text(m.group(1))
    py = shutil.which("python3")
    subprocess.run([py, str(prog), str(tmp_path), "1", "fail", "note"], check=True)
    caps = json.loads((tmp_path / "report.json").read_text())["conformance"]["capabilities"]
    assert caps == {
        "object-store": {"subject": "real", "result": "pass"},
        "inference": {"subject": "fake", "result": "pass"},
        "cases": {"subject": "fake", "result": "no-suite"},
        "secrets": {"subject": "real", "result": "fail"},
    }


def _summary(tmp_path, log: str, env: dict[str, str] | None = None) -> list[str]:
    m = re.search(r"^conform_failure_summary\(\) \{\n.*?^\}\n", SMOKE.read_text(), re.M | re.S)
    assert m, "smoke.sh defines conform_failure_summary"
    f = tmp_path / "conform.log"
    f.write_text(log)
    p = subprocess.run(
        [
            shutil.which("bash"),
            "-c",
            m.group(0) + 'conform_failure_summary "$1"\n',
            "smoke",
            str(f),
        ],
        capture_output=True,
        text=True,
        check=True,
        env={"PATH": "/usr/bin:/bin", **(env or {})},
    )
    return p.stdout.splitlines()


def test_a_failed_capability_names_each_failed_check_in_the_job_log(tmp_path):
    log = "PASS-ish noise\n" + FAILED_CHECK + "  [skip] something: not applicable\n"
    assert _summary(tmp_path, log) == [
        "smoke.sh:   FAIL  object-store  target=lab  9 executed",
        "smoke.sh:     [FAIL] get-missing-raises: HTTP Error 404: Not Found",
        "smoke.sh:     [FAIL] list-paginates: table not found; feature not available",
    ]


def test_the_failure_summary_is_bounded(tmp_path):
    log = "FAIL  object-store  target=lab  40 executed\n" + "".join(
        f"  [FAIL] check-{i}: {'x' * 1000}\n" for i in range(40)
    )
    lines = _summary(tmp_path, log)
    assert len(lines) == 20 and all(len(line) <= len("smoke.sh:   ") + 300 for line in lines)


def test_output_in_another_shape_shows_its_last_lines(tmp_path):
    log = "".join(f"line {i}\n" for i in range(10)) + "Traceback: boom\n"
    assert _summary(tmp_path, log)[-1] == "smoke.sh:   Traceback: boom"
    assert len(_summary(tmp_path, log)) == 5


def test_negative_a_credential_an_adapter_echoes_is_masked(tmp_path):
    echoed = "fade" * 3 + "0123"
    log = f"FAIL  object-store  target=lab  1 executed\n  [FAIL] put: rejected key {echoed}\n"
    out = _summary(tmp_path, log, env={"LAB_S3_SECRET_KEY": echoed})
    assert echoed not in "\n".join(out) and out[-1].endswith("rejected key ***")
