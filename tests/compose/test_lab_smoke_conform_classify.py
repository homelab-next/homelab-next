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

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")


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
