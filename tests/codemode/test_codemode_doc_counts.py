# SPDX-License-Identifier: Apache-2.0
"""docs/codemode.md states how many MUST checks each Code Mode suite has: held to the suites."""

from __future__ import annotations

import re
from pathlib import Path

from conformance.suites import codemode_executor, codemode_runner

DOC = (Path(__file__).resolve().parents[2] / "docs" / "codemode.md").read_text()
WORDS = [
    "zero",
    "one",
    "two",
    "three",
    "four",
    "five",
    "six",
    "seven",
    "eight",
    "nine",
    "ten",
    "eleven",
    "twelve",
    "thirteen",
    "fourteen",
    "fifteen",
    "sixteen",
    "seventeen",
    "eighteen",
    "nineteen",
    "twenty",
]


def _stated(pattern: str) -> int:
    m = re.search(pattern, DOC)
    assert m, pattern
    return WORDS.index(m.group(1))


def test_the_executor_suite_count_is_the_suites():
    stated = _stated(r"codemode_executor\.py` has (\w+) MUST checks")
    assert stated == len(codemode_executor.SUITE.ids())
    assert f"{stated} checks of the 24-check maximum" in DOC


def test_the_runner_suite_count_is_the_suites():
    stated = _stated(r"with (\w+) MUST\s+checks, `result-matches-the-schema`")
    assert stated == len(codemode_runner.SUITE.ids())
