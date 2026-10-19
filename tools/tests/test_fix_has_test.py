# SPDX-License-Identifier: Apache-2.0
"""Q-08: the fix_has_test gate -- a fix commit without a test file fails, waivers are listed,
and --prove catches a regression test that passes without the fix."""

import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import fix_has_test as gate

GIT = ["git", "-c", "user.email=t@example.org", "-c", "user.name=t", "-c", "commit.gpgsign=false"]


@pytest.mark.parametrize(
    "msg, fix",
    [
        ("fix: off by one", True),
        ("fix(events): lost ack", True),
        ("fix!: breaking fix", True),
        ("Fix: capitalised", True),
        ("feat: new thing\n\nFixes: #12", True),
        ("feat: new thing", False),
        ("fixture: add data", False),
        ("docs: mention fix: in text", False),
        ("", False),
    ],
)
def test_is_fix(msg, fix):
    assert gate.is_fix(msg) is fix


def test_test_files():
    files = ["homelabnext/a.py", "tests/a/test_b.py", "tools/tests/x.json", "pkg/b_test.py"]
    assert gate.test_files(files) == files[1:]
    assert gate.test_files(["conformance/dns/test_dns.py"]) == ["conformance/dns/test_dns.py"]
    assert gate.test_files(["docs/testing.md", "src/latest.py"]) == []


def test_check_classifies_commits():
    commits = [
        gate.Commit("a" * 40, "fix: no test", ["homelabnext/x.py"]),
        gate.Commit("b" * 40, "fix: with test", ["homelabnext/x.py", "tests/x/test_x.py"]),
        gate.Commit("c" * 40, "feat: no test needed", ["homelabnext/x.py"]),
        gate.Commit("d" * 40, "chore: bump\n\nFixes: #3", ["pyproject.toml"]),
        gate.Commit("e" * 40, "fix: typo\n\nNo-regression-test: documentation only", ["README.md"]),
        gate.Commit("f" * 40, "fix: typo\n\nNo-regression-test: x", ["README.md"]),  # too short
    ]
    problems, notes = gate.check(commits)
    assert [p[:10] for p in problems] == ["a" * 10, "d" * 10, "f" * 10]
    assert notes == ["waived eeeeeeeeee 'fix: typo': documentation only"]


def _repo(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(r)], check=True)

    def commit(msg, **files):
        for rel, text in files.items():
            p = r / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)
        subprocess.run([*GIT, "add", "-A"], cwd=r, check=True)
        subprocess.run([*GIT, "commit", "-q", "-m", msg], cwd=r, check=True)
        return subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=r, capture_output=True, text=True, check=True
        ).stdout.strip()

    return r, commit


TEST_TEMPLATE = (
    "import sys, pathlib\n"
    "sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))\n"
    "from mod import add\n\n"
    "def test_add():\n    assert add(2, 2) == {want}\n"
)


def test_end_to_end_on_a_scratch_repository(tmp_path):
    r, commit = _repo(tmp_path)
    base = commit("feat: add", **{"mod.py": "def add(a, b):\n    return a - b\n"})
    real = commit(
        "fix: add adds",
        **{"mod.py": "def add(a, b):\n    return a + b\n", "tests/test_mod.py": TEST_TEMPLATE.format(want=4)},
    )  # fmt: skip
    commits = gate.commits_in(f"{base}..HEAD", cwd=r)
    assert [c.sha for c in commits] == [real]
    assert gate.check(commits) == ([], [])
    assert gate.prove(commits[0], cwd=r) is None  # the test fails on the parent: proven

    vacuous = commit(
        "fix: comment only",
        **{"mod.py": "# adds\ndef add(a, b):\n    return a + b\n", "tests/test_other.py": "def test_true():\n    assert True\n"},
    )  # fmt: skip
    (c,) = gate.commits_in(f"{real}..HEAD", cwd=r)
    assert c.sha == vacuous
    assert "passes WITHOUT the fix" in gate.prove(c, cwd=r)

    commit("fix: forgot the test", **{"mod.py": "def add(a, b):\n    return b + a\n"})
    repo = ["--repo", str(r)]
    assert gate.main([*repo, "--range", f"{base}..HEAD"]) == 1  # the last fix has no test
    assert gate.main([*repo, "--range", f"{base}..{real}", "--prove"]) == 0
    assert gate.main([*repo, "--range", f"{base}..{vacuous}"]) == 0  # it does touch a test...
    assert gate.main([*repo, "--range", f"{base}..{vacuous}", "--prove"]) == 1  # ...a vacuous one
    assert gate.main([*repo, "--range", "nope..HEAD"]) == 2
    assert gate.main([*repo, "--range", "nope..HEAD", "--allow-missing-base"]) == 0


def test_this_repository_passes():
    assert gate.main(["--range", "HEAD", "--allow-missing-base"]) == 0
