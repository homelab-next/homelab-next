# SPDX-License-Identifier: Apache-2.0
"""tools/dup_check.py: the duplication ratchet (new clones fail, the baseline only shrinks)."""

import io
import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import dup_check as dup

REPO = Path(__file__).resolve().parents[2]
GIT = ["git", "-c", "user.email=t@example.org", "-c", "user.name=t"]

# a distinctive helper: well over 50 tokens and 5 lines
HELPER = '''
def merge_windows(spans, gap):
    """Merge spans closer than gap."""
    spans = sorted(spans)
    merged = [list(spans[0])]
    for start, end in spans[1:]:
        last = merged[-1]
        if start - last[1] <= gap:
            last[1] = max(last[1], end)
        else:
            merged.append([start, end])
    total = sum(e - s for s, e in merged)
    return [tuple(m) for m in merged], total
'''
OTHER = """
def describe(rows):
    out = {}
    for r in rows:
        out.setdefault(r["kind"], []).append(r["name"])
    return {k: ", ".join(sorted(v)) for k, v in out.items()}
"""


def _tree(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "tree"
    if not (root / ".git").exists():
        root.mkdir(exist_ok=True)
        subprocess.run([*GIT, "init", "-q", str(root)], check=True)
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if text is None:
            p.unlink()
            subprocess.run([*GIT, "rm", "-q", "--cached", rel], cwd=root, check=True)
            continue
        p.write_text(text)
        subprocess.run([*GIT, "add", rel], cwd=root, check=True)
    return root


def _run(root: Path, *args: str) -> tuple[int, str]:
    out, err = io.StringIO(), io.StringIO()
    rc = dup.main([str(root), *args], out=out, err=err)
    return rc, out.getvalue() + err.getvalue()


def _baseline(root: Path) -> dict:
    return json.loads((root / dup.DEFAULT_BASELINE).read_text())


def _with_baseline(tmp_path, files):
    root = _tree(tmp_path, files)
    rc, log = _run(root, "--update-baseline")
    assert rc == 0, log
    return root


def test_a_planted_clone_fails_and_names_both_copies(tmp_path):
    root = _with_baseline(tmp_path, {"pkg/a.py": HELPER, "pkg/b.py": OTHER})
    assert _run(root)[0] == 0
    _tree(tmp_path, {"pkg/c.py": "X = 1\n" + HELPER})
    rc, log = _run(root)
    assert rc == 1
    assert "new clone" in log and "pkg/a.py:2-13" in log and "pkg/c.py:3-14" in log


def test_no_baseline_means_every_clone_is_new(tmp_path):
    root = _tree(tmp_path, {"a.py": HELPER, "b.py": HELPER})
    rc, log = _run(root)
    assert rc == 1 and "no baseline" in log and "a.py:2-13 <-> b.py:2-13" in log


def test_a_renamed_identifier_clone_fails_in_normalised_mode_only(tmp_path):
    renamed = HELPER.replace("spans", "ranges").replace("merged", "out").replace("gap", "slack")
    root = _tree(tmp_path, {"a.py": HELPER, "b.py": renamed})
    assert _run(root, "--mode", "exact")[0] == 0  # no baseline needed: nothing found
    rc, log = _run(root, "--mode", "normalised")
    assert rc == 1 and "a.py:2-13 <-> b.py:2-13" in log


def test_baselined_clones_pass(tmp_path):
    root = _with_baseline(tmp_path, {"a.py": HELPER, "b.py": HELPER, "c.py": OTHER})
    rc, log = _run(root)
    assert rc == 0, log
    doc = _baseline(root)
    assert doc["summary"]["clones"] == 1 and doc["params"] == dup.DEFAULTS
    (entry,) = doc["clones"].values()
    assert entry["files"] == ["a.py", "b.py"] and entry["count"] == 1


def test_moving_code_does_not_fail_or_churn_the_baseline(tmp_path):
    root = _with_baseline(tmp_path, {"a.py": HELPER, "b.py": HELPER})
    before = _baseline(root)["clones"]
    shifted = "# a comment\nA = 1\n\n\nB = 2\n" + HELPER + OTHER
    _tree(tmp_path, {"a.py": shifted, "b.py": "C = 3\n" + HELPER})
    rc, log = _run(root)
    assert rc == 0, log
    assert _run(root, "--update-baseline")[0] == 0
    assert _baseline(root)["clones"] == before


def test_removing_a_clone_reports_a_stale_entry_and_the_update_shrinks(tmp_path):
    root = _with_baseline(tmp_path, {"a.py": HELPER, "b.py": HELPER})
    _tree(tmp_path, {"b.py": OTHER})
    rc, log = _run(root)
    assert rc == 1 and "stale baseline entry" in log and "a.py, b.py" in log
    assert _run(root, "--update-baseline")[0] == 0
    assert _baseline(root)["clones"] == {} and _run(root)[0] == 0


def test_the_update_refuses_to_raise_the_total_without_a_reason(tmp_path):
    root = _with_baseline(tmp_path, {"a.py": HELPER, "b.py": OTHER})
    _tree(tmp_path, {"c.py": HELPER})
    rc, log = _run(root, "--update-baseline")
    assert rc == 2 and "refusing" in log and _baseline(root)["clones"] == {}
    assert _run(root, "--allow-increase", "x")[0] == 2  # only with --update-baseline
    rc, log = _run(root, "--update-baseline", "--allow-increase", "vendored on purpose")
    assert rc == 0, log
    doc = _baseline(root)
    assert doc["increases"] == [{"reason": "vendored on purpose", "from": 0, "to": 24}]
    assert _run(root)[0] == 0


def test_a_third_copy_of_a_baselined_clone_fails(tmp_path):
    root = _with_baseline(tmp_path, {"a.py": HELPER, "b.py": HELPER})
    _tree(tmp_path, {"c.py": HELPER})
    rc, log = _run(root)
    assert rc == 1 and "c.py:2-13" in log


def test_a_clone_that_shrank_is_still_covered_but_one_that_grew_is_not(tmp_path):
    root = _with_baseline(tmp_path, {"a.py": HELPER, "b.py": HELPER})
    # one copy is edited near its end: less is duplicated, nothing new
    edited = HELPER.replace("total = sum(e - s for s, e in merged)", "total = len(merged)")
    _tree(tmp_path, {"b.py": edited})
    rc, log = _run(root)
    assert rc == 0 and "shrank" in log, log
    # both copies gain the same lines: the clone is longer than the baseline holds
    grown = HELPER + "    print(total)\n    print(merged)\n    print(gap)\n"
    _tree(tmp_path, {"a.py": grown, "b.py": grown})
    rc, log = _run(root)
    assert rc == 1 and "new clone" in log


def test_comments_docstrings_imports_and_tests_are_ignored(tmp_path):
    imports = "".join(f"import mod_{i}\n" for i in range(30))
    stub = "def f():\n    '''" + "doc words " * 40 + "'''\n    return 1\n"
    files = {
        "a.py": imports + stub,
        "b.py": imports + "# " + "comment " * 60 + "\n" + stub,
        "tests/test_x.py": HELPER,
        "pkg/tests/helpers.py": HELPER,
        "test_y.py": HELPER,
        "conftest.py": HELPER,
        "schemas/_frozen/1.0/m.py": HELPER,
        "gen.py": "# @generated by a tool\n" + HELPER,
        "notes.txt": HELPER,
    }
    root = _tree(tmp_path, files)
    rc, log = _run(root)
    assert rc == 0, log
    assert "2 files" in log  # a.py and b.py; gen.py is generated
    (root / "untracked.py").write_text(HELPER)
    (root / "untracked2.py").write_text(HELPER)
    assert _run(root)[0] == 0  # only tracked files are scanned


def test_thresholds_are_configurable_and_must_match_the_baseline(tmp_path):
    small = "def g(x):\n    y = x + 1\n    z = y * 2\n    w = z - 3\n    return w\n"
    root = _with_baseline(tmp_path, {"a.py": small, "b.py": small})
    assert _baseline(root)["summary"]["clones"] == 0  # 29 tokens: below the default 50
    rc, log = _run(root, "--min-tokens", "20")
    assert rc == 2 and "differ from the baseline" in log
    assert _run(root, "--min-tokens", "20", "--update-baseline")[0] == 2
    rc, _ = _run(root, "--min-tokens", "20", "--update-baseline", "--allow-increase", "tighter")
    assert rc == 0 and _baseline(root)["params"]["min_tokens"] == 20
    assert _baseline(root)["summary"]["clones"] == 1 and _run(root)[0] == 0


@pytest.mark.parametrize("bad", ["not json", '{"schema": 99}', '{"schema": 1, "params": {}}'])
def test_a_bad_baseline_is_a_usage_error(tmp_path, bad):
    root = _tree(tmp_path, {"a.py": OTHER})
    (root / dup.DEFAULT_BASELINE).parent.mkdir(parents=True, exist_ok=True)
    (root / dup.DEFAULT_BASELINE).write_text(bad)
    rc, log = _run(root)
    assert rc == 2 and "bad baseline" in log


def test_the_repository_holds_its_baseline_in_seconds():
    t0 = time.perf_counter()
    rc, log = _run(REPO)
    assert rc == 0, log
    assert time.perf_counter() - t0 < 20
    doc = _baseline(REPO)
    assert doc["params"] == dup.DEFAULTS
    assert doc["summary"]["clones"] == sum(e["count"] for e in doc["clones"].values())


def test_tokens_are_the_same_on_every_interpreter():
    """An f-string is one STRING token on every Python, so the baseline holds on 3.11 and 3.12+."""
    src = 'x = f"a{b!r:>{w}}c" + f"""\n{d}\n"""\n'
    toks, lines = dup.tokens_of(src, "exact")
    assert toks == ["x", "=", 'f"a{b!r:>{w}}c"', "+", 'f"""\n{d}\n"""', ";"]
    assert lines == [1, 1, 1, 1, 1, 3]
