# SPDX-License-Identifier: Apache-2.0
"""Q-08: the fix_has_test gate -- a fix commit without a test file fails, waivers are listed,
and --prove catches a regression test that passes without the fix (pytest modules and Go
packages, the latter on a fixture module when a Go toolchain is installed)."""

import shutil
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
    go = ["orchestrator/internal/queue/queue_test.go", "orchestrator/internal/queue/queue.go"]
    assert gate.test_files(go) == go[:1]
    assert gate.test_files(["orchestrator/go.mod", "orchestrator/testing.go"]) == []
    # Go fixtures and golden files are test files: staged with the tests, and a test change
    data = ["orchestrator/internal/api/testdata/case.json", "testdata/golden.txt"]
    assert gate.test_files(data) == data
    assert gate.test_files(["orchestrator/internal/mytestdata/x.go"]) == []


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


# --- Go: a fixture module in orchestrator/ --------------------------------------------------------

GO_MOD = "module example.com/fixture\n\ngo 1.21\n"
CALC = "package calc\n\nfunc Add(a, b int) int {{\n\treturn a {op} b\n}}\n"
CALC_TEST = (
    'package calc\n\nimport "testing"\n\n'
    "func TestOther(t *testing.T) {{\n\tif Add(0, 0) != 0 {{\n\t\tt.Fatal(0)\n\t}}\n}}\n"
    "{extra}"
)
TEST_ADD = "\nfunc TestAdd(t *testing.T) {\n\tif Add(2, 2) != 4 {\n\t\tt.Fatal(Add(2, 2))\n\t}\n}\n"
TEST_TRUE = "\nfunc TestTrue(t *testing.T) {}\n"
GO = "orchestrator/internal/calc/"


def _go_repo(tmp_path):
    r, commit = _repo(tmp_path)
    base = commit(
        "feat: calc",
        **{
            "orchestrator/go.mod": GO_MOD,
            GO + "calc.go": CALC.format(op="-"),
            GO + "calc_test.go": CALC_TEST.format(extra=""),
        },
    )
    return r, commit, base


needs_go = pytest.mark.skipif(shutil.which("go") is None, reason="go is not installed")


@needs_go
def test_go_fix_is_proved_by_its_changed_test_functions(tmp_path):
    r, commit, base = _go_repo(tmp_path)
    fix = commit(
        "fix: add adds",
        **{GO + "calc.go": CALC.format(op="+"), GO + "calc_test.go": CALC_TEST.format(extra=TEST_ADD)},
    )  # fmt: skip
    (c,) = gate.commits_in(f"{base}..{fix}", cwd=r)
    assert gate.changed_go_tests(c, GO + "calc_test.go", cwd=r) == ["TestAdd"]
    assert gate.prove(c, cwd=r) is None  # TestAdd fails on the parent: proven
    assert gate.main(["--repo", str(r), "--range", f"{base}..{fix}", "--prove"]) == 0

    # only TestTrue is new, and it passes without the fix (TestAdd is not re-run)
    vacuous = commit(
        "fix: comment only",
        **{
            GO + "calc.go": "// Package calc adds.\n" + CALC.format(op="+"),
            GO + "calc_test.go": CALC_TEST.format(extra=TEST_ADD + TEST_TRUE),
        },
    )
    (c,) = gate.commits_in(f"{fix}..{vacuous}", cwd=r)
    assert gate.changed_go_tests(c, GO + "calc_test.go", cwd=r) == ["TestTrue"]
    problem = gate.prove(c, cwd=r)
    assert "passes WITHOUT the fix" in problem and "-run ^(TestTrue)$" in problem
    assert gate.main(["--repo", str(r), "--range", f"{fix}..{vacuous}", "--prove"]) == 1


@needs_go
def test_go_test_that_does_not_build_without_the_fix_counts_as_failing(tmp_path):
    r, commit, base = _go_repo(tmp_path)
    test_sub = "\nfunc TestSub(t *testing.T) {\n\tif Sub(3, 1) != 2 {\n\t\tt.Fatal(1)\n\t}\n}\n"
    fix = commit(
        "fix: calc subtracts too",
        **{
            GO + "calc.go": CALC.format(op="-") + "\nfunc Sub(a, b int) int { return a - b }\n",
            GO + "sub_test.go": 'package calc\n\nimport "testing"\n' + test_sub,
        },
    )
    (c,) = gate.commits_in(f"{base}..{fix}", cwd=r)
    assert gate.prove(c, cwd=r) is None


READS_FIXTURE = (
    'package calc\n\nimport (\n\t"os"\n\t"testing"\n)\n\n'
    "func TestCase(t *testing.T) {\n"
    '\tif _, err := os.ReadFile("testdata/case.json"); err != nil {\n\t\tt.Fatal(err)\n\t}\n}\n'
)


@needs_go
def test_go_fixtures_are_staged_on_the_parent_with_the_tests(tmp_path):
    r, commit, base = _go_repo(tmp_path)
    # the test only reads its new fixture: it fails on the parent only if the fixture is missing
    vacuous = commit(
        "fix: add adds",
        **{
            GO + "calc.go": CALC.format(op="+"),
            GO + "case_test.go": READS_FIXTURE,
            GO + "testdata/case.json": "{}\n",
        },
    )
    (c,) = gate.commits_in(f"{base}..{vacuous}", cwd=r)
    problem = gate.prove(c, cwd=r)
    assert problem is not None and "passes WITHOUT the fix" in problem


@needs_go
def test_a_go_fix_whose_only_test_change_is_testdata_runs_its_package(tmp_path):
    r, commit, base = _go_repo(tmp_path)
    golden = (
        'package calc\n\nimport (\n\t"os"\n\t"strconv"\n\t"strings"\n\t"testing"\n)\n\n'
        "func TestGolden(t *testing.T) {\n"
        '\tb, _ := os.ReadFile("testdata/add.golden")\n'
        "\tif got := strconv.Itoa(Add(2, 2)); got != strings.TrimSpace(string(b)) {\n"
        "\t\tt.Fatal(got)\n\t}\n}\n"
    )
    base = commit(
        "test: a golden file",
        **{GO + "golden_test.go": golden, GO + "testdata/add.golden": "0\n"},
    )
    fix = commit(
        "fix: add adds", **{GO + "calc.go": CALC.format(op="+"), GO + "testdata/add.golden": "4\n"}
    )
    (c,) = gate.commits_in(f"{base}..{fix}", cwd=r)
    assert gate.check([c]) == ([], [])  # the golden file is its test
    assert gate.prove(c, cwd=r) is None  # the whole package fails on the parent: proven
    vacuous = commit("fix: whitespace", **{GO + "testdata/add.golden": "4\n\n"})
    (c,) = gate.commits_in(f"{fix}..{vacuous}", cwd=r)
    problem = gate.prove(c, cwd=r)
    assert (
        problem is not None and "passes WITHOUT the fix" in problem and "./internal/calc" in problem
    )


def _module_proxy(root: Path) -> str:
    """A GOPROXY directory serving example.com/dep v1.0.0 (``func One() int { return 1 }``)."""
    import zipfile

    d = root / "example.com" / "dep" / "@v"
    d.mkdir(parents=True)
    mod = "module example.com/dep\n\ngo 1.21\n"
    (d / "list").write_text("v1.0.0\n")
    (d / "v1.0.0.info").write_text('{"Version":"v1.0.0"}\n')
    (d / "v1.0.0.mod").write_text(mod)
    with zipfile.ZipFile(d / "v1.0.0.zip", "w") as z:
        z.writestr("example.com/dep@v1.0.0/go.mod", mod)
        z.writestr("example.com/dep@v1.0.0/dep.go", "package dep\n\nfunc One() int { return 1 }\n")
    return root.as_uri()


@pytest.mark.parametrize(
    ("err", "can_run"),
    [
        ("go: downloading example.com/dep v1.0.0\n--- FAIL: TestAdd\nFAIL\n", True),
        ("FAIL\texample.com/fixture/internal/calc [setup failed]\n", False),
        ("go: errors parsing go.mod:\n", False),
        ("go: cannot find main module, but found .git/config\n", False),
        ("go: updates to go.mod needed; to update it:\n", False),
    ],
)
def test_go_setup_errors_are_told_from_progress_lines(err, can_run):
    assert (gate.GO_SETUP_ERROR.search(err) is None) is can_run


@needs_go
def test_a_go_fix_with_a_dependency_is_proved_on_a_cold_module_cache(tmp_path, monkeypatch):
    # go test prints "go: downloading ..." for every module it fetches: that is no setup error
    monkeypatch.setenv("GOPROXY", _module_proxy(tmp_path / "proxy"))
    monkeypatch.setenv("GOSUMDB", "off")
    monkeypatch.setenv("GOFLAGS", "-modcacherw")  # so tmp_path can be removed
    monkeypatch.setenv("GOTOOLCHAIN", "local")
    monkeypatch.setenv("GOMODCACHE", str(tmp_path / "warm"))
    r, commit = _repo(tmp_path)
    mod = r / "orchestrator"
    calc = 'package calc\n\nimport "example.com/dep"\n\nfunc Add(a, b int) int {{ return a {op} b * dep.One() }}\n'
    (mod / "internal" / "calc").mkdir(parents=True)
    (mod / "go.mod").write_text(GO_MOD + "\nrequire example.com/dep v1.0.0\n")
    (mod / "internal" / "calc" / "calc.go").write_text(calc.format(op="-"))
    subprocess.run(["go", "mod", "tidy"], cwd=mod, check=True, capture_output=True)
    base = commit("feat: calc with a dependency")
    fix = commit(
        "fix: add adds",
        **{GO + "calc.go": calc.format(op="+"), GO + "calc_test.go": CALC_TEST.format(extra=TEST_ADD)},
    )  # fmt: skip
    monkeypatch.setenv("GOMODCACHE", str(tmp_path / "cold"))  # nothing downloaded yet
    (c,) = gate.commits_in(f"{base}..{fix}", cwd=r)
    assert gate.prove(c, cwd=r) is None


def test_the_regression_tests_job_has_a_go_toolchain_once_the_module_exists():
    import yaml

    root = Path(__file__).resolve().parents[2]
    jobs = yaml.safe_load((root / ".github" / "workflows" / "ci.yml").read_text())["jobs"]
    steps = jobs["regression-tests"]["steps"]
    (go,) = [s for s in steps if s.get("uses", "").startswith("actions/setup-go@")]
    (pinned,) = [
        s
        for s in jobs["orchestrator"]["steps"]
        if s.get("uses", "").startswith("actions/setup-go@")
    ]
    assert go["uses"] == pinned["uses"]  # the same pinned commit as the orchestrator job
    assert go["with"]["go-version-file"] == "orchestrator/go.mod"
    assert (
        go["with"].get("cache", True) is not False
        and "go.sum" in go["with"]["cache-dependency-path"]
    )
    assert "orchestrator/go.mod" in go["if"]
    names = [s.get("name") or s.get("uses") for s in steps]
    assert names.index(go["uses"]) < next(
        i for i, s in enumerate(steps) if "fix_has_test" in s.get("run", "")
    )


def test_go_fix_without_a_go_toolchain_cannot_be_proved(tmp_path):
    r, commit, base = _go_repo(tmp_path)
    fix = commit(
        "fix: add adds",
        **{GO + "calc.go": CALC.format(op="+"), GO + "calc_test.go": CALC_TEST.format(extra=TEST_ADD)},
    )  # fmt: skip
    (c,) = gate.commits_in(f"{base}..{fix}", cwd=r)
    problem = gate.prove(c, cwd=r, go="go-toolchain-that-is-not-there")
    assert problem is not None and "cannot prove its Go tests: no Go toolchain" in problem


@needs_go
def test_go_test_outside_a_module_cannot_be_proved(tmp_path):
    r, commit = _repo(tmp_path)
    base = commit("feat: loose", **{"loose/x.go": "package loose\n"})
    fix = commit("fix: loose", **{"loose/x_test.go": "package loose\n"})
    (c,) = gate.commits_in(f"{base}..{fix}", cwd=r)
    assert "is in no Go module on the parent" in gate.prove(c, cwd=r)
