# SPDX-License-Identifier: Apache-2.0
"""Q-08: the fix_has_test gate -- a fix commit without a test file fails, waivers are listed,
and --prove catches a regression test that passes without the fix (pytest modules and Go
packages, the latter on a fixture module when a Go toolchain is installed)."""

import re
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
    files = ["homelabnext/a.py", "tests/a/test_b.py", "tools/tests/x.json", "pkg/tests/b_test.py"]
    assert gate.test_files(files) == files[1:]
    # *_test.py is a test only under a test directory: tools/x_test.py is a tool
    assert gate.test_files(["pkg/b_test.py", "tools/lint_test.py"]) == []
    assert gate.TEST_MODULE.search("pkg/tests/b_test.py")
    assert not gate.TEST_MODULE.search("tools/lint_test.py")
    assert gate.test_files(["conformance/dns/test_dns.py"]) == ["conformance/dns/test_dns.py"]
    assert gate.test_files(["docs/testing.md", "src/latest.py"]) == []
    go = ["orchestrator/internal/queue/queue_test.go", "orchestrator/internal/queue/queue.go"]
    assert gate.test_files(go) == go[:1]
    assert gate.test_files(["orchestrator/go.mod", "orchestrator/testing.go"]) == []
    # Go fixtures and golden files are test files: staged with the tests, and a test change
    data = ["orchestrator/internal/api/testdata/case.json", "testdata/golden.txt"]
    assert gate.test_files(data) == data
    assert gate.test_files(["orchestrator/internal/mytestdata/x.go"]) == []


def test_nested_testdata_is_the_data_of_the_package_holding_the_outermost_testdata():
    m = gate.GO_TESTDATA.match("orchestrator/internal/api/testdata/sub/testdata/b.txt")
    assert m.group("pkg") == "orchestrator/internal/api/"
    assert gate.GO_TESTDATA.match("testdata/golden.txt").group("pkg") == ""


def test_the_gate_itself_is_not_a_test_file():
    # its name ends in _test.py: a fix to the gate alone used to count as shipping a test
    assert gate.test_files(["tools/fix_has_test.py"]) == []
    problems, _ = gate.check([gate.Commit("a" * 40, "fix: gate", ["tools/fix_has_test.py"])])
    assert problems and "a fix without a regression test" in problems[0]


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


PY_PATH = (
    "import sys, pathlib\nsys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))\n"
)
CLAMP = "def clamp(x):\n    return min(x, {cap})\n"


def _py_fix(tmp_path, mod: str, test: str, extra: dict | None = None):
    """A scratch repository with clamp(), then one fix commit; the fix's Commit."""
    r, commit = _repo(tmp_path)
    commit("feat: clamp", **{"mod.py": "def clamp(x):\n    return x\n"})
    sha = commit(
        "fix: clamp", **{"mod.py": mod, "tests/test_mod.py": PY_PATH + test, **(extra or {})}
    )
    (c,) = gate.commits_in(f"{sha}^..{sha}", cwd=r)
    return r, c


@pytest.mark.parametrize(
    "test",
    [
        # module level: the module does not import on the parent
        "from mod import VERSION\n\ndef test_v():\n    assert VERSION == '2'\n",
        # inside the test: an ImportError in the test
        "def test_v():\n    from mod import VERSION\n    assert VERSION == '2'\n",
        # an attribute of the module
        "import mod\n\ndef test_v():\n    assert mod.VERSION == '2'\n",
    ],
    ids=["module-level import", "in-function import", "module attribute"],
)
def test_a_missing_name_the_fix_adds_counts_as_failing(tmp_path, test):
    """One rule (Python and Go): a test that fails on the parent only because a name is missing
    proves the fix when the fix's own diff adds that name."""
    r, c = _py_fix(tmp_path, CLAMP.format(cap=10) + "VERSION = '2'\n", test)
    assert gate.added_symbols(c, cwd=r).names >= {"VERSION"}
    assert gate.prove(c, cwd=r) is None


@pytest.mark.parametrize(
    "test, name",
    [
        ("from mod import helper\n\ndef test_v():\n    assert helper()\n", "helper"),
        ("def test_v():\n    from mod import helper\n    assert helper()\n", "helper"),
        ("import mod\n\ndef test_v():\n    assert mod.helper()\n", "helper"),
        ("import nosuchmodule\n\ndef test_v():\n    assert True\n", "nosuchmodule"),
        ("def test_v():\n    assert undefined_thing() == 1\n", "undefined_thing"),
    ],
    ids=["module-level import", "in-function import", "module attribute", "module", "NameError"],
)
def test_a_missing_name_the_fix_does_not_add_cannot_prove_it(tmp_path, test, name):
    r, c = _py_fix(tmp_path, CLAMP.format(cap=10), test)
    problem = gate.prove(c, cwd=r)
    assert problem and "cannot prove the fix" in problem and name in problem
    assert "which the fix does not add" in problem


def test_a_new_module_the_fix_adds_counts_as_failing(tmp_path):
    test = "from limits import CAP\n\ndef test_cap():\n    assert CAP == 10\n"
    r, c = _py_fix(tmp_path, CLAMP.format(cap=10), test, {"limits.py": "CAP = 10\n"})
    assert "limits" in gate.added_symbols(c, cwd=r).modules
    assert gate.prove(c, cwd=r) is None


def test_an_error_that_is_not_a_failing_test_cannot_prove_the_fix(tmp_path):
    # a fixture that raises on the parent for a reason other than a missing name is an error
    test = (
        "import pytest\n\n"
        "@pytest.fixture\ndef cfg():\n    raise RuntimeError('no config')\n\n"
        "def test_v(cfg):\n    assert True\n"
    )
    r, c = _py_fix(tmp_path, CLAMP.format(cap=10), test)
    problem = gate.prove(c, cwd=r)
    assert problem and "an error that is not a failing test" in problem


def test_a_real_failure_proves_the_fix(tmp_path):
    test = "def test_clamp():\n    from mod import clamp\n    assert clamp(12) == 10\n"
    r, c = _py_fix(tmp_path, CLAMP.format(cap=10), test)
    assert gate.prove(c, cwd=r) is None


@pytest.mark.parametrize(
    "rel",
    ["tests/fixtures/data.json", "tests/conftest.py", "tests/NOTES.txt", "pkg/tests/golden.txt"],
)
def test_a_fix_whose_only_test_files_are_not_test_modules_cannot_be_proven(tmp_path, rel):
    r, commit = _repo(tmp_path)
    base = commit("feat: f", **{"mod.py": "def f():\n    return 1\n"})
    sha = commit("fix: change f", **{"mod.py": "def f():\n    return 2\n", rel: "x = 1\n"})
    (c,) = gate.commits_in(f"{base}..{sha}", cwd=r)
    assert gate.check([c]) == ([], [])  # it does touch a file under tests/...
    problem = gate.prove(c, cwd=r)  # ...but nothing there can show the fix
    assert problem and "cannot prove the fix: it changes no test module" in problem
    assert gate.main(["--repo", str(r), "--range", f"{base}..{sha}", "--prove"]) == 1
    waived = commit(
        "fix: change f again\n\nNo-regression-test: the golden file is the whole change",
        **{"mod.py": "def f():\n    return 3\n", rel: "x = 2\n"},
    )
    (c,) = gate.commits_in(f"{sha}..{waived}", cwd=r)
    assert gate.prove(c, cwd=r) is None


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


needs_go = pytest.mark.usefixtures("go_toolchain")  # tools/tests/conftest.py (HNX_REQUIRE_GO)


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
def test_go_test_that_does_not_build_for_a_symbol_the_fix_adds_counts_as_failing(tmp_path):
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


@needs_go
@pytest.mark.parametrize(
    "test_body, calc, name",
    [
        # Mul exists nowhere: the package does not build for a name the fix does not add
        ("\tif Mul(3, 1) != 3 {\n\t\tt.Fatal(1)\n\t}\n", CALC.format(op="+"), "Mul"),
        # a method the fix does not add
        (
            "\tvar x struct{ N int }\n\tif x.Size() != 0 {\n\t\tt.Fatal(1)\n\t}\n",
            CALC.format(op="+"),
            "Size",
        ),
    ],
    ids=["function", "method"],
)
def test_go_test_that_does_not_build_for_another_symbol_cannot_prove_the_fix(
    tmp_path, test_body, calc, name
):
    r, commit, base = _go_repo(tmp_path)
    test = "\nfunc TestNew(t *testing.T) {\n" + test_body + "}\n"
    fix = commit(
        "fix: calc adds",
        **{GO + "calc.go": calc, GO + "new_test.go": 'package calc\n\nimport "testing"\n' + test},
    )
    (c,) = gate.commits_in(f"{base}..{fix}", cwd=r)
    problem = gate.prove(c, cwd=r)
    assert problem and "cannot prove the fix" in problem and name in problem


@needs_go
def test_go_build_error_that_names_no_symbol_cannot_prove_the_fix(tmp_path):
    # the fix changes Add's signature; the test calls the new one: "too many arguments", no
    # missing name, so the parent's failure proves nothing about the behaviour
    r, commit, base = _go_repo(tmp_path)
    calc3 = "package calc\n\nfunc Add(a, b, c int) int {\n\treturn a + b + c\n}\n"
    test = "\nfunc TestAdd3(t *testing.T) {\n\tif Add(1, 1, 1) != 3 {\n\t\tt.Fatal(1)\n\t}\n}\n"
    fix = commit(
        "fix: add takes three",
        **{
            GO + "calc.go": calc3,
            GO + "calc_test.go": 'package calc\n\nimport "testing"\n' + test,
        },
    )
    (c,) = gate.commits_in(f"{base}..{fix}", cwd=r)
    problem = gate.prove(c, cwd=r)
    assert problem and "an error that is not a failing test" in problem


@needs_go
def test_go_fixture_only_change_outside_a_go_package_cannot_prove_the_fix(tmp_path):
    r, commit, base = _go_repo(tmp_path)
    fix = commit(
        "fix: add adds",
        **{GO + "calc.go": CALC.format(op="+"), "orchestrator/tests/golden/add.txt": "4\n"},
    )
    (c,) = gate.commits_in(f"{base}..{fix}", cwd=r)
    problem = gate.prove(c, cwd=r)
    assert problem and "it changes no test module" in problem


def test_go_outcome_reads_compiler_errors_under_the_rule():
    added = gate.Added(names={"Sub"}, modules={"orchestrator/internal/newpkg"})
    out = "# example.com/x/calc [example.com/x/calc.test]\n./sub_test.go:6:5: undefined: Sub\nFAIL\texample.com/x/calc [build failed]\n"
    assert gate.go_outcome(out, 1, added).failed == 1
    out2 = out.replace("undefined: Sub", "undefined: Mul")
    assert gate.go_outcome(out2, 1, added).missing == {"Mul"}
    out3 = (
        "calc_test.go:4:2: no required module provides package example.com/x/internal/newpkg; to add it:\n"
        "FAIL\texample.com/x/calc [setup failed]\n"
    )
    assert (
        gate.go_outcome(
            out3.replace(
                "example.com/x/internal/newpkg", "example.com/x/orchestrator/internal/newpkg"
            ),
            1,
            added,
        ).failed
        == 1
    )
    assert gate.go_outcome(out3, 1, added).missing == {"example.com/x/internal/newpkg"}
    assert gate.go_outcome("--- FAIL: TestAdd\nFAIL\n", 1, added).failed == 1
    assert gate.go_outcome("go: errors parsing go.mod:\n", 1, added).errors


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


def test_the_regression_tests_job_has_a_go_toolchain_once_a_module_exists():
    import yaml

    root = Path(__file__).resolve().parents[2]
    ci = yaml.safe_load((root / ".github" / "workflows" / "ci.yml").read_text())
    jobs = ci["jobs"]
    steps = jobs["regression-tests"]["steps"]
    (go,) = [s for s in steps if s.get("uses", "").startswith("actions/setup-go@")]
    (pinned,) = [
        s for s in jobs["go"]["steps"] if s.get("uses", "").startswith("actions/setup-go@")
    ]
    assert go["uses"] == pinned["uses"]  # the same pinned commit as the go job
    # any discovered module, not one named directory; the workflow's pinned Go version
    assert jobs["regression-tests"]["needs"] == "go-modules"
    assert go["if"] == "needs.go-modules.outputs.present == 'true'"
    assert go["with"]["go-version"] == "${{ env.GO_VERSION }}"
    assert re.fullmatch(r"\d+\.\d+\.\d+", ci["env"]["GO_VERSION"])
    assert go["with"]["cache-dependency-path"] == "**/go.sum"
    names = [s.get("name") or s.get("uses") for s in steps]
    assert names.index(go["uses"]) < next(
        i for i, s in enumerate(steps) if "fix_has_test" in s.get("run", "")
    )


def test_go_test_functions_are_gos_own_rule_and_end_at_their_closing_brace():
    src = (
        'package calc\n\nimport "testing"\n\n'
        "func TestMain(m *testing.M) { m.Run() }\n\n"
        "func Testable(t *testing.T) {}\n\n"
        "func Test(t *testing.T) {}\n\n"
        "func TestJSON(t *testing.T) {\n"
        "\twant := `{\n}\n`\n"  # a raw string with a } alone on a line
        "\t/* } */ r := '}'\n"
        '\ts := "}\\"{"\n'
        "\t// }\n"
        "\t_ = want + s + string(r)\n"
        "}\n\n"
        "func Fuzz_Parse(f *testing.F) {}\n"
        "func TestLast(t *testing.T) {"  # no newline at the end of the file
    )
    funcs = gate._go_funcs(src)
    assert sorted(funcs) == ["Fuzz_Parse", "Test", "TestJSON", "TestLast"]
    assert funcs["TestJSON"].endswith("_ = want + s + string(r)\n}")
    assert funcs["TestLast"] == "func TestLast(t *testing.T) {"


@needs_go
def test_a_go_fix_that_changes_only_testmain_runs_the_whole_package(tmp_path):
    r, commit, base = _go_repo(tmp_path)
    main = "\nfunc TestMain(m *testing.M) {\n\tif Add(2, 2) != 4 {\n\t\tpanic(Add(2, 2))\n\t}\n\tm.Run()\n}\n"
    fix = commit(
        "fix: add adds",
        **{GO + "calc.go": CALC.format(op="+"), GO + "calc_test.go": CALC_TEST.format(extra=main)},
    )  # fmt: skip
    (c,) = gate.commits_in(f"{base}..{fix}", cwd=r)
    assert gate.changed_go_tests(c, GO + "calc_test.go", cwd=r) == []  # a helper: run it all
    assert gate.prove(c, cwd=r) is None


def test_the_go_module_probe_prints_no_git_errors(tmp_path, capfd):
    r, _commit, base = _go_repo(tmp_path)
    (c,) = gate.commits_in(base, cwd=r)
    capfd.readouterr()
    # orchestrator/internal/calc/go.mod and orchestrator/internal/go.mod do not exist: no noise
    assert gate._go_module_at(c, GO + "calc_test.go", cwd=r) is True
    assert gate._go_module_at(c, "loose/x_test.go", cwd=r) is False
    assert capfd.readouterr().err == ""


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
