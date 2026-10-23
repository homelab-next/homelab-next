# SPDX-License-Identifier: Apache-2.0
"""tools/go_test_policy.py (Q-02 for Go): a go test -json run fails on a failing test, a broken
build or a silent skip; quarantines are bounded like pytest's; root-only tests need their run.

Event streams are fixtures in the shape ``go test -json`` writes (Go 1.24, ``Time`` dropped); one
test also runs a real ``go test -json`` when a Go toolchain is installed.
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import go_test_policy as policy

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "go_test_json"
MOD = "example.com/fixture"
TODAY = "2026-01-10"


def ev(action: str, pkg: str = "internal/queue", test: str | None = None, **extra) -> str:
    e = {"Action": action, "Package": f"{MOD}/{pkg}"}
    if test:
        e["Test"] = test
    e.update(extra)
    return json.dumps(e)


def events_of(pkg: str, test: str, verdict: str, *output: str) -> list[str]:
    word = verdict.upper()
    return [
        ev("run", pkg, test),
        ev("output", pkg, test, Output=f"=== RUN   {test}\n"),
        *(ev("output", pkg, test, Output=f"    queue_test.go:12: {o}\n") for o in output),
        ev("output", pkg, test, Output=f"--- {word}: {test} (0.00s)\n"),
        ev(verdict, pkg, test, Elapsed=0),
    ]


def package(pkg: str, verdict: str, *tests: list[str], **extra) -> list[str]:
    lines = [ev("start", pkg)]
    for t in tests:
        lines += t
    return [*lines, ev("output", pkg, Output=f"{verdict.upper()}\n"), ev(verdict, pkg, **extra)]


GREEN = package(
    "internal/queue",
    "pass",
    events_of("internal/queue", "TestAdmit", "pass"),
    events_of("internal/queue", "TestSeal", "skip", "python3 not available"),
)


def run(tmp_path, lines, *args, policy_yaml: str | None = None, capsys=None):
    f = tmp_path / "run.json"
    f.write_text("\n".join(lines) + "\n")
    extra = []
    if policy_yaml is not None:
        (tmp_path / "skips.yml").write_text(policy_yaml)
        extra = ["--policy", str(tmp_path / "skips.yml")]
    return policy.main([*extra, "--today", TODAY, *args, str(f)])


def test_a_green_run_with_a_registered_skip_passes(tmp_path, capsys):
    assert run(tmp_path, GREEN) == 0
    out = capsys.readouterr().out
    assert "note: skip example.com/fixture/internal/queue TestSeal: 'python3 not available'" in out
    assert "2 tests in 1 packages (1 passed, 0 failed, 1 skipped), 0 problem(s)" in out


@pytest.mark.parametrize(
    ("lines", "expected"),
    [
        (
            package("internal/queue", "fail", events_of("internal/queue", "TestAdmit", "fail", "boom")),
            "FAIL example.com/fixture/internal/queue TestAdmit",
        ),
        (  # a build failure, as Go 1.24 reports it
            [
                json.dumps({"ImportPath": f"{MOD}/internal/api [{MOD}/internal/api.test]", "Action": "build-output", "Output": "internal/api/api.go:3:9: undefined: x\n"}),
                json.dumps({"ImportPath": f"{MOD}/internal/api [{MOD}/internal/api.test]", "Action": "build-fail"}),
                *package("internal/api", "fail", FailedBuild=f"{MOD}/internal/api [{MOD}/internal/api.test]"),
            ],
            "BUILD FAIL example.com/fixture/internal/api: internal/api/api.go:3:9: undefined: x",
        ),
        (  # a timeout or a TestMain panic: the package fails with no failing test
            [ev("start"), ev("output", Output="panic: test timed out after 10m0s\n"), ev("fail")],
            "package failed without a failing test (panic: test timed out after 10m0s)",
        ),
        (
            package("internal/queue", "pass", events_of("internal/queue", "TestSeal", "skip", "flaky today")),
            "silent skip, reason 'flaky today' matches no pattern in skip_reasons",
        ),
        (
            package("internal/queue", "pass", events_of("internal/queue", "TestSeal", "skip")),
            "silent skip, reason '' matches no pattern",
        ),
        (["this is not json"], "line 1: not a go test -json event"),
        ([], "no go test -json events"),
    ],
)  # fmt: skip
def test_failures_and_silent_skips_fail_the_run(tmp_path, capsys, lines, expected):
    assert run(tmp_path, lines) == 1
    assert expected in capsys.readouterr().out


def test_a_failing_subtest_is_reported_and_its_parent_not_twice(tmp_path, capsys):
    pkg = "internal/queue"
    lines = package(
        pkg,
        "fail",
        events_of(pkg, "TestTable", "pass")[:2],  # the parent's run
        events_of(pkg, "TestTable/ok", "pass"),
        events_of(pkg, "TestTable/bad", "fail", "sub boom"),
        [ev("fail", pkg, "TestTable")],
    )
    assert run(tmp_path, lines) == 1
    problems = [line for line in capsys.readouterr().out.splitlines() if line.startswith("FAIL")]
    assert problems == ["FAIL example.com/fixture/internal/queue TestTable/bad"]


def fixture(name: str) -> list[str]:
    """A real ``go test -json`` stream (Go 1.24, module example.com/fixture)."""
    return (FIXTURES / name).read_text().splitlines()


def test_a_failure_is_sticky_when_the_same_test_runs_again(tmp_path, capsys):
    # go test -count=2: the first run fails, the second passes; the package fails
    assert run(tmp_path, fixture("count2_fail_then_pass.json")) == 1
    out = capsys.readouterr().out
    assert "FAIL example.com/fixture/internal/fl TestFlip\n" in out
    # a quarantined failure elsewhere in the package must not hide the flip's first failure
    pkg = "internal/queue"
    lines = package(
        pkg,
        "fail",
        events_of(pkg, "TestFlip", "fail", "first run"),
        events_of(pkg, "TestFlip", "pass"),
        events_of(pkg, "TestStall", "fail", "stalled"),
    )
    assert run(tmp_path, lines, policy_yaml=QUARANTINE.format(test="TestStall", until="2026-02-01")) == 1  # fmt: skip
    assert "FAIL example.com/fixture/internal/queue TestFlip\n" in capsys.readouterr().out


def test_forbid_rejects_a_reason_that_is_legitimate_elsewhere(tmp_path, capsys):
    assert run(tmp_path, GREEN, "--forbid", "python3 not available") == 1
    assert "must not skip in this run (--forbid)" in capsys.readouterr().out


QUARANTINE = """\
quarantine:
  - test: {test}
    package: internal/queue
    owner: maintainers
    until: {until}
    reason: timing-sensitive under -race on shared runners
"""
FLAKY = package(
    "internal/queue",
    "fail",
    events_of("internal/queue", "TestAdmit", "pass"),
    events_of("internal/queue", "TestStall", "fail", "stalled"),
)


def test_a_valid_quarantine_tolerates_its_failure(tmp_path, capsys):
    yaml_text = QUARANTINE.format(test="TestStall", until="2026-02-01")
    assert run(tmp_path, FLAKY, policy_yaml=yaml_text) == 0
    out = capsys.readouterr().out
    assert "quarantined failure example.com/fixture/internal/queue TestStall" in out
    # it covers that test only
    other = QUARANTINE.format(test="TestAdmit", until="2026-02-01")
    assert run(tmp_path, FLAKY, policy_yaml=other) == 1


def test_a_quarantined_subtest_carries_its_parent(tmp_path):
    pkg = "internal/queue"
    lines = package(
        pkg,
        "fail",
        events_of(pkg, "TestTable/slow", "fail", "late"),
        [ev("fail", pkg, "TestTable")],
    )
    assert run(tmp_path, lines, policy_yaml=QUARANTINE.format(test="TestTable/slow", until="2026-02-01")) == 0  # fmt: skip
    assert run(tmp_path, lines, policy_yaml=QUARANTINE.format(test="TestTable", until="2026-02-01")) == 0  # fmt: skip


@pytest.mark.parametrize(
    ("until", "why"),
    [
        ("2026-01-09", "quarantine expired on 2026-01-09 (owner maintainers)"),
        ("2026-04-11", "is more than 90 days ahead; renew it in steps"),
        ("soon", "is not a YYYY-MM-DD date"),
    ],
)
def test_quarantine_is_bounded_like_pytests(tmp_path, capsys, until, why):
    # judged wherever the test is, even in a green run, so it cannot be parked
    assert run(tmp_path, GREEN, policy_yaml=QUARANTINE.format(test="TestStall", until=until)) == 1
    assert why in capsys.readouterr().out


def test_quarantine_boundary_dates(tmp_path):
    for until in ("2026-01-10", "2026-04-10"):  # today, and exactly 90 days ahead
        assert run(tmp_path, FLAKY, policy_yaml=QUARANTINE.format(test="TestStall", until=until)) == 0  # fmt: skip


def test_quarantine_needs_owner_and_reason(tmp_path, capsys):
    text = "quarantine:\n  - {test: TestStall, package: internal/queue, until: 2026-02-01}\n"
    assert run(tmp_path, FLAKY, policy_yaml=text) == 1
    assert "quarantine needs owner, reason" in capsys.readouterr().out


PRIVILEGED = (
    "privileged:\n  - {test: TestHardening, package: internal/api, reason: chowns a file}\n"
)
ROOT_SKIP = package(
    "internal/api",
    "pass",
    events_of("internal/api", "TestHardening", "skip", "needs root to chown"),
)


def test_a_privileged_skip_needs_its_root_run_to_pass(tmp_path, capsys):
    assert run(tmp_path, ROOT_SKIP, policy_yaml=PRIVILEGED) == 1
    assert "needs the privileged run (chowns a file)" in capsys.readouterr().out

    root_run = tmp_path / "root.json"
    root_run.write_text(
        "\n".join(
            package("internal/api", "pass", events_of("internal/api", "TestHardening", "pass"))
        )
    )
    assert run(tmp_path, ROOT_SKIP, "--privileged", str(root_run), policy_yaml=PRIVILEGED) == 0
    assert "skipped here, passed in the root run" in capsys.readouterr().out

    root_run.write_text(
        "\n".join(
            package(
                "internal/api", "fail", events_of("internal/api", "TestHardening", "fail", "EPERM")
            )
        )
    )
    assert run(tmp_path, ROOT_SKIP, "--privileged", str(root_run), policy_yaml=PRIVILEGED) == 1
    out = capsys.readouterr().out
    assert "did not pass in the privileged run" in out
    assert "FAIL (privileged run) example.com/fixture/internal/api TestHardening" in out
    # the same skip reason without a privileged entry is a silent skip
    assert run(tmp_path, ROOT_SKIP, policy_yaml="privileged: []\n") == 1


def test_list_privileged_prints_one_run_per_package(tmp_path, capsys):
    text = PRIVILEGED + "  - {test: TestMount/race, package: pkg/safefs, reason: bind mounts}\n"
    (tmp_path / "skips.yml").write_text(text)
    assert policy.main(["--policy", str(tmp_path / "skips.yml"), "--list-privileged"]) == 0
    assert capsys.readouterr().out.splitlines() == [
        "./internal/api ^(TestHardening)$",
        "./pkg/safefs ^(TestMount)$",
    ]


@pytest.mark.parametrize(
    "text",
    [
        "quarantine: {test: x}\n",  # not a list
        "skips: []\n",  # unknown section
        "quarantine:\n  - {test: TestX, package: p, owner: o, until: 2026-02-01, reason: r, extra: 1}\n",
        "quarantine:\n  - {package: p, owner: o, until: 2026-02-01, reason: r}\n",  # no test
        "privileged:\n  - {test: TestX, package: p}\n",  # no reason
        "quarantine: [\n",  # not YAML
    ],
)
def test_malformed_policy_is_a_usage_error(tmp_path, text):
    assert run(tmp_path, GREEN, policy_yaml=text) == 2


def test_usage_errors(tmp_path):
    assert policy.main(["--today", TODAY]) == 2  # no input
    assert policy.main(["--today", TODAY, str(tmp_path / "missing.json")]) == 2
    assert policy.main(["--policy", str(tmp_path / "missing.yml"), "--list-privileged"]) == 2
    assert policy.main(["--today", "someday", str(tmp_path)]) == 2
    (tmp_path / "pyproject.toml").write_text("[tool.pytest.ini_options]\n")
    f = tmp_path / "run.json"
    f.write_text("\n".join(GREEN))
    assert policy.main(["--today", TODAY, "--pyproject", str(tmp_path / "pyproject.toml"), str(f)]) == 2  # fmt: skip


def test_skip_reasons_are_the_repositorys_pytest_ones():
    patterns, max_days = policy.skip_reasons(ROOT / "pyproject.toml")
    assert r"\bnot installed\b" in patterns and max_days == 90


def test_skip_reason_drops_framing_and_the_caller_prefix():
    res = policy.Result(
        "skip",
        [
            "=== RUN   TestX\n",
            "    x_test.go:9: flock(1) not on PATH\n",
            "--- SKIP: TestX (0.00s)\n",
        ],
    )
    assert policy.skip_reason(res) == "flock(1) not on PATH"


@pytest.mark.skipif(shutil.which("go") is None, reason="go is not installed")
def test_a_real_go_test_json_stream(tmp_path):
    mod = tmp_path / "mod"
    (mod / "calc").mkdir(parents=True)
    (mod / "go.mod").write_text("module example.com/fixture\n\ngo 1.21\n")
    (mod / "calc" / "calc_test.go").write_text(
        'package calc\n\nimport "testing"\n\n'
        "func TestOK(t *testing.T) {}\n"
        'func TestTool(t *testing.T) { t.Skip("flock(1) not installed") }\n'
        'func TestSilent(t *testing.T) { t.Skip("later") }\n'
    )
    out = subprocess.run(
        ["go", "test", "-json", "-count=1", "./..."], cwd=mod, capture_output=True, text=True
    )
    (tmp_path / "run.json").write_text(out.stdout)
    parsed = policy.parse(out.stdout.splitlines())
    verdicts = {t: r.action for (_, t), r in parsed.tests.items()}
    assert verdicts == {"TestOK": "pass", "TestTool": "skip", "TestSilent": "skip"}
    problems, _notes = policy.judge(
        parsed, policy.Policy(), [r"\bnot installed\b"], today=policy.date(2026, 1, 10)
    )
    assert problems == [
        "SKIP example.com/fixture/calc TestSilent: silent skip, reason 'later' matches no pattern "
        "in skip_reasons ([tool.pytest.ini_options] in pyproject.toml)"
    ]


def test_the_ci_job_is_pinned_and_a_no_op_without_the_module():
    import re

    import yaml

    job = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())["jobs"][
        "orchestrator"
    ]
    steps = job["steps"]
    for step in steps:
        if "uses" in step and not step["uses"].startswith("./"):
            assert re.fullmatch(r"[\w-]+/[\w-]+@[0-9a-f]{40}", step["uses"]), step["uses"]
    gate = steps[1]
    assert gate["id"] == "module" and "orchestrator/go.mod" in gate["run"]
    assert all("steps.module.outputs.present == 'true'" in s.get("if", "") for s in steps[2:])
    runs = "\n".join(s.get("run", "") for s in steps)
    assert "go test -race -shuffle=on -count=1 -json ./..." in runs
    assert "unshare --net" in runs and "tools/go_test_policy.py" in runs
