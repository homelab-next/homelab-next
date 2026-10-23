# SPDX-License-Identifier: Apache-2.0
"""tools/go_test_policy.py (Q-02 for Go): a go test -json run fails on a failing test, a broken
build or a silent skip; quarantines are bounded like pytest's; root-only tests need their run.

Event streams are fixtures in the shape ``go test -json`` writes (Go 1.24, ``Time`` dropped); one
test also runs a real ``go test -json`` when a Go toolchain is installed.
"""

import json
import re
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
        (tmp_path / "go.mod").write_text(f"module {MOD}\n\ngo 1.24\n")
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


def test_a_quarantined_subtest_does_not_carry_its_parents_own_failure(tmp_path, capsys):
    # TestParent runs t.Run("flaky", ...) (quarantined) and then fails an assertion of its own
    lines = fixture("parent_own_failure.json")
    sub = "quarantine:\n  - {test: TestParent/flaky, package: internal/p, owner: me, until: 2026-02-01, reason: flaky}\n"
    assert run(tmp_path, lines, policy_yaml=sub) == 1
    out = capsys.readouterr().out
    assert "FAIL example.com/fixture/internal/p TestParent: fails with output of its own" in out
    assert "parent's own real assertion" in out
    # a quarantine naming the parent itself tolerates it
    assert run(tmp_path, lines, policy_yaml=sub.replace("TestParent/flaky", "TestParent")) == 0


@pytest.mark.parametrize(
    ("name", "pkg", "problem"),
    [
        # -timeout: TestHang never gets a verdict, the panic is in its output (Go 1.24)
        ("timeout.json", "internal/to", "package failed beyond its quarantined tests"),
        # TestMain panics after m.Run returned
        ("teardown_panic.json", "internal/tmp", "panic: teardown failed"),
        # -race: a data race reported after the tests, outside any of them
        ("post_test_race.json", "internal/race", "WARNING: DATA RACE"),
    ],
)
def test_a_quarantined_failure_does_not_hide_a_package_failure(
    tmp_path, capsys, name, pkg, problem
):
    text = QUARANTINE.format(test="TestFlaky", until="2026-02-01").replace("internal/queue", pkg)
    assert run(tmp_path, fixture(name), policy_yaml=text) == 1
    out = capsys.readouterr().out
    assert f"FAIL example.com/fixture/{pkg}: package failed beyond its quarantined tests" in out
    assert problem in out or problem.startswith("package failed")


def test_a_package_failing_only_through_quarantined_tests_is_tolerated(tmp_path, capsys):
    text = QUARANTINE.format(test="TestFlaky", until="2026-02-01").replace(
        "internal/queue", "internal/ok"
    )
    assert run(tmp_path, fixture("quarantined_only.json"), policy_yaml=text) == 0
    assert (
        "package example.com/fixture/internal/ok failed only through its quarantined tests"
        in capsys.readouterr().out
    )


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
    text += f"  - {{test: TestFull, package: {MOD}/pkg/safefs, reason: a full import path}}\n"
    (tmp_path / "go.mod").write_text(f"module {MOD}\n")
    (tmp_path / "skips.yml").write_text(text)
    assert policy.main(["--policy", str(tmp_path / "skips.yml"), "--list-privileged"]) == 0
    assert capsys.readouterr().out.splitlines() == [
        "./internal/api ^(TestHardening)$",
        "./pkg/safefs ^(TestFull|TestMount)$",
    ]


@pytest.mark.parametrize(
    ("entry_package", "event_package", "covered"),
    [
        ("internal/api", "internal/api", True),
        ("internal/api", "cmd/x/internal/api", False),  # same suffix, another package
        ("api", "internal/api", False),
        (f"{MOD}/internal/api", "internal/api", True),  # the full import path
        (".", "", True),  # the module root package
    ],
)
def test_a_policy_entry_names_exactly_one_package(tmp_path, entry_package, event_package, covered):
    pkg = event_package.strip("/")
    lines = package(pkg, "fail", events_of(pkg, "TestStall", "fail", "stalled"))
    lines = [line.replace(f'"{MOD}/"', f'"{MOD}"') for line in lines]  # the root package
    text = QUARANTINE.format(test="TestStall", until="2026-02-01")
    text = text.replace("package: internal/queue", f"package: {entry_package}")
    assert run(tmp_path, lines, policy_yaml=text) == (0 if covered else 1)


def test_the_module_path_comes_from_go_mod_or_module(tmp_path, capsys):
    lines = FLAKY
    (tmp_path / "run.json").write_text("\n".join(lines) + "\n")
    (tmp_path / "skips.yml").write_text(QUARANTINE.format(test="TestStall", until="2026-02-01"))
    args = ["--policy", str(tmp_path / "skips.yml"), "--today", TODAY, str(tmp_path / "run.json")]
    assert policy.main(args) == 2  # no go.mod beside skips.yml, no --module
    assert "no module path" in capsys.readouterr().err
    assert policy.main(["--module", MOD, *args]) == 0
    assert policy.main(["--module", "example.com/other", *args]) == 1
    (tmp_path / "go.mod").write_text(f'module "{MOD}" // quoted\n')
    assert policy.main(args) == 0


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


def test_the_skip_reason_is_the_last_line_before_skip_not_earlier_logs(tmp_path, capsys):
    pkg = "internal/queue"
    # t.Log("flock(1) not installed") then t.Skip("later"): the reason is "later"
    logged = package(
        pkg, "pass", events_of(pkg, "TestSeal", "skip", "flock(1) not installed", "later")
    )
    assert run(tmp_path, logged) == 1
    assert "TestSeal: silent skip, reason 'later' matches no pattern" in capsys.readouterr().out
    # --forbid is matched against the reason too, not against a logged line
    forbidden_log = package(
        pkg,
        "pass",
        events_of(pkg, "TestSeal", "skip", "python3 not available", "flock(1) not installed"),
    )
    assert run(tmp_path, forbidden_log, "--forbid", "python3 not available") == 0
    assert (
        "note: skip example.com/fixture/internal/queue TestSeal: 'flock(1) not installed'"
        in capsys.readouterr().out
    )


@pytest.mark.usefixtures("go_toolchain")  # tools/tests/conftest.py (HNX_REQUIRE_GO)
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


def go_job() -> dict:
    import yaml

    return yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())["jobs"]["go"]


def test_the_ci_job_is_pinned_and_runs_once_per_discovered_module():
    import re

    job = go_job()
    steps = job["steps"]
    for step in steps:
        if "uses" in step and not step["uses"].startswith("./"):
            assert re.fullmatch(r"[\w-]+/[\w-]+@[0-9a-f]{40}", step["uses"]), step["uses"]
    # a matrix over tools/go_modules.py's list, skipped (a no-op) when there is no module
    assert job["needs"] == "go-modules"
    assert job["if"] == "needs.go-modules.outputs.present == 'true'"
    assert (
        job["strategy"]["matrix"]["module"] == "${{ fromJSON(needs.go-modules.outputs.modules) }}"
    )
    assert job["defaults"]["run"]["working-directory"] == "${{ matrix.module.dir }}"
    runs = "\n".join(s.get("run", "") for s in steps)
    assert "orchestrator" not in json.dumps(job)  # no module is named: they are discovered
    assert job["env"] == {"GOFLAGS": "-mod=readonly", "GOTOOLCHAIN": "local", "GOWORK": "off"}
    # sudo resets the environment: what go needs is passed through by name
    assert '"GOFLAGS=$GOFLAGS" "GOTOOLCHAIN=$GOTOOLCHAIN" "GOWORK=$GOWORK"' in runs
    (go,) = [s for s in steps if s.get("uses", "").startswith("actions/setup-go@")]
    assert go["with"]["go-version-file"] == "${{ matrix.module.dir }}/go.mod"
    assert go["with"]["cache-dependency-path"].startswith("${{ matrix.module.dir }}/**/go.sum")
    assert "go test -race -shuffle=on -count=1 -json ./..." in runs
    assert "unshare --net" in runs and "tools/go_test_policy.py" in runs


def test_discovery_gates_the_go_job_and_one_check_sums_it_up():
    import yaml

    jobs = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())["jobs"]
    (discover,) = [s for s in jobs["go-modules"]["steps"] if s.get("id") == "discover"]
    assert "tools/go_modules.py --github-output" in discover["run"]
    assert set(jobs["go-modules"]["outputs"]) == {"modules", "present"}
    ok = jobs["go-ok"]
    assert ok["needs"] == ["go-modules", "go"] and ok["if"] == "always()"


# --- the CI step itself, run with stand-ins for sudo, unshare, ip, setpriv and go ----------------

FAKE_TOOLS = {
    "sudo": 'exec "$@"\n',
    "unshare": 'while [ "$1" != "--" ]; do shift; done; shift; exec "$@"\n',
    "setpriv": 'while [ "$1" != "--" ]; do shift; done; shift; exec "$@"\n',
    "ip": "exit 0\n",
    # go test -c writes a "test binary" that prints FAKE_PRIV_STREAM and exits FAKE_PRIV_EXIT;
    # go test prints FAKE_STREAM and exits FAKE_EXIT; go tool test2json passes its input through
    "go": """case "$1" in
  test)
    [ -z "$FAKE_TAMPER" ] || [ "$2" = -c ] || sh -c "$FAKE_TAMPER"
    if [ "$2" = -c ]; then
      while [ "$1" != -o ]; do shift; done
      printf '#!/bin/sh\\ncat "$FAKE_PRIV_STREAM"; exit "$FAKE_PRIV_EXIT"\\n' > "$2"
      chmod +x "$2"; exit 0
    fi
    cat "$FAKE_STREAM"; exit "$FAKE_EXIT";;
  list) if [ "$2" = ./... ]; then cat "$FAKE_PACKAGES"; else echo "$FAKE_MODULE/${2#./}"; fi;;
  tool) cat;;
esac
""",
}


def ci_step(name: str) -> str:
    (step,) = [s for s in go_job()["steps"] if s.get("name", "").startswith(name)]
    return step["run"]


def run_test_step(
    tmp_path,
    lines: list[str],
    go_exit: int,
    *,
    skips: str | None = None,
    privileged: tuple[list[str], int] | None = None,
    packages: list[str] | None = None,
    tamper: str = "",
) -> subprocess.CompletedProcess:
    """The go job's root-only and test steps, in a scratch checkout, with go replaced by streams:
    ``lines`` and ``go_exit`` for go test, ``privileged`` = (stream, exit status) for the root
    run's test binary; ``packages`` for go list ./... (default: the packages ``lines`` names);
    ``tamper``, a shell command the main run's go test runs first, in the module.  The test step's
    result, or the result of the first step that fails."""
    bin_dir, mod, rt = tmp_path / "bin", tmp_path / "orchestrator", tmp_path / "runner-temp"
    for d in (bin_dir, mod, rt):
        d.mkdir(parents=True)
    for name, body in FAKE_TOOLS.items():
        (bin_dir / name).write_text("#!/bin/sh\n" + body)
        (bin_dir / name).chmod(0o755)
    (tmp_path / "tools").symlink_to(ROOT / "tools")
    (tmp_path / "pyproject.toml").symlink_to(ROOT / "pyproject.toml")
    (mod / "go.mod").write_text(f"module {MOD}\n\ngo 1.24\n")
    (mod / "skips.yml").write_text(
        skips
        or QUARANTINE.format(test="TestFlaky", until="2026-02-01").replace(
            "internal/queue", "internal/ok"
        )
    )
    for pkg in ("hard", "race"):
        (mod / "internal" / pkg).mkdir(parents=True)
    (tmp_path / "stream.json").write_text("\n".join(lines) + "\n")
    priv_lines, priv_exit = privileged or ([], 0)
    if packages is None:
        events = [json.loads(x) for x in lines if x.strip().startswith("{")]
        packages = sorted({e["Package"] for e in events if e.get("Package")})
    (tmp_path / "packages.txt").write_text("".join(f"{x}\n" for x in packages))
    (tmp_path / "priv.json").write_text("\n".join(priv_lines) + "\n")
    env = {
        "PATH": f"{bin_dir}:{Path(sys.executable).parent}:/usr/bin:/bin",
        "HOME": str(tmp_path),
        "RUNNER_TEMP": str(rt),
        "GITHUB_WORKSPACE": str(tmp_path),
        "HNX_TODAY": TODAY,
        "FAKE_STREAM": str(tmp_path / "stream.json"),
        "FAKE_EXIT": str(go_exit),
        "FAKE_PRIV_STREAM": str(tmp_path / "priv.json"),
        "FAKE_PRIV_EXIT": str(priv_exit),
        "FAKE_MODULE": MOD,
        "FAKE_PACKAGES": str(tmp_path / "packages.txt"),
        "FAKE_TAMPER": tamper,
    }
    for name in ("a root-owned results directory", "root-only tests", "tests (race"):
        (tmp_path / "step.sh").write_text(ci_step(name))
        # GitHub runs a bash step as: bash --noprofile --norc -eo pipefail {0}
        r = subprocess.run(
            ["bash", "--noprofile", "--norc", "-eo", "pipefail", str(tmp_path / "step.sh")],
            cwd=mod,
            env=env,
            capture_output=True,
            text=True,
        )
        if r.returncode:
            break
    return r


needs_bash = pytest.mark.skipif(shutil.which("bash") is None, reason="bash is not installed")


@needs_bash
@pytest.mark.parametrize(
    ("stream", "go_exit", "passes"),
    [
        ("quarantined_only.json", 1, True),  # go exits 1 on the quarantined failure: tolerated
        ("timeout_truncated.json", 1, False),  # the stream stops before any verdict
        ("timeout_truncated.json", 143, False),  # go test killed
        ("quarantined_only.json", 2, False),  # a status no test failure explains
        ("green", 0, True),
        ("green", 1, False),  # go failed, the stream does not say why: events were lost
    ],
)
def test_the_ci_step_judges_the_stream_and_go_tests_exit_status(tmp_path, stream, go_exit, passes):
    # green: no skip, since the step forbids the one GREEN has
    green = package("internal/queue", "pass", events_of("internal/queue", "TestAdmit", "pass"))
    lines = green if stream == "green" else fixture(stream)
    r = run_test_step(tmp_path, lines, go_exit)
    assert (r.returncode == 0) is passes, r.stdout + r.stderr


def test_a_cut_off_stream_fails_with_or_without_the_exit_status(tmp_path, capsys):
    text = QUARANTINE.format(test="TestFlaky", until="2026-02-01").replace(
        "internal/queue", "internal/to"
    )
    lines = fixture("timeout_truncated.json")
    assert run(tmp_path, lines, policy_yaml=text) == 1
    out = capsys.readouterr().out
    assert "FAIL example.com/fixture/internal/to TestFlaky: no verdict" in out
    assert "FAIL example.com/fixture/internal/to TestHang: no verdict" in out
    assert "FAIL example.com/fixture/internal/to: no package verdict" in out
    # a panic in parallel TestB kills the binary while TestA is still running
    assert run(tmp_path, fixture("parallel_panic.json")) == 1
    out = capsys.readouterr().out
    assert "FAIL example.com/fixture/internal/par TestB\n" in out
    assert "FAIL example.com/fixture/internal/par TestA: no verdict" in out
    # a whole package missing its end, in a stream that is otherwise green
    assert run(tmp_path, GREEN[:-1]) == 1
    assert "no package verdict" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("lines", "status", "ok", "why"),
    [
        (GREEN, 0, True, ""),
        (GREEN, 1, False, "go test exited 1 but the stream shows no failure"),
        (GREEN, 2, False, "go test exited 2: not a test verdict"),
        (FLAKY, 1, True, ""),  # explained by the quarantined failure
        (FLAKY, 0, False, "go test exited 0 but the stream has a failure"),
    ],
)  # fmt: skip
def test_go_exit_must_agree_with_the_stream(tmp_path, capsys, lines, status, ok, why):
    text = QUARANTINE.format(test="TestStall", until="2026-02-01")
    assert run(tmp_path, lines, "--go-exit", str(status), policy_yaml=text) == (0 if ok else 1)
    assert why in capsys.readouterr().out


def test_every_step_runs_in_the_module_and_the_linters_wait_for_theirs():
    steps = go_job()["steps"]
    assert not any("hashFiles" in s.get("if", "") for s in steps)  # silent when the file is gone
    (lint,) = [s for s in steps if "staticcheck" in s.get("run", "")]
    assert lint["if"] == "matrix.module.tools"


# the root run: test2json reads the binary's text, so its package verdict can be "pass" while the
# binary failed (TestMain panics after m.Run printed PASS); a race after the tests fails the package
HARD = "privileged:\n  - {test: TestHard, package: internal/hard, reason: needs root}\n"
HARD_SKIP = package(
    "internal/hard", "pass", events_of("internal/hard", "TestHard", "skip", "needs root")
)
RACE = "privileged:\n  - {test: TestOther, package: internal/race, reason: needs root}\n"
RACE_SKIP = package(
    "internal/race", "pass", events_of("internal/race", "TestOther", "skip", "needs root")
)


def _exits(tmp_path, text: str) -> str:
    f = tmp_path / "root.exit"
    f.write_text(text)
    return str(f)


def test_a_privileged_binary_that_exits_non_zero_fails_even_when_its_stream_passed(
    tmp_path, capsys
):
    root = tmp_path / "root.json"
    root.write_text("\n".join(fixture("privileged_testmain_panic.json")))
    priv = ["--privileged", str(root)]
    exits = _exits(tmp_path, f"{MOD}/internal/hard 2\n")
    assert run(tmp_path, HARD_SKIP, *priv, "--privileged-exit", exits, policy_yaml=HARD) == 1
    out = capsys.readouterr().out
    assert f"FAIL (privileged run) {MOD}/internal/hard: the test binary exited 2" in out
    assert "panic: TestHard left root-owned state behind" in out
    # exit 0 recorded for it: the same stream is the clean root run it looks like
    exits = _exits(tmp_path, f"{MOD}/internal/hard 0\n")
    assert run(tmp_path, HARD_SKIP, *priv, "--privileged-exit", exits, policy_yaml=HARD) == 0


def test_a_privileged_package_that_failed_without_a_failing_test_fails(tmp_path, capsys):
    root = tmp_path / "root.json"
    root.write_text("\n".join(fixture("privileged_post_test_race.json")))
    assert run(tmp_path, RACE_SKIP, "--privileged", str(root), policy_yaml=RACE) == 1
    out = capsys.readouterr().out
    assert f"FAIL (privileged run) {MOD}/internal/race: package failed (WARNING: DATA RACE)" in out


def test_every_privileged_binary_needs_a_zero_exit_status_and_events(tmp_path, capsys):
    root = tmp_path / "root.json"
    root.write_text("\n".join(fixture("privileged_testmain_panic.json")))
    priv = ["--privileged", str(root)]
    for text, why in [
        ("", "no exit status recorded for its test binary"),
        (f"{MOD}/internal/hard 0\n{MOD}/internal/gone 0\n", "internal/gone: exited 0 but wrote no"),
        (f"{MOD}/internal/hard 1\n{MOD}/internal/hard 0\n", "the test binary exited 1"),  # sticky
    ]:
        exits = _exits(tmp_path, text)
        assert run(tmp_path, HARD_SKIP, *priv, "--privileged-exit", exits, policy_yaml=HARD) == 1
        assert why in capsys.readouterr().out
    assert (
        run(
            tmp_path,
            HARD_SKIP,
            *priv,
            "--privileged-exit",
            _exits(tmp_path, "x y z\n"),
            policy_yaml=HARD,
        )
        == 2
    )
    assert (
        run(tmp_path, HARD_SKIP, "--privileged-exit", _exits(tmp_path, ""), policy_yaml=HARD) == 2
    )
    assert "--privileged-exit needs the root run" in capsys.readouterr().err


@needs_bash
@pytest.mark.parametrize(
    ("priv_stream", "priv_exit", "passes"),
    [
        (
            "privileged_testmain_panic.json",
            2,
            False,
        ),  # the binary's status, not test2json's verdict
        ("privileged_testmain_panic.json", 0, True),
        ("privileged_post_test_race.json", 1, False),
    ],
)
def test_the_ci_steps_record_and_judge_each_privileged_binarys_exit_status(
    tmp_path, priv_stream, priv_exit, passes
):
    skip = HARD_SKIP if "testmain" in priv_stream else RACE_SKIP
    skips = HARD if "testmain" in priv_stream else RACE
    r = run_test_step(tmp_path, skip, 0, skips=skips, privileged=(fixture(priv_stream), priv_exit))
    assert (r.returncode == 0) is passes, r.stdout + r.stderr
    exits = (tmp_path / "runner-temp" / "go-results" / "go-test-root.exit").read_text().split()
    assert exits[1] == str(priv_exit)


def test_every_package_go_list_names_needs_events_in_the_stream(tmp_path, capsys):
    # verify.md: one package with a quarantined failure, another with a real one whose events
    # were lost at the package boundary; go test's exit 1 is "explained" by the quarantine
    text = QUARANTINE.format(test="TestStall", until="2026-02-01")
    expected = tmp_path / "packages.txt"
    expected.write_text(f"{MOD}/internal/queue\n{MOD}/internal/fl\n")
    assert run(tmp_path, FLAKY, "--go-exit", "1", policy_yaml=text) == 0  # the stream alone
    args = ("--go-exit", "1", "--expect-packages", str(expected))
    assert run(tmp_path, FLAKY, *args, policy_yaml=text) == 1
    out = capsys.readouterr().out
    assert f"FAIL {MOD}/internal/fl: no events" in out
    assert "internal/queue: no events" not in out
    expected.write_text(f"{MOD}/internal/queue\n")
    assert run(tmp_path, FLAKY, *args, policy_yaml=text) == 0
    assert run(tmp_path, FLAKY, "--expect-packages", str(tmp_path / "missing")) == 2


@needs_bash
def test_the_ci_step_lists_the_packages_and_requires_each_in_the_stream(tmp_path):
    lines = fixture("quarantined_only.json")
    assert run_test_step(tmp_path / "a", lines, 1).returncode == 0
    r = run_test_step(
        tmp_path / "b", lines, 1, packages=[f"{MOD}/internal/ok", f"{MOD}/internal/fl"]
    )
    assert r.returncode == 1 and f"FAIL {MOD}/internal/fl: no events" in r.stdout, (
        r.stdout + r.stderr
    )


@needs_bash
def test_the_policy_and_its_inputs_are_copied_before_any_test_can_change_them(tmp_path):
    # verify3.md: the policy step read skips.yml (and the tool) from the workspace after the tests
    # ran as the user who owns it, so a test could quarantine its own failure on the way out
    lines = fixture("quarantined_only.json")
    quarantine = QUARANTINE.format(test="TestFlaky", until="2026-02-01").replace(
        "internal/queue", "internal/ok"
    )
    none = "privileged: []\n"
    assert run_test_step(tmp_path / "a", lines, 1, skips=none).returncode == 1
    tamper = f"printf '%s' '{quarantine}' > skips.yml"
    r = run_test_step(tmp_path / "b", lines, 1, skips=none, tamper=tamper)
    assert "quarantine:" in (tmp_path / "b" / "orchestrator" / "skips.yml").read_text()
    assert r.returncode == 1 and f"FAIL {MOD}/internal/ok TestFlaky" in r.stdout, (
        r.stdout + r.stderr
    )
    # the same file in place from the start is the quarantine it looks like
    assert run_test_step(tmp_path / "c", lines, 1, skips=quarantine).returncode == 0


def test_the_results_are_root_owned_and_the_tests_cannot_sudo():
    steps = go_job()["steps"]
    names = [s.get("name", "") for s in steps]
    snap = names.index(
        "a root-owned results directory with a copy of the policy, before any test runs"
    )
    assert snap < names.index("modules downloaded and verified against go.sum")
    copy = steps[snap]["run"]
    assert 'sudo install -d -m 0755 "$RUNNER_TEMP/go-results" "$pol"' in copy
    assert '"$GITHUB_WORKSPACE/tools/go_test_policy.py"' in copy and "pyproject.toml" in copy
    assert "sudo install -m 0644 skips.yml go.mod" in copy
    root, main = ci_step("root-only tests"), ci_step("tests (race")
    for run in (root, main, ci_step("every skip names its reason")):
        # the policy runs from the copy, never from the workspace the tests could rewrite
        assert "$GITHUB_WORKSPACE" not in run and "go-results" in run
        assert "go_test_policy.py" in run
    assert "exec setpriv --no-new-privs --reuid=" in main
    assert "exec setpriv --no-new-privs -- " in root
    # every write into the results directory is root's: sudo tee, or a file root opened
    assert '| sudo tee -a "$exits" > /dev/null' in root
    assert '| sudo tee -a "$out" > /dev/null' in root
    assert """-json ./... > "$3"'""" in main and 'sh "$(id -u)" "$(id -g)" "$out"' in main
    assert '| sudo tee "$res/go-packages.txt" > /dev/null' in main
    for run in (root, main):
        assert not re.search(r'>>? *"\$(out|exits|res)', run.replace("> /dev/null", ""))
    # the limit is stated beside the job, and the job stays on a hosted runner
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    assert "guards against accidents" in text and "not against hostile test code" in text
    assert go_job()["runs-on"] == "ubuntu-latest" and "pull_request_target" not in text


# --- skip calls in the sources: the forms whose reason the stream cannot show --------------------

SKIP_SOURCES = {
    # verify.md: a logged line becomes the "reason" of SkipNow, the last line of a multi-line one
    "internal/p/p_test.go": 'func TestSkipLog(t *testing.T) {\n\tt.Log("backend not available")\n\tt.SkipNow()\n}\n',
    "internal/multi/m_test.go": 'func TestMulti(t *testing.T) { t.Skip("feature flag off\\ndocker not available") }\n',
    "internal/bare/b_test.go": "func TestBare(t *testing.T) { t.Skip() }\nfunc TestVar(t *testing.T) { t.Skipf(msg) }\n",
    "internal/raw/r_test.go": "func TestRaw(b *testing.B) { b.Skip(`one\ntwo`) }\n",
    # verify3.md: a helper in a non-test file skips too, and Skipf's reason is its formatted args
    "internal/ok/ok.go": "func f(t T) { t.SkipNow() }\n",
    "internal/fmt/f_test.go": 'func TestF(t *testing.T) { t.Skipf("%s not installed", "flock") }\n',
    # accepted: a one-line literal, a comment, Skipped(), test data
    "internal/ok/o_test.go": (
        'func TestA(t *testing.T) { t.Skip("docker not available") }\n'
        "func TestC(t *testing.T) { t.Skip(`dnsmasq not installed`) }\n"
        "// t.SkipNow() would hide the reason\n"
        "func TestD(t *testing.T) { if t.Skipped() { return } }\n"
    ),
    "internal/ok/testdata/x_test.go": "func TestX(t *testing.T) { t.SkipNow() }\n",
}


def test_check_sources_rejects_skips_whose_reason_the_stream_cannot_show(tmp_path, capsys):
    for rel, body in SKIP_SOURCES.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("package x\n\n" + body)
    found = policy.check_sources(tmp_path)
    assert [f.split(": ", 1)[0] for f in found] == [
        "internal/bare/b_test.go:3",
        "internal/bare/b_test.go:4",
        "internal/fmt/f_test.go:3",
        "internal/multi/m_test.go:3",
        "internal/ok/ok.go:3",
        "internal/p/p_test.go:5",
        "internal/raw/r_test.go:3",
    ]
    assert "argument list must be one string literal" in found[0]
    assert "Skipf's reason is what its arguments format to" in found[1] and "Skipf" in found[2]
    assert "reason spans lines" in found[3] and "reason spans lines" in found[6]
    assert "SkipNow has no reason of its own" in found[4] and "SkipNow" in found[5]
    assert policy.main(["--check-sources", str(tmp_path)]) == 1
    assert "SKIP CALL internal/p/p_test.go:5: .SkipNow: " in capsys.readouterr().out
    clean = tmp_path / "internal" / "ok"
    (clean / "ok.go").unlink()
    assert policy.main(["--check-sources", str(clean)]) == 0
    assert policy.main(["--check-sources", str(tmp_path / "missing")]) == 2


# verify3.md (v3/cs): each test logs "docker not available" and then skips some other way, so the
# logged line is read as its reason; the old check found 0 of these 9
BYPASSES = {
    "method value": "f := t.SkipNow\n\tf()",
    "method expression": "(*testing.T).SkipNow(t)",
    "a call's result": "suite{t}.T().SkipNow()",
    "line break after the dot": "t.\n\t\tSkipNow()",
    "after a // in a string": 't.Run("http://x", func(t *testing.T) { t.SkipNow() })',
    "two arguments": 't.Skip("later", "\\ndocker not available")',
    "Skipf with a newline argument": 't.Skipf("%s", "later\\ndocker not available")',
    "Skipf of an error": 't.Skipf("docker: %v", err)',
    "a concatenation": 't.Skip("later" + "\\n" + "docker not available")',
    "a constant": "t.Skip(reason)",
    "Skip as a value": 'skip := t.Skip\n\tskip("x")',
    "a hex newline escape": 't.Skip("later\\x0adocker not available")',
    "an octal newline escape": 't.Skip("later\\012docker not available")',
    "a unicode newline escape": 't.Skip("later\\u000Adocker not available")',
    "a carriage return": 't.Skip("later\\rdocker not available")',
    "a comment inside the selector": "t. /* x */ SkipNow()",
}


@pytest.mark.parametrize("call", BYPASSES.values(), ids=BYPASSES.keys())
def test_check_sources_sees_every_way_a_skip_can_take_its_reason_from_a_log(tmp_path, call):
    (tmp_path / "p").mkdir()
    (tmp_path / "p" / "p_test.go").write_text(
        'package p\n\nimport "testing"\n\nfunc TestX(t *testing.T) {\n'
        f'\tt.Log("docker not available")\n\t{call}\n}}\n'
    )
    found = policy.check_sources(tmp_path)
    assert len(found) == 1 and found[0].startswith("p/p_test.go:7: ."), found


def test_check_sources_reads_helpers_in_non_test_files(tmp_path):
    (tmp_path / "testutil").mkdir()
    (tmp_path / "testutil" / "testutil.go").write_text(
        'package testutil\n\nimport "testing"\n\n'
        "// NeedDocker skips with whatever was logged last.\n"
        "func NeedDocker(t testing.TB) { t.SkipNow() }\n"
    )
    found = policy.check_sources(tmp_path)
    assert [f.split(": ", 1)[0] for f in found] == ["testutil/testutil.go:6"]


ACCEPTED = {
    "a literal": 't.Skip("docker not available")',
    "a raw literal": "t.Skip(`docker not available`)",
    "a trailing comma": 't.Skip(\n\t\t"docker not available",\n\t)',
    "a space before the call": 't.Skip ("docker not available")',
    "a backslash and an n": 't.Skip("C:\\\\new not available")',
    "a line comment": "// t.SkipNow() would hide the reason",
    "a block comment": '/* t.SkipNow()\n\tt.Skipf("%v", err) */',
    "a string": 'msg := "call t.SkipNow() here"\n\t_ = msg',
    "a raw string over lines": "msg := `t.\nSkipNow()`\n\t_ = msg",
    "a quote rune": 'q := \'"\'\n\t_ = q\n\tt.Skip("docker not available")',
    "a backquote rune": "q := '`'\n\t_ = q\n\tt.Skip(\"docker not available\")",
    "Skipped": "if t.Skipped() {\n\t\treturn\n\t}",
    "a float with a leading dot": "x := .5\n\t_ = x",
}


@pytest.mark.parametrize("code", ACCEPTED.values(), ids=ACCEPTED.keys())
def test_check_sources_accepts_one_literal_and_ignores_comments_and_literals(tmp_path, code):
    (tmp_path / "p_test.go").write_text(
        f'package p\n\nimport "testing"\n\nfunc TestX(t *testing.T) {{\n\t{code}\n}}\n'
    )
    assert policy.check_sources(tmp_path) == []


def test_go_tokens_keep_lines_and_tell_literals_from_code():
    toks = policy.go_tokens("a := \"x.y\" // t.Skip\nb := `\n`.\n\tc /* d\ne */ '.' 1.5\n")
    assert [(t.kind, t.text, t.line) for t in toks] == [
        ("ident", "a", 1),
        ("op", ":", 1),
        ("op", "=", 1),
        ("string", '"x.y"', 1),
        ("comment", "// t.Skip", 1),
        ("ident", "b", 2),
        ("op", ":", 2),
        ("op", "=", 2),
        ("raw", "`\n`", 2),
        ("op", ".", 3),
        ("ident", "c", 4),
        ("comment", "/* d\ne */", 4),
        ("rune", "'.'", 5),
        ("number", "1.5", 5),
    ]


def test_the_go_job_checks_the_skip_calls_before_the_tests():
    names = [s.get("name", "") for s in go_job()["steps"]]
    assert "--check-sources ." in ci_step("every skip names its reason")
    assert names.index("every skip names its reason in the call") < next(
        i for i, n in enumerate(names) if n.startswith("tests (race")
    )


@pytest.mark.parametrize(
    ("required", "outcome", "why"),
    [
        ("", pytest.skip.Exception, "go is not installed"),
        ("1", pytest.fail.Exception, "HNX_REQUIRE_GO=1 requires it"),
    ],
)
def test_go_toolchain_skips_without_go_unless_go_is_required(
    request, monkeypatch, tmp_path, required, outcome, why
):
    monkeypatch.setenv("PATH", str(tmp_path))  # no go here
    monkeypatch.setenv("HNX_REQUIRE_GO", required)
    with pytest.raises(outcome, match=why):
        request.getfixturevalue("go_toolchain")  # evaluated once per test: its result is cached


def test_one_test_leg_installs_go_and_requires_it():
    import yaml

    ci = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())
    job = ci["jobs"]["test"]
    legs = job["strategy"]["matrix"]["include"]
    assert [bool(leg.get("go")) for leg in legs].count(True) == 1  # the other legs prove no-Go
    (go,) = [s for s in job["steps"] if s.get("uses", "").startswith("actions/setup-go@")]
    (pinned,) = [s for s in go_job()["steps"] if s.get("uses", "").startswith("actions/setup-go@")]
    assert go["uses"] == pinned["uses"] and go["if"] == "matrix.go"
    assert go["with"]["go-version"] == "${{ env.GO_VERSION }}"
    (pytest_step,) = [s for s in job["steps"] if "pytest" in s.get("run", "")]
    assert pytest_step["env"]["HNX_REQUIRE_GO"] == "${{ matrix.go && '1' || '' }}"
