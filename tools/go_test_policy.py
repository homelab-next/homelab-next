#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: go-test-policy
#   kind: check
#   purpose: Fail when a go test -json run has a failing test, a package that did not build, a skip without a registered reason or an invalid quarantine.
#   owner: maintainers
#   trigger: [ci:ci/go]
#   inputs: go test -json output files (or - for stdin); the module's skips.yml; skip_reasons and quarantine_max_days in pyproject.toml
#   outputs: one line per problem, notes for tolerated skips and quarantined failures, a summary
#   exit:
#     "0": the run is trustworthy
#     "1": a failure, a silent skip, a missing privileged run or an invalid quarantine
#     "2": usage error, an unreadable file or a malformed policy
"""The Go side of the test-suite policy (checklist Q-02): what tests/suite_policy.py does for pytest.

Reads the event stream of ``go test -json`` (one or more files) and fails on:

* a failing test, unless a valid quarantine names it (or, for a parent test, every failing
  subtest under it is quarantined and the parent wrote nothing of its own: a parent whose own
  output has a line outside its subtests, its own ``t.Error`` say, needs an entry naming it);
* a package that failed without a failing test: a build failure (``build-fail``), a panic in
  ``TestMain`` or ``init``, a timeout -- and one whose only failing tests are quarantined unless
  every test in it has a verdict and the package wrote nothing beyond its ``FAIL`` summary, so a
  quarantine cannot hide a hang, a race reported after the tests or a ``TestMain`` crash;
* with ``--check-sources DIR`` (instead of a run): any use of ``SkipNow`` or ``Skipf``, or a
  ``Skip`` whose whole argument list is not one one-line string literal, in any ``.go`` file
  under DIR (a helper's too, called or taken as a method value) -- the forms whose reason the
  stream cannot show (see ``skip_reason`` and ``check_sources``);
* a skip whose reason (the last line the test wrote before ``--- SKIP``) matches none of the
  ``skip_reasons`` regular expressions of ``[tool.pytest.ini_options]`` in pyproject.toml, or one
  that ``--forbid`` names for this run (a reason that is legitimate elsewhere, such as a tool CI
  always installs);
* an invalid quarantine entry, wherever its test is: owner, until and reason missing, the date in
  the past, or more than ``quarantine_max_days`` (90) ahead -- the same rule as pytest's marker;
* a line that is not a ``go test -json`` event, or input with no events at all;
* a cut-off stream: a test or a package with no verdict (``pass``/``fail``/``skip``), as when the
  run was killed or its output only partly captured;
* with ``--go-exit N`` (``go test``'s own exit status): any status but 0 and 1, a 1 with nothing
  in the stream to explain it but quarantined failures, or a 0 next to a failure in the stream.
  So a stream that lost its failing part cannot pass while ``go test`` itself failed;
* with ``--expect-packages FILE`` (``go list ./...``): a listed package with no events at all, so
  a stream cut exactly at a package boundary cannot pass on a quarantined failure's exit 1 (a
  package without test files still has events: its ``skip``);
* with ``--expect-tests FILE`` (``<import path> <dir>`` per package ``go list`` gives test files):
  a package whose test files declare a ``Test`` or ``Fuzz`` function, or an ``Example`` with an
  ``// Output:`` comment, that did not fail yet reported no test at all -- a floor under tests
  hidden from the run by an ``os.Exit(0)`` before ``m.Run``, which is not a skip.  Test files with
  only benchmarks, helpers or examples without output run nothing and are not expected to.  It is
  a floor, not a guard: hiding some tests (``flag.Set("test.skip", ...)``), or a ``TestMain`` that
  forges the events, still passes.

The policy file (``skips.yml`` in the module's root)::

    quarantine:          # a known-flaky test keeps running; its failure or skip is tolerated
      - {test: TestStall, package: internal/hermesagent, owner: maintainers,
         until: 2026-01-31, reason: timing-sensitive under -race on shared runners}
    privileged:          # needs root: skips in the normal run, must pass in the privileged run
      - {test: TestHardening, package: internal/api, reason: chowns a file to another user}

``package`` is the import path relative to the module (``.`` for the module root) or the full
import path; it names exactly that package, never one whose path merely ends the same way
(``internal/api`` is not ``cmd/x/internal/api``).  The module path comes from the ``go.mod`` beside
the policy file, or ``--module``.  ``test`` names a top-level test or a ``Parent/sub`` subtest, and a parent covers its subtests.
A ``privileged`` test's skip is accepted only when ``--privileged FILE`` (the ``go test -json``
output of the root run) shows it passed, so a missing root run fails instead of passing silently.
In the root run nothing is quarantined: a failing test or package fails, and with
``--privileged-exit FILE`` (``<import path> <exit status>`` per test binary) every binary must
have exited 0 and written events, since test2json judges that stream from its text alone.
``--list-privileged`` prints ``./<package> <-run regex>`` lines for the CI step that runs them.

What the stream cannot show, so this tool cannot judge it:

* A parent's *silent* failure next to a quarantined subtest.  A parent's "own failure" is its own
  output: ``t.Error``/``t.Fatal`` write a line, but ``t.Fail()`` (or a message-less
  ``t.FailNow()``) after a quarantined subtest failed reads exactly like a parent failing only
  through that subtest, and is tolerated with it.  The other way round fails closed: a parent that
  wrote anything of its own (a ``t.Log`` too) next to a quarantined subtest is reported, and needs
  its own entry -- prefer fixing the log line over quarantining the whole parent.
* A skip's reason given any other way than ``t.Skip("<one line>")`` (see ``skip_reason``):
  ``--check-sources`` rejects those forms in the sources instead.

Usage::

    go test -json ./... > run.json; python tools/go_test_policy.py --policy skips.yml \
        --go-exit $? run.json
    python tools/go_test_policy.py --policy skips.yml --list-privileged
    python tools/go_test_policy.py --check-sources .

Exit: 0 clean, 1 a policy failure, 2 usage error / unreadable input / malformed policy.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tomllib
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
# PyYAML copied beside this file (CI's results directory, run with an isolated interpreter)
VENDOR = Path(__file__).resolve().parent / "vendor"
EXIT_OK, EXIT_FAIL, EXIT_USAGE = 0, 1, 2
QUARANTINE_FIELDS = ("test", "package", "owner", "until", "reason")
PRIVILEGED_FIELDS = ("test", "package", "reason")
# test2json framing lines, not a test's own output
FRAMING = re.compile(r"^\s*(?:=== (?:RUN|PAUSE|CONT|NAME)\b|--- (?:SKIP|PASS|FAIL):)")
# the "file_test.go:12: " prefix t.Skip puts before its message
CALLER = re.compile(r"^\s*[\w.-]+\.go:\d+: ?")


class PolicyError(Exception):
    """Unusable input or policy (exit 2)."""


@dataclass
class Entry:
    test: str
    package: str
    reason: str
    owner: str = ""
    until: str = ""
    module: str = ""  # the module path the relative ``package`` is resolved against

    def import_path(self) -> str:
        if self.package == ".":
            return self.module
        if self.package == self.module or self.package.startswith(self.module + "/"):
            return self.package  # already a full import path
        return f"{self.module}/{self.package}"

    def covers(self, package: str, test: str) -> bool:
        pkg_ok = package in (self.package, self.import_path())  # exact: no suffix matching
        return pkg_ok and (test == self.test or test.startswith(self.test + "/"))


@dataclass
class Policy:
    quarantine: list[Entry] = field(default_factory=list)
    privileged: list[Entry] = field(default_factory=list)


@dataclass
class Result:
    action: str = ""  # pass | fail | skip ("" when the stream ended before a verdict)
    output: list[str] = field(default_factory=list)
    failed_build: str = ""  # a package's FailedBuild: the import path whose build failed


@dataclass
class Run:
    tests: dict[tuple[str, str], Result] = field(default_factory=dict)
    packages: dict[str, Result] = field(default_factory=dict)
    build_output: dict[str, list[str]] = field(default_factory=dict)
    build_failed: list[str] = field(default_factory=list)
    events: int = 0
    bad_lines: list[str] = field(default_factory=list)


MODULE_LINE = re.compile(r"^module\s+\"?([^\s\"]+)\"?\s*(?://.*)?$", re.M)


def module_path(go_mod: Path) -> str:
    """The ``module`` directive of a go.mod; '' when the file is missing or has none."""
    try:
        m = MODULE_LINE.search(go_mod.read_text(encoding="utf-8"))
    except OSError:
        return ""
    return m.group(1) if m else ""


def load_policy(path: Path | None, module: str | None = None) -> Policy:
    if path is None:
        return Policy()
    if not path.is_file():
        raise PolicyError(f"policy file not found: {path}")
    if VENDOR.is_dir() and str(VENDOR) not in sys.path:
        sys.path.append(str(VENDOR))  # CI's copy of PyYAML beside the policy copy, for python3 -I
    import yaml  # the yaml extra; only needed when a policy file is given

    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise PolicyError(f"{path}: not YAML ({exc.__class__.__name__})") from exc
    if not isinstance(doc, dict) or set(doc) - {"quarantine", "privileged"}:
        raise PolicyError(f"{path}: expected only 'quarantine' and 'privileged' lists")
    policy = Policy()
    for key, fields in (("quarantine", QUARANTINE_FIELDS), ("privileged", PRIVILEGED_FIELDS)):
        entries = doc.get(key) or []
        if not isinstance(entries, list):
            raise PolicyError(f"{path}: '{key}' must be a list")
        for i, e in enumerate(entries):
            if not isinstance(e, dict) or set(e) - set(fields):
                raise PolicyError(f"{path}: {key}[{i}] takes only {', '.join(fields)}")
            # a date-looking YAML scalar arrives as a date; keep its ISO text
            values = {k: str(e.get(k) or "").strip() for k in fields}
            if key == "privileged" and not all(values.values()):
                raise PolicyError(f"{path}: {key}[{i}] needs {', '.join(fields)}")
            if not values["test"] or not values["package"]:
                raise PolicyError(f"{path}: {key}[{i}] needs test and package")
            getattr(policy, key).append(Entry(**values))
    if policy.quarantine or policy.privileged:
        module = module or module_path(path.parent / "go.mod")
        if not module:
            raise PolicyError(
                f"{path}: no module path to resolve its packages against: "
                "no go.mod beside it, and no --module"
            )
        for e in (*policy.quarantine, *policy.privileged):
            e.module = module
    return policy


def skip_reasons(pyproject: Path) -> tuple[list[str], int]:
    """``(skip_reasons, quarantine_max_days)`` from ``[tool.pytest.ini_options]``."""
    try:
        doc = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise PolicyError(f"cannot read {pyproject}: {exc}") from exc
    ini = doc.get("tool", {}).get("pytest", {}).get("ini_options", {})
    patterns = list(ini.get("skip_reasons") or [])
    if not patterns:
        raise PolicyError(f"{pyproject}: no skip_reasons in [tool.pytest.ini_options]")
    return patterns, int(ini.get("quarantine_max_days", 90))


def parse(lines: Iterable[str], run: Run | None = None) -> Run:
    """Fold ``go test -json`` events into per-test and per-package results."""
    run = run or Run()
    for n, raw in enumerate(lines, 1):
        if not raw.strip():
            continue
        try:
            ev = json.loads(raw)
        except json.JSONDecodeError:
            ev = None
        if not isinstance(ev, dict) or not isinstance(ev.get("Action"), str):
            run.bad_lines.append(f"line {n}: not a go test -json event: {raw.strip()[:80]!r}")
            continue
        run.events += 1
        action, pkg, test = ev["Action"], ev.get("Package", ""), ev.get("Test")
        if action in ("build-output", "build-fail"):  # Go 1.24+: builds report separately
            path = ev.get("ImportPath", "?")
            if action == "build-fail":
                run.build_failed.append(path)
            else:
                run.build_output.setdefault(path, []).append(ev.get("Output", ""))
            continue
        pkg_res = run.packages.setdefault(pkg, Result())  # every package needs its own verdict
        res = run.tests.setdefault((pkg, test), Result()) if test else pkg_res
        if action == "output":
            res.output.append(ev.get("Output", ""))
        elif action in ("pass", "fail", "skip") and res.action != "fail":
            # a failure is sticky: with -count=N (or a test name run twice) a later pass of the
            # same test must not erase an earlier failure
            res.action = action
            res.failed_build = ev.get("FailedBuild") or ""
    return run


SKIP_LINE = re.compile(r"^\s*--- SKIP:")


def skip_reason(res: Result) -> str:
    """The message of ``t.Skip``: the last line the test wrote before its ``--- SKIP`` line.

    For ``t.Skip("<one line>")`` that is the message, and earlier ``t.Log`` lines are not taken
    for it.  The stream cannot tell that apart from ``t.Log(...); t.SkipNow()`` (the logged line
    becomes the reason) or from the last line of a multi-line message, so ``--check-sources``
    rejects those forms in the module's sources: a skip states its reason in the call, on one line.

    The last line is taken even when it is empty: ``t.Skip("")`` writes an empty message line of its
    own, and stepping over it would read an earlier ``t.Log`` line as the reason.
    """
    out = res.output
    ends = [i for i, line in enumerate(out) if SKIP_LINE.match(line)]
    before = out[: ends[-1]] if ends else out
    for line in reversed(before):
        if not FRAMING.match(line):
            return CALLER.sub("", line).strip()
    return ""


def _quarantine_problem(e: Entry, today: date, max_days: int) -> str | None:
    """None when the entry is valid (the rule of tests/suite_policy.py's marker)."""
    missing = [k for k in ("owner", "until", "reason") if not getattr(e, k)]
    if missing:
        return f"quarantine needs {', '.join(missing)}"
    try:
        end = date.fromisoformat(e.until)
    except ValueError:
        return f"quarantine until={e.until!r} is not a YYYY-MM-DD date"
    if end < today:
        return f"quarantine expired on {end} (owner {e.owner}): fix the test or remove it"
    if (end - today).days > max_days:
        return f"quarantine until {end} is more than {max_days} days ahead; renew it in steps"
    return None


def judge(
    run: Run,
    policy: Policy,
    patterns: list[str],
    *,
    today: date,
    max_days: int = 90,
    privileged_run: Run | None = None,
    privileged_exit: dict[str, int] | None = None,
    forbid: Iterable[str] = (),
    go_exit: int | None = None,
    expected_packages: Iterable[str] | None = None,
    expected_tests: Iterable[str] | None = None,
) -> tuple[list[str], list[str]]:
    """``(problems, notes)`` for one run against the policy."""
    problems = list(run.bad_lines)
    notes: list[str] = []
    if run.events == 0:
        problems.append("no go test -json events: the test run did not happen or was not captured")

    valid: list[Entry] = []
    for e in policy.quarantine:
        why = _quarantine_problem(e, today, max_days)
        if why:
            problems.append(f"{e.package} {e.test}: {why}")
        else:
            valid.append(e)

    def quarantined(pkg: str, test: str) -> Entry | None:
        return next((e for e in valid if e.covers(pkg, test)), None)

    failing = {k for k, r in run.tests.items() if r.action == "fail"}
    reported: set[str] = set()  # packages with a failing test reported as a problem
    tolerated: set[str] = set()  # packages with a quarantined failing test

    for pkg, test in sorted(failing):
        e = quarantined(pkg, test)
        subs = [t for p, t in failing if p == pkg and t.startswith(test + "/")]
        own = _own_lines(run.tests[(pkg, test)])
        if e:
            notes.append(f"quarantined failure {pkg} {test} (owner {e.owner}, until {e.until})")
            tolerated.add(pkg)
        elif not subs:
            problems.append(f"FAIL {pkg} {test}")
            reported.add(pkg)
        elif own:
            reported.add(pkg)
            # its own assertion failed too: a quarantined subtest must not carry it
            problems.append(
                f"FAIL {pkg} {test}: fails with output of its own, outside its subtests "
                f"({_oneline(own)}); only a quarantine naming {test} tolerates that"
            )
        # otherwise a parent fails with its subtests: they are judged (reported or quarantined)

    reported_builds = set()
    for pkg, res in sorted(run.packages.items()):
        if res.action != "fail" or pkg in reported:
            continue  # a failing test of it is already a problem: no second line for the package
        if pkg in tolerated and _explained_by_tests(run, pkg, res):
            notes.append(f"package {pkg} failed only through its quarantined tests")
            continue
        if res.failed_build:
            reported_builds.add(res.failed_build)
            out = _oneline(run.build_output.get(res.failed_build, res.output))
            problems.append(f"BUILD FAIL {pkg}: {out}")
        elif pkg in tolerated:  # a quarantined failure, and something else went wrong too
            open_ = sorted(t for (p, t), r in run.tests.items() if p == pkg and r.action == "")
            why = f"no verdict for {', '.join(open_)}" if open_ else _beyond_summary(res)
            problems.append(
                f"FAIL {pkg}: package failed beyond its quarantined tests ({why})"[:300]
            )
        else:  # a timeout, a panic in TestMain or init, or (before Go 1.24) a build failure
            problems.append(
                f"FAIL {pkg}: package failed without a failing test ({_oneline(res.output)})"
            )
    for path in sorted(set(run.build_failed) - reported_builds):
        problems.append(f"BUILD FAIL {path}: {_oneline(run.build_output.get(path, []))}")

    problems += _cut_off(run)
    for pkg in sorted(set(expected_packages or ()) - set(run.packages)):
        problems.append(
            f"FAIL {pkg}: no events: --expect-packages lists it, the stream never mentions it "
            "(lost from a partly captured stream)"
        )
    tested = {p for (p, _t) in run.tests}
    for pkg in sorted(set(expected_tests or ()) - tested):
        if pkg in run.packages and run.packages[pkg].action != "fail":
            problems.append(
                f"FAIL {pkg}: declares tests (a Test or Fuzz function, or an Example with an "
                "// Output: comment; --expect-tests) but reported none: they were hidden from the "
                "run, as by an os.Exit before m.Run in TestMain"
            )

    forbid_rx = [re.compile(f) for f in forbid]
    priv_passed = {
        k for k, r in (privileged_run.tests.items() if privileged_run else ()) if r.action == "pass"
    }
    for (pkg, test), res in sorted(run.tests.items()):
        if res.action != "skip":
            continue
        reason = skip_reason(res)
        q = quarantined(pkg, test)
        priv = next((e for e in policy.privileged if e.covers(pkg, test)), None)
        if q:
            notes.append(f"quarantined skip {pkg} {test}: {reason!r}")
        elif priv:
            if privileged_run is None:
                problems.append(
                    f"SKIP {pkg} {test}: needs the privileged run ({priv.reason}); "
                    "pass its go test -json output with --privileged"
                )
            elif (pkg, test) not in priv_passed:
                problems.append(f"SKIP {pkg} {test}: did not pass in the privileged run")
            else:
                notes.append(f"privileged {pkg} {test}: skipped here, passed in the root run")
        elif any(rx.search(reason) for rx in forbid_rx):
            problems.append(f"SKIP {pkg} {test}: {reason!r} must not skip in this run (--forbid)")
        elif reason and any(re.search(p, reason) for p in patterns):
            notes.append(f"skip {pkg} {test}: {reason!r}")
        else:
            problems.append(
                f"SKIP {pkg} {test}: silent skip, reason {reason!r} matches no pattern in "
                "skip_reasons ([tool.pytest.ini_options] in pyproject.toml)"
            )
    if privileged_run is not None:
        problems += _privileged_problems(privileged_run, privileged_exit)
    if go_exit is not None:
        problems += _exit_status_problems(run, go_exit, notes, problems)
    return problems, notes


def _privileged_problems(run: Run, exits: dict[str, int] | None) -> list[str]:
    """The root run: no quarantine applies there, so any failure is one.

    Its stream comes from ``go tool test2json`` reading the test binary's output, which decides the
    package verdict from the text alone: a ``TestMain`` that panics after ``m.Run`` printed
    ``PASS`` still reads as a pass.  So each binary's own exit status (``--privileged-exit``) must
    be 0 as well, and a package the stream says failed (a race reported after the tests, a crash)
    fails even when no test did.
    """
    out = []
    reported = set()
    for (pkg, test), res in sorted(run.tests.items()):
        if res.action == "fail":
            out.append(f"FAIL (privileged run) {pkg} {test}")
            reported.add(pkg)
    for pkg, res in sorted(run.packages.items()):
        if res.action == "fail" and pkg not in reported:
            out.append(f"FAIL (privileged run) {pkg}: package failed ({_beyond_summary(res)})")
    out += [f"(privileged run) {b}" for b in run.bad_lines]
    out += [f"(privileged run) {c}" for c in _cut_off(run)]
    if exits is None:
        return out
    for pkg, status in sorted(exits.items()):
        if status != 0:
            out.append(
                f"FAIL (privileged run) {pkg}: the test binary exited {status} "
                f"({_beyond_summary(run.packages[pkg]) if pkg in run.packages else 'no events'})"
            )
        elif pkg not in run.packages:
            out.append(f"FAIL (privileged run) {pkg}: exited 0 but wrote no go test events")
    for pkg in sorted(set(run.packages) - set(exits)):
        out.append(f"FAIL (privileged run) {pkg}: no exit status recorded for its test binary")
    return out


def _cut_off(run: Run) -> list[str]:
    """A test or package that never got a verdict: the run was killed or the stream truncated."""
    out = []
    for (pkg, test), res in sorted(run.tests.items()):
        if not res.action:
            first = next(iter(_own_lines(res)), "").strip()
            out.append(
                f"FAIL {pkg} {test}: no verdict: the test did not finish or the stream was cut "
                f"off{f' ({first[:120]})' if first else ''}"
            )
    for pkg, res in sorted(run.packages.items()):
        if not res.action:
            out.append(f"FAIL {pkg}: no package verdict: the run or its stream was cut off")
    return out


def _exit_status_problems(
    run: Run, status: int, notes: list[str], problems: list[str]
) -> list[str]:
    """``go test``'s exit status against the stream (``--go-exit``)."""
    failed = any(r.action == "fail" for r in (*run.tests.values(), *run.packages.values()))
    if status == 0:
        return (
            ["go test exited 0 but the stream has a failure: it is not this run's"]
            if failed
            else []
        )
    if status != 1:
        return [f"go test exited {status}: not a test verdict (killed, a signal or a usage error)"]
    if not problems and not any(n.startswith("quarantined failure") for n in notes):
        return [
            "go test exited 1 but the stream shows no failure: events were lost (a cut-off or "
            "partly captured stream)"
        ]
    return []


# what the test binary itself prints at the end of a failing run, and go test's summary line
PACKAGE_SUMMARY = re.compile(r"^(?:FAIL|PASS|(?:FAIL|ok)\s+\S+\s.*|coverage: .*)$")


def _explained_by_tests(run: Run, pkg: str, res: Result) -> bool:
    """A failed package whose failure its failing tests account for: every test has a verdict
    and the package's own output is only the closing summary (no panic, race report or timeout)."""
    if res.failed_build or any(r.action == "" for (p, _), r in run.tests.items() if p == pkg):
        return False
    return all(PACKAGE_SUMMARY.match(line.strip()) for line in res.output if line.strip())


def _beyond_summary(res: Result) -> str:
    """The first lines a package wrote besides its PASS/FAIL summary: a panic, a race report."""
    lines = (x.strip() for x in res.output)
    extra = [x for x in lines if x and x != "=" * 18 and not PACKAGE_SUMMARY.match(x)]
    return " | ".join(extra[:3])[:200] or "no output of its own"


def _own_lines(res: Result) -> list[str]:
    """What a test wrote itself: its output minus test2json framing (subtests have their own)."""
    return [line for line in res.output if line.strip() and not FRAMING.match(line)]


def _oneline(lines: list[str], limit: int = 200) -> str:
    return " | ".join(line.strip() for line in lines[-5:] if line.strip())[:limit]


# a skip method named by a selector: t.Skip(...), x.T().SkipNow(), (*testing.T).Skipf, f := t.SkipNow
SKIP_NAMES = frozenset({"Skip", "Skipf", "SkipNow"})

# Go's tokens (the spec's lexical elements), enough to tell code from comments and literals: a
# rune literal is one token, so '"' starts no string; a number takes its dot, so .5 is no selector
_GO_TOKEN = re.compile(
    r"""(?P<space>[ \t\r\n]+)
      | (?P<comment>//[^\n]*|/\*.*?(?:\*/|\Z))
      | (?P<raw>`[^`]*(?:`|\Z))
      | (?P<string>"(?:[^"\\\n]|\\.)*(?:"|$))
      | (?P<rune>'(?:[^'\\\n]|\\.)*(?:'|$))
      | (?P<number>\.?[0-9](?:[eEpP][+-]|[0-9A-Za-z_.])*)
      | (?P<ident>[^\W\d]\w*)
      | (?P<op>.)""",
    re.VERBOSE | re.DOTALL | re.MULTILINE,
)
# an interpreted literal's escapes, one at a time: \\\\n in the source is a backslash, an n
_ESCAPE = re.compile(r"\\(?:x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8}|[0-7]{3}|.)", re.DOTALL)


@dataclass(frozen=True)
class GoToken:
    kind: str  # comment, raw, string, rune, number, ident or op; space is dropped
    text: str
    line: int
    pos: int = 0  # its offset in the text


def go_tokens(text: str) -> list[GoToken]:
    """The tokens of Go source ``text``, comments included and white space left out."""
    out, line = [], 1
    for m in _GO_TOKEN.finditer(text):
        kind = m.lastgroup or "op"
        if kind != "space":
            out.append(GoToken(kind, m.group(), line, m.start()))
        line += m.group().count("\n")
    return out


def check_sources(root: Path) -> list[str]:
    """``--check-sources``: every skip in the module under ``root`` names its reason in the call.

    Every ``.go`` file is read (a helper in a non-test file skips just the same) and tokenized, so
    comments and string literals are not code.  ``testdata`` and ``_*`` directories are read too:
    ``./...`` leaves them out, but a test that imports a package there compiles it, so a fixture
    that calls ``SkipNow`` fails closed rather than being a helper no check sees.  Each selector of ``Skip``, ``Skipf`` or ``SkipNow``
    is checked, called or not, whatever is before the dot (``t.``, ``x.T().``, ``(*testing.T).``)
    and with any space or line break around it.  Accepted is only ``.Skip(<one string literal>)``,
    the literal the whole argument list and on one line; rejected are ``SkipNow`` (its reason is
    whatever the test logged last), ``Skipf`` (its reason is what the arguments format to: the last
    line of ``%v`` of an error), ``Skip`` with no, several or a non-literal argument, and a method
    value or expression, whose eventual call cannot be read here.

    It reads the sources, not types: a skip through reflection, or inside a dependency outside the
    tree (the module cache), is not seen; so a ``Skip`` method of an unrelated type is checked too.
    """
    out = []
    for path in sorted(root.rglob("*.go")):
        rel = path.relative_to(root)
        if any(part.startswith(".") for part in rel.parts[:-1]):
            continue  # no import path runs through a dot directory (.git, .cache)
        if not path.is_file():
            continue
        toks = [
            t
            for t in go_tokens(path.read_text(encoding="utf-8", errors="replace"))
            if t.kind != "comment"
        ]
        for i, tok in enumerate(toks[:-1]):
            name = toks[i + 1]
            if (tok.kind, tok.text) != ("op", ".") or name.kind != "ident":
                continue
            why = _skip_problem(name.text, toks[i + 2 :]) if name.text in SKIP_NAMES else None
            if why:
                out.append(f"{rel.as_posix()}:{tok.line}: .{name.text}: {why}")
    return out


def _skip_problem(name: str, rest: list[GoToken]) -> str | None:
    use = 'use Skip("<one-line reason>")'
    if name == "SkipNow":
        return f"SkipNow has no reason of its own (the last line logged is read): {use}"
    if name == "Skipf":
        return f"Skipf's reason is what its arguments format to, unseen here: {use}"
    if not rest or rest[0].text != "(":
        return f"Skip as a method value or expression: its call cannot be checked: {use}"
    args = rest[1:4]
    texts = [t.text for t in args]
    one = (
        len(args) >= 2
        and args[0].kind in ("string", "raw")
        and (texts[1] == ")" or texts[1:3] == [",", ")"])
    )
    if not one:
        return f"Skip's whole argument list must be one string literal: {use}"
    value = go_literal_value(args[0])
    if "\n" in value or "\r" in value:
        return f"Skip's reason spans lines: only its last line would be read: {use}"
    if not any(c.isprintable() and not c.isspace() for c in value):
        return f"Skip's reason is empty or only white space: {use}"
    return None


_SIMPLE_ESCAPES = {"a": "\a", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v"}


def go_literal_value(tok: GoToken) -> str:
    """The value of a Go string literal token: a raw one without its carriage returns (as the
    spec drops them), an interpreted one with its escapes decoded."""
    body = tok.text[1:-1]
    if tok.kind == "raw":
        return body.replace("\r", "")

    def decode(m: re.Match[str]) -> str:
        e = m.group()[1:]
        if e[0] in "xuU" and len(e) > 1:
            return chr(min(int(e[1:], 16), 0x10FFFF))
        if len(e) == 3 and e.isdigit():
            return chr(int(e, 8))
        return _SIMPLE_ESCAPES.get(e, e)

    return _ESCAPE.sub(decode, body)


def list_privileged(policy: Policy) -> list[str]:
    by_pkg: dict[str, list[str]] = {}
    for e in policy.privileged:
        top = e.test.split("/", 1)[0]
        full = e.import_path()
        rel = "." if full == e.module else full.removeprefix(e.module + "/")
        tests = by_pkg.setdefault(rel, [])
        if top not in tests:
            tests.append(top)
    return [
        f"{'.' if pkg == '.' else './' + pkg} ^({'|'.join(sorted(ts))})$"
        for pkg, ts in sorted(by_pkg.items())
    ]


def read_exits(path: str) -> dict[str, int]:
    """``--privileged-exit``: one ``<import path> <exit status>`` line per test binary run."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyError(f"cannot read {path}: {exc.strerror}") from exc
    exits: dict[str, int] = {}
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        fields = line.split()
        if len(fields) != 2 or not re.fullmatch(r"\d+", fields[1]):
            raise PolicyError(f"{path}:{n}: expected '<import path> <exit status>', got {line!r}")
        status = int(fields[1])
        exits[fields[0]] = exits.get(fields[0], 0) or status  # a non-zero status is sticky
    return exits


# a top-level function the test binary runs: TestXxx and FuzzXxx (Xxx not lowercase), or
# ExampleXxx, which runs only when its body has an output comment
_RUNS = re.compile(r"(?:Test|Fuzz)(?![a-z])\w*")
_EXAMPLE = re.compile(r"Example\w*")
_OUTPUT = re.compile(r"(?i)^//\s*(?:unordered )?output:")


def declares_tests(directory: Path) -> bool:
    """Whether the ``*_test.go`` files in ``directory`` declare a test the binary runs."""
    examples = output = False
    for path in sorted(directory.glob("*_test.go")):
        toks = go_tokens(path.read_text(encoding="utf-8", errors="replace"))
        output = output or any(t.kind == "comment" and _OUTPUT.match(t.text) for t in toks)
        code = [t for t in toks if t.kind != "comment"]
        for i in range(len(code) - 2):
            if code[i].text != "func" or code[i + 1].kind != "ident" or code[i + 2].text != "(":
                continue
            name = code[i + 1].text
            if _RUNS.fullmatch(name):
                return True
            examples = examples or bool(_EXAMPLE.fullmatch(name))
    return examples and output


def runnable(lines: list[str]) -> list[str]:
    """The import paths of ``--expect-tests`` whose packages declare tests; a line without a
    directory is taken as declaring them."""
    out = []
    for line in lines:
        pkg, _, directory = line.partition(" ")
        if not directory or declares_tests(Path(directory)):
            out.append(pkg)
    return out


def _read_lines(path: str) -> list[str]:
    try:
        return [x.strip() for x in Path(path).read_text(encoding="utf-8").splitlines() if x.strip()]
    except OSError as exc:
        raise PolicyError(f"cannot read {path}: {exc.strerror}") from exc


def _read(paths: list[str], run: Run | None = None) -> Run:
    run = run or Run()
    for p in paths:
        try:
            text = sys.stdin.read() if p == "-" else Path(p).read_text(encoding="utf-8")
        except OSError as exc:
            raise PolicyError(f"cannot read {p}: {exc.strerror}") from exc
        # one event per "\n" exactly: splitlines() also breaks at \x85 (NEL), which go's JSON
        # encoder leaves unescaped inside an Output string
        parse(text.split("\n"), run)
    return run


def _today(arg: str | None) -> date:
    text = arg or os.environ.get("HNX_TODAY")
    if text:
        try:
            return date.fromisoformat(text)
        except ValueError as exc:
            raise PolicyError(f"--today {text!r} is not a YYYY-MM-DD date") from exc
    return date.today()  # quarantine expiry is relative to the real date (--today for tests)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("results", nargs="*", help="go test -json output files ('-' = stdin)")
    ap.add_argument("--policy", type=Path, help="skips.yml (quarantine and privileged lists)")
    ap.add_argument("--module", help="module path (default: the go.mod beside --policy)")
    ap.add_argument("--pyproject", type=Path, default=REPO_ROOT / "pyproject.toml")
    ap.add_argument("--privileged", action="append", default=[], metavar="FILE")
    ap.add_argument(
        "--privileged-exit",
        metavar="FILE",
        help="'<import path> <status>' per root-run test binary; every status must be 0",
    )
    ap.add_argument("--forbid", action="append", default=[], metavar="REGEX")
    ap.add_argument("--today", help="YYYY-MM-DD (default: env HNX_TODAY, else today)")
    ap.add_argument(
        "--go-exit",
        type=int,
        metavar="N",
        help="go test's exit status: 0, or 1 when only quarantined failures explain it",
    )
    ap.add_argument(
        "--expect-packages",
        metavar="FILE",
        help="the packages the run covers, one import path a line (go list ./...): each needs events",
    )
    ap.add_argument(
        "--expect-tests",
        metavar="FILE",
        help="'<import path> <dir>' per package with test files: one that declares tests needs a "
        "test event",
    )
    ap.add_argument("--list-privileged", action="store_true")
    ap.add_argument(
        "--check-sources",
        type=Path,
        metavar="DIR",
        help="check every Skip/Skipf/SkipNow in the .go files under DIR instead of judging a run",
    )
    args = ap.parse_args(argv)
    try:
        policy = load_policy(args.policy, args.module)
        if args.list_privileged:
            print("\n".join(list_privileged(policy)))
            return EXIT_OK
        if args.check_sources:
            if not args.check_sources.is_dir():
                raise PolicyError(f"--check-sources: not a directory: {args.check_sources}")
            found = check_sources(args.check_sources)
            for f in found:
                print(f"SKIP CALL {f}")
            print(f"go_test_policy: {len(found)} skip call(s) without a one-line literal reason")
            return EXIT_FAIL if found else EXIT_OK
        if not args.results:
            raise PolicyError("no go test -json input given")
        patterns, max_days = skip_reasons(args.pyproject)
        forbid = [re.compile(f).pattern for f in args.forbid]
        run = _read(args.results)
        privileged = _read(args.privileged) if args.privileged else None
        if args.privileged_exit and privileged is None:
            raise PolicyError("--privileged-exit needs the root run's stream (--privileged)")
        exits = read_exits(args.privileged_exit) if args.privileged_exit else None
        expected = _read_lines(args.expect_packages) if args.expect_packages else None
        tests = runnable(_read_lines(args.expect_tests)) if args.expect_tests else None
        problems, notes = judge(
            run,
            policy,
            patterns,
            today=_today(args.today),
            max_days=max_days,
            privileged_run=privileged,
            privileged_exit=exits,
            forbid=forbid,
            go_exit=args.go_exit,
            expected_packages=expected,
            expected_tests=tests,
        )
    except (PolicyError, re.error) as exc:
        print(f"go_test_policy: {exc}", file=sys.stderr)
        return EXIT_USAGE
    for n in notes:
        print(f"note: {n}")
    for p in problems:
        print(p)
    counts = {a: sum(r.action == a for r in run.tests.values()) for a in ("pass", "fail", "skip")}
    print(
        f"go_test_policy: {len(run.tests)} tests in {len(run.packages)} packages "
        f"({counts['pass']} passed, {counts['fail']} failed, {counts['skip']} skipped), "
        f"{len(problems)} problem(s)",
        file=sys.stderr if problems else sys.stdout,
    )
    return EXIT_FAIL if problems else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
