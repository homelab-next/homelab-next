#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: go-test-policy
#   kind: check
#   purpose: Fail when a go test -json run has a failing test, a package that did not build, a skip without a registered reason or an invalid quarantine.
#   owner: maintainers
#   trigger: [ci:ci/orchestrator]
#   inputs: go test -json output files (or - for stdin); orchestrator/skips.yml; skip_reasons and quarantine_max_days in pyproject.toml
#   outputs: one line per problem, notes for tolerated skips and quarantined failures, a summary
#   exit:
#     "0": the run is trustworthy
#     "1": a failure, a silent skip, a missing privileged run or an invalid quarantine
#     "2": usage error, an unreadable file or a malformed policy
"""The Go side of the test-suite policy (checklist Q-02): what tests/suite_policy.py does for pytest.

Reads the event stream of ``go test -json`` (one or more files) and fails on:

* a failing test, unless a valid quarantine names it (or, for a parent test, every failing
  subtest under it is quarantined);
* a package that failed without a failing test: a build failure (``build-fail``), a panic in
  ``TestMain`` or ``init``, a timeout;
* a skip whose reason (the last line the test wrote before ``--- SKIP``) matches none of the
  ``skip_reasons`` regular expressions of ``[tool.pytest.ini_options]`` in pyproject.toml, or one
  that ``--forbid`` names for this run (a reason that is legitimate elsewhere, such as a tool CI
  always installs);
* an invalid quarantine entry, wherever its test is: owner, until and reason missing, the date in
  the past, or more than ``quarantine_max_days`` (90) ahead -- the same rule as pytest's marker;
* a line that is not a ``go test -json`` event, or input with no events at all.

The policy file (``orchestrator/skips.yml``)::

    quarantine:          # a known-flaky test keeps running; its failure or skip is tolerated
      - {test: TestStall, package: internal/hermesagent, owner: maintainers,
         until: 2026-01-31, reason: timing-sensitive under -race on shared runners}
    privileged:          # needs root: skips in the normal run, must pass in the privileged run
      - {test: TestHardening, package: internal/api, reason: chowns a file to another user}

``package`` is the import path relative to the module (a full import path ending in it matches);
``test`` names a top-level test or a ``Parent/sub`` subtest, and a parent covers its subtests.
A ``privileged`` test's skip is accepted only when ``--privileged FILE`` (the ``go test -json``
output of the root run) shows it passed, so a missing root run fails instead of passing silently.
``--list-privileged`` prints ``./<package> <-run regex>`` lines for the CI step that runs them.

Usage::

    go test -json ./... > run.json; python tools/go_test_policy.py --policy skips.yml run.json
    python tools/go_test_policy.py --policy skips.yml --list-privileged

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

    def covers(self, package: str, test: str) -> bool:
        pkg_ok = package == self.package or package.endswith("/" + self.package)
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


def load_policy(path: Path | None) -> Policy:
    if path is None:
        return Policy()
    if not path.is_file():
        raise PolicyError(f"policy file not found: {path}")
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
        if test:
            res = run.tests.setdefault((pkg, test), Result())
        else:
            res = run.packages.setdefault(pkg, Result())
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

    Earlier ``t.Log`` lines are not the reason, so a logged phrase cannot make an unregistered
    skip look registered (or trip ``--forbid``) on its own.
    """
    out = res.output
    ends = [i for i, line in enumerate(out) if SKIP_LINE.match(line)]
    before = out[: ends[-1]] if ends else out
    for line in reversed(before):
        if FRAMING.match(line):
            continue
        text = CALLER.sub("", line).strip()
        if text:
            return text
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
    forbid: Iterable[str] = (),
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

    for pkg, test in sorted(failing):
        e = quarantined(pkg, test)
        subs = [t for p, t in failing if p == pkg and t.startswith(test + "/")]
        if e:
            notes.append(f"quarantined failure {pkg} {test} (owner {e.owner}, until {e.until})")
        elif not subs:
            problems.append(f"FAIL {pkg} {test}")
        # a parent fails with its subtests: they are judged (reported or quarantined) on their own

    reported_builds = set()
    for pkg, res in sorted(run.packages.items()):
        if res.action != "fail" or any(p == pkg for p, _ in failing):
            continue  # a package whose failing tests are judged above needs no line of its own
        if res.failed_build:
            reported_builds.add(res.failed_build)
            out = _oneline(run.build_output.get(res.failed_build, res.output))
            problems.append(f"BUILD FAIL {pkg}: {out}")
        else:  # a timeout, a panic in TestMain or init, or (before Go 1.24) a build failure
            problems.append(
                f"FAIL {pkg}: package failed without a failing test ({_oneline(res.output)})"
            )
    for path in sorted(set(run.build_failed) - reported_builds):
        problems.append(f"BUILD FAIL {path}: {_oneline(run.build_output.get(path, []))}")

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
        for (pkg, test), res in sorted(privileged_run.tests.items()):
            if res.action == "fail":
                problems.append(f"FAIL (privileged run) {pkg} {test}")
        problems += [f"(privileged run) {b}" for b in privileged_run.bad_lines]
    return problems, notes


def _oneline(lines: list[str], limit: int = 200) -> str:
    return " | ".join(line.strip() for line in lines[-5:] if line.strip())[:limit]


def list_privileged(policy: Policy) -> list[str]:
    by_pkg: dict[str, list[str]] = {}
    for e in policy.privileged:
        top = e.test.split("/", 1)[0]
        by_pkg.setdefault(e.package, [])
        if top not in by_pkg[e.package]:
            by_pkg[e.package].append(top)
    return [f"./{pkg} ^({'|'.join(sorted(ts))})$" for pkg, ts in sorted(by_pkg.items())]


def _read(paths: list[str], run: Run | None = None) -> Run:
    run = run or Run()
    for p in paths:
        try:
            text = sys.stdin.read() if p == "-" else Path(p).read_text(encoding="utf-8")
        except OSError as exc:
            raise PolicyError(f"cannot read {p}: {exc.strerror}") from exc
        parse(text.splitlines(), run)
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
    ap.add_argument("--pyproject", type=Path, default=REPO_ROOT / "pyproject.toml")
    ap.add_argument("--privileged", action="append", default=[], metavar="FILE")
    ap.add_argument("--forbid", action="append", default=[], metavar="REGEX")
    ap.add_argument("--today", help="YYYY-MM-DD (default: env HNX_TODAY, else today)")
    ap.add_argument("--list-privileged", action="store_true")
    args = ap.parse_args(argv)
    try:
        policy = load_policy(args.policy)
        if args.list_privileged:
            print("\n".join(list_privileged(policy)))
            return EXIT_OK
        if not args.results:
            raise PolicyError("no go test -json input given")
        patterns, max_days = skip_reasons(args.pyproject)
        forbid = [re.compile(f).pattern for f in args.forbid]
        run = _read(args.results)
        privileged = _read(args.privileged) if args.privileged else None
        problems, notes = judge(
            run,
            policy,
            patterns,
            today=_today(args.today),
            max_days=max_days,
            privileged_run=privileged,
            forbid=forbid,
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
