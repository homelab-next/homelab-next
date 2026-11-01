# SPDX-License-Identifier: Apache-2.0
"""The commit a CI check compares the working tree with (``--ci-base``).

One rule for every check that takes ``--ci-base`` (``tools/schema_check.py``,
``tools/product_name_lint.py``, ``hnx modules review-tier`` and ``swap-check``), kept in the
package so a CLI never loads a file from the checkout to find it.  It is still the code of
whatever is installed: in a pull request's own CI run that is the pull request's, which is why the
gates that must not trust the change run from a checkout of the base (``.github/workflows/ci.yml``,
job ``trusted-gates``; docs/modules.md, "Swap record 1.2").

It is also the one copy of the rule for CI's shell steps: ``python -m homelabnext.gitbase`` prints
the base commit (the reason goes to stderr), and the jobs that compare with a base call it rather
than writing the rule out again (``register-ids`` and ``regression-tests``, with
``--allow-root``; ``trusted-gates`` reads this file from the commit it trusts and calls
:func:`ci_base_from_env`, refusing a root commit)."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

__all__ = ["ZERO_SHA", "add_base_arguments", "ci_base", "ci_base_from_env", "main"]

ZERO_SHA = "0" * 40


def ci_base(root: Path, event: str, pr_base: str, before: str) -> tuple[str | None, str]:
    """The commit CI checks ``_frozen/`` against, and why.  Fails closed (ValueError): a pull
    request's base must be readable; a push compares with its previous tip, else ``HEAD^`` (a
    new branch, whose previous tip is zero, or a force-push, whose old tip is gone), else none
    only for a root commit, never for a shallow checkout; any other event (merge_group,
    workflow_dispatch, schedule, pull_request_target, unset) has no base rule and is an error."""

    def git(*args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["git", "-C", str(root), *args], capture_output=True, text=True, check=False
        )

    def commit(rev: str) -> str | None:
        r = git("rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}")
        return r.stdout.strip() if r.returncode == 0 else None

    if event == "pull_request":
        sha = commit(pr_base) if pr_base else None
        if not sha:
            raise ValueError(
                f"the pull request's base {pr_base or '(unset)'} is not readable "
                "(check out with fetch-depth: 0)"
            )
        return sha, "the pull request's base"
    if event != "push":
        raise ValueError(
            f"event {event or '(unset)'}: only push and pull_request have a base rule "
            "(pass --base explicitly)"
        )
    if before and before != ZERO_SHA and (sha := commit(before)):
        return sha, "the push's previous tip"
    why = (
        "a new branch: the push's previous tip is zero"
        if not before or before == ZERO_SHA
        else f"the push's previous tip {before} is not fetchable (a force-push)"
    )
    # With fetch-depth: 0 (every CI job) an unreadable non-zero tip is a force-push.  A shallow
    # checkout of depth > 1 would also reach HEAD^ here and be labelled a force-push; that is
    # latent, and a depth-1 checkout (no HEAD^) is refused below.
    if sha := commit("HEAD^"):
        return sha, f"HEAD^ ({why})"
    if git("rev-parse", "--is-shallow-repository").stdout.strip() == "true":
        raise ValueError(f"{why}, and the checkout is shallow (check out with fetch-depth: 0)")
    return None, f"none: a root commit ({why})"


def ci_base_from_env(root: Path) -> tuple[str | None, str]:
    """:func:`ci_base` with the event and commits CI passes in the environment
    (``GITHUB_EVENT_NAME``, ``HNX_PR_BASE``, ``HNX_PUSH_BEFORE``)."""
    return ci_base(
        root,
        os.environ.get("GITHUB_EVENT_NAME", ""),
        os.environ.get("HNX_PR_BASE", ""),
        os.environ.get("HNX_PUSH_BEFORE", ""),
    )


def add_base_arguments(parser: argparse.ArgumentParser) -> None:
    """``--base REV`` or ``--ci-base`` (one required): the commit a check compares with."""
    which = parser.add_mutually_exclusive_group(required=True)
    which.add_argument("--base", help="the commit to compare with")
    which.add_argument(
        "--ci-base",
        action="store_true",
        help="pick the base like tools/schema_check.py --ci-base (GITHUB_EVENT_NAME, "
        "HNX_PR_BASE, HNX_PUSH_BEFORE)",
    )


def main(argv: list[str] | None = None) -> int:
    """Print the base commit :func:`ci_base_from_env` picks for the repository at ``--root``.

    Exit 0 with the commit on stdout; exit 1 when there is no rule for the event, the base is not
    readable, or the checkout is shallow; and for a root commit (which has no base) unless
    ``--allow-root``, which prints nothing and exits 0 instead.  The reason is always on stderr."""
    ap = argparse.ArgumentParser(
        prog="python -m homelabnext.gitbase",
        description="print the commit a CI check compares the working tree with",
    )
    ap.add_argument("--root", type=Path, default=Path("."), help="the repository (default: .)")
    ap.add_argument(
        "--allow-root",
        action="store_true",
        help="a root commit has no base: print nothing and exit 0 (default: an error)",
    )
    args = ap.parse_args(argv)
    try:
        sha, why = ci_base_from_env(args.root)
    except ValueError as exc:
        print(f"gitbase: {exc}", file=sys.stderr)
        return 1
    if sha is None and not args.allow_root:
        print(f"gitbase: no base: {why}", file=sys.stderr)
        return 1
    print(f"gitbase: base {sha or '-'} ({why})", file=sys.stderr)
    if sha:
        print(sha)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
