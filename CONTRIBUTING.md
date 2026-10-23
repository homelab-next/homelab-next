# Contributing to HomelabNext

Thanks for helping. The project is contract-first: a change is welcome when a stranger can run its
tests on a laptop with no network and no private context.

## Ground rules

1. **Sign off every commit** (Developer Certificate of Origin): `git commit -s`. The sign-off
   certifies you may submit the work under Apache-2.0. CI's `dco` job fails a pull request with
   a commit that lacks a `Signed-off-by:` for its author. Commit with your GitHub noreply address
   (Settings -> Emails); CI rejects any other author or committer e-mail. Commits authored by a
   GitHub App bot (Dependabot) are exempt; the maintainer who merges them takes the sign-off.
2. **Every schema change ships an example and a negative** (an input that must be rejected).
   Evolution is additive within a major version (ADR-0001). A schema whose ADR is still proposed
   may be a **draft** (`"x-draft": "<why, naming the ADR>"`): it has no frozen baseline and may
   change until the ADR is accepted, when removing `x-draft` and `tools/schema_check.py --freeze`
   freeze it.
3. **Every library ships a fake**, and the fake passes the conformance test for its capability.
4. **No raw endpoints.** Addresses come from the registry; an unset endpoint raises, it never
   defaults (ADR-0002). `tools/no_raw_endpoints.py` gates this.
5. **No real identifiers, ever.** Use `example.internal`, `192.0.2.0/24`, `198.51.100.0/24`,
   `203.0.113.0/24`, `2001:db8::/32`, MACs `00:00:5e:00:53:xx`, account id `123456789012`, and role
   names such as `hv-01`. This covers code, tests, fixtures, docs, commit messages and branch names.
6. **Records are identified by uids; numbers are computed.** Every lesson, runbook and strategy
   record carries a `uid` (a UUIDv7: `hnx records uid` prints one) and lives in `<uid>.md`; links
   name uids, and no record stores a number (ADR-0019). The number it is shown with (`LL 3`,
   `PIR 2.1`) is computed from its type, parent and `order`, so nothing is allocated, renumbered
   or resolved at merge time and two pull requests never collide. A new lesson is a new file
   `examples/registers/lessons/<uid>.md` (format, lifecycle, reviews and the review process:
   [docs/registers.md](docs/registers.md)). CI checks that no record of the base branch vanished,
   that no uid repeats and that every record carries its uid (`make ids-check`). A record is never
   deleted: a solved lesson is retired (a pitfall, by the mechanism that replaced it) or
   incorporated (a practice, into a runbook). Invariant ids are the checklist's row ids; one that
   was wrong is tombstoned under the register's `retired:` block with a `reason:` (and
   `replaced_by:`), never deleted.
   Machine state is never edited inside a record: reviews, recurrences and verification runs are
   append-only event files in `<record>.events/` (`hnx registers events add`), and a status change
   is a `register-transition` intent in the records inbox that `hnx registers decide` applies
   (ADR-0014, [docs/registers.md](docs/registers.md#events-and-derived-state)). Scripts write
   scratch output only under `homelabnext.runs.run_dir(run_id)` or `build/`
   (`make run-output-lint`).
7. **A contract change needs an ADR** (copy `docs/adr/_template.md`; one file, five headings).
8. Python >= 3.11, standard library first. New dependencies go in an extra in `pyproject.toml`,
   must be permissively licensed (LGPL only as an unmodified dependency), and are justified in the PR.
   CI installs every package from the hash-pinned `constraints/ci.txt`; regenerate it with
   `make constraints` (needs `uv`) in the same PR.
9. Tests do not use the network, wall-clock time or unseeded randomness. Anything needing a real
   server is marked `@pytest.mark.live` and never runs in default CI. Enforced: an unmarked test
   that connects beyond loopback or resolves a non-local name fails (`tests/network_guard.py`), and
   `make hermetic-lint` rejects direct clock and unseeded-random calls in test code, and any
   clock read in `homelabnext/` that is not the default or fallback of an injectable clock/`now`.
   Every component ships tests (`make component-tests`), and the security-critical units (broker,
   scope guard, records lifecycle, decide cascade, agent grant ceiling, reader rule and handoff,
   memory, screen, workflows, model budgets, MCP, context retrieval, the status hub's front door,
   ingest, approval page and server, the generators' safety backstop and the leak scan) keep >= 80%
   line coverage, each from its own tests (`make coverage`; `tools/coverage_floor.py` lists them).
   Suites stay trustworthy (`tests/suite_policy.py`, see "Skips, quarantine and time budgets").
10. Every Python, shell, YAML, TOML and Jinja template file starts with
    `# SPDX-License-Identifier: Apache-2.0` (in a template: `{# SPDX-License-Identifier: Apache-2.0 -#}`,
    which renders nothing; `tools/check_spdx.py` lists the suffixes it checks).

## Setup

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pre-commit install          # optional; installs the same checks as CI
make check                  # lint, tests, schema/registry gates, leak scan, changelog
```

## The leak scan

`make leak-scan` runs `tools/leak_scan.py` over the files git tracks (plus untracked files that are
not ignored). It looks for generic shapes only: private, CGNAT and public IPv4 addresses (outside
the documentation ranges), IPv6 outside `2001:db8::/32`, MACs, non-documentation e-mail, private
TLDs, workstation paths, secret-variable names, keyed password/secret/token values, cloud keys, PEM
blocks, tokens and high-entropy strings. `python3 tools/leak_scan.py --list` prints them all. A file
it cannot read as text (binary, over 5 MB) fails the run unless `--allow-skip GLOB` names it.

A reviewed false positive is suppressed with an end-of-line marker `scrub-allow: <reason>` (a few
plain words). It waives only what precedes it on that line, never a secret-shaped hit and never a
deny-list term, and CI prints every suppression (pattern names and reason, not the line).

In CI the scanner also reads every line added by the commits of a pull request
(`--history BASE..HEAD`), so a value committed and deleted again is still caught, and checks that
every author and committer e-mail is a noreply address (`--check-authors`).
`make leak-scan-history RANGE=origin/main..HEAD` runs the history scan locally.

### Your own names: the run-time deny-list

The built-in patterns know nothing about any real lab. Your own identifiers (domain, host names,
user names, paths, project code names) go in a private deny-list file that is never committed:

```bash
mkdir -p ~/.config/homelabnext && chmod 700 ~/.config/homelabnext
cat > ~/.config/homelabnext/denylist.txt <<'TXT'
# one term per line, matched case-insensitively on word boundaries; `re:` starts a regex
mylab.example
nas-basement
re:hv-[0-9]{3}
TXT
export HNX_DENYLIST=~/.config/homelabnext/denylist.txt   # e.g. in your shell profile
make leak-scan                                           # the tree, with your terms
make leak-scan-history RANGE=origin/main..HEAD           # what you are about to push
```

The pre-commit hooks read the same variable. A hit prints only `term on deny-list line N`, never the
term itself, so CI logs and screenshots do not leak the list. Deny-list hits cannot be suppressed
with `scrub-allow`. An empty or missing file is an error (exit 2), not a silent pass.

## Hygiene lints

Part of `make check` and CI; each reviewed exception lives in one allowlist file with a reason,
and an entry that no longer excuses anything fails the lint.

- `tools/shared_helpers_lint.py` (M-03): no private notify, state-file or lake-query helper
  outside `homelabnext/notify`, `homelabnext/state` and `homelabnext/lake` (AST; test code is out
  of scope). Allowlist: `tools/shared_helpers.allow.yml` (`path`, `rule`, `reason`).
- `tools/dup_check.py` (M-03, textual side): no copy-pasted Python beyond the committed baseline
  `tools/dup_check.baseline.json` (stdlib `tokenize`; runs of at least 50 tokens and 5 lines,
  compared exactly, comments, docstrings and module-level imports ignored; test code,
  `schemas/_frozen/` and generated files out of scope). The baseline is keyed by content hash, so
  moving code does not touch it, and it only shrinks: a removed clone is a stale entry that fails
  until `make dup-baseline` drops it, and an update that would raise the duplicated-line total is
  refused unless `--update-baseline --allow-increase "<reason>"` records why. The helpers lint
  above is the semantic side (a re-implemented seam, copied or not); a copied seam helper trips
  both and the one fix clears both. `--mode normalised` (identifiers and literals abstracted)
  finds renamed copies too, as an audit.
- `tools/tls_verify_lint.py` (F-07): no `verify=False`, unverified SSL context, `CERT_NONE`,
  `check_hostname=False` or silenced urllib3 warnings in Python, and no
  `validate_certs`/`verify_ssl`/`insecure_skip_verify`-style key turning verification off in YAML
  or JSON (role tasks are also covered by role-lint RL013). Allowlist:
  `tools/tls_verify.allow.yml`, or `tls-verify: allow <reason>` on the line.
- `tools/workstation_refs.py` (F-17): runtime configuration (roles, playbooks, inventory, compose,
  examples, generator templates, golden outputs) names no home directory, workstation path or
  host, and no role step runs on the Ansible control node. Allowlist:
  `tools/workstation_refs.allow.yml` (`path`, optional `match`, `reason`), or
  `workstation-ref: allow <reason>` on the line.
- `make keyring-check` (M-12): `examples/keyring/keyring.json` is exactly what
  `hnx agent keyring build examples/keyring/sources.yml` generates (`make keyring` rebuilds it).

## Skips, quarantine and time budgets

`tests/suite_policy.py` runs with every `pytest` invocation:

- **No silent skips.** A skip's reason must match one of the `skip_reasons` patterns in
  `[tool.pytest.ini_options]` (an optional extra or external tool is absent, the platform cannot run
  the test). Anything else, including a bare `@pytest.mark.skip`, fails. Prefer
  `pytest.importorskip("module")` for optional extras and `reason="<tool> not installed"` for tools.
  A genuinely new legitimate cause is a reviewed one-line addition to `skip_reasons`.
- **Quarantine, not deletion, for a flaky test:**
  `@pytest.mark.quarantine(owner="<team-or-handle>", until="YYYY-MM-DD", reason="<what is flaky>")`.
  The test still runs but cannot break the build; all three fields are required, the date may be at
  most 90 days ahead, and on expiry the test fails until it is fixed or the quarantine is renewed.
- **Time budgets.** Each suite (a test file's first two directories, e.g. `tests/lake`) has a budget
  (`suite_budget_default`, `suite_budgets`); a suite over it fails the run. `pytest --suite-times`
  prints the table; `HNX_SUITE_BUDGET_SCALE=3` scales every budget on a slow machine.

## Bug fixes carry a regression test

A bug fix is a commit whose subject is a conventional-commit fix (`fix: ...`, `fix(scope): ...`) or
whose message has a `Fixes: <issue or description>` trailer. Use one of them for every fix, and in
the same commit add or change a test that **fails without the fix and passes with it** (write the
test first and watch it fail). CI's `regression-tests` job (`tools/fix_has_test.py --prove`) checks
both halves for every commit of a pull request: a fix must touch a test file, and its test modules,
run on the fix's parent commit, must fail. `make fix-check` runs the first half locally
(`make fix-check PROVE=1` both). A fix that cannot have a test (a documentation typo, a CI setting)
says why in a trailer, `No-regression-test: <reason>`; the gate lists every waiver.

## Adding a capability

1. Contract: a schema (with example and negative) or a Python protocol, listed in `docs/interfaces.md`.
2. Fake: an in-memory implementation.
3. Conformance test under `conformance/<capability>/` that the fake passes and a deliberately broken
   fake fails, naming the check.
4. Adapter for a real product, kept behind the same contract and `live`-marked where it needs a server.
5. ADR if the contract introduces a new rule.

## Pull requests

Small, one concern, green `make check`. Describe what a reviewer can run. The maintainers read each
new top-level directory once for identifiers before it ships in a release.

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
