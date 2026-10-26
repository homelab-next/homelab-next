# Contributing to HomelabNext

Thanks for helping. The project is contract-first: a change is welcome when a stranger can run its
tests on a laptop with no network and no private context.

## Ground rules

1. **Sign off every commit** (Developer Certificate of Origin): `git commit -s`. The sign-off
   certifies you may submit the work under Apache-2.0. CI's `dco` job fails a pull request with
   a commit that lacks a `Signed-off-by:` for its author. Commit with your GitHub noreply address
   (Settings -> Emails); CI rejects any other author or committer e-mail. Dependabot's own
   commits, in a pull request GitHub records as opened by Dependabot, are exempt; the maintainer
   who merges them takes the sign-off. A bot's address in a commit's author field exempts
   nothing on its own: anyone can set it.
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
10. Every Python, shell, YAML, TOML, Go and Jinja template file starts with
    `# SPDX-License-Identifier: Apache-2.0` (in Go: `// SPDX-License-Identifier: Apache-2.0` on line 1;
    in a template: `{# SPDX-License-Identifier: Apache-2.0 -#}`, which renders nothing;
    `tools/check_spdx.py` lists the suffixes it checks).

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
- `tools/caddy_lint.py` (F-23): over every Caddy config in the tree (`git ls-files`: Caddyfiles
  and their templates and imports, markdown fences, Caddyfiles in YAML, Caddy JSON/YAML, the
  `caddy` generator's output for each registry), in a config with a `forward_auth` anywhere
  every site that runs it or proxies deletes the identity headers first at site level with no
  matcher (`request_header -*authentik*`, as the generator writes it; the IdP's own site is
  exempt), every `forward_auth` sits in a `route`, with no matcher, after a delete (site level
  or in the route) of each header its `copy_headers` sets in every `-`/`_` spelling; no header directive sets, adds
  or copies an identity header (`copy_headers A>B` is the way to rename one), or rewrites one
  through a `*` field; no FastCGI `env` sets an
  identity CGI variable or a client-chosen value (only `REMOTE_USER`, `AUTH_USER` and
  `REDIRECT_REMOTE_USER` may take the IdP's answer, after the site-level strip: PHP rebuilds
  `PHP_AUTH_*` from the client's `Authorization`; and if the app falls back to the
  `Remote-User` header, strip `Remote-User`/`Remote_User` too, or use
  `copy_headers X-Authentik-Username>Remote-User` with
  `env REMOTE_USER {http.request.header.Remote-User}`); no `forward_auth` (or forward-auth site proxy)
  dials a request placeholder (`dial`); what the lint cannot read (a heredoc, `{$ENV}` in
  directive position, a header name that is a placeholder, an import outside the tree, a
  `forward_auth` in a `.conf` nothing imports, a Python string or a caddy-docker-proxy label)
  fails closed; and every Caddy pin (registry `impl: caddy`,
  `caddy_*version` keys, any `.../caddy` image, Dockerfile `FROM`/`COPY --from` and `xcaddy
  build`, `caddy=` packages, `go.mod`, `.env`) is 2.11.2 or later. With a `caddy` binary on PATH
  (or `HNX_CADDY`) it also judges Caddy's own `caddy adapt` JSON; CI pins one and requires it,
  and a local run without one says what it skipped. Exceptions: `caddy-lint: allow <reason>` on
  the line, or `tools/caddy_lint.allow.yml` (a file path, the `rules` it excuses and a reason).
  It guards against accidental misconfiguration: Caddy config authors are trusted and reviewed,
  and deliberate obfuscation is left to review.
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
  `pytest.importorskip("module")` for optional extras, and `require_tool("<tool>")`
  (`tests/suite_policy.py`) for an external tool: it returns the tool's path or skips with
  "<tool> is not installed", and fails instead where `HNX_REQUIRE_TOOLS=<tool>,...` (or the older
  `HNX_REQUIRE_GO=1`, for `go`) says the tool must be there; CI sets it where it installs tools.
  A genuinely new legitimate cause is a reviewed one-line addition to `skip_reasons`.
- **Quarantine, not deletion, for a flaky test:**
  `@pytest.mark.quarantine(owner="<team-or-handle>", until="YYYY-MM-DD", reason="<what is flaky>")`.
  The test still runs but cannot break the build; all three fields are required, the date may be at
  most 90 days ahead, and on expiry the test fails until it is fixed or the quarantine is renewed.
- **Go tests** follow the same rules through `tools/go_test_policy.py`, which CI's go job runs on
  every Go module's `go test -json` stream: the same `skip_reasons`, quarantines and privileged
  (root-only) tests listed in the module's `skips.yml` with the same fields and 90-day limit. A
  skip states its reason in the call, on one line: `t.Skip("docker not available")`, never
  `t.SkipNow()`, `t.Skipf(...)` or a message built elsewhere, in a test or in a helper
  (`--check-sources` reads every `.go` file of the module, `testdata/` and `_*` directories
  included since a test can import a package there, and rejects those, because the stream
  shows only the last line before `--- SKIP`). A package whose test files declare a `Test` or
  `Fuzz` function, or an `Example` with an `// Output:` comment, must report at least one test in
  the run (`--expect-tests`), so a `TestMain` that exits before `m.Run` fails; test files with
  only benchmarks, helpers or examples without output run nothing and need not (an output-less
  example still satisfies `component_tests`). One limit of the stream: a parent test that fails
  silently (`t.Fail()`) next to a quarantined subtest is tolerated with it, so fail with a message.
- **Time budgets.** Each suite (a test file's first two directories, e.g. `tests/lake`) has a budget
  (`suite_budget_default`, `suite_budgets`); a suite over it fails the run. `pytest --suite-times`
  prints the table; `HNX_SUITE_BUDGET_SCALE=3` scales every budget on a slow machine.
- **Shards.** CI runs the suite as six jobs per Python version: `pytest --shard I/6
  --shard-report FILE` runs the tests whose node id hashes to the I-th sixth and writes what it
  collected, ran and timed. Each shard holds the budgets on its own share of each suite; the `test-ok` job
  (`python -m tests.shard_report --groups 3.11,3.12 DIR`) fails unless every shard passed, together
  they ran each collected test exactly once, and each suite's time summed over the shards is
  within its budget. A module- or session-scoped fixture runs, and is timed, once per shard that
  uses it, so the summed time can exceed a whole run's. Branch protection requires `test-ok`, the
  one stable check name. Locally, `make test` still runs the suite whole.

## Bug fixes carry a regression test

A bug fix is a commit whose subject is a conventional-commit fix (`fix: ...`, `fix(scope): ...`) or
whose message has a `Fixes: <issue or description>` trailer. Use one of them for every fix, and in
the same commit add or change a test that **fails without the fix and passes with it** (write the
test first and watch it fail). CI's `regression-tests` job (`tools/fix_has_test.py --prove`) checks
both halves for every commit of a pull request: a fix must touch a test file, and its test modules,
run on the fix's parent commit, must have at least one failing test. One rule covers Python and Go:
a test that fails on the parent only because it does not build, collect or import counts as failing
only if every such error names a symbol (or module, or Go package) that the fix's own diff adds;
any other build, collection or import error, and any error that is not a failing test, means the
fix cannot be proven. A fix whose only test files are fixtures, `conftest.py` or other non-test
files (outside a Go package's `testdata/`) cannot be proven either. All of these are reported,
never passed. `make fix-check` runs the first half locally
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
