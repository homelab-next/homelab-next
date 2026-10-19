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
   Evolution is additive within a major version (ADR-0001).
3. **Every library ships a fake**, and the fake passes the conformance test for its capability.
4. **No raw endpoints.** Addresses come from the registry; an unset endpoint raises, it never
   defaults (ADR-0002). `tools/no_raw_endpoints.py` gates this.
5. **No real identifiers, ever.** Use `example.internal`, `192.0.2.0/24`, `198.51.100.0/24`,
   `203.0.113.0/24`, `2001:db8::/32`, MACs `00:00:5e:00:53:xx`, account id `123456789012`, and role
   names such as `hv-01`. This covers code, tests, fixtures, docs, commit messages and branch names.
6. **Ids are allocated, not chosen.** In register entries write `XX-NEW` (`LL-NEW`, `RB-NEW`, ...)
   and commit it as is; never renumber an existing entry. A maintainer allocates the numbers once,
   at merge time, on the target branch (`make ids-resolve`), so two pull requests never claim the
   same id. CI checks that no id of the base branch vanished and that no allocated id repeats.
   An id that was wrong is retired, not deleted: move it to the register's top-level `retired:`
   block with a `reason:` (and `replaced_by:`), a tombstone that keeps it accounted for and
   unreusable (see `homelabnext/registers/ids.py`; `examples/registers/invariants.yml` has three).
7. **A contract change needs an ADR** (copy `docs/adr/_template.md`; one file, five headings).
8. Python >= 3.11, standard library first. New dependencies go in an extra in `pyproject.toml`,
   must be permissively licensed (LGPL only as an unmodified dependency), and are justified in the PR.
   CI installs every package from the hash-pinned `constraints/ci.txt`; regenerate it with
   `make constraints` (needs `uv`) in the same PR.
9. Tests do not use the network, wall-clock time or unseeded randomness. Anything needing a real
   server is marked `@pytest.mark.live` and never runs in default CI.
10. Every source file starts with `# SPDX-License-Identifier: Apache-2.0` (or the equivalent comment).

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
