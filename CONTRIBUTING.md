# Contributing to HomelabNext

Thanks for helping. The project is contract-first: a change is welcome when a stranger can run its
tests on a laptop with no network and no private context.

## Ground rules

1. **Sign off every commit** (Developer Certificate of Origin): `git commit -s`. The sign-off
   certifies you may submit the work under Apache-2.0.
2. **Every schema change ships an example and a negative** (an input that must be rejected).
   Evolution is additive within a major version (ADR-0001).
3. **Every library ships a fake**, and the fake passes the conformance test for its capability.
4. **No raw endpoints.** Addresses come from the registry; an unset endpoint raises, it never
   defaults (ADR-0002). `tools/no_raw_endpoints.py` gates this.
5. **No real identifiers, ever.** Use `example.internal`, `192.0.2.0/24`, `198.51.100.0/24`,
   `203.0.113.0/24`, `2001:db8::/32`, MACs `00:00:5e:00:53:xx`, account id `123456789012`, and role
   names such as `hv-01`. This covers code, tests, fixtures, docs, commit messages and branch names.
6. **Ids are allocated, not chosen.** In register entries write `XX-NEW` and let the tooling assign
   the number; never renumber an existing entry.
7. **A contract change needs an ADR** (copy `docs/adr/_template.md`; one file, five headings).
8. Python >= 3.11, standard library first. New dependencies go in an extra in `pyproject.toml`,
   must be permissively licensed (LGPL only as an unmodified dependency), and are justified in the PR.
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

`make leak-scan` runs `tools/leak_scan.py`: generic shapes only (private and CGNAT addresses, MACs,
non-documentation e-mail, private TLDs, hypervisor-style names, workstation paths, secret-variable
names, cloud keys, PEM blocks, tokens, high-entropy strings). Maintainers additionally point
`HNX_DENYLIST` at a private file of terms that must never be published; the scanner never prints
those terms. A reviewed false positive is suppressed on its own line with
`scrub-allow: <reason>`; CI prints every suppression.

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
