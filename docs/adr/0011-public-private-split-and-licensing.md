---
summary: Public repo is greenfield with fictional example data and a three-layer leak defence; real inventory, detections and credentials stay private.
summary_of: outline:sha256:bf87496b641e22c5
---
# ADR-0011: What is public, what stays private, and the licence rule

- **Status:** proposed
- **Date:** 2026-10-15
- **Related:** `CONTRIBUTING.md`, `SECURITY.md`, `NOTICE`, `tools/leak_scan.py`; extended by
  ADR-0021 (the private overlay, credentials and deploys)
- **Amended (2026-11-01):** decision 4 refused every copyleft "dependency" without saying what
  counts as one, while the repository declares ansible-core (GPL-3.0) as an extra and its lab
  stack runs AGPL-3.0 images; and CI's licence check left out SSPL. Decision 4 now separates code
  the project links or vendors (refused) from tools it invokes and services it deploys (allowed,
  recorded), and `tools/tests/test_licence_policy.py` holds CI's deny list to it. And 2026-11-07 by
  ADR-0026: decision 1 lets generic code the operator owns come in from the private repository,
  fresh and without its history (see the amendment after Decision). And 2026-11-07 by ADR-0046
  (decision 8): decision 3's third layer, the deny-list scan, also runs on GitHub's copy after
  every push, in the overlay's private CI with the list sealed; the pre-push check stays.
- **Amended-by:** ADR-0026, ADR-0046

## Context

The project is developed from experience running a private lab, but a public repository must
carry contracts, libraries, fakes and tests, never the lab itself. Two risks follow: leaking
identifying or security-relevant material, and ambiguity about licence and third-party content.

## Decision

1. The public repository is greenfield: files are written fresh from generalised designs, never
   copied from private sources, and its history starts empty. Private history never touches the
   public remote.
2. Public: schemas, libraries, generators, fakes, conformance tests, example data (a complete
   fictional lab using `example.internal` and RFC 5737/3849/7042 documentation values), ADRs and
   docs. Private: real inventory, detection content that is the lab's playbook, tuned thresholds,
   credentials and their locations, internal assessment (auditing tool) and deception (honeypot) material,
   personal and employer context.
3. Leaks are prevented three times: a pre-commit hook and public CI run the generic scanner
   (`tools/leak_scan.py`) and a secret scanner; a private pre-push check on the maintainer's
   machine runs a real deny-list supplied only at run time (`HNX_DENYLIST`) and never published.
4. Licence: Apache-2.0, with an SPDX header on every source file and DCO sign-off on commits.
   - **Linked or vendored code** (a Python package `homelabnext/` imports, in its core or an
     extra, and any file copied into the tree) with a copyleft licence (GPL, AGPL, SSPL) is
     refused; LGPL is allowed as an unmodified dependency only. CI's dependency review denies
     each of those licence families.
   - **Separately invoked tools and deployed services** may be copyleft: a program run as its own
     process (the `ansible` extra installs ansible-core, GPL-3.0, which `homelabnext/` never
     imports; the test suite and deploys run `ansible-playbook`), and a service or container
     image a role, compose file or provider module deploys (the lab-in-a-box object store is
     AGPL-3.0). Nothing of theirs is shipped in this repository. Each such tool is named in
     `NOTICE` and is the one listed exception in CI's dependency review; an open-source
     provider module records its product's licence in `licence.spdx` (module schema).
   - The Ansible plugins under `ansible/plugins/` subclass ansible-core classes and run only
     inside it. They are Apache-2.0 source, which GPL-3.0 can combine with; ansible-core is not
     distributed with them.

   Third-party content (OCSF subset, ATT&CK attribution, rule licences) is recorded in `NOTICE`.
   The maintainers hold copyright in the original private material and re-author it under
   Apache-2.0.

### Amendment (2026-11-07, ADR-0026): operator-owned generic code may come in fresh

Decision 1 said files are never copied from private sources. ADR-0026 moves the operator's own
orchestrator into this repository, so decision 1 now reads: files are written fresh, **or** they are
generic code the operator owns brought in from a private repository **as new files, in a new
commit, without its history**, each reviewed file by file and rewritten for this repository, and
passing the gates of ADR-0026 decision 4 (the leak scan on the tree, on every added line and on
every author; the raw-endpoint gate; the product-name lint; `tools/private_leak_check.py public`;
and the operator's own deny-list before the branch is pushed). Lab data never comes in this way: it
goes to the private overlay (ADR-0021). The rest of decision 1 stands: the public history starts
empty, and private history never touches the public remote. The alternative below, a scrubbed
export of the private repository, stays rejected, because what it would carry is the history and
the rename trail, and neither is carried.

## Consequences

- Contributors get a repository that runs on a laptop with no private context.
- Every contribution passes a scanner that knows shapes, not secrets; humans still review new
  top-level directories once.

## Alternatives

Publish a scrubbed export of the private repository: history and context leak through diffs and
renames. Keep everything private: forfeits review and reuse.
