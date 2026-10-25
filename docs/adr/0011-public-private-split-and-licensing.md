---
summary: Public repo is greenfield with fictional example data and a three-layer leak defence; real inventory, detections and credentials stay private.
---
# ADR-0011: What is public, what stays private, and the licence rule

- **Status:** proposed
- **Date:** 2026-10-15
- **Related:** `CONTRIBUTING.md`, `SECURITY.md`, `NOTICE`, `tools/leak_scan.py`; extended by
  ADR-0021 (the private overlay, credentials and deploys)

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
   Dependencies with copyleft licences (GPL, AGPL, SSPL) are refused; LGPL is allowed as an
   unmodified dependency only. Third-party content (OCSF subset, ATT&CK attribution, rule
   licences) is recorded in `NOTICE`. The maintainers hold copyright in the original private
   material and re-author it under Apache-2.0.

## Consequences

- Contributors get a repository that runs on a laptop with no private context.
- Every contribution passes a scanner that knows shapes, not secrets; humans still review new
  top-level directories once.

## Alternatives

Publish a scrubbed export of the private repository: history and context leak through diffs and
renames. Keep everything private: forfeits review and reuse.
