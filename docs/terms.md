<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- generated from homelabnext/agent/terms.md by `hnx agent terms --write`; edit that file, not this page -->

# Terms and scope

What this project's words mean, so that every agent and every reader understands the work and its
goals the same way. Every agent session's context pack carries this text as its stable `terms`
section; `docs/terms.md` is generated from it.

## Scope

All security work in this project is done by the operator, in the operator's own lab, with the
operator's authorization. Nothing in it targets, scans or probes systems the operator does not own
or run.

## Our activity

- **Auditing**: examining our own work and controls for what is wrong, missing or unproven, and
  recording the evidence.
- **Audit review** (review role `audit`): an independent agent audit that looks for what is wrong,
  missing or unproven. It comes from a different agent than every `check` review. The other roles:
  `check` (an agent confirms the work is correct and complete) and `approve` (a human signs off).
  The deprecated name of `audit` is `challenge`; a file that still says it is read as `audit`.
- **Auditing tool**: a tool the project creates to test its own controls: hostile inputs,
  deliberately broken fakes, prompt-injection evaluations, detection tests.
- **Internal assessment, validation, engagement**: an exercise run against the operator's own lab,
  authorized by the operator, to confirm that a control works.
- **Authorized scope**: the operator's own lab (the hosts, services and accounts the operator owns
  or runs) and nothing else.

## How we use threat vocabulary

Attacker, adversary, threat actor, exploited and ATT&CK technique names describe external threats
only: threat models, detection rules, intelligence about others (CTI extraction, requirements about
the environment or an adversary) and the untrusted text an injection corpus quotes. They never
describe our own activity; for that, say auditing, internal assessment, validation or engagement.
