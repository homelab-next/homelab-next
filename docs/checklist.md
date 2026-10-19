<!-- SPDX-License-Identifier: Apache-2.0 -->
# Checklist: what "complete" looks like

Every row is a property that must be **continuously true**, with an observable that someone who has never seen the platform can run.

- **PUBLIC-NOW**: decidable on a laptop or in CI with fakes, fixtures and goldens. These are the rows the invariants runner (`python3 -m homelabnext.invariants run`) can execute from this repository.
- **SERVER**: needs the running platform (hypervisors, network, real products). The row is documented; the interface and a fake exist where the plan calls for one; nothing here pretends to test it.

Criteria register in `invariants.yml` using the same shape as these rows (statement, observable, expected, remediation). Exit codes: 0 pass, 1 fail, >= 100 could not measure.
Pillar X rows are implemented as runner plugins (`evidence: plugin`); X-02, X-07 and X-08 always report `skip` with a `SERVER:` reason.

## F - Foundation

Platform-wide properties. Most need a running platform; the repository-level ones run in CI today.

| ID | Must be true | Observable / pass criterion | Tag |
|---|---|---|---|
| F-01 | The platform is rebuildable from git | IaC plan against the live environment shows no changes; a from-scratch deploy on a spare host succeeds | SERVER |
| F-02 | Network segments are enforced | From a monitored-system segment, connections to management and AI-worker segments are refused; only listed flows succeed (reachability matrix) | SERVER |
| F-03 | People authenticate with SSO and MFA | Every web UI redirects an unauthenticated request to SSO or demands its own MFA; 0 anonymous UIs | SERVER |
| F-04 | Every service and agent has its own identity | Credential inventory: no credential shared by two consumers; no service or agent holds admin rights | SERVER |
| F-05 | Secrets are not in git or readable on disk | Secret scan over full history reports 0 unaccepted findings; 0 secret files readable by other | PUBLIC-NOW |
| F-06 | Credentials are short-lived and rotated | Every inventoried secret is within its rotate-by date | SERVER |
| F-07 | Internal TLS is verified | 0 clients with certificate verification disabled (lint over client config; RL013 for roles); endpoints present certificates from the internal CA | PUBLIC-NOW |
| F-08 | The main branch is protected by CI | Branch protection requires passing checks; CI runs tests, lint, secret scan on every change | PUBLIC-NOW |
| F-09 | Backups follow 3-2-1 with an immutable copy | Newest backup < 24 h; offsite or immutable copy < 7 days; a delete attempt with the automation identity fails | SERVER |
| F-10 | Restores are proven | A full-system restore drill was completed <= 90 days ago and verified | SERVER |
| F-11 | The monitoring is itself monitored | Stopping the alerting service raises an external dead-man alert within 15 minutes | SERVER |
| F-12 | Changes go through staging first | Every production deploy in 30 days has a green staging run of the same version | SERVER |
| F-13 | Break-glass access works | Each break-glass procedure was exercised <= 180 days ago | SERVER |
| F-14 | Recovery targets are defined and met | Every service records an RTO and RPO; the last drill met them | SERVER |
| F-15 | Changes are versioned and visible | Components are released as tagged versions with changelogs; every deploy emits a what-changed event | PUBLIC-NOW |
| F-16 | The fleet runs without the admin workstation | With the workstation off for 24 h, all canaries pass and 0 jobs fail because of it | SERVER |
| F-17 | Nothing at runtime points at the workstation | 0 runtime configs reference the admin workstation (runs as part of X-01) | PUBLIC-NOW |
| F-18 | The public tree contains no private identifiers | `tools/leak_scan.py` over the tree exits 0 (no private IPs, domains, emails, MACs, keys) | PUBLIC-NOW |

## C - Collection

Every asset sends logs; the sensors see what they should.

| ID | Must be true | Observable / pass criterion | Tag |
|---|---|---|---|
| C-01 | Every asset is inventoried | Network discovery finds 0 active addresses missing from the inventory | SERVER |
| C-02 | Every inventoried asset is logging | Each asset reported within its expected cadence (default 1 h); a silent source alerts | SERVER |
| C-03 | Endpoint telemetry is complete | Every server and workstation runs the endpoint agent and OS audit logging, both reporting | SERVER |
| C-04 | Network devices send logs | Every router, switch, firewall and AP is a log source within 24 h | SERVER |
| C-05 | The network sensor sees mirrored traffic | IDS alerts and connection logs from the mirror port < 15 min old; packet-drop rate < 1% | SERVER |
| C-06 | Cloud and application logs are collected | Every cloud account audit log and tier-1 application log is present within 24 h | SERVER |
| C-07 | Collection survives outages | After a 30-minute collector outage, 0 events are lost (buffer drains) | SERVER |

## T - Transport and processing

Events move through one bus, in one schema, with nothing silently dropped.

| ID | Must be true | Observable / pass criterion | Tag |
|---|---|---|---|
| T-01 | All events flow through the event bus | Every source appears on its subject; consumer lag < 5 min | SERVER |
| T-02 | Events validate against the schema | Fixture events validate against the event schema in CI; >= 99.5% of live events validate, the rest reach the dead-letter queue | PUBLIC-NOW |
| T-03 | Nothing is silently dropped | Dead-letter depth is alerted on; 0 unreviewed items older than 7 days | SERVER |
| T-04 | Events are enriched | Enrichment fixture adds asset owner and criticality; >= 95% of live events carry them | PUBLIC-NOW |
| T-05 | Flows have provenance | Every flow definition is in git; provenance shows source, time, transform per record | SERVER |
| T-06 | End-to-end latency is bounded | p95 event creation to searchable < 2 min | SERVER |
| T-07 | Event envelopes are contract-tested | Publisher and consumer tests pass against the envelope schema for every event type | PUBLIC-NOW |

## S - Storage and query

The lake is authenticated, write-once where it matters, and queryable.

| ID | Must be true | Observable / pass criterion | Tag |
|---|---|---|---|
| S-01 | Recent data is searchable | Hot index answers a 24-hour query across all sources in < 10 s | SERVER |
| S-02 | The lake requires authentication | Anonymous query is refused; analyst and AI roles read but cannot write or delete | SERVER |
| S-03 | Evidence is write-once | Overwriting or deleting stored evidence with a non-admin credential fails; versioning or lock is on | SERVER |
| S-04 | Retention is enforced as documented | Oldest data per tier matches its policy within 1 day | SERVER |
| S-05 | Lake writers are scoped | Production catalog; each writer has its own table-scoped credential; 0 shared storage keys | SERVER |
| S-06 | Replaying a batch creates no duplicates | Crash between commit and checkpoint, then replay: 0 duplicate rows (fake catalog test) | PUBLIC-NOW |
| S-07 | Query results are engine-independent | The fixed query set returns identical result hashes on two engines (fake vs recorded cassette) | PUBLIC-NOW |

## D - Detection as code

Rules live in git and are proven by fixtures.

| ID | Must be true | Observable / pass criterion | Tag |
|---|---|---|---|
| D-01 | Every rule is in git | Deployed rules match the repo by hash | SERVER |
| D-02 | Every rule is tested | Each rule has must-fire and must-not-fire fixtures that pass in CI (fixture runner against a fake engine) | PUBLIC-NOW |
| D-03 | Rule deploys are safe | A deliberately broken rule is rejected or rolled back with the engine left healthy | SERVER |
| D-04 | Coverage counts only tested rules | Coverage report derived from passing fixtures only (golden report) | PUBLIC-NOW |
| D-05 | Alert volume is manageable | Alerts reaching a human < 100/day on a 7-day average; every suppression has owner and expiry | SERVER |
| D-06 | Evasion variants are reported | Fixture runner reports evasion fixtures that slip through, without failing the rule | PUBLIC-NOW |
| D-07 | Rules compile for every supported engine | Sigma to generic backend compile goldens match | PUBLIC-NOW |

## O - Outputs

Cases, status, notifications and reports reach people.

| ID | Must be true | Observable / pass criterion | Tag |
|---|---|---|---|
| O-01 | High-severity alerts become cases | Every high or critical alert has a case or documented auto-close within 15 min | SERVER |
| O-02 | The status grid reflects reality | Stopping a monitored service turns its tile red within 5 min | SERVER |
| O-03 | Notifications are authenticated | Anonymous publish to an alert channel is refused | SERVER |
| O-04 | Scheduled reports are produced | Daily and weekly reports exist for the last 7 days / 4 weeks | SERVER |
| O-05 | The ops console shows exceptions only | With every source healthy, the console shows only the green count, live work and attention items | SERVER |
| O-06 | A dead adapter reads as stale | Stopping an adapter marks its module stale within its SLA | SERVER |
| O-07 | A hung source cannot stall the console | With one source blackholed, the view renders in < 2 s with that module stale | SERVER |
| O-08 | Notifications are state-diffed | Same state twice sends once; recovery sends one message (fake sender test) | PUBLIC-NOW |

## P - Control plane

Action broker, approvals, operator-away mode.

| ID | Must be true | Observable / pass criterion | Tag |
|---|---|---|---|
| P-01 | Every state change goes through the broker | No agent or workflow identity can change a system directly; every change has an action id | SERVER |
| P-02 | Default deny | A caller with no manifest entry for an intent is denied; manifests live in git (table test) | PUBLIC-NOW |
| P-03 | Approvals are bound and attributable | Approval record has approver identity and request digest; a request altered after approval is refused (test) | PUBLIC-NOW |
| P-04 | The broker audit is complete and fresh | Audit table <= 15 min stale; request count equals audit rows daily | SERVER |
| P-05 | Operator-away mode works | Drill: switch on forces live intents to shadow within 1 min; daily summary arrives | SERVER |
| P-06 | Broker decisions reach the SIEM | Allow, deny and needs-approval all appear in the SIEM within 5 min | SERVER |
| P-07 | Broker isolation holds | One caller cannot read or cancel another's request (`access_cases` table test; broker conformance checks `requests-bound-to-caller`, `foreign-request-access-audited`) | PUBLIC-NOW |

## R - Orchestration

Workflows are code, event-driven, bounded.

| ID | Must be true | Observable / pass criterion | Tag |
|---|---|---|---|
| R-01 | Workflows are code | Every pack is in git, validated offline in CI, deployed only from passing commits | PUBLIC-NOW |
| R-02 | Reaction is event-driven | A test event triggers its workflow within 60 s; no polling where an event exists | SERVER |
| R-03 | Deterministic steps come first | Every workflow calling a model first runs deterministic enrichment (offline validator) | PUBLIC-NOW |
| R-04 | Risky actions need bound approval | Risky action without approval of its payload hash does not run (test) | PUBLIC-NOW |
| R-05 | Actions use scoped service accounts | Off-list command as an action account fails | SERVER |
| R-06 | Every run is recorded | Executions with inputs, outputs, approver, result retained >= 1 year | SERVER |
| R-07 | Workflow fixtures round-trip | Fixture events produce the expected action calls in the offline validator | PUBLIC-NOW |

## Q - Quality gates

Caught before deploy.

| ID | Must be true | Observable / pass criterion | Tag |
|---|---|---|---|
| Q-01 | Every repo's tests run on every change | CI runs unit and contract tests on push and merge request; main is green | PUBLIC-NOW |
| Q-02 | Test suites are trustworthy | Each suite within its time budget; 0 silent skips; quarantined tests have owner and unexpired date | PUBLIC-NOW |
| Q-03 | Live-dependent tests are marked | Tests needing real systems carry the `live` marker and CI skips them; an unmarked test that reaches a non-loopback address fails (`tests/network_guard.py`) | PUBLIC-NOW |
| Q-04 | Every component ships tests | CI fails a component directory with no tests (`tools/component_tests.py`, reviewed allowlist) | PUBLIC-NOW |
| Q-05 | Every seam has a contract test | Each event type and shared table has a schema plus publisher and consumer tests | PUBLIC-NOW |
| Q-06 | Security tests run in CI | Secret scan, dependency audit and lint pass | PUBLIC-NOW |
| Q-07 | Security-critical code is well covered | Broker, guard, approval and decision code >= 80% line coverage per unit (`make coverage`, `tools/coverage_floor.py`) | PUBLIC-NOW |
| Q-08 | Fixed bugs stay fixed | Every bugfix in 90 days has a regression test that fails without the fix | PUBLIC-NOW |
| Q-09 | Every source file carries an SPDX header | Grep over tracked source files finds 0 without the header | PUBLIC-NOW |
| Q-10 | Every schema ships an example and a negative | Schema check passes (X-03 covers pinning and validity) | PUBLIC-NOW |
| Q-11 | Tests are hermetic | No test uses the network, wall clock, or unseeded randomness (clock and sender injected); network enforced by the test guard, direct clock and randomness calls in tests by `tools/hermetic_lint.py`; library code that falls back to the real clock is not yet detected | PUBLIC-NOW |

## M - Scripts, context and access

Catalogued scripts, controlled agent context, one map of access.

| ID | Must be true | Observable / pass criterion | Tag |
|---|---|---|---|
| M-01 | Every script is catalogued | Each script has a valid header; generated catalog is current | PUBLIC-NOW |
| M-02 | The catalog matches reality | 0 scheduled-but-uncatalogued scripts, 0 uncalled active scripts, 0 duplicate ids | PUBLIC-NOW |
| M-03 | Helpers are shared, not copied | 0 private notify/state/lake-query helpers outside the shared libraries (allowlist with reason) | PUBLIC-NOW |
| M-04 | Checks run in one place | Every check script runs through the invariants runner; no standalone check timers | PUBLIC-NOW |
| M-05 | Every agent job gets its context pack | Job log records pack hash and contents built from the charter manifest | SERVER |
| M-06 | No agent runs blind | A job with a missing or stale pre-gate is deferred with a reason | PUBLIC-NOW |
| M-07 | Agents prove they used the pack | Result citing no must_cite pre-gate is rejected (test) | PUBLIC-NOW |
| M-08 | Packs fit and are never silently cut | Assembler reports tier used; 0 silent truncations (test) | PUBLIC-NOW |
| M-09 | Agent memory is controlled | Writes only through validated memory updates; cross-agent read refused (test) | PUBLIC-NOW |
| M-10 | The context store is dependable | Authenticated, backed up, restore-tested; outage falls back to flagged cache | SERVER |
| M-11 | One map of access | Every principal is in the keyring with grants by level and denials | SERVER |
| M-12 | The keyring comes from the sources | 0 drift between generated keyring and its sources | PUBLIC-NOW |
| M-13 | Access is proven, not assumed | Each grant and denial has a probe as the principal at least daily; a passing denial pages | SERVER |
| M-14 | Every agent starts knowing its access | Session start injects the access block for where it runs | PUBLIC-NOW |
| M-15 | The keyring is protected | Served only behind SSO; a new privileged grant is flagged | SERVER |
| M-16 | No placeholder ids survive a commit | `grep -rn -- '-NEW' registers/` finds 0 after the commit hook runs | PUBLIC-NOW |
| M-17 | Register ids are never lost | `tools/register_ids.py check-lost` exits 0 for every register | PUBLIC-NOW |

## A - AI layer

Tiered: screen, fast model, heavy model.

| ID | Must be true | Observable / pass criterion | Tag |
|---|---|---|---|
| A-01 | The pre-AI screener handles every item first | 100% of AI-bound items show a routing decision in the log | SERVER |
| A-02 | The screener reduces volume | at least 70% closed or deduplicated before any LLM call; false-negative rate < 1% on the evaluation set | SERVER |
| A-03 | The screener redacts sensitive data | 0 secrets or PII tokens reach a model prompt on the evaluation set | PUBLIC-NOW |
| A-04 | The fast model returns validated output | 100% schema-validated; invalid output retried once then escalated | PUBLIC-NOW |
| A-05 | Low confidence escalates | Below-threshold items reach the heavy model or a human; none auto-actioned | PUBLIC-NOW |
| A-06 | The heavy model is reserved for hard cases | <= 10% of routed items reach the heavy tier; cost within budget | SERVER |
| A-07 | The AI agrees with analysts | Agreement >= 90% on a rolling 30-day sample | SERVER |

## G - AI safety guardrails

Untrusted content cannot drive actions.

| ID | Must be true | Observable / pass criterion | Tag |
|---|---|---|---|
| G-01 | Untrusted content is delimited | Every prompt template wraps ingested content in untrusted-data delimiters (template lint) | PUBLIC-NOW |
| G-02 | Prompt-injection defences are tested | Injection corpus passes with 0 instruction-follows before each model or prompt change | PUBLIC-NOW |
| G-03 | Readers cannot act | Agents that read raw content hold no shell, file-write or egress tool (profile lint and refusal test) | PUBLIC-NOW |
| G-04 | Actors act only through allowlisted actions | Actors receive validated structured input; actions pass the allowlist | PUBLIC-NOW |
| G-05 | Agents are never admin | No agent identity can use sudo or read admin credentials | SERVER |
| G-06 | Agent egress is allowlisted | A connection to a non-allowlisted destination is refused | SERVER |
| G-07 | Kernel enforcement is active | Runtime policy loaded on every AI host; a write outside allowed paths is blocked and reported | SERVER |
| G-08 | The policy layer is in path | 100% of tool calls pass the guardrail layer; a call with a secret is redacted or blocked | SERVER |
| G-09 | Every AI action is auditable | Model and tool calls logged off-host tamper-evidently | SERVER |
| G-10 | Rate and cost limits hold | Exceeding a limit throttles and alerts (test) | PUBLIC-NOW |
| G-11 | Model versions are pinned | Each model is pinned by version and hash; changes pass CI evaluation | PUBLIC-NOW |

## K - Fast classifiers and decision specs

Decision specs run through one gate with a cascade and a replay gate.

| ID | Must be true | Observable / pass criterion | Tag |
|---|---|---|---|
| K-01 | The decision service is healthy and fast | Health probe passes; inline specs p95 <= 1 s, async <= 10 s | SERVER |
| K-02 | Every decision spec is complete and in git | Spec lint passes: question set, decision table, tiers, error direction, on_error, latency budget, audit sample (`hnx decide lint` over every spec in git) | PUBLIC-NOW |
| K-03 | Questions are well-formed | Spec lint: single-axis questions; pairwise questions asked in both orders; <= 5 labels (`hnx decide lint`) | PUBLIC-NOW |
| K-04 | Inline callers use only fast specs | Spec lint: specs declaring `callers: [inline]` use only fast tiers within the inline latency budget (`hnx decide lint`) | PUBLIC-NOW |
| K-05 | Every decision is logged | 100% of calls produce a cascade-event row with spec, version, answers, tier, latency, caller | SERVER |
| K-06 | Failure means escalate | Fault injection (down, timeout, malformed, abstain) returns escalate for every spec; 0 auto-closes | PUBLIC-NOW |
| K-07 | Safety gates only add caution | 0 safety-gate decisions lowered a tier or granted anything (property test) | PUBLIC-NOW |
| K-08 | Noise gates de-escalate only with corroboration | Each de-escalation carries a deterministic corroboration reference (test) | PUBLIC-NOW |
| K-09 | Noise gates are audited | Weekly sample reviewed within 7 days; miss rate <= spec limit | SERVER |
| K-10 | Specs go live only on evidence | Recorded shadow period and precision on time-split held-out data | SERVER |
| K-11 | Drift is caught | Per-spec precision, escalation rate, tier share published; abstain-rate band alert | SERVER |
| K-12 | Changes pass a replay gate | Model or threshold change replayed against the decision set; report stored (golden report) | PUBLIC-NOW |
| K-13 | Classifiers never delete data at ingest | Records in equal records out; results only as annotation columns | PUBLIC-NOW |
| K-14 | The serving config is what we think it is | Health check reads actual loaded context length and model id and alerts on mismatch (fake server) | PUBLIC-NOW |
| K-15 | Required safety specs are live | Sensitive-content, hostile-content, purpose-consistency and disclosure-risk specs pass their cases | PUBLIC-NOW |

## E - End-to-end flows

Canaries traced across whole paths.

| ID | Must be true | Observable / pass criterion | Tag |
|---|---|---|---|
| E-01 | Alert to case | Daily canary traverses sensor to closed case; end to end <= 5 min | SERVER |
| E-02 | Containment approval path | Monthly drill: canary request reaches needs_approval with digest; altered request refused | SERVER |
| E-03 | Threat intel to detection | Canary indicator reaches a retro-hunt and an alert within 1 h | SERVER |
| E-04 | Exposure to verified fix | Per patch window: canary finding closes on the next scan | SERVER |
| E-05 | Self-healing is bounded | Allowlisted canary service restarts within 5 min; others page | SERVER |
| E-06 | Agent task lifecycle | Canary task dispatched, runs, proposal validated within 2 min | SERVER |
| E-07 | Change delivery | Failing-test canary commit is not deployed; drift deployed = git within 1 h | SERVER |
| E-08 | Learning loop | Verdicts in calibration set; every incident has a lesson within 7 days | SERVER |
| E-09 | Outputs reach the operator | Each canary on the status grid within 5 min | SERVER |
| E-10 | Silence is loud | Pausing a canary stage raises a silence alert within its window | SERVER |
| E-11 | Items are traceable | One id returns the complete chain for each canary in 7 days | SERVER |
| E-12 | Migration from the previous stack is complete | Retired components disabled and removed; 0 references remain | SERVER |

## L - Feedback and assurance

The checks themselves.

| ID | Must be true | Observable / pass criterion | Tag |
|---|---|---|---|
| L-01 | Analyst verdicts feed back | Verdicts from 30 days applied to thresholds and tuning | SERVER |
| L-02 | Metrics are tracked | MTTD, MTTR, false-positive rate, AI agreement trended over 90 days | SERVER |
| L-03 | Continuous checks page once | The runner pages a newly red criterion once and never the standing set (fake sender test) | PUBLIC-NOW |
| L-04 | Detections are validated by emulation | Purple-team run <= 90 days ago; every step maps to a firing rule or ticket | SERVER |
| L-05 | Documentation matches reality | Docs regenerated from or checked against the live inventory; 0 drift | PUBLIC-NOW |
| L-06 | Every lesson has a root cause, control and verification | `python3 -m homelabnext.registers build` exits 0 (fatal schema) | PUBLIC-NOW |
| L-07 | Every runbook step has a verify | Same build exits 0 | PUBLIC-NOW |
| L-08 | Invariant exits are unambiguous | Runner returns 0 pass, 1 fail, >= 100 could-not-measure (unit tests) | PUBLIC-NOW |

## X - Modularity

Swap anything behind a contract. Checked by plugins in `homelabnext/invariants/plugins/pillar_x.py`.

| ID | Must be true | Observable / pass criterion | Tag |
|---|---|---|---|
| X-01 | No raw endpoints outside the registry | `tools/no_raw_endpoints.py` exits 0 over the tree (plugin skips when the tool is absent) | PUBLIC-NOW |
| X-02 | Registry rows match live listeners | Every registry row has health, metrics, backup, auth mode, and every live listener has a row | SERVER |
| X-03 | Schemas version-pinned, examples valid | Each schema has $schema, $id, a version; examples validate; negatives are rejected | PUBLIC-NOW |
| X-04 | Every capability has a conformance test | Each capability has a `conformance/<cap>/test_*.py` | PUBLIC-NOW |
| X-05 | Role linter clean | `tools/role_lint.py ansible/roles` exits 0 (a directory of roles is expanded), including RL011-RL014: `no_log` on secret use, no `shell` or templated free-form `command`, no `validate_certs: false`, no privileged container or docker socket | PUBLIC-NOW |
| X-06 | Detection ids are logical | No raw rule number in charters, profiles, decisions or schedules; every `det:` id resolves in `det_map.yml` | PUBLIC-NOW |
| X-07 | Export hooks are exercised | Every stateful product's export restored once in a drill | SERVER |
| X-08 | Cutover commits are audited | Each cutover has a swap record with parity, rollback and flip commits | SERVER |
| X-09 | Customizations are owned and not expired | Every customization has reason, owner and `review_by`, none is past its date, none conflicts (`hnx custom check`; plugin `homelabnext.customization.plugins.x09_customizations`, loaded through the `homelabnext.invariants.checks` entry point) | PUBLIC-NOW |
| X-10 | Every capability has a conformance test that passes and could fail | `hnx conform report --json` lists no `capabilities_without_passing_test`: each suite ran enough checks, no MUST check failed, every deliberately broken fake was caught (X-04 only asks that a test file exists; plugin `homelabnext.conform.plugins.x10_conformance`, same entry-point group; `HNX_CONFORM_TARGET` aims it at a real deployment) | PUBLIC-NOW |

---

**Totals:** 159 criteria across 16 pillars; 77 PUBLIC-NOW, 82 SERVER.
