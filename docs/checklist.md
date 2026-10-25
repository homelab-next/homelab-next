---
summary: 'The completeness checklist: continuously true properties with runnable observables, in sixteen groups (F to X), each row PUBLIC-NOW or SERVER.'
summary_of: outline:sha256:39d76040f3e846bc
---
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Checklist: what "complete" looks like

Every row is a property that must be **continuously true**, with an observable that someone who has never seen the platform can run.

- **PUBLIC-NOW**: decidable on a laptop or in CI with fakes, fixtures and goldens. Every one has a criterion in `examples/registers/invariants.yml` that the invariants runner (`python3 -m homelabnext.invariants run`) executes from this repository, with no exception (`tests/invariants/test_inv_example_register.py` holds every row to this).
- **SERVER**: needs the running platform (hypervisors, network, real products, and the settings of the hosted repository, such as branch protection). The row is documented; the interface and a fake exist where the plan calls for one; nothing here pretends to test it.

Criteria register in `invariants.yml` using the same shape as these rows (statement, observable, expected, remediation). Exit codes: 0 pass, 1 fail, >= 100 could not measure.
Pillar X rows are implemented as runner plugins (`evidence: plugin`), except X-02, X-07 and X-08: they are SERVER rows with no check yet, registered as deferred `evidence: server` criteria with a `why`, so the runner neither runs nor counts them.

## F - Foundation

Platform-wide properties. Most need a running platform; the repository-level ones run in CI today.

| ID | Must be true | Observable / pass criterion | Tag |
|---|---|---|---|
| F-01 | The platform is rebuildable from git | IaC plan against the live environment shows no changes; a from-scratch deploy on a spare host succeeds | SERVER |
| F-02 | Network segments are enforced | From a monitored-system segment, connections to management and AI-worker segments are refused; only listed flows succeed (reachability matrix) | SERVER |
| F-03 | People authenticate with SSO and MFA | Every web UI redirects an unauthenticated request to SSO or demands its own MFA; 0 anonymous UIs | SERVER |
| F-04 | Every service and agent has its own identity | Credential inventory: no credential shared by two consumers; no service or agent holds admin rights | SERVER |
| F-05 | Secrets are not in git | Secret scan of the tracked tree (`tools/leak_scan.py --groups secret`) and of the full history (CI's pinned `gitleaks git` over every fetched ref) reports 0 unaccepted findings | PUBLIC-NOW |
| F-06 | Credentials are short-lived and rotated | Every inventoried secret is within its rotate-by date | SERVER |
| F-07 | Internal TLS is verified | 0 clients with certificate verification disabled (lint over client config; RL013 for roles); endpoints present certificates from the internal CA (`tools/tls_verify_lint.py` over Python and YAML/JSON) | PUBLIC-NOW |
| F-08 | The main branch is protected by CI | Branch protection on the hosted repository requires the ci.yml checks to pass before a merge (`gh api repos/OWNER/REPO/branches/main/protection`; a manual criterion). That CI runs tests, lint and the secret scan on every change is decided from the checkout by Q-01 and Q-06 | SERVER |
| F-09 | Backups follow 3-2-1 with an immutable copy | Newest backup < 24 h; offsite or immutable copy < 7 days; a delete attempt with the automation identity fails | SERVER |
| F-10 | Restores are proven | A full-system restore drill was completed <= 90 days ago and verified | SERVER |
| F-11 | The monitoring is itself monitored | Stopping the alerting service raises an external dead-man alert within 15 minutes | SERVER |
| F-12 | Changes go through staging first | Every production deploy in 30 days has a green staging run of the same version | SERVER |
| F-13 | Break-glass access works | Each break-glass procedure was exercised <= 180 days ago | SERVER |
| F-14 | Recovery targets are defined and met | Every service records an RTO and RPO; the last drill met them | SERVER |
| F-15 | Changes are versioned and visible | Components are released as tagged versions with changelogs; every deploy emits a what-changed event (`homelabnext.deploy.changed` event built from the changelog section and emitted by the release workflow) | PUBLIC-NOW |
| F-16 | The fleet runs without the admin workstation | With the workstation off for 24 h, all canaries pass and 0 jobs fail because of it | SERVER |
| F-17 | Nothing at runtime points at the workstation | 0 runtime configs reference the admin workstation (runs as part of X-01) (`tools/workstation_refs.py`) | PUBLIC-NOW |
| F-18 | The public tree contains no private identifiers | `tools/leak_scan.py` over the tree exits 0 (no private IPs, domains, emails, MACs, keys) | PUBLIC-NOW |
| F-19 | Every guest has a defense baseline | With a baseline set (`_baselines.yml`), every guest (vm, lxc, host) names one or more baselines or carries a documented exemption (`hnx guests baselines DIR --site SITE --check`; `--require-bound` also fails while a needed control has no role) | PUBLIC-NOW |
| F-20 | Every machine says what powers it | With a site `power` section, the router, every switch and edge device, every hypervisor and physical host names a known UPS or `none` with a reason (or takes `power.default`), and every UPS feeds something (`hnx guests validate DIR --site SITE`; `homelabnext/power.py`); each UPS with `monitored_by: nut` and a `nut_name` is a live `poll-nut` status source generated from the site, on battery is warn and pages once naming the guests on it, low or replace battery is fail (`pytest tests/status/test_status_nut.py`, replaying recorded upsd 2.8.1 transcripts) | PUBLIC-NOW |
| F-21 | The public tree carries no part of a private overlay | `tools/private_leak_check.py public .` exits 0: no overlay marker outside the fictional skeleton, no file under the skeleton's private layout paths, no `.sops.yaml`, no SOPS ciphertext, no key file; a private overlay's CI runs the same tool as `private ROOT` (no plaintext credential value after masking well-formed ciphertext only; every file under the pinned `lab/sealed/`, the marker's `sealed_paths` or a `.sops.yaml` rule SOPS-encrypted throughout, with real metadata, no key set twice, and every value a well-formed `ENC[]` token but the keys of the SOPS-default or marker-pinned `unencrypted_suffix` (a file's own other suffix is partial), never partially; a token is masked only in a SOPS file and only as a whole value or comment; a `.sops.yaml` that narrows that set is a finding; every vault file the bare header-plus-hex envelope; a file it cannot scan fails unless the marker's `allow_unscanned` names it; ADR-0021) | PUBLIC-NOW |
| F-22 | The CI deploy reaches only what the site declares | With a site `tailnet.deploy`, `hnx site validate` refuses a wildcard (`*`, `any`) or unknown destination zone and a port beyond SSH without an `exceptions` entry and reason; `hnx guests render DIR --site SITE --target tailscale-acl` emits `tag:ci-deploy` in `tagOwners`, its TCP 22 rule to the declared zones only, and a policy `tests` block (accept the declared zones on 22, deny other ports, every other tag, and any zone tag back to the deploy tag) that holds against the rendered rules (`homelabnext/tailnet.py`, `tests/compute/test_tailnet_deploy.py`; ADR-0021) | PUBLIC-NOW |
| F-23 | No Caddy config lets a client set its own identity headers | `tools/caddy_lint.py` exits 0 over every Caddy config in the tree (the files `git ls-files` lists: Caddyfiles and their templates and imports, markdown fences, Caddyfiles embedded in YAML, Caddy JSON/YAML, the `caddy` generator's output for every registry that loads): in a config with a `forward_auth` anywhere, every site that runs it or proxies (`reverse_proxy`, `php_fastcgi`), whatever it dials, deletes at site level and with no matcher every header carrying `authentik` and every copied one (`request_header -*authentik*` first in the site; the IdP's own site, whose every proxy dials the IdP, is the one exemption); every `forward_auth` sits directly in a `route`, after a delete (site level, or earlier in that route) of each header its `copy_headers` sets, in every `-`/`_` spelling, and has no matcher; no header directive sets, adds or replaces a header named after `authentik` or a copied name, or copies one through a header placeholder, and none rewrites them through a `*` field from a placeholder value; no FastCGI `env` sets an identity CGI variable (`HTTP_<identity header>`, `REMOTE_USER`, `AUTH_*`) or any variable from a client-chosen value; no `forward_auth` dial, and no proxy dial in a forward-auth site, is a request placeholder;  a construct the lint cannot read (a heredoc, a multi-line quoted token, a brace sharing a line, `{$ENV}` or a template in directive position, a header name that is not literal, an import it cannot follow or substitute, a global `order` option) or a `forward_auth` in a file it does not read fails closed; with a `caddy` binary (pinned 2.11.7 and required in CI; a local run without one says so and relies on the text rules), Caddy's own `caddy adapt` JSON reaches no `reverse_proxy` with an identity header undeleted on any path and sets none outside the auth answer; and every Caddy pin is 2.11.2 or later by semver (registry `impl: caddy`, `caddy_*version`/`_tag`/`_release` keys, any image whose last path segment is `caddy` behind any prefix, Dockerfile `FROM`/`COPY --from`/`RUN --mount` and `xcaddy build` with `ARG` defaults resolved, `caddy=` packages, `go.mod`, `.env`; an unresolvable pin fails, an image built on Caddy needs a reviewed allow); threat model: accidental misconfiguration of the tree's Caddyfiles and Caddy JSON (authors are trusted and reviewed; deliberate obfuscation, the operator's environment and caddy-docker-proxy labels (a `caddy.*forward_auth` label is a coverage finding) are out of scope; that every human-facing service is reachable only through the authed front door is the separate front-door work's job, Rule 1) | PUBLIC-NOW |
| F-24 | Secrets are not readable on disk | On every host, 0 files holding a secret are readable by other; the `config_leak_scan` role reports secret-looking values outside its accepted paths (path, line, pattern; never the value) | SERVER |

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
| T-04 | Events are enriched | Enrichment fixture adds asset owner and criticality; >= 95% of live events carry them (`homelabnext/events/enrich.py`; `hnx events enrich-coverage` measures live coverage) | PUBLIC-NOW |
| T-05 | Flows have provenance | Every flow definition is in git; provenance shows source, time, transform per record | SERVER |
| T-06 | End-to-end latency is bounded | p95 event creation to searchable < 2 min | SERVER |
| T-07 | Event envelopes are contract-tested | Publisher and consumer tests pass against the envelope schema for every event type (generated publisher and consumer tests per event type) | PUBLIC-NOW |

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
| D-04 | Coverage counts only tested rules | Coverage report derived from passing fixtures only (golden report) (`python -m homelabnext.detections coverage --check`; a rule counts only when all its fixtures pass) | PUBLIC-NOW |
| D-05 | Alert volume is manageable | Alerts reaching a human < 100/day on a 7-day average; every suppression has owner and expiry | SERVER |
| D-06 | Evasion variants are reported | Fixture runner reports evasion fixtures that slip through, without failing the rule | PUBLIC-NOW |
| D-07 | Rules compile for every supported engine | Sigma to generic backend compile goldens match | PUBLIC-NOW |

## O - Outputs

Cases, status, notifications and reports reach people.

| ID | Must be true | Observable / pass criterion | Tag |
|---|---|---|---|
| O-01 | High-severity alerts become cases | Every high or critical alert has a case or documented auto-close within 15 min | SERVER |
| O-02 | The status grid reflects reality | Stopping a monitored service turns its tile red within 5 min (mechanism tested with fakes: `tests/status`; the live 5-minute check stays on the server) | SERVER |
| O-03 | Notifications are authenticated | Anonymous publish to an alert channel is refused | SERVER |
| O-04 | Scheduled reports are produced | Daily and weekly reports exist for the last 7 days / 4 weeks | SERVER |
| O-05 | The ops console shows exceptions only | With every source healthy, the console shows only the green count, live work and attention items (`homelabnext/status`, tested in `tests/status`; the live console is measured on the server) | PUBLIC-NOW |
| O-06 | A dead adapter reads as stale | Stopping an adapter marks its module stale within its SLA (`stale_after_s` per status source; tested with an injected clock in `tests/status`; live SLA measured on the server) | PUBLIC-NOW |
| O-07 | A hung source cannot stall the console | With one source blackholed, the view renders in < 2 s with that module stale (per-source timeouts in the collector scheduler; `tests/status`) | PUBLIC-NOW |
| O-08 | Notifications are state-diffed | Same state twice sends once; recovery sends one message (fake sender test) | PUBLIC-NOW |
| O-09 | The hub lists every service link, scheduled job and agent from repository data | The Links, Schedule and Agent roster pages are generated from the registry, role timers / fleet units / CI schedules / workflow packs / status sources, and the roster with compiled profiles and broker manifests; every catalogued `timer:` trigger, scheduled workflow and status source is a Schedule row with a computed next run, every profile named anywhere has a roster owner and runtime, and no page writes an address (`tests/maps/test_directory.py`) | PUBLIC-NOW |
| O-10 | Every role timer reports its runs | Each role or profile `.timer` has its service run the shared last-run writer (role `last_run`) on start and on stop with its own job id, calendar and delay, and its role installs it; the `job-last-run` mapping turns the records into one item per job and host, fail on a failed run and warn once the next run is overdue (next calendar time + randomized delay + run duration), and the Schedule page dates each timer's last run from them; a record shipped under `<dir>/<host>/` speaks only for that host and one dated more than 300 s ahead is unknown, and record file names are injective in the job id (`tests/roles/test_last_run.py`, `tests/status/test_status_last_run.py`, `tests/maps/test_directory.py`) | PUBLIC-NOW |
| O-11 | Every orchestration job's usage is recorded and shown, names and numbers only | The controller's `homelabnext.agent.job.finished` 1.0 (closed schema: no prompt, task, tool or model text) is consumed idempotently by event and run id, only from the configured controller service id (default `svc:llm-orchestrator`), into the hub's store; per-turn records come through a turn-source adapter (the `inference` capability's `turn-records` feature; the first adapter reads LiteLLM's `/spend/logs/v2` with a viewer key by secret name), reduced to the neutral turn record and joined by `gateway_tag`; the store exports and imports as JSON lines; the Orchestration page shows per profile, backend and lane outcomes, p50/p95 wall and queue wait, tokens, cache-read share, cost, retries, fallbacks, sizes, a daily trend and one job's turns, "no gateway data" rather than zeros (`tests/orchestration/`, the generated event contract tests) | PUBLIC-NOW |

## P - Control plane

Action broker, approvals, operator-away mode.

| ID | Must be true | Observable / pass criterion | Tag |
|---|---|---|---|
| P-01 | Every state change goes through the broker | No agent or workflow identity can change a system directly; every change has an action id | SERVER |
| P-02 | Default deny | A caller with no manifest entry for an intent is denied; manifests live in git (table test) | PUBLIC-NOW |
| P-03 | Approvals are bound and attributable | Approval record has approver identity and request digest; a request altered after approval is refused (test); the approver allowlist matches (issuer, subject) exactly, so a spelling variant of a listed approver is refused (`approver-variant-*` decision-table cases) and the hub never folds a username (`test_a_non_canonical_username_is_not_folded_and_cannot_decide`) | PUBLIC-NOW |
| P-04 | The broker audit is complete and fresh | Audit table <= 15 min stale; request count equals audit rows daily | SERVER |
| P-05 | Operator-away mode works | Drill: switch on forces live intents to shadow within 1 min; daily summary arrives | SERVER |
| P-06 | Broker decisions reach the SIEM | Allow, deny and needs-approval all appear in the SIEM within 5 min | SERVER |
| P-07 | Broker isolation holds | One caller cannot read or cancel another's request (`access_cases` table test; broker conformance checks `requests-bound-to-caller`, `foreign-request-access-audited`) | PUBLIC-NOW |
| P-08 | Work follows the board rules and links to strategy by uid | Every project, step and task keeps the board rules (a step belongs to an open project; a project whose steps and tasks are all finished is closed; finished items, closed projects included, carry a result; links resolve; no cycles): `hnx projects check` exits 0 on a non-empty projects directory; the `projects` conformance suite passes on the reference store and on OpenProject (recorded fake, `--target projects-openproject`) and catches its ten mutants (ADR-0020) | PUBLIC-NOW |
| P-09 | The project tool mirrors strategy faithfully | `hnx projects doctor --target openproject` all ok and `hnx projects sync-strategy --dry-run` reports 0 writes after an apply (repository unchanged), against the live OpenProject | SERVER |
| P-10 | Agents cannot crowd the broker's records | A records-inbox note is dated by the broker and its name is tagged per caller, so no agent can claim another's proposal name (`test_an_agent_whose_slug_prefixes_another_cannot_claim_its_file_name`); refused requests are rate limited per peer and audited once per window, and filed decisions are read from their own index, re-indexed for the newest audit records on every start and rebuilt until a rebuild completes (`test_refusals_are_rate_limited_per_peer_and_audited_once_per_window`, `test_recent_decisions_read_the_decisions_index_not_the_trail`, `test_a_decision_whose_index_write_was_lost_is_reindexed_on_start`); a note whose front matter holds a template marker is refused (`test_records_inbox_refuses_template_markers_in_the_front_matter`) | PUBLIC-NOW |
| P-11 | The broker's decisions reach the bus, in order, at least once | `hnx broker relay` publishes `<state>/outbox/` in emit order with the event id as `Nats-Msg-Id`, marks an event delivered only after the PubAck, stops at the first failure and backs off, so a bus outage never blocks a decision and a crash before the mark is deduplicated by the stream (`tests/broker/test_broker_relay.py`: order, lost PubAck, crash between publish and mark, bus down then up, nothing secret logged, the decision through to the st2 bridge); only the broker's NATS user may publish `homelabnext.decision.>` / `homelabnext.proposal.>` (docs/broker.md); the lab's `bus-relay` e2e step | PUBLIC-NOW |
| P-12 | Only the broker may publish the broker's decisions | On the lab bus no client connects without a user, and only `hnx-broker` may publish `<prefix>.homelabnext.decision.>` / `.proposal.>`; every user has an allow-list with no `$JS.API.>` wildcard and its own `_INBOX.<user>` (`compose/lab-in-a-box/config/nats/nats.conf`; `tests/compose/test_lab_in_a_box.py::test_only_the_broker_may_publish_the_brokers_subjects`; the lab broker scenario's `bus-acl` step: a forged `decision.returned` from `hnx-st2-bridge` is refused) | PUBLIC-NOW |
| P-13 | The broker's outbox relay is ordered, bounded and least-privileged | Emit order is a flock-guarded persisted counter; a malformed file is quarantined and a permanently refused event goes to `undeliverable/` (stats `fail`) without stalling later ones; the relay runs as its own user, reads `outbox/` only, publishes only valid `svc:broker` events, never creates a stream and never sends a password over plaintext `nats://` off loopback (`tests/broker/test_broker_outbox.py`, `tests/broker/test_broker_relay.py`) | PUBLIC-NOW |
| P-14 | Every MCP server comes from one reviewed catalog | One record per server (`schemas/platform/mcp_server.schema.json`): pinned origin with its reviewed `bins`, its tools and classes, egress, data tier, secrets by name only; a stdio launch is generated from the origin (`npx --prefix=<absolute npm_prefix>`/`uvx --no-config`/`docker run`/`hnx <allowlisted MCP entry>`/an absolute first-party path, with fixed flags; the bin is one of `bins`; a record holds no launcher or launcher flag, and no setting, env or parameter key configures the process or launcher, or loads code or redirects trust in it: `OPENSSL_*`, `*_PROXY`, glibc and shell knobs); a third party's hosted server is an https `remote` URL naming a public DNS host (never an IPv4 address in any notation) with internet egress, `cloud-allowed` data and secret headers; an `hnx` entry's path flags are absolute; render refuses an `npm_prefix` that is the root, a symlink or not empty; `hnx mcp catalog check` refuses unpinned, unclassed, credential-bearing or unreviewed records and no message prints a value (nor a record's reason or an unknown grant name); render runs the whole record check, needs the review policy, and writes Claude Code, Claude Desktop, Hermes and llm-orchestrator configs only for profiles `hnx agent verify` accepts against the ceiling policy (which attests each profile's data tier and model role), and `--check` reports drift; grants name catalog ids and the compiler refuses unknown, retired, draft and local-only-to-cloud grants, and a local-only profile is granted an internet-reaching server only by a named `internet_mcp` policy exception (`make mcp-check`, `tests/mcp/`, `tests/agent/test_agent_readers.py`; ADR-0024) | PUBLIC-NOW |

## R - Orchestration

Workflows are code, event-driven, bounded.

| ID | Must be true | Observable / pass criterion | Tag |
|---|---|---|---|
| R-01 | Workflows are code | Every pack is in git, validated offline in CI, deployed only from passing commits (`hnx workflows validate`; deploy pins must match validated pack digests) | PUBLIC-NOW |
| R-02 | Reaction is event-driven | A test event triggers its workflow within 60 s; no polling where an event exists | SERVER |
| R-03 | Deterministic steps come first | Every workflow calling a model first runs deterministic enrichment (offline validator) (validator rules `deterministic-first`, `model-input`) | PUBLIC-NOW |
| R-04 | Risky actions need bound approval | Risky action without approval of its payload hash does not run (test) (`BrokerExecutor` through the broker approval binding; table test and validator `approval-binding`) | PUBLIC-NOW |
| R-05 | Actions use scoped service accounts | Off-list command as an action account fails | SERVER |
| R-06 | Every run is recorded | Executions with inputs, outputs, approver, result retained >= 1 year | SERVER |
| R-07 | Workflow fixtures round-trip | Fixture events produce the expected action calls in the offline validator (`hnx workflows validate` runs every pack's fixtures offline) | PUBLIC-NOW |
| R-08 | The agent-session controller honours the orchestration contract | `hnx conform run orchestration --target orchestration-llm-orchestrator` passes against the running controller with the conformance `hermes` stand-in (docs/orchestration-controller.md); offline, `tests/conform/test_conform_orchestration_controller.py` pins the recorded API's known MUST gaps (`unknown-job-raises`, `retries-until-success`, `retries-are-bounded` at `a52a1c4`) and shows the proposed controller fixes clear them | SERVER |
| R-09 | StackStorm is the when-engine for pinned packs | `hnx workflows st2 check` (in `make workflows`): the StackStorm pack rendered from `workflows/stackstorm.yml` + deploy pins + packs is committed and current; every webhook rule's criteria fire for exactly the events its pack triggers on (tests/workflows/test_workflows_st2.py, against every event example and fixture); rules ship in shadow (nothing reaches the broker), live needs a >= 7-day shadow window with tracked evidence; agent dispatch is coalesced and job-failed retries are bounded (`st2-coalesce`, `st2-bound`); every effect goes through the broker, risky ones submitted for approval (`decision.requested`); secrets are datastore references only; event data reaches StackStorm only URL-encoded and is decoded in Python, never as a Jinja/YAQL expression (`st2-template` checks the rendered tree); the actions take a pack and step id and read the step, mode and risk from the rendered `pinned/<pack>.json` (digest re-checked), never from parameters; every event-triggered pack pins its producer (`st2-source`); called handlers are in the tree, digest-pinned (`st2-handler`); a schedule may not set both day of month and day of week; `admit` drops a redelivered event id (StackStorm's webhook dedupes nothing); the event bridge (`hnx workflows st2 bridge`) is a durable consumer per `bridge.json` subject that validates each event (schema, type, pinned producer) and acks only after a 2xx, nacks with backoff otherwise, and terminates poison into the dead-letter stream with a counted reason (tests/workflows/test_st2_bridge.py); a held request runs after a person's approval only through the built-in approved-run rule (A03), only when a live step here recorded it and it is owned, unchanged, pending and approved, at most once (forged accepts are refused and logged); dispatch sends only what the controller takes; A02 pins the controller's own source, skips a run it already retried and keys a resubmit on the failed run (`st2-bound`) (docs/stackstorm.md); the event bridge treats any undecodable or oversized body (>256 KiB, nested past the parser) and any exception while checking one delivery as poison, never a crash (tests/workflows/test_st2_bridge.py); it creates no stream and refuses one without max_bytes (event stream and DLQ provisioned per docs/stackstorm.md), leases deliveries longer than a POST (ack_wait 30 s, refuses a shorter durable), backs off per subject, and its fail state clears a day after the last dead letter; the runtime's seen/coalesce/submitted datastore names are HMAC-keyed with the encrypted pack config `kv_key`; the agent.job.submit handler sends the controller's jobs token (ORCHESTRATOR_JOBS_TOKEN) from a private header file, never argv | PUBLIC-NOW |

## Q - Quality gates

Caught before deploy.

| ID | Must be true | Observable / pass criterion | Tag |
|---|---|---|---|
| Q-01 | Every repo's tests run on every change | CI runs unit and contract tests on push and merge request (`tools/tests/test_ci_runs_tests.py`); main is green (the forge's latest run: `gh run list --branch main --workflow ci --limit 1`) | PUBLIC-NOW |
| Q-02 | Test suites are trustworthy | Each suite within its time budget; 0 silent skips; quarantined tests have owner and unexpired date (`tests/suite_policy.py`: per-suite budgets, registered skip reasons, `quarantine` marker with owner and expiry) | PUBLIC-NOW |
| Q-03 | Live-dependent tests are marked | Tests needing real systems carry the `live` marker and CI skips them; an unmarked test that reaches a non-loopback address fails (`tests/network_guard.py`) | PUBLIC-NOW |
| Q-04 | Every component ships tests | CI fails a component directory with no tests (`tools/component_tests.py`, reviewed allowlist) | PUBLIC-NOW |
| Q-05 | Every seam has a contract test | Each event type and shared table has a schema plus publisher and consumer tests (`tools/contract_coverage.py`) | PUBLIC-NOW |
| Q-06 | Security tests run in CI | Secret scan, dependency audit and lint pass | PUBLIC-NOW |
| Q-07 | Security-critical code is well covered | Broker, guard, approval and decision code >= 80% line coverage per unit (`make coverage`, `tools/coverage_floor.py`) | PUBLIC-NOW |
| Q-08 | Fixed bugs stay fixed | Every bugfix in 90 days has a regression test that fails without the fix (`tools/fix_has_test.py`; CI `--prove` runs the fix's tests on its parent) | PUBLIC-NOW |
| Q-09 | Every source file carries an SPDX header | Grep over tracked source files finds 0 without the header | PUBLIC-NOW |
| Q-10 | Every schema ships an example and a negative | Schema check passes (X-03 covers pinning and validity) | PUBLIC-NOW |
| Q-11 | Tests are hermetic | No test uses the network, wall clock, or unseeded randomness (clock and sender injected); network enforced by the test guard, direct clock and randomness calls in tests, and library clock reads outside an injectable default or fallback, by `tools/hermetic_lint.py` | PUBLIC-NOW |

## M - Scripts, context and access

Catalogued scripts, controlled agent context, one map of access.

| ID | Must be true | Observable / pass criterion | Tag |
|---|---|---|---|
| M-01 | Every script is catalogued | Each script has a valid header; generated catalog is current (`hnx scripts catalog --check`) | PUBLIC-NOW |
| M-02 | The catalog matches reality | 0 scheduled-but-uncatalogued scripts, 0 uncalled active scripts, 0 duplicate ids (`hnx scripts reality`) | PUBLIC-NOW |
| M-03 | Helpers are shared, not copied | 0 private notify/state/lake-query helpers outside the shared libraries (allowlist with reason) (`tools/shared_helpers_lint.py`), and 0 copy-pasted clones beyond `tools/dup_check.baseline.json`, which only shrinks (`tools/dup_check.py`) | PUBLIC-NOW |
| M-04 | Checks run in one place | Every check script runs through the invariants runner; no standalone check timers (`hnx scripts runner-lint`) | PUBLIC-NOW |
| M-05 | Every agent job gets its context pack | Job log records pack hash and contents built from the charter manifest | SERVER |
| M-06 | No agent runs blind | A job with a missing or stale pre-gate is deferred with a reason | PUBLIC-NOW |
| M-07 | Agents prove they used the pack | Result citing no must_cite pre-gate is rejected (test) | PUBLIC-NOW |
| M-08 | Packs fit and are never silently cut | Assembler reports tier used; 0 silent truncations (test) | PUBLIC-NOW |
| M-09 | Agent memory is controlled | Writes only through validated memory updates; cross-agent read refused (test) (`homelabnext/agent/memory.py`) | PUBLIC-NOW |
| M-10 | The context store is dependable | Authenticated, backed up, restore-tested; outage falls back to flagged cache | SERVER |
| M-11 | One map of access | Every principal is in the keyring with grants by level and denials | SERVER |
| M-12 | The keyring comes from the sources | 0 drift between generated keyring and its sources (`hnx agent keyring check`) | PUBLIC-NOW |
| M-13 | Access is proven, not assumed | Each grant and denial has a probe as the principal at least daily; a passing denial pages | SERVER |
| M-14 | Every agent starts knowing its access | Session start injects the access block for where it runs (`homelabnext/agent/access.py`: a reserved stable `access` section) | PUBLIC-NOW |
| M-15 | The keyring is protected | Served only behind SSO; a new privileged grant is flagged | SERVER |
| M-16 | No placeholder ids survive a commit | `make ids-check` (`hnx ids check-uids` and `check-dupes` over every register, on pull requests and main alike) exits 0: every record carries its canonical uid and is named `<uid>.md`, so none is keyed by a number or an `XX-NEW` placeholder (records are identified by uids, ADR-0019; nothing is allocated); the families that keep their own key (invariant criteria: checklist row ids; system and capability pages: registry and capability names) are named in ADR-0019's Scope, which `tests/identity/test_uid_scope.py` holds to the register specs, and `hnx records assign-uids` refuses them by name | PUBLIC-NOW |
| M-17 | Register ids are never lost | `tools/register_ids.py check-lost` exits 0 for every register: no record uid (and no invariant id) of the parent commit has vanished; a parent's numbered code counts through the tree's `aliases.yml` | PUBLIC-NOW |

## A - AI layer

Tiered: screen, fast model, heavy model.

| ID | Must be true | Observable / pass criterion | Tag |
|---|---|---|---|
| A-01 | The pre-AI screener handles every item first | 100% of AI-bound items show a routing decision in the log | SERVER |
| A-02 | The screener reduces volume | at least 70% closed or deduplicated before any LLM call; false-negative rate < 1% on the evaluation set | SERVER |
| A-03 | The screener redacts sensitive data | 0 secrets or PII tokens reach a model prompt on the evaluation set (`homelabnext/agent/screen.py` in pack assembly; `tests/agent/fixtures/screen_eval.yml`, precision floor 0.95) | PUBLIC-NOW |
| A-04 | The fast model returns validated output | 100% schema-validated; invalid output retried once then escalated (`ModelTier` validates every reply, retries once, then escalates) | PUBLIC-NOW |
| A-05 | Low confidence escalates | Below-threshold items reach the heavy model or a human; none auto-actioned | PUBLIC-NOW |
| A-06 | The heavy model is reserved for hard cases | <= 10% of routed items reach the heavy tier; cost within budget | SERVER |
| A-07 | The AI agrees with analysts | Agreement >= 90% on a rolling 30-day sample | SERVER |
| A-08 | Each model is on disk once, pinned | The store manifest lists each (source, revision, quant) once, every hub entry at a 40-hex commit (never `main`), every file with sha256 and size; every role binding resolves to an entry its engine may serve, and a pinned digest names it (`hnx models store validate --roles`, `make models-check`; `tests/models/test_model_store.py`) | PUBLIC-NOW |
| A-09 | The store's bytes are the manifest's | `hnx models store check` passes by sha256 (missing, resized, changed or unlisted files fail); the `model_store` role fetches with `--revision <commit>` and refuses a mismatch (`tests/models/test_model_store.py`, `tests/roles/test_serving_roles.py` against a fake `hf`) | PUBLIC-NOW |
| A-10 | vLLM runs what the role table says | Units generated from store + role table + serving spec: `--served-model-name` = binding model id, `--max-model-len` = role context, `--scheduling-policy priority`, one model per instance, distinct ports and GPUs; the `vllm_server` health hook agrees with the K-14 probe (`hnx models serving check`, `tests/models/test_serving_plan.py`, `tests/roles/test_serving_roles.py`) | PUBLIC-NOW |
| A-11 | Chat goes through the gateway | Open WebUI's only backend is the gateway URL with its own key by secret name; a backend id, Ollama or a direct connection is refused (`open_webui` role, `tests/roles/test_serving_roles.py`) | PUBLIC-NOW |
| A-12 | The serving stack runs on the GPU host | `vllm_server` health passes on the CMP 170HX host for every instance; TP/PP benchmarked; the docs/model-serving.md hardware items checked off | SERVER |
| A-13 | Served model bytes are pinned end to end | `uv run pytest tests/models tests/roles/test_serving_roles.py` exits 0: vLLM `args` are a typed allowlist (`homelabnext.models.serving.ALLOWED_ARGS`, mirrored into `vllm_server/vars/main.yml` and the schema, held equal by a test); a serving spec states `exposure` and the gateway refuses a loopback plan or a registry port that is not the plan's; `model_store` fetches into staging and renames only sha256-verified files into place, locks promoted exports (store-owned, sticky `exports/`), and writes per-entry listings; every vLLM unit runs `ExecStartPre=hnx-model-verify` (listing hashes to the pinned digest, `sha256sum --check --strict`); `check_disk` refuses files resolving out of their entry/blobs; Open WebUI's target must resolve to the registry's `llm-gateway` capability; units allow only their own `/dev/nvidiaN` | PUBLIC-NOW |

## G - AI safety guardrails

Untrusted content cannot drive actions.

| ID | Must be true | Observable / pass criterion | Tag |
|---|---|---|---|
| G-01 | Untrusted content is delimited | Every prompt template wraps ingested content in untrusted-data delimiters (template lint: `hnx agent prompts lint`) | PUBLIC-NOW |
| G-02 | Prompt-injection defences are tested | Injection corpus passes with 0 instruction-follows before each model or prompt change (`hnx agent injection run`; CI against the fence-respecting fake with a golden report, `make injection-eval` against a real model) | PUBLIC-NOW |
| G-03 | Readers cannot act | Agents that read raw content hold no shell, file-write or egress tool (profile lint and refusal test: `reads_untrusted`, `hnx agent lint`, compiler and `verify` refuse) | PUBLIC-NOW |
| G-04 | Actors act only through allowlisted actions | Actors receive validated structured input; actions pass the allowlist (`homelabnext.agent.handoff`: only a validated `report_result` output is accepted, free text never becomes an action parameter, undeclared or unlisted actions are refused); the observable also runs the broker rule over every profile (G-13), since an actor holding a direct tool is not limited to allowlisted actions | PUBLIC-NOW |
| G-05 | Agents are never admin | No agent identity can use sudo or read admin credentials | SERVER |
| G-06 | Agent egress is allowlisted | A connection to a non-allowlisted destination is refused | SERVER |
| G-07 | Kernel enforcement is active | Runtime policy loaded on every AI host; a write outside allowed paths is blocked and reported | SERVER |
| G-08 | The policy layer is in path | 100% of tool calls pass the guardrail layer; a call with a secret is redacted or blocked | SERVER |
| G-09 | Every AI action is auditable | Model and tool calls logged off-host tamper-evidently | SERVER |
| G-10 | Rate and cost limits hold | Exceeding a limit throttles and alerts (test) (`homelabnext/registry/limits.py`) | PUBLIC-NOW |
| G-11 | Model versions are pinned | Each model is pinned by version and hash; changes pass CI evaluation (`hnx golden pins check`) | PUBLIC-NOW |
| G-13 | Agents act only through the broker | Any profile, reader or not, holds an acting grant (exec, file-write, send, credential) only through the broker: an acting MCP server is the broker's own front (structural, with its exact tools) or a direct exception (a `direct_reason`, a current human approve review and the ceiling policy's `direct_mcp` entry for that profile), every capability classed (an unclassed one is refused), no acting capability but `cap:broker`, an acting tier only with `cap:broker` (`hnx agent lint --rule actors-act-via-broker` with the ceiling policy; the compiler, `verify`, the client render and the module rules refuse; ADR-0030) | PUBLIC-NOW |

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
| K-08 | Noise gates de-escalate only with corroboration | Each de-escalation carries a deterministic corroboration reference (test) (`noise_gate` corroborators; uncorroborated de-escalation escalates) | PUBLIC-NOW |
| K-09 | Noise gates are audited | Weekly sample reviewed within 7 days; miss rate <= spec limit | SERVER |
| K-10 | Specs go live only on evidence | Recorded shadow period and precision on time-split held-out data | SERVER |
| K-11 | Drift is caught | Per-spec precision, escalation rate, tier share published; abstain-rate band alert | SERVER |
| K-12 | Changes pass a replay gate | Model or threshold change replayed against the decision set; report stored (golden report) | PUBLIC-NOW |
| K-13 | Classifiers never delete data at ingest | Records in equal records out; results only as annotation columns (`homelabnext/decide/annotate.py`, property test) | PUBLIC-NOW |
| K-14 | The serving config is what we think it is | Health check reads actual loaded context length and model id and alerts on mismatch (fake server) (`check_serving` against the fake server; alert via notify) | PUBLIC-NOW |
| K-15 | Required safety specs are live | Sensitive-content, hostile-content, purpose-consistency and disclosure-risk specs pass their cases (`hnx decide safety`) | PUBLIC-NOW |

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
| L-04 | Detections are validated by internal assessment | An authorized internal assessment of detections <= 90 days ago, against the lab's own systems; every step maps to a firing rule or ticket | SERVER |
| L-05 | Documentation matches reality | Docs regenerated from or checked against the live inventory; 0 drift (`hnx docs systems check`; capability reference pages generated from the conformance code, `hnx docs capabilities check`) | PUBLIC-NOW |
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

**Totals:** 184 criteria across 16 pillars; 100 PUBLIC-NOW, 84 SERVER.
