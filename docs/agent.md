# Agent profiles, context packs and the broker contracts

Vendor-neutral building blocks for running agents under least privilege. Everything here is
data plus pure functions: no model, network or hardware is involved, and the tests use in-memory
fakes. Contracts live in `schemas/agent/` and `schemas/broker/`; code in `homelabnext/agent/` and
`homelabnext/broker/`; command `hnx agent`.

## Why these exist

- A profile is **compiled**, not hand-assembled, so "this agent can never do more than its
  ceiling" is a property of the compiler rather than a review habit. The ceiling comes from a
  policy file owned separately from the specs, so editing a spec cannot raise it.
- A context pack is a **pure function** of a manifest and its inputs, so identical inputs give an
  identical pack and hash. A job log that records the hash can be replayed and audited.
- An agent never runs blind: a required pre-gate that is missing, stale or failed **defers** the
  job with a reason instead of letting the agent infer health from raw data.
- The broker is **default deny**, and an approval is bound to the digest of the exact request it
  approved, so a request changed after approval no longer matches.

## Schemas

| Schema | Purpose |
|---|---|
| `agent/profile` | compiled profile: `parts` by logical id, `grants`, `ceiling`, `budgets`, `reads_untrusted`, `include`, `digest`, `provenance` |
| `agent/context_manifest` | persona, skills, tools, pre-gates, memory scopes, tiered sections, character budget, must-cite sources, `screen` |
| `agent/pregate_output` | `ok` / `degraded` / `stale` / `failed`, with per-source ages; a non-ok status needs a reason |
| `agent/report_result` | `pack_id`, cites, unknowns, memory updates, optional structured `output`; `ok` needs at least one cite, `deferred` is how a job reports it did nothing |
| `agent/handoff` | reader -> actor handoff: reader, actor, `output_schema`, the actions the actor may take and how their params bind to the output (G-04) |
| `agent/golden_task` | the existing `homelabnext.golden` suite format, described unchanged |
| `agent/prompt_template` | trusted `system`/`instructions`, slots each declaring `trust`; untrusted slots render only fenced |
| `agent/injection_corpus` | versioned injection cases: payload, canary or forbidden tool, fake-model markers |
| `broker/manifest` | the allowlist; `default` is the constant `deny`; `approvers` lists who may approve |
| `broker/handler` | one handler implementation; execute and privileged handlers require approval; always audited |
| `broker/request` | one call; `digest` binds `{action, actor, target, params}` |
| `broker/decision` | `allow` / `deny` / `needs-approval` with a closed reason vocabulary; shadow mode records but does not enforce |
| `broker/approval` | approver identity plus `request_digest` |

All are versioned 1.0 except `agent/profile` (1.1, additive: `reads_untrusted`; 1.2, additive: `include`),
`agent/report_result` (1.1, additive: `output`),
`agent/context_manifest` (1.1, additive: `screen`), `broker/manifest` (1.1, additive: approvers)
and `broker/decision` (1.1 adds the approval reasons; 1.2 adds `not-request-owner` and the optional
`operation` and `caller`), frozen under `schemas/_frozen/`, and registered with `tools/schema_check.py`
(each has an example and several negatives). `agent/profile` is the compiler's output;
`platform/agent_profile` stays as the lean runtime view.

Rules JSON Schema cannot express are code, with tests: grants subset of ceiling, digest equals
content, `pack_id` equals the pack hash, must-cite coverage, and that a manifest, its handler
documents and the broker table agree (`check_manifest_handlers`).

## Profile compiler

```python
from homelabnext.agent import CeilingPolicy, PartsLibrary, compile_profile
from homelabnext.ids import MappingResolver

library = PartsLibrary(MappingResolver("parts", {"persona:analyst": "personas/analyst.md", ...}),
                       reader=read_text)          # reader(locator) -> str
profile = compile_profile(spec, library, policy=CeilingPolicy.from_mapping(policy_doc))
```

The spec names a persona, skills, capabilities, a model **role** (never a model id), the MCP
servers it wants, a tier and budgets. The **ceiling** is read from a `CeilingPolicy`:

```yaml
# policy.yml: owned and reviewed by someone other than the spec authors (CODEOWNERS)
ceilings:
  profile:reader: {mcp: [lake], capabilities: [cap:lake-query], tier: read,
                   budgets: {max_input_tokens: 64000, max_output_tokens: 4000,
                             max_runtime_s: 900, max_tool_calls: 40}}
```

A spec may also carry a `ceiling`; with a policy it may only narrow the policy's entry, and a
profile id with no entry is refused. Without a policy the compiler falls back to the spec's own
`ceiling` (and `hnx agent compile` says so): that output is self-consistent but bounded by
nothing the spec author could not change, so do not rely on it for least privilege.

The compiler:

1. resolves every logical id through the library and reports **all** missing ids together
   (`MissingPartError`), never skipping one;
2. refuses a spec whose MCP servers, capabilities or tier exceed the ceiling (`CeilingViolation`,
   listing every excess);
3. refuses a **reader** that holds an acting grant (`ReaderViolation`, see below), even when the
   ceiling allows it;
4. refuses an `include:` rule that would seed knowledge from something the profile is not granted
   (`IncludeViolation`, see "Linked knowledge" below);
5. requires all four budgets to be integers within the ceiling's budget caps (`BudgetError`);
6. sorts and de-duplicates lists, so source order never changes the result;
7. records `provenance`: each part's id, source and content digest, plus the digest of the
   normalised spec;
8. sets `digest` to the sha256 of the canonical JSON of everything else, and validates the result
   against its own schema.

`verify_profile(profile, policy=..., lock=...)` re-checks a profile you did not just compile:
schema, digest, and grants and budgets **against the policy's ceiling** (the ceiling stored in
the profile may not be wider). The digest only proves the content was not changed *without
recomputing it*; anyone can recompute a sha256. To pin the reviewed profile, commit a lock file
next to the policy, `{profiles: {<profile id>: <digest>}}`, and pass it as `lock`: a profile whose
digest is not the pinned one is refused. Without `policy`, `verify_profile` checks the profile
against its own stored ceiling, which proves internal consistency only.

Raising a ceiling is a reviewed change to the policy file, never a compiler option.

### Readers cannot act (G-03)

A profile that reads raw or untrusted content (feed items, alerts, mail, web pages: anything an
outsider can write) can be steered by it, so it may hold **no** grant that turns a persuaded model
into an action. Work that needs both is two profiles: a reader that reports, and an actor with
`reads_untrusted: false` that receives the reader's validated structured output and acts only
through allowlisted broker actions (G-04).

- **Declared, fail closed.** `reads_untrusted` is a field of the spec and of the compiled profile
  (the compiler always writes it). Nothing else in the model says what a profile reads:
  `data_tier` is where data may *go*, `memory_scopes` name stores, and the context manifest, whose
  `source: input` sections are the untrusted ones, is bound to a persona rather than a profile. So
  it is declared, and an absent value means `true`: an actor has to say `false`. A ceiling-policy
  entry with `reads_untrusted: true` makes the profile a reader whatever its spec says, so the
  policy owner can pin it.
- **Classified by data.** `homelabnext/agent/tool_classes.yml` maps every MCP server, capability
  (`cap:` id) and broker tier to capability classes (`read`, `record-write`, `exec`, `file-write`,
  `egress`, `credential`) and lists the classes a reader may not hold (`reader_forbidden`: exec,
  file-write, egress, credential). A grant with several classes counts as its worst. A grant the
  table does not know is refused for a reader (unknown is never assumed harmless); adding a tool
  means classifying it there in a reviewed change (the repository's own read-only server,
  `hnx-catalog`, is `read`: [MCP server](mcp.md), [[mcp]]). `--classes FILE` substitutes another table.
- **Enforced three times.** `compile_profile` raises `ReaderViolation` naming every offending grant
  and its class, after the ceiling check and whatever the ceiling allows; `verify_profile` (and
  `hnx agent verify`) refuses a compiled profile edited into that state, digest recomputed or not;
  `hnx agent lint` (`make agent-lint`, part of `make check` and CI) applies the rule to every agent
  profile in the repository (specs, compiled `agent/profile`, the lean `platform/agent_profile`)
  and to every context manifest, where it *is* derivable: a manifest with an input section feeds
  untrusted content, so its `tools` obey the same rule. The lint fails when it finds no profile.

### Actors act only on validated structured input (G-04)

`homelabnext.agent.handoff` is the seam between the two. A **handoff** (`schemas/agent/handoff`,
example `schemas/agent/examples/handoff.phish-block.json`) names the reader, the actor, the JSON
Schema the reader's `report_result.output` must satisfy, and the broker actions the actor may
take, each with params that are literals or `$output.<path>` references (`$$` escapes a `$`).

- **Structured input only.** `accept(handoff, report, pack=, pack_hash=, manifest=)` is the only
  way to get an `Accepted` output. Raw text is refused unparsed (even text that *is* a valid
  report); the report must pass `validate_report` against the pack it ran on, come from the
  declared reader, not be deferred, and carry an `output` that validates against
  `output_schema`. Anything else raises `HandoffRefused` with every reason.
- **Free text never becomes a parameter.** The actor does not choose params: `build_request`
  computes them from the declaration and the accepted output. A reference may name only a
  *constrained* field (`is_constrained`: `enum`/`const`, number, boolean, a checked `format` -
  `date`, `ipv4`, `ipv6`, `uuid` - or a closed `pattern`: anchored at both ends, no top-level `|`,
  no `.`, negated class or `\S`/`\W`/`\D`). `summary`, `unknowns`, cites, memory updates and
  any unconstrained string are free text; a declaration that binds one is refused. Bound strings
  are also refused if they hold a control character (`$` matches before a final newline). This is
  the workflows validator's `risky-params` rule, applied to every action, since everything an actor
  gets here came from a reader of untrusted content.
- **Actions pass the allowlist.** `act(accepted, action, broker_manifest, request_id=, now=,
  approval=)` refuses an action the handoff does not declare, and sends a declared one through
  `homelabnext.broker.decide`: an action the manifest does not list is `deny`/`default-deny`, a
  risky one still needs its bound approval.
- **Checked offline.** `declaration_problems(doc, reader_profile=, actor_profile=,
  broker_manifest=)`: schema, closed `output_schema`, every reference constrained, the reader
  passes the G-03 rule, the actor has `reads_untrusted: false`, every action is in the broker
  manifest and granted to the actor at its tier. Tests: `tests/agent/test_agent_handoff.py`.

## Context-pack assembler

```python
from homelabnext.agent import assemble_pack

pack, pack_hash = assemble_pack(manifest, {"sections": {...}, "pregates": {...}})
```

- **Order**: tier (`stable`, `session`, `volatile`), then section name. The stable prefix is
  identical across runs; `stable_prefix_digest` exposes it for caching.
- **Pure**: no I/O, no clock, arguments untouched. The hash is the digest of the pack, so any
  changed byte of any input changes it; dict, list and process (`PYTHONHASHSEED`) ordering do not.
- **No silent truncation**: a section over its `max_chars` is cut and listed; when the pack
  exceeds `budget_chars`, optional volatile then session sections are dropped and required ones
  trimmed, each cut recorded in `truncations` with its tier, and `budget.tiers_cut` says how deep
  the cut went. Stable content is never cut: if it alone does not fit, the pack is `deferred`.
- **Deferral**: a missing required section, or a required pre-gate that is missing, `stale` or
  `failed`, makes `status: deferred` with `deferred_reasons`. Pre-gate outputs are included in the
  pack as volatile sections so the agent sees the verdict itself.
- **Screening (A-03)**: before fencing, every `source: input` section is passed through the
  screener (`homelabnext/agent/screen.py`), which replaces secrets and PII with typed labels,
  `[REDACTED:<type>:<n>]`, stable across the pack (the same address is the same label in every
  section, compared normalised; numbers follow first appearance in pack order). Types: private
  keys, JWTs, vendor tokens (AWS, GitHub, GitLab, Slack, Google, npm, Hugging Face, Stripe-style,
  `sk-` keys, bearer credentials), keyed secrets (`password=`, `"token":`, `--password x`, "the
  password is x", `user:pass@` in URLs), deny-list terms, Luhn-checked card numbers with an issuer
  prefix, e-mail addresses, national-id shapes (SSN, NINO, keyed passport/tax ids), IP addresses
  and phone numbers. Documentation values (`example.org`, the RFC 5737 ranges, 555 numbers) **are**
  redacted: the screener cannot tell a fixture from real data. Version numbers, dates, UUIDs,
  hashes and commit ids in prose, CVE and ATT&CK ids are not. Private, loopback, link-local and
  CGNAT addresses are redacted unless the manifest sets `screen: {redact_private_ips: false}`.
  Screening is on by default; `screen: {redact: false, reason: ...}` opts out, and the reason is
  required. The pack's `screen` block records the settings, the screened sections and counts per
  type, never a value. A caller's deny-list (`assemble_pack(..., denylist=lines)`,
  `hnx agent pack --denylist FILE`, the leak scanner's format) is applied even when the manifest
  opts out. Static sections and pre-gate verdicts are platform-authored and are not screened. The
  credential and e-mail shapes are shared with `tools/leak_scan.py` (`homelabnext/shapes.py`);
  the leak scanner's exemptions for placeholders are not. The evaluation set
  (`tests/agent/fixtures/screen_eval.yml`, 120+ synthetic cases including hard negatives) must
  leak 0 values into the rendered pack and keep redaction precision >= 0.95.
- Section text is fenced with the manifest's delimiter and tier so untrusted input stays
  distinguishable from instructions. Stable sections (manifest text) open with
  `<delim> <name> [stable] <delim>`. Session and volatile sections are input, so their fences
  carry a per-pack nonce derived from the digest of that content
  (`<delim> <name> [<tier>] <nonce> <delim>` ... `<delim> end <name> <nonce> <delim>`), and any line
  of their text that starts with the delimiter is prefixed `[escaped] `. Input therefore cannot
  open a section of its own, least of all a stable one. This is a structural guarantee about the
  text, not about the model: a model can still be persuaded by data it reads, so the broker, not
  the pack, is what limits what an agent can do.

`validate_report(report, pack, pack_hash, manifest)` checks a `report_result` against the pack it
ran on: schema, `pack_id`, deferred-only-when-deferred, cites name real pack sources, and the
manifest's `must_cite` sources are cited by an `ok` report.

## Session start: the access block (M-14)

`start_session(manifest, inputs, profile, registry, runs_on=None, broker=None)` is how a session
gets its pack: it renders the profile's **access block** and adds it as a required `stable`
section named `access`, then calls `assemble_pack`. The block is derived from the compiled
profile (digest-checked) and the registry, for the host the agent runs on (default: the host of
the registry's `agent-runtime` service):

- who it is, where it runs (host and zone), model role, data tier, whether it reads untrusted
  content, broker tier, its own memory scopes and budgets;
- **may**: every granted capability and MCP server with its level (the worst of its classes in
  `tool_classes.yml`: read, write, execute, privileged; `unclassified` if the table does not know
  it) and the registry alias it goes through, plus the broker actions granted to it;
- **may not**: every other registry capability, MCP server and broker action, explicitly;
- the registry aliases reachable from its zone, and the profile and registry digests.

It also adds the project's **terms** as a second required `stable` section named `terms`: the
vocabulary and authorized scope of [Terms and scope](terms.md) ([[terms]]) -- auditing, the
`audit` review, auditing tools, internal assessments, the operator's own lab as the only scope,
and threat vocabulary kept for external threats. Its single source is the packaged
`homelabnext/agent/terms.md` (`docs/terms.md` is generated from it, `hnx agent terms --check` in
`make check`), so every session pack carries the same text and the pack digest pins it.

`access` and `terms` are reserved section names: a manifest that defines either is refused, so a
manifest cannot replace or remove what the agent is told. The manifest's persona must be the profile's. Stable content is
never cut, so a block that does not fit `budget_chars` defers the pack. On the command line,
`hnx agent pack MANIFEST --inputs F --profile P --registry R [--runs-on HOST] [--broker M]`.

## Linked knowledge: `include:` rules

A profile can carry the knowledge its task needs, not just pointers to it: the record or page
text goes into the pack (a lab measured a 1.6% follow rate for pointers). A spec lists rules
(`homelabnext/agent/include.py`); a spec without `include` compiles exactly as before, and its
profile has no `include` key.

```yaml
include:
  - from: capabilities          # capabilities | mcp | services | task
    only: [cap:lake-query]      # optional (capabilities, mcp): a subset of the grants
    kinds: [runbook, lesson, check, schema, doc]   # also adr, inv
    depth: 1                    # hops from the seeds, 1..3 (default 1)
    budget: 12                  # max nodes this rule includes, 1..50 (default 12)
    max_chars: 4000             # per node, the pack's section cap (default 4000)
    require_reviews: [agent_check, audit]           # optional
```

- **Seeds are grants.** `capabilities` seeds from the granted `cap:` ids, `mcp` from the granted
  MCP servers, `services` from the registry services providing a granted capability, `task` from
  `seeds_for(graph, paths, text)` over the task's paths and text. The compiler refuses (`IncludeViolation`,
  every problem listed) an `only` entry that is not granted and a rule seeding from a grant set
  the profile does not hold; `verify_profile` and the pack build re-check the rules, so a profile
  edited afterwards, digest recomputed or not, gains nothing. Rules are normalised (sorted,
  defaults written) and covered by the profile digest. **Include adds knowledge, never a grant**:
  grants, tools, the access block and the reader rule are untouched.
- **Grant filtering.** `homelabnext/agent/knowledge.py` runs the rules over a fresh graph
  (`homelabnext.graph`). Capabilities, services, MCP servers and broker actions are the
  access-bearing nodes; the profile holds its granted capabilities and MCP servers and the
  services providing a granted capability (never a broker action). A node's *subjects* are the
  access-bearing nodes it links to directly, seen through nodes that only name one (a system tag,
  a product, an adapter, a compose service), transitively: a tag naming a product reaches the
  services that run it and the capabilities its adapters and compose services implement. A proxy
  that reaches nothing access-bearing is itself an ungranted subject (fail closed); a system tag
  that resolves to nothing is a free-form topic and adds none. A node is eligible only if it has a subject and
  **every** subject is granted: a page about a granted and an ungranted capability is excluded,
  one hop away or not. The search runs on the graph minus ungranted access-bearing nodes, but
  subjects are read on the full graph. System tags are transparent for `depth`: a lesson tagged
  `backup` is one hop from `cap:backup`. An ungranted capability, service or MCP server named in
  the task is dropped as a seed.
- **Also excluded, never silently**: inactive records (retired, superseded, incorporated), records
  missing a tier `require_reviews` asks for (it applies to lessons, runbooks and criteria, the
  reviewed records; other kinds are reviewed in git), nodes over the rule's `budget` (lowest rank
  first), unreadable content and paths outside the checkout. Another rule may still include a
  node one rule excluded.
- **Into the pack.** Each included node is an optional volatile section `knowledge-<rank>-<id>`:
  a header with id, kind, title, path, current review tiers, rank and content digest, then the
  content itself (a file only that node defines, else the node's own graph record, e.g. a
  conformance check). It is repository content, not input, so it is not screened; it is fenced and
  escaped like every volatile section. Order is `related` rank (distance, edge weight, id). Over
  `budget_chars`, knowledge is dropped first, lowest rank first, before any other section, and
  each drop is in `truncations`. The `knowledge-` prefix is reserved for manifests.
- **Auditable.** The pack's `knowledge` block records the profile and graph digests, the
  normalised rules, each rule's seeds, every included id with its rank, path, review tiers and
  content digest, and every exclusion with its rule and reason. Same profile, same checkout and
  same task give a byte-identical pack. A pack built without a selection has no `knowledge` key.

```
hnx agent pack MANIFEST --inputs F --profile P --registry R [--root .] \
    [--task-path FILE ...] [--task-text T | --task-file F] [--explain]
```

`--explain` prints the rules, seeds, included nodes (rank, distance, score, the edge that reached
them, review tiers) and every exclusion with its reason; the pack itself then goes only to `--out`.
Tests: `tests/agent/test_agent_knowledge.py`.

## The keyring (M-12)

ADR-0002 lists keyring rows among the outputs generated from the registry; checklist M-11 asks
for every principal with grants by level and denials. The keyring is therefore a **generated**
document (`homelabnext/agent/keyring.py`) whose only inputs are the sources that already decide
access: the registry, the compiled agent profiles and, optionally, the broker manifest. It uses
the same derivation as the access block, so the two cannot disagree. Principals: every profile,
every profile the broker grants actions to without a compiled profile in the set
(`profile: null`), every broker approver, and every registry zone (`kind: network`, which
services it may connect to). `generated_from` records the digest of each source.

```
hnx agent keyring build examples/keyring/sources.yml   # make keyring
hnx agent keyring check examples/keyring/sources.yml   # make keyring-check (make check, CI)
```

`check` regenerates the keyring and fails on any difference from the committed file, naming the
principals that drifted. Never edit `keyring.json` by hand: change a source and rebuild. Serving
it behind SSO and flagging new privileged grants (M-15) and probing each row (M-13) need the
running platform.

## Agent memory (M-09)

`homelabnext.agent.memory.MemoryStore` is the only way to change an agent's memory, and it takes
only the `memory_updates` of a `report_result` (`apply_report`, which validates the report and,
given the pack, checks it with `validate_report`) or a list of them (`apply_updates`). Updates
are validated exactly as inside a report, then applied all or nothing: `add` needs a value and a
key that is not live, `replace` a live key and a value, `retire` a live key and no value (kept as
a tombstone). A deferred report may not change memory, and a report updates only its own
profile's memory.

Reads are scoped to the owner: `read(profile, scope)` returns that profile's own entries in one
of its `memory_scopes`; `owner=` naming another profile is a cross-agent read and is refused
(`MemoryAccessError`), and the same scope name on two profiles is two memories. Every call
checks the profile's digest, so widening `memory_scopes` on a profile in hand gains nothing.
Backends store data only: `InMemoryBackend` (the fake) and `FileBackend` (one
`homelabnext.state` file keyed by profile id).

## Prompt templates (G-01)

Every prompt the platform sends is a template under `homelabnext/agent/prompts/templates/`
(`schemas/agent/prompt_template`). A template is trusted text plus declared slots:

```yaml
id: alert-triage-summariser
persona: persona:alert-triage
system: |
  You are the alert triage summariser for {{ site-label }}. ...   # trusted text
instructions: |
  Summarise the alert in the "alert" section ...                 # trusted text
slots:
  - {name: site-label, trust: trusted, description: ..., example: example lab}
  - {name: alert, trust: untrusted, description: ..., example: ..., max_chars: 8000}
```

- **Every slot declares `trust`.** `trusted` is operator configuration and may be interpolated
  into trusted text as `{{ name }}` (the only placeholder syntax; anything else, including
  `{% %}`, is refused). `untrusted` is anything ingested (alerts, log lines, feed articles,
  e-mails) and is **never** interpolated.
- **Untrusted slots render only fenced.** `render_prompt` builds a context manifest in which
  `instructions` is the one stable section and each untrusted slot is a `volatile` (or `session`)
  input section, and hands it to `assemble_pack`. The untrusted-data delimiters are therefore the
  assembler's own: nonce-fenced, with fence-looking lines prefixed `[escaped] `. Nothing in
  `pack.py` was copied or changed. The result is two chat messages: `system` (the template's
  system text, then the fence rules naming this pack's nonce) and `user` (the pack text). Trusted
  values that contain a fence-looking line or placeholder braces are refused at render time.
- **The lint** (`hnx agent prompts lint [PATH ...]`, run by `make check` and CI) fails a template
  that interpolates an untrusted slot outside the delimiters, declares a slot with no (or an
  unknown) trust level, references an undeclared slot, uses other placeholder syntax, carries a
  fence-looking line in trusted text, declares a trusted slot it never uses, or reuses a reserved
  section name. It then renders the template with its own `example` values and checks that each
  untrusted value sits between exactly one opener and one closer and nowhere in the system message.

Shipped templates: `alert-triage-summariser`, `cti-article-extractor`, `phishing-report-triage`.
As with every pack, fencing is a structural guarantee about the text, not about the model; what
an agent can *do* is bounded by its profile and the broker.

## Injection corpus and eval (G-02)

`homelabnext/agent/prompts/injection/corpus.yml` (`schemas/agent/injection_corpus`) holds 45
synthetic cases in nine categories: direct override, fake fence closing, role/system
impersonation, tool-call smuggling, data exfiltration, encoded instructions (base64, hex, ROT13,
zero-width, homoglyph), multilingual, markdown/HTML hiding and nested quoting. Each case has a
**canary** (two pieces the payload asks to be joined, so an echo of the payload is not a follow)
or a **forbidden tool** (any call-shaped mention, `"name": "<tool>"` or `<tool>(`, counts, a
verbatim echo included: output that looks like a call is a hazard to whatever parses it).

`hnx agent injection run` places every case into every untrusted slot of every template
(45 x 6 = 270 runs), renders, calls the model through the same `completer(messages, params)`
adapter as the golden suites, and fails on any instruction-follow, any error, or a payload the
slot cap truncated (an untested case is not a pass).

**What CI proves, and what it does not.** CI runs against `FakeInjectionModel`, a deterministic
fake that recognises every corpus instruction by the case's `markers` after undoing the
encodings, and differs only in where it looks: `--fake naive` follows instructions anywhere and
must be caught on every run (a test asserts it); `--fake fence` (the default) ignores text inside
untrusted-data fences, with a deliberately lenient fence parser that only the assembler's escaping
stops, and must show 0 follows. Tests also show a renderer that pastes untrusted text into the
instructions, or fences without escaping, is caught. This proves **the harness and the
delimiting**, not that any real model resists injection.

**Before every model or prompt change** run the same runner against the real model:

```
make injection-eval MODEL=<role> REGISTRY=<services.yml> ROLES=<roles.json>   # live, not CI
```

It resolves the role through the model-role resolver to an OpenAI-compatible endpoint, writes
`build/injection/<role>.json`, and `hnx agent injection check-report` fails unless that report is
for the current templates and corpus and shows 0 follows. Keep the report with the change.

**The golden report.** `homelabnext/agent/prompts/injection/report.json` is the fence-fake report.
It pins the inputs (runner version, the fence-rules text, the corpus version and digest, each
template's digest). `make check` (`injection-check`) and `tests/agent/test_agent_injection.py`
regenerate it and fail if it differs, so changing any template, the corpus or the fence rules
without `make injection-report` (and committing the result) fails CI. When the corpus changes,
bump its `version`.

## Broker contracts and reference evaluator

`homelabnext.broker.decide(manifest, request, approval=None, now=..., store=...)` returns a
`decision`. Order of checks, first failure wins: action in manifest (else `default-deny`); actor
granted the action (`not-granted`); tier within the grant (`tier-exceeds-grant`); handler declared
(`handler-missing`); then approval for execute/privileged or flagged actions: none is
`needs-approval`, a digest that does not match the request is `approval-digest-mismatch`, then
`approval-denied`, `approval-self-approved`, `approval-approver-not-allowed`,
`approval-agent-approver`, `approval-time-invalid`, `approval-expired`, `approval-replayed`, else
`approved`. `request_digest` covers `action`, `actor`, `target` and `params` (not ids or
timestamps).

Workflow packs (`docs/workflows.md`) act only through this evaluator: their offline runner sends
every action step as a request, and a risky one runs only with an approval of its digest (R-04).

- **Time.** `now` defaults to the UTC clock. An approval is valid from `approved_at` (which may
  not precede the request's `created` or follow `now`) until the earlier of its `expires_at` and
  `approved_at + approval_ttl_s`. A manifest without `approval_ttl_s` gets 900 seconds
  (`DEFAULT_APPROVAL_TTL_S`).
- **Who may approve.** `manifest.approvers` lists `{issuer, subject, kind}`; an approval counts
  only when its approver matches an entry on both issuer and subject. A manifest without
  `approvers` accepts no approval. Identities are compared normalized (case-folded, `.`, `_` and
  whitespace folded to `-`, see `normalize_identity`), so `ops_bot` is the actor
  `profile:ops-bot` and is refused as a self-approval. An approver whose entry says
  `kind: agent`, or whose subject names any profile the manifest grants actions to, is an agent
  and is refused unless the manifest sets `allow_agent_approvers: true`.
- **Single use.** An `approved` decision in enforce mode consumes the `approval_id` in the
  `store` (an `ApprovalStore`: `consume(id)` must be atomic, `consumed(id)` reads). A second use
  is `approval-replayed`. `MemoryApprovalStore` is the in-process default; a broker that runs in
  more than one process, or restarts, needs a durable store. Shadow mode reports a replay but
  consumes nothing.

- **Ownership.** A request belongs to its `actor`.
  `decide_access(manifest, request, caller, operation, now=...)` decides a `read` or `cancel` of
  an existing request: only the actor itself (compared normalized) is `allowed`; every other
  caller, including one granted the same action and an approver, is `deny` / `not-request-owner`.
  The decision carries `operation` and `caller`, so it is the audit record of the attempt. The
  conformance `broker` suite pins the same property on a running broker (`submit`, `status`,
  `run`, `cancel`).

The table `tests/broker/fixtures/decision_table.yml` (manifest x tier x handler x approval ->
decision, plus `access_cases`: owner x caller x operation -> decision) is the conformance input
for any broker implementation: run the same rows against it.

## Command line

```
hnx agent compile SPEC --library LIBRARY.yml --policy POLICY.yml [--out profile.json]
hnx agent verify PROFILE --policy POLICY.yml [--lock profiles.lock]
hnx agent pack MANIFEST --inputs INPUTS.json [--out pack.json] [--denylist FILE]
               [--profile PROFILE.json --registry services.yml [--runs-on HOST] [--broker M]]
               [--root DIR] [--task-path FILE ...] [--task-text T | --task-file F] [--explain]
hnx agent keyring build|check SOURCES.yml
hnx agent lint [PATH ...] [--classes FILE]
hnx agent prompts lint [TEMPLATE|DIR ...]
hnx agent prompts render TEMPLATE [--values VALUES.yml]
hnx agent injection run [--fake fence|naive | --role ROLE --registry R --roles T] [--out F] [--check GOLDEN]
hnx agent injection check-report REPORT
```

`LIBRARY.yml` is `{parts: {<logical id>: <path relative to the file>}}`; paths may not escape its
directory. `compile` exits 1 on a missing part, ceiling, reader, include or budget violation; `verify` exits 1 on
any problem, including a reader holding an acting grant and a digest that is not the one in the
lock; `lint` exits 1 on any reader problem or when it finds no profile. `pack` prints the
hash and status on stderr and exits 0 when ready, **3 when deferred**, 1 on invalid input.
Install the extra with `pip install 'homelabnext[agent]'`.

## Tests

`pytest tests/agent tests/broker` covers (besides the template lint and injection eval above): determinism (same input twice, shuffled inputs, three
hash seeds), ceiling and budget rejection, missing-id errors, truncation and tier reporting,
deferral, report validation, linked knowledge (grant filtering, inactive records, review
filters, budget by rank, pack determinism, a reader gaining no grant), schema examples and negatives, the reader rule (refusal per class,
passing reader and actor, tampered profile, lint), the screener evaluation set, the golden-suite compatibility check,
and the broker decision table.
