---
summary: Glossary of the project's terms, such as capability, seam, contract, fake and conformance, each defined in a short entry.
summary_of: outline:sha256:050f5dfb3c4eafcd
---
# Glossary

**Capability.** A job the platform needs done, named independently of the product that does it
(`lake-query`, `notify`, `detections`). Each capability has a contract, a fake and a conformance
test. There are <!-- hnx:gen:fact:capability-count-word -->eighteen<!-- /hnx:gen --> core capabilities (<!-- hnx:gen:fact:capabilities -->`lake-query`, `lake-catalog`, `object-store`, `inference`, `fast-classifier`, `notify`, `cases`, `events`, `orchestration`, `broker`, `secrets`, `idp`, `records`, `detections`, `context`, `projects`, `codemode-executor`, `codemode-runner`<!-- /hnx:gen -->;
`CAPABILITIES` in `homelabnext/conform/registry.py`, also in `docs/interfaces.md` section 3);
fourteen existed at the first drop and the rest were added by later decisions. The
<!-- hnx:gen:fact:extended-count-word -->seven<!-- /hnx:gen --> **extended** suites (<!-- hnx:gen:fact:extended-suites -->`backup`, `dns`, `edge`, `broker-tokens`, `orchestration-features`, `migration`, `log-pipeline`<!-- /hnx:gen -->; `EXTENDED` in the same
file) also carry a conformance directory without being core capabilities. Not to be confused with a **`cap:` id** (a grant class in
`homelabnext/agent/tool_classes.yml`, what an agent profile may use), a **`cap_` group** (an
inventory group that places a role on hosts, ADR-0004) or a **slot** (below).

**Module, slot, provider.** A module (ADR-0027) is one feature's declaration, a `module.yml`
manifest: what it provides and requires, its data, grants and egress. A slot is a named place a
module fills or reaches (`examples/modules/slots.yml`, the slot registry). A provider is the module
that fills a slot with a product; it is the only place a product's name may appear (the
product-name lint).

**Seam.** The boundary between a capability and the consumers of it. A product can be replaced
without touching consumers if, and only if, the seam has a testable contract.

**Contract.** A JSON Schema, a Python protocol, or both, plus examples and negatives that pin down
what crosses a seam.

**Fake.** An in-memory implementation of a contract, used in unit tests, CI and the conformance
harness. A fake that passes while the real product fails is a bug in the fake.

**Conformance test.** A runnable check, per capability, that decides whether an implementation
meets the contract. The same test runs against a fake, a staging deployment and the real thing.

**Swap.** Replacing the product behind a capability using the fixed procedure in ADR-0005: staging
test, shadow run, parity window, cutover by registry change, rollback window, decommission.

**Service registry.** `services.yml`: one hand-written file of facts about each service. Generators
turn it into DNS records, proxy sites, monitors, scrape targets and documents. It is data, never a
running service (ADR-0002).

**Veritas.** The project's single source of truth
([ADR-0028](adr/0028-veritas-single-source-of-truth.md)): every authored file that a generator or a
gate reads as the standard or as a source it copies from. Its public tier is this repository's
contracts and gates (schemas with `schemas/_frozen/`, capability protocols, conformance suites,
schema generators, `tools/` gates and their configuration), profiles, Sigma rules, workflow packs,
prompt templates and fictional examples; its private tier is one site's overlay (registry, site
facts, guests, records, inventory, module selection, secret names; the values stay in the secret
store). Every other copy is generated from it or checked against it; a hand-edited copy is drift.
It is not yet compared with what actually runs.

**Capability alias.** `<capability>.svc.example.internal`; the only address a consumer uses.

**Logical id.** A stable name, `<kind>:<slug>`, that does not change when the thing behind it is
replaced (`det:auth-failure-burst`). Prose and specs cite logical ids, never engine rule numbers.

**Model role.** A named job for a language model (`main-reasoner`, `fast-classifier`, `embedder`,
`redactor`, `summariser`). Only the gateway maps a role to a backend and model id (ADR-0007).

**Tier (decision tier).** A capacity class used when deciding where work runs: `fast` (small,
cheap, low latency), `main` (larger reasoning model), `escalate` (human or cloud, only by policy).
"Tier" alone means this one. Other tiers are always qualified: the **broker action tier** (`read` <
`write` < `execute` < `privileged`, ADR-0017), the **review tier** a change needs (agent check,
agent audit, human approve), the status hub's **summary and detail tiers**, and Veritas's
**public and private tiers** (above).

**TLP label, TLP ceiling.** A label (`clear` < `green` < `amber` < `amber+strict` < `red`) is what
a piece of data carries from its source (ADR-0033); unlabelled data is `red`. A reader's ceiling is
the highest label it may receive. Neither is the **ceiling policy**, which attests where an
agent's or MCP server's data may go (`data_tier`: `local-only` or `cloud-allowed`); ADR-0033
decision 12 derives `data_tier` from a TLP ceiling.

**Lane.** A directory a writer may put files in under fixed rules: the records lanes (`inbox/`, the
only agent-writable one, and `decided/...`, ADR-0010) and the broker's write lanes (`lanes:` in a
broker manifest, written only by its built-in lane handler, ADR-0017).

**Detection.** A Sigma rule with fixtures: `must_fire`, `must_not_fire` and `evasion` sets.

**Decision spec.** A declarative description of how a note is classified and what escalates,
replayed against a gold set before it can change behaviour.

**Invariant.** A property that should be continuously true and that a command can decide today. A
check returns pass, fail, or "could not measure" (exit 100 or above).

**Register.** Human-edited records with a strict schema from which pages and JSON are generated:
lessons and runbooks are one Markdown file per record, invariants one YAML list
([registers](registers.md)).

**Pitfall / practice.** The two kinds of lesson: a problem with a root cause and a control, which
graduates into a mechanism (`retired_by`); a method that works, which graduates into a procedure
(`incorporated_into`). An active lesson of either kind is backlog.

**Review (of a record or page).** An entry of its `reviews:` list (agent check, agent audit,
human approve) that counts only while its content digest matches; the policy says which a status
needs (`homelabnext/reviews.py`, `examples/review-policy.yml`).

**Audit review / auditing.** The `audit` review role: an independent agent audit that looks for
what is wrong, missing or unproven, by a different agent than every `check`. Auditing tools,
internal assessments and the authorized scope (the operator's own lab) are defined in
[Terms and scope](terms.md), which every agent session's context pack carries.

**Records lifecycle.** propose, approve or deny, complete. Agents write only to `inbox/`; an
operator moves items to `decided/`; a `completion-request` note with a `related:` list closes
approved items (ADR-0010).

**Lab in a box.** The rehearsal stack in `compose/lab-in-a-box/`, small enough for a CI runner. It
is not a staging environment: its services run in dev mode with known credentials and no
authentication, bound to loopback (see [architecture.md](architecture.md), "The reference
environment").

**SERVER.** A tag for work that needs hardware that is not part of the first drop. Its interface
and a fake ship; the implementation does not.

**Placeholder values.** `example.internal`, `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`,
`2001:db8::/32`, `00:00:5e:00:53:xx`, account id `123456789012`. The only values allowed in
examples, fixtures and prose.

**Strategy.** The one record a lab's strategy-to-task layer hangs from (`docs/strategy.md`):
mission, intent, end state, priorities of work, assumptions and constraints (each with an owner).

**SO / OO / TO / TT.** The objective cascade: a strategic objective (an enduring end state), an
operational objective (a decomposition of an SO), a tactical objective (assignable work under an
OO) and a tactical task (a step of a TO). Each is measured by MOPs and MOEs.

**MOP / MOE.** A measure of performance asks whether the work is being done; a measure of
effectiveness asks whether it is working. Activity counts are MOPs, never MOEs. Each measure has
seven fields: id, objective, definition, source, value and time, target, confidence and thinness.

**Requirements: CCIR, FFIR, PIR.** The three types of requirement: a commander's critical
information requirement (what the owner needs to know to decide), a friendly force information
requirement (what the lab needs to know about its own readiness and posture) and a priority
intelligence requirement (what we need to know about the environment or an adversary). An FFIR may
serve CCIRs, a PIR CCIRs or FFIRs; every requirement supports objectives.

**LTIOV.** Last time information is of value: the date after which an answer no longer helps. An
RFI past its LTIOV is expired by the sweep.

**RFI.** A request for information: a question raised by a gap (a red or not-measurable measure,
an unmet requirement), triaged into a CR or a PR, closed by an answer, a no-find or expiry.

**CR / PR.** A collection requirement (the answer needs data the lab does not hold, so it must be
collected) and a production requirement (the lab holds the data and must produce the answer): the
two triage outcomes of an RFI.
