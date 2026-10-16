# Glossary

**Capability.** A job the platform needs done, named independently of the product that does it
(`lake-query`, `notify`, `detections`). Each capability has a contract, a fake and a conformance
test. Fourteen exist at the first drop; the list is in `docs/interfaces.md` section 3.

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

**Capability alias.** `<capability>.svc.example.internal`; the only address a consumer uses.

**Logical id.** A stable name, `<kind>:<slug>`, that does not change when the thing behind it is
replaced (`det:auth-failure-burst`). Prose and specs cite logical ids, never engine rule numbers.

**Model role.** A named job for a language model (`main-reasoner`, `fast-classifier`, `embedder`,
`redactor`, `summariser`). Only the gateway maps a role to a backend and model id (ADR-0007).

**Tier.** A capacity class used when deciding where work runs: `fast` (small, cheap, low latency),
`main` (larger reasoning model), `escalate` (human or cloud, only by policy).

**Detection.** A Sigma rule with fixtures: `must_fire`, `must_not_fire` and `evasion` sets.

**Decision spec.** A declarative description of how a note is classified and what escalates,
replayed against a gold set before it can change behaviour.

**Invariant.** A property that should be continuously true and that a command can decide today. A
check returns pass, fail, or "could not measure" (exit 100 or above).

**Register.** A human-edited YAML list with a strict schema (a board, a lessons list, runbooks,
invariants) from which pages and JSON are generated.

**Records lifecycle.** propose, approve or deny, complete. Agents write only to `inbox/`; an
operator moves items to `decided/`; a `completion-request` note with a `related:` list closes
approved items (ADR-0010).

**Lab in a box.** The staging stack in `compose/lab-in-a-box/`, small enough for a CI runner.

**SERVER.** A tag for work that needs hardware that is not part of the first drop. Its interface
and a fake ship; the implementation does not.

**Placeholder values.** `example.internal`, `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`,
`2001:db8::/32`, `00:00:5e:00:53:xx`, account id `123456789012`. The only values allowed in
examples, fixtures and prose.
