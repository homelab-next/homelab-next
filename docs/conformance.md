---
summary: 'The conformance harness: one suite per capability run against any target, how mutants prove a suite can fail, adding a suite, and the X-10 exporter.'
---
# Conformance harness

A capability is *replaceable* when a stranger can prove a replacement honours the same contract
as the incumbent, without reading either implementation.  The conformance harness is that proof:
one **suite** per capability, run against any **target** that implements the capability's
contract.  The same suite passes the in-memory fake, the incumbent product and the candidate that
replaces it.

```
conformance/protocols/   the contract: a small typing.Protocol per capability (+ error types)
conformance/fakes/       an in-memory implementation per capability, and its deliberately broken twin
conformance/suites/      the checks: SUITE, make_fake(), MUTANTS - one module per capability
conformance/<cap>/       test_conformance_<cap>.py: runs the suite under pytest (what invariant X-04 looks for)
conformance/targets/     example target files naming a real implementation
homelabnext/conform/     the harness: suite format, runner, targets, report, `hnx conform`, X-10
```

The reference page of each capability, [docs/capabilities/](capabilities/README.md), is generated
from these files (`hnx docs capabilities generate`; `hnx docs capabilities check` in `make check`
and CI): the Protocol operations and signatures, the data shapes and errors, the check table, the
fake, the target-file adapters with their product limits, and the integration steps.

## Running

```bash
hnx conform list                      # the eighteen capabilities (also: hnx conform --list)
hnx conform list --all                # plus the extended suites (backup, dns, edge, broker-tokens)
hnx conform run object-store          # against the in-memory fake
hnx conform run all --out build/conform.json
hnx conform run secrets --target broken            # a defective fake: must FAIL, naming the check
hnx conform run object-store --target staging      # a real service, see "Targets" below
hnx conform mutants                   # prove every core suite catches its broken fakes
hnx conform mutants broker-tokens     # an extended suite's, named ("all" is the core ones)
hnx conform mutants --all             # every suite's mutants, the extended ones too
hnx conform report --json             # capabilities without a passing test
python -m pytest -q conformance       # the same checks under pytest, one test per check
HNX_CONFORM_TARGET=staging python -m pytest conformance/object-store
```

`hnx conform` needs a source checkout (suites live in `conformance/`); `--root DIR` points at one.
Exit codes follow the repository convention: `0` ok, `1` a check failed, too few checks executed
(or a capability has no passing test), `2` misconfiguration (including a `--check` id no suite
has), `100` the run could not be measured (the subject could not be built, for example the
service is unreachable - neither a pass nor a failure).

`hnx conform run` fails a capability that executed fewer than six checks (or, with `--check`,
none of the selected ones): skips do not count, so a subject on which everything skips cannot
pass.  Under pytest, each `conformance/<cap>/` module also has a `..._enough_checks_executed`
test for the same reason.

## What a suite is

```python
from homelabnext.conform.core import Mutant, Suite

SUITE = Suite("object-store", "S3-like blobs", "conformance.protocols.object_store:ObjectStore")


@SUITE.check("put-get-roundtrip", "bytes written are the bytes read back")
def _(store):  # the subject: any implementation of the Protocol
    store.put("b", "k", b"x")
    assert store.get("b", "k") == b"x"
```

* A check is a function of the **subject**.  It passes by returning, fails by raising
  `AssertionError` (the message is the evidence) or when the subject raises something unexpected.
  A check never raises into the runner.
* **Skipping is the suite's decision, never the subject's.**  Only a check declared
  `skippable=True` may raise `Skip(reason)`, and only from the suite module itself.  A `Skip`
  that comes out of the subject (an adapter that raises the harness's own exception), or from a
  check not declared skippable, is a **failure**.
* Every check gets a **fresh subject** from the target's factory; subjects with `close()` are
  closed.  Real-service adapters give each subject its own namespace so checks stay independent
  (`conformance.suites._util.uniq()` and `HNX_CONFORM_NONCE` namespace what a check creates).
* **Severity.** `must` is part of the contract: a failure fails the capability.  `should` is
  expected behaviour: it is reported, and fails the run only with `--strict`.  A `must` check can
  never be waived.
* **Features.** Optional abilities are a set of names on the subject or in the target file, of
  two kinds.  *Product* features (`streaming`, `embeddings`, `wildcards`, `metadata`) describe
  what the implementation offers: a check with `requires=[...]` is skipped, not failed, when one
  is absent.  *Test hooks* (`clock-control`, `fault-injection`, `approval-control`: an
  approver's decision on a pending request, `decide_request(request_id, verdict)`) only let the
  suite reach a state:
  a `must` check that needs an undeclared hook is **`untested`**, which fails the capability like
  a failure, so not declaring a hook is never a way around a MUST.  The product decides first: a
  check that needs both a product feature and a hook skips when the product feature is absent
  (a target without `admission` has no capacity for a killed worker to leak), and is
  `untested` only when the product is there and the hook is not.  Security properties do not
  hide behind a hook at all: token and lease expiry use `tick()` when the subject has it and
  otherwise wait in real time (a one-second ttl).  Skips never count as a pass of anything.
* **Waivers.** A target may waive a `should` check with a written reason; the report shows it.
* Each suite has 6 to 24 checks, at least six of them `must`: one check per clause of the
  Protocol docstring, so a suite says something and a failure names what broke.  The ceiling
  keeps a suite one readable file and a run against a real service short; a contract with more
  clauses than that is two capabilities.  Do not fold a second clause into an existing check to
  stay under it: a check named for redaction that also fails when a deferred run is broken sends
  the reader to the wrong place.
* Errors are the Protocol's own exception types.  An adapter translates its client library's
  errors into them; that translation is part of what is being proved.

## Targets

A target maps capabilities to adapters.  `fake` and `broken[:MUTANT]` are built in.  Anything
else is a file (YAML or JSON).  A spec containing `/` or ending in `.yml`, `.yaml` or `.json` is a
path (`./staging.yml` for a file in the current directory); a bare word is a *name*, resolved
only from `conformance/targets/NAME.yml` and then `$HNX_CONFORM_TARGETS` - never from the current
directory, so a stray file there cannot stand in for a named target:

```yaml
name: staging
capabilities:
  object-store:
    adapter: my_adapters.s3:make_store     # callable(**config) -> subject
    config: {namespace: conformance}       # keyword arguments; never a raw URL
    features: [metadata]
    waive: {list-unicode-keys: "backend normalises keys"}   # SHOULD checks only
```

The adapter module must be importable (`pip install` it or put its directory on `PYTHONPATH`).
It resolves its own endpoint through the registry resolver (ADR-0002), reads credentials at call
time, and never holds a secret in a `repr`.  The same suite then runs unchanged:

```bash
hnx conform run object-store --target staging
```

**Trust model.**  Conformance assumes an *honest* adapter.  The adapter is imported and runs in
the harness's process with the harness's permissions: the suite proves that an implementation
meets the contract, it is not a sandbox, and it cannot catch an adapter written to deceive it
(one that patches the harness, inspects the suite, or prints a fake report).  Review an adapter
like any other code you run.  To make a result attributable, every run and report records its
provenance: the sha256 of each suite file, the git SHA of the checkout (when there is one) and
the adapter's dotted path and module file (`provenance` in `run --json` and in each report
entry, `git_sha` at the top of the report).

`conformance/targets/lake-iceberg.yml` is a worked example: the real Iceberg lake adapter on a
temporary SQLite catalog passes the same `lake-query` and `lake-catalog` suites as `FakeLake`
(`pip install 'homelabnext[lake]'`).  Without the extra the run is `could not measure`, not a
failure.  From Python: `homelabnext.conform.run("object-store", {"adapter": "pkg.mod:factory"})`.

## The capabilities

The eighteen names are fixed by `docs/interfaces.md`.  Contracts that already have a library
(lake, notify, records, detections, context, projects) reuse it; the rest are the Protocols in
`conformance/protocols/`.

| Capability | Contract (Protocol) | Properties the suite pins |
|---|---|---|
| `lake-query` | `LakeClient` read side | bound parameters (many injection shapes, two placeholders, verbatim round trip), ordering, no duplicate rows, UTC instants, struct columns, errors |
| `lake-catalog` | `LakeClient` write/catalog side | idempotent replay, content-key dedup, atomic rejection, naive timestamps refused, source marks |
| `object-store` | `ObjectStore` | round trips, binary safety, etag tracks content, ordered paginated listing, `..` keys never escape, bucket isolation, error types |
| `inference` | OpenAI-compatible client | models list, requested model echoed, 4xx for unknown models, determinism, streaming, embeddings |
| `fast-classifier` | `Classifier` | label only from the offered set, confidence in [0, 1], determinism, no guessing |
| `notify` | `Sender` + `NotifyTarget` | exactly-once delivery, fidelity, one page per state change, one recovery, failed send retried |
| `cases` | `CaseStore` | dedup, promotion links, dismissal needs a reason, status machine, closed cases reject notes |
| `events` | `EventBus` | order, ack/nack, bounded redelivery, DLQ, msg-id dedup, independent durables, at-least-once across a consumer restart, settle once |
| `orchestration` | `Orchestrator` | idempotency key runs once, bounded retries, cancel, isolation |
| `broker` | `Broker` | per-command allowlist, validated arguments, one audit record per call, secret arguments redacted by schema on every outcome, handler errors opaque, deferred requests bound to their caller (another caller's read, run or cancel is `Denied` with reason `not-request-owner` and audited) |
| `secrets` | `SecretStore` | versions, leases (expiry, unknown ids, ttl > 0), **no value in any error, cause chain, traceback or repr** |
| `idp` | `IdentityProvider` | forged (splice, alg=none, empty or tampered signature), altered, expired, revoked and garbage tokens are always `InvalidToken`, on JWTs and compact tokens alike |
| `records` | `RecordsTarget` | validated notes, agent lane only, never overwrite, completion of approved notes only and all-or-nothing, `..` names refused on every verb |
| `detections` | `DetectionTarget` | must-fire fire, must-not-fire stay silent, deterministic, no mutation |
| `context` | `ContextStore` | mandatory exact scope (nothing outside it as a hit, snippet, error or relation path), inactive records excluded, relation outranks keywords, deterministic order with ties by id, budget prefix, re-index replaces, delete removes, hostile text, byte-exact content and digest |
| `projects` | `ProjectStore` | the board rules (a step belongs to an open project, a project closes in the same write as its last step and stays closed, a finished item carries a result, blocks hold), UUIDv7 uids, idempotent create by external key, optimistic versions (a stale one conflicts, every change adds one), a complete change feed, links that resolve, no cycles; also proved on OpenProject over a recorded fake (`tests/projects`) |
| `codemode-executor` | `CodeExecutor` | one program per fresh sandbox (ADR-0031 decision 5), in the vocabulary of `schemas/codemode`: no connection or name lookup but the broker endpoint (served where the executor declares, `broker_bind`), no caller environment, files or token in the sandbox environment, CPU, resident-memory, wall-clock and output caps end the run as `limit` naming the cap, the call cap refuses a call as `call-cap-reached`, nothing survives into the next run, an oversized value comes back as a truncated prefix of its pinned JSON, errors are `{kind, message}` with a bounded single-line message, a denial's reason reaches the program, a pending call pauses the run however the program catches it, programs over 65536 characters or not UTF-8 text are refused; the client-side pause and call cap are behaviour, the broker's refusal on the token (CM-5) is the enforcement; checks hold their programs per language and a declared language without one is untested; the reference fake forks each run from a warm process and puts it behind an audit hook, test-only and not a boundary |
| `codemode-runner` | `CodemodeRunner` | the handler of `codemode.execute` (ADR-0031 decisions 2, 6, 7 and 10), asked through the broker as an agent: a result that is the `schemas/codemode/execution_result` (the actor, the program's code digest, every call with its request ids, printed output as single lines), a broker refusal reaching the program as `broker.Denied` with the broker's reason and recorded as a denied call (with request ids once the broker built the request, none for a token refusal), a `journal_step` record of every call the broker answered with a request id, a submit pausing the run with `pending` naming it and nothing sent after, a resume answering journalled steps from the journal (`replayed`) and running the paused request by its id without sending a journalled step again, a resume refusing a call that differs from the journal's, a denied pause told to the program as `request-denied`, and the broker's `call-cap-reached` ending the run `limit` (`calls`); proved over the fake broker and the reference service (`broker-reference`), with the forking test executor |

Extended suites (listed with `--all`, not among the eighteen): `backup` (immutable snapshots,
verified restores, retention), `dns` (zone semantics the registry's aliases rely on) and `edge`
(reverse-proxy routing and forward-auth hygiene).

## Proving the suite can fail: mutants

A test that cannot fail proves nothing.  Every suite module defines `MUTANTS`: deliberately
defective fakes (the lake returns duplicate rows, notify sends twice, secrets leaks a value in an
error, the broker audits secret arguments, ...), each mapped to the check that must catch it:

```python
MUTANTS = {
    "error-leaks-value": Mutant(
        LeakyErrorSecretStore,
        "errors-never-contain-values",
        "the invalid-path error echoes the submitted values",
    )
}
```

`hnx conform mutants` (the core suites; name an extended one to run its own, or pass `--all`
for every suite) and
`tests/conform/test_conform_mutants.py` (every suite, extended ones included) assert each mutant is
caught **by that check**, and for the newer suites (`ONLY_ITS_OWN` there) by that check alone, so a regression in a suite shows up as a named check, not as silence.  The named check
must be a `must` that always executes against the mutant (not `skippable`, and every feature it
`requires` declared by the mutant: `Mutant(..., features=frozenset({"admission"}))` says what the
mutant's factory supports, and the mutant runs with those declared): a mutant caught only by a
check that can skip proves nothing about a target on which it skips, and the report counts it as
not caught.  Each conformance gap fixed in a suite ships with the mutant that reproduces it.

**Model the Protocol's clauses, not only the defects you expect.**  A suite that pins only what
its own mutants model passes anything else: a review wrote sixteen defects, each breaking one
sentence of a Protocol docstring, and every one passed its suite - a broker whose `submit` skipped
the allowlist (anyone could queue any command and run it as its owner), an event bus whose stale
`ack` swallowed the live redelivery's `nack` (the reference fake itself did this), records whose
`approve` overturned a denial, secrets that read version `0` as the latest or deleted only the
newest version, an identity provider that matched scopes as substrings, an object store whose
`delete` reached every bucket.  So, when writing or reviewing a suite:

* walk the Protocol docstring sentence by sentence and name the check that fails a subject
  breaking it;
* a second way into the same operation (the broker's `submit`/`run` next to `call`) gets every
  gate the first one has;
* probe the boundary values the type allows, not only the obvious bad one (version `0` and `-1`
  as well as `9`; a `nan` or `inf` ttl as well as `-5`);
* write state twice before checking it is all gone, write it again after deleting it, and change
  what the caller handed over after the call (and what a call handed back);
* name the error a refusal raises, and check that each way in leaves the audit record the
  Protocol promises, refused or not;
* a clause about concurrency (records: "a decision is atomic") is checked with
  `conformance.suites._util.interleavings`: an unpaused run finds the lines of the subject's own
  package (wherever it is installed) and a few of the other source it calls; then, for each line,
  one operation is stopped before it and the other runs whole in between.  The same schedules run
  every time, and a wait only decides when to resume a paused operation, never a verdict.  It
  catches a check-then-act window inside one operation; it cannot catch a race that needs both
  operations preempted (a lock file taken by check-then-create), one behind a network call, or
  one in code it does not trace, so such a check is a `should` that says so, and a run with
  nothing to pause at is "could not judge", not a pass.

A second review of the tightened suites found seventeen more (a broker that kept the caller's
argument mapping and so ran what was changed after validation, a stale `term` that dead-lettered
the live redelivery, a namesake that replaced an approved note, a secret history revived by a
`put` after `delete`, a space-delimited scope claim that turned `"read admin"` into `admin`, a
flat `bucket+key` namespace), and a verify pass of those fixes thirteen more (WorkQueue retention,
a dead-letter list in client memory, a crash loop the reference fake never dead-lettered, a
cached lease shared between holders, a scope gate reading the unverified payload, form-decoded
and case-folded keys, a dotted flat key space, redaction by a name guess, a refusal echoing the
value it refused) plus six racy records deciders.  Each plausible defect is registered in its suite's `MUTANTS`, the one table of
broken fake -> the check that must fail it; `tests/conform/test_conform_protocol_mutants.py`
keeps the record, by name, of which ones review found.

### How to review a suite

A review writes subjects that break one clause of the Protocol each and runs them through the
suite.  An escape is a finding, but not every escape is worth a check.  **The stopping rule:** an
escaped mutant ranks above a nit only if it models a behaviour that a real adapter for that
product class plausibly ships - name the product, the configuration or the common pattern it
models (JetStream's WorkQueue retention, a case-insensitive filesystem under a directory store,
an HTTP front end that form-decodes keys, a logging filter that redacts by name).  A contrived
mutant - one that breaks the clause in a way no implementation would by accident - is a nit:
note it, and do not grow the suite for it.  Only plausible mutants are registered in `MUTANTS`.

Judged contrived in the verify pass, and so not registered: a provider that compares scopes after
NFKC normalisation (the scope grammar is now printable ASCII, so `scope-enforced` refuses the
fullwidth form anyway), and a `Denied` that carries the refused request as an attribute (already
caught).  The records deciders it wrote are plausible, but `decide-is-atomic` is a `should`, so
they are pinned by tests rather than as `must` mutants.

The suites cover the protocol, not the handler behind it.  The broker's `ArgSpec` checks the
shape of arguments, not their content: a validated `str` is still untrusted caller input, and the
command handler is the trust boundary (`conformance/protocols/broker.py`).

## The exporter and invariant X-10

`hnx conform report --json` emits `homelabnext.conform.report/1`:

```json
{"schema": "homelabnext.conform.report/1", "target": "fake", "ok": true,
 "capabilities": {"secrets": {"suite": true, "passing": true, "executed": 11,
                              "failed_must": [], "mutants": [{"name": "...", "detected": true}]}},
 "capabilities_without_passing_test": []}
```

A capability has a **passing test** when its suite exists, executes at least six checks, has no
failing `must` check, and (on the `fake` target) catches every one of its mutants.  Capabilities
named in `capabilities.yml` but lacking a suite are listed too.

`capabilities.yml` at the repository root is the list of capabilities this tree declares (the eighteen
names, one per line under `capabilities:`).  The exporter and invariants X-04 and X-10 read it, so a
deployment that adds a capability adds it there and must then ship its suite, or the report and the
invariants go red.  It is a source-tree file: the wheel does not carry it (without it the exporter
falls back to the built-in eighteen).  `make conform-check` (`tools/conform_coverage.py`) runs
`hnx conform list` and `hnx conform report --json` and fails if any of the eighteen lacks a passing
test; `make conform` runs every suite against the built-in fakes, and the nightly workflow runs
`hnx conform run all` after the lab-in-a-box smoke.

`homelabnext/conform/plugins/x10_conformance.py` is the invariant plugin **X-10, "every
capability has a passing conformance test"** (pillar X; X-04 only asks that a test file
exists).  It runs `hnx conform report --out FILE` and fails naming each capability and why.  It
reads the report from that file, never from the process output (an adapter can print anything),
requires the `homelabnext.conform.report/1` schema, and reports *could not measure* when the
verdict and the exit code disagree.  Register it with the
entry point `x10_conformance = "homelabnext.conform.plugins.x10_conformance:register"` in group
`homelabnext.invariants.checks`, or run `hnx invariants run REGISTER --plugins-dir
homelabnext/conform/plugins`, and add a criterion with `evidence: plugin` and `plugin: X-10`.
Set `HNX_CONFORM_TARGET` to run the invariant against a real target.

## Adding a capability suite

1. **Contract.** Add `conformance/protocols/<name>.py`: a `typing.Protocol`, the error types,
   and a docstring stating the rules in prose.  Reuse a library Protocol when one exists.
2. **Fake.** Add `conformance/fakes/<name>.py`: an in-memory implementation with a `features`
   set, injected clocks, no network.  Add the broken twin(s) next to it.
3. **Suite.** Add `conformance/suites/<name_with_underscores>.py` with `SUITE`, `make_fake()` and
   `MUTANTS`: 6 to 24 checks, at least six `must`, each with an id (`kebab-case`), a one-line
   summary and a precise assertion message.  Test errors and negative cases, not only the happy
   path.
4. **Wire it.** Add the name to `CAPABILITIES` (core, only by changing `docs/interfaces.md`) or to
   `EXTENDED` in `homelabnext/conform/registry.py`; add `conformance/<name>/test_conformance_<name>.py`
   (copy any sibling); for a core capability add it to `capabilities.yml`.
5. **Prove it.** `python -m pytest -q tests/conform conformance` must pass: the fake passes with
   no skips, each mutant is caught by its named check.  A new check ships with a fake update in
   the same change (`docs/interfaces.md` section 6): checks are never removed, only added.

## Findings recorded while building the suites

* The DuckDB-backed lake adapters return `time` columns as naive UTC datetimes while `FakeLake`
  returns aware ones (documented in `homelabnext/lake/duck.py`).  The contract therefore pins the
  *instant* (aware UTC, or a naive wall time that is UTC), not the Python type.
