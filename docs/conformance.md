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
hnx conform list                      # the fifteen capabilities (also: hnx conform --list)
hnx conform list --all                # plus the extended suites (backup, dns, edge)
hnx conform run object-store          # against the in-memory fake
hnx conform run all --out build/conform.json
hnx conform run secrets --target broken            # a defective fake: must FAIL, naming the check
hnx conform run object-store --target staging      # a real service, see "Targets" below
hnx conform mutants                   # prove every suite catches its broken fakes
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
  is absent.  *Test hooks* (`clock-control`, `fault-injection`) only let the suite reach a state:
  a `must` check that needs an undeclared hook is **`untested`**, which fails the capability like
  a failure, so not declaring a hook is never a way around a MUST.  Security properties do not
  hide behind a hook at all: token and lease expiry use `tick()` when the subject has it and
  otherwise wait in real time (a one-second ttl).  Skips never count as a pass of anything.
* **Waivers.** A target may waive a `should` check with a written reason; the report shows it.
* Each suite has 6 to 16 checks, at least six of them `must`.
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

The fifteen names are fixed by `docs/interfaces.md`.  Contracts that already have a library
(lake, notify, records, detections, context) reuse it; the rest are the Protocols in
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

Extended suites (listed with `--all`, not among the fifteen): `backup` (immutable snapshots,
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

`hnx conform mutants` and `tests/conform/test_mutants.py` assert each mutant is caught **by that
check**, so a regression in a suite shows up as a named check, not as silence.  The named check
must be a `must` that always executes (no `requires`, not `skippable`): a mutant caught only by a
check that can skip proves nothing about a target on which it skips, and the report counts it as
not caught.  Each conformance gap fixed in a suite ships with the mutant that reproduces it.

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

`capabilities.yml` at the repository root is the list of capabilities this tree declares (the fifteen
names, one per line under `capabilities:`).  The exporter and invariants X-04 and X-10 read it, so a
deployment that adds a capability adds it there and must then ship its suite, or the report and the
invariants go red.  It is a source-tree file: the wheel does not carry it (without it the exporter
falls back to the built-in fifteen).  `make conform-check` (`tools/conform_coverage.py`) runs
`hnx conform list` and `hnx conform report --json` and fails if any of the fifteen lacks a passing
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
   `MUTANTS`: 6 to 16 checks, at least six `must`, each with an id (`kebab-case`), a one-line
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
