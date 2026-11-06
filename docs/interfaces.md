---
summary: 'The interface index: ownership map, package layout and signatures, command line, library surfaces, registry naming, logical ids, schemas and version policy.'
summary_of: outline:sha256:4b75245702ae5a49
---
# Interface index

This page fixes the names every task writes against, so parallel work never edits another task's
files. It is the contract of the repository skeleton (task W1). A task may **extend** what its
section says; it may not rename or break it. A change another task needs is requested in
an issue or pull request and decided by the skeleton owner. Anything marked SERVER needs
hardware that is not part of the first drop: document the interface and ship a fake instead.

## 1. Ownership map

| Path | Owner | Notes |
|---|---|---|
| `LICENSE NOTICE README.md CONTRIBUTING.md SECURITY.md CODE_OF_CONDUCT.md CHANGELOG.md pyproject.toml Makefile .pre-commit-config.yaml .github/workflows/ci.yml` | W1 | README has a marked quick-start section handed to W12 |
| `docs/adr/ docs/interfaces.md docs/glossary.md tools/leak_scan.py tools/check_*.py tools/tests/` | W1 | |
| `homelabnext/__init__.py homelabnext/_version.py` | W1 | no one else creates these |
| `schemas/{ids,events,records,registers,platform}/ tools/schema_check.py homelabnext/ids/` | W2 | |
| `schemas/ocsf/ homelabnext/lake/ tests/lake/` | W3 | |
| `homelabnext/registry/ homelabnext/generators/ generators/ examples/services.yml tools/no_raw_endpoints.py` | W4 | `registry/models.py` is W7 |
| `homelabnext/{notify,state,records}/ tests/{notify,state,records}/` | W5 | |
| `conformance/ homelabnext/conform/ homelabnext/cli.py` | W6 | `hnx conform` |
| `homelabnext/{decide,golden}/ homelabnext/registry/models.py tests/{decide,golden}/ conformance/fakes/openai_server.py` | W7 | |
| `docs/role-interface.md ansible/ homelabnext/generators/fleet_units.py tools/role_lint.py homelabnext/scaffold/` | W8 | |
| `detections/ homelabnext/detections/ tests/detections/` | W9 | |
| `homelabnext/{registers,invariants}/ tools/register_ids.py docs/checklist.md examples/registers/` | W10 | |
| `homelabnext/network/ schemas/platform/site.schema.json docs/network-model.md tests/network/` | W13 | |
| `homelabnext/compute/ schemas/platform/guest.schema.json docs/compute-model.md tests/compute/` | W14 | |
| `homelabnext/customization/ profiles/ schemas/platform/customization.schema.json docs/customization.md tests/customization/` | W15 | |
| `homelabnext/{agent,broker}/ schemas/{agent,broker}/ docs/{agent,broker}.md tests/{agent,broker}/ examples/broker/` | W18 | `hnx broker` |
| `tests/integration/ tests/packaging/` | integration | cross-package end-to-end tests |
| `homelabnext/{swap,parity}/ tools/decommission_check.py tests/swap/` | W11 | |
| `compose/lab-in-a-box/ .github/workflows/nightly.yml docs/build-order.md docs/architecture.md` | W12 | |
| `conformance/{protocols,suites}/codemode_executor.py conformance/fakes/{code_executor,code_executor_child}.py conformance/codemode-executor/` | codemode | ADR-0031 decision 10; docs/codemode.md CM-4 |
| `homelabnext/codemode/{runner,journal,mcp_tools}.py conformance/{protocols,suites}/codemode_runner.py conformance/fakes/codemode_runner.py conformance/codemode-runner/ examples/mcp/hnx-codemode.yml` | codemode | ADR-0031 decisions 3, 7 and 10; docs/codemode.md CM-5b |
| `homelabnext/projects/ conformance/{protocols,suites}/projects.py conformance/fakes/{project_store,openproject_api}.py docs/projects.md tests/projects/ examples/projects/` | projects | `hnx projects`; ADR-0020 |
| `homelabnext/novelty/ schemas/platform/novelty_spec.schema.json schemas/ocsf/novelty_finding.v1.json docs/novelty.md tests/novelty/ examples/novelty/` | novelty | `hnx novelty`; ADR-0036 |

Rules that apply to every task: Python >= 3.11, standard library first; an SPDX header on every
source file; no network in tests; clocks and randomness injected; no real identifiers (see
`CONTRIBUTING.md`); tests live under `tests/<package>/` (or `<package>/tests/` for a separate
distribution) and run with `python -m pytest -q <dir>`.

## 2. Package layout

One distribution, `homelabnext`, one namespace, one console script `hnx = homelabnext.cli:main`
(module owned by W6). Each sub-package has its own `__init__.py`, is importable with only the core
dependencies unless its extra says otherwise, and ships an in-memory fake.

```
homelabnext/
  ids/          logical ids                         (W2)   core
  registry/     service registry + resolver         (W4)   core;  models.py (W7)
  generators/   registry -> artefacts, goldens      (W4, fleet_units W8)   extra: generators
  lake/         query, catalog, write, fakes        (W3)   extras: lake, trino
  notify/       state-diffed, dedup-keyed send      (W5)   core
  state/        cursors and history, atomic writes  (W5)   core
  records/      propose/finding/completion          (W5)   core (the records extra is unused)
  decide/       decision specs, replay, eval        (W7)   core (the decide extra is unused)
  golden/       golden-task format and runner       (W7)   core
  models/       model store manifest, serving plan  (ADR-0023)  core (+ yaml for the serving spec)
  paths.py      locates schemas/, profiles/, examples/  (W16)  core
  conform/      conformance harness core            (W6)   core (+ yaml for target files)
  swap/         nine-step swap runner and record    (W11)  extra: swap (= yaml + schema)
  parity/       parity and drift tools              (W11)  core (uses lake and notify)
  detections/   fixtures, engine adapters, det: map (W9)   extra: detections
  logpipeline/  runtime label table and enrich rule (docs/log-pipeline.md)  core
  novelty/      novelty baselines, corroborate      (ADR-0036, docs/novelty.md)  core (+ yaml for specs; reads via lake)
  registers/    register schemas -> HTML/JSON       (W10)  core
  invariants/   runner, check plugin API            (W10)  core
  scaffold/     `hnx new ...` templates             (W8)   core
  network/      site model, IR, adapters            (W13)  core + core extra (PyYAML, jsonschema)
  compute/      guest model, validation, renderers  (W14)  core + core extra
  customization/ lab/vendor customizations, X-09    (W15)  core + core extra
  cli.py        argparse entry point                (W6)
```

### 2.1 Initial signatures

These are the shapes the other sections of the repo are written against. Owners may add
parameters with defaults and new functions; they may not change what is listed.

```python
# homelabnext.ids
@dataclass(frozen=True)
class LogicalId: kind: str; slug: str                # str(x) == f"{kind}:{slug}"
def parse(text: str) -> LogicalId                    # raises ValueError
def is_valid(text: str) -> bool

# homelabnext.registry
class ResolutionError(Exception): ...                          # .capability, .trail (what was tried)
class UnknownCapability(ResolutionError): ...
class InvalidOverride(ResolutionError): ...
@dataclass(frozen=True)
class Endpoint: capability: str; scheme: str; host: str; port: int; source: str   # source: env|dns|hosts; .url
def load(path: str | os.PathLike) -> Registry                  # raises RegistryError
class Resolver:
    def __init__(self, registry: Registry | None = None, *, domain: str | None = None,
                 dns: DNSBackend | None = None, hosts: Mapping | None = None,
                 environ: Mapping[str, str] | None = None)
    def alias(self, capability: str) -> str                    # '<capability>.svc.example.internal'
    def resolve(self, capability: str) -> Endpoint             # env override, then DNS SRV, then hosts
def resolve(capability: str, **resolver_kwargs) -> Endpoint    # raises ResolutionError, never a default

# homelabnext.lake   (protocols; real adapters and in-memory fakes both implement them)
class LakeQuery(Protocol):
    def query(self, sql: str, params: Mapping[str, Any] | None = None) -> list[dict[str, Any]]: ...
    def named(self, name: str, params: Mapping[str, Any] | None = None) -> list[dict[str, Any]]: ...
class LakeWriter(Protocol):
    def write(self, table: str, rows: Sequence[Mapping[str, Any]], *, batch_id: str) -> int: ...
    # commit-then-checkpoint: a retried batch_id after a crash writes zero duplicate rows
# additive (see 2.3): describe(table), list_tables(), write_batch(...) -> WriteResult

# homelabnext.paths  (where schemas/, profiles/ and examples/ live; wheel, editable and checkout alike)
resource_dir(kind) / schemas_dir() / schema_file(*parts) / ocsf_dir() / profiles_dir() / examples_dir()
example_file(*parts) / data_root() / source_root() / clear_cache()    # kind in {schemas, profiles, examples}
# order: HNX_<KIND>_DIR (HNX_DATA_DIR for the whole tree) -> homelabnext/_data/<kind> (wheel) -> checkout;
# every function takes env=, package_root=, source_root= for tests; ResourceNotFound lists the places tried.

# homelabnext.notify
@dataclass(frozen=True)
class Message: key: str; title: str; body: str; level: str = "info"   # level: info|warn|crit
    # also priority, tags, topic, email, click; tlp: str | None = None, the label it claims (ADR-0033)
class Sender(Protocol):
    def send(self, message: Message) -> None: ...
class Notifier:
    def __init__(self, sender: Sender, store: StateStore, clock: Callable[[], float]): ...
    def report(self, key: str, state: str, message: Message) -> bool   # True if a message was sent
    # same (key, state) twice sends once; a return to 'ok' sends one recovery message

# homelabnext.state
class StateStore:
    def __init__(self, path: str | os.PathLike): ...
    def get(self, key: str, default: Any = None) -> Any
    def put(self, key: str, value: Any) -> None                # atomic: write temp, fsync, rename

# homelabnext.records
class Records:
    def __init__(self, root: str | os.PathLike, clock: Callable[[], datetime]): ...
    def propose(self, note: Mapping[str, Any]) -> Path         # validates; writes only under inbox/
    def completion_request(self, related: Sequence[str], body: str, *, agent: str) -> Path
def validate_note(note: Mapping[str, Any]) -> None             # raises ValueError naming the field

# homelabnext.conform
@dataclass(frozen=True)
class CheckResult: check: str; ok: bool; evidence: str
class Capability(Protocol):
    name: str
    def checks(self) -> Sequence[Callable[[Any], CheckResult]]: ...
def run(capability: str, target: Mapping[str, Any]) -> list[CheckResult]

# homelabnext.detections
class Engine(Protocol):
    def evaluate(self, rule: Mapping[str, Any], events: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]: ...

# homelabnext.invariants
class Status(enum.IntEnum): PASS = 0; FAIL = 1; UNMEASURABLE = 100     # >=100 means "could not measure"
@dataclass(frozen=True)
class Result: id: str; status: Status; evidence: str
Check = Callable[[Mapping[str, Any]], Result]                           # the plugin API
```

### 2.2 Command line

`hnx` sub-commands are rows in `COMMANDS` in `homelabnext/cli.py` (name, one-line help, handler that
imports its package lazily). Current names, in that order: `registry`, `new`, `gen`, `detections`,
`registers`, `invariants`, `strategy`, `projects`, `records`, `orchestration`, `reviews`, `ids`, `decide`, `models`,
`golden`,
`site`, `guests`, `schema-check`, `secrets`, `swap`, `conform`, `decommission`, `docs`, `agent`, `workflows`,
`scripts`, `events`, `status`, `graph`, `mcp`, `broker`, `codemode`, `modules`, `custom`,
`ssh-ca`, `novelty`.
`parity` is a library only (the swap runner calls it; no sub-command).
Exit codes everywhere: `0` ok, `1` a check failed, `2` misconfiguration or bad input, `>=100` the
check itself could not measure.

### 2.3 Library surfaces added in the second drop

Names below are the stable entry points; each package's own module docstring and `__all__` are the
full list. Everything runs without a server: each has an in-memory fake or a pure function, and
anything that needs hardware is documented as SERVER rather than implemented.

```python
# homelabnext.lake   (extra: lake; imports of duckdb / pyiceberg / trino are lazy -> MissingExtra)
class LakeClient(LakeQuery, LakeWriter, Protocol):
    def describe(self, table: str) -> TableInfo
    def list_tables(self) -> list[str]
    def write_batch(self, table, rows, *, idempotency_key: str, source=None, high_water=None,
                    expect_source=None) -> WriteResult   # a replay is judged by expect_source, else source
FakeLake(schemas=None, *, named_queries=None)                # in-memory, same contract as the adapters
DuckDBLake(tables, schemas=None, ...)  IcebergLake(catalog, schemas=None, *, namespace="ocsf")
TrinoLake(*, catalog, schema, user, resolver=None, ...)     # endpoint via the registry resolver
Ingestor(client, checkpoint, *, table, source)               # commit-then-checkpoint, idempotent retry
# OCSF table schemas come from schemas/ocsf/*.v1.json (located by homelabnext.paths; override: HNX_SCHEMAS_DIR); cassette parity
# (CassetteLake / record / compare) pins that every adapter returns the same rows.

# homelabnext.notify
Notifier(sender, store, clock=time.time, rate_limit=None, namespace="notify")
    .register_pair(problem_title, recovery_title); .report(key, state, message) -> bool; .state_of(key)
NtfySender(endpoint=None, *, default_topic=None, auth=None, opener=None, ...) ; FakeSender()
# a problem with no registered recovery pair raises UnregisteredProblem; SendError on delivery failure

CeilingSender(inner, ceiling)      # ADR-0033: a message above the channel's ceiling becomes a withheld notice
record_in(directory, owner) -> PairsRecord | None   # the census record of the pairs a notifier holds

# homelabnext.tlp   (ADR-0033 decision 1; standard library only)
class Label(enum.Enum): CLEAR; GREEN; AMBER; AMBER_STRICT; RED     # ordered; str() is the canonical spelling
parse(value) -> Label           # a declaration: raises on anything but an accepted spelling
read(value) -> Label            # a carried label: anything else is RED
allows(ceiling, label) -> bool; strictest(labels) -> Label; at_or_below(ceiling) -> tuple[str, ...]
item_label(declared, item, *, honour_item_labels=False) -> Label   # decision 3
row_filter_sql(ceiling, column="tlp") -> str | None

# homelabnext.tlp_egress   (decision 13; where each egress point applies it: docs/modules.md)
egress_label(claimed, *, recorded, body=None) -> Label   # strictest of claim, record and body markers
egress_check(ceiling, claimed, *, recorded, body=None) -> EgressDecision
markers(body) -> list[Label]; job_label(records, submitter_ceiling) -> Label
analyzers_for(job, maxima) -> list[str]   # a declared maximum that is not canonical raises ValueError

# homelabnext.logpipeline   (docs/log-pipeline.md)
enrich(event, observed, table: RuntimeTable)     # labels.hnx_runtime
enrich_tlp(event, route, table: SourceTable)     # labels.hnx_tlp, from the route's declaration

# homelabnext.lake: TLP (decisions 5 and 6) and the Trino REST adapter
TrinoRestLake(trino: TrinoHTTP, catalog: RestCatalog, *, namespace, trino_catalog="iceberg", ...)
lake.rows.row_from_event(event, schema) -> dict     # the row's tlp is labels.hnx_tlp, never the event's tlp
lake.ceiling.reader_for(lake, reader, tlp_readers, schemas) -> CeilingReader  # the declared ceiling; none: refused
lake.ceiling.CeilingReader(lake, ceiling, schemas, *, grant=None)  # .select(table, ...) filtered; raw .query only at red, which needs a RedGrant
CeilingReader.count_by(table, entity, values, *, since, until, time_column="time", where=None, limit=10000) -> list[GroupCount]
    # ADR-0036: (entity, values, UTC day, label, count) groups; dotted column paths checked against the schema;
    # ceiling filter + per-group label recheck; > limit groups raises TooManyGroups; adapters declare sql_dialect
    # only_entities=/skip_entities= (<= MAX_ENTITIES); no values: per entity (no entity: per day); typed keys
CeilingReader.cardinality(table, entity, values, *, since, until, above, time_column="time", where=None, limit=MAX_ENTITIES) -> dict
lake.ceiling.raw_query(lake, grant: RedGrant, sql, params=None)   # the one raw read outside homelabnext/lake/ (raw_named likewise)
lake.backfill.plan(schema, *, table, sources: Mapping[str, Source], source_map, source_column=None)
    # Source(label, honour_item_labels=False, items_carried_no_labels=False): red unless recorded

# homelabnext.novelty   (ADR-0036, docs/novelty.md; schemas platform/novelty_spec, ocsf/novelty_finding)
load_spec(path, schemas) -> Spec; parse_spec(doc, schemas) -> Spec   # SpecError names every problem
run(reader: CeilingReader, spec, as_of, *, writer=None, limit=MAX_GROUPS) -> list[ProfileResult]
    # reader = reader_for(lake, "analyzer:novelty", tlp_readers, schemas); writer None = dry run
score_profile(profile, as_of, learn, scoring, history, *, spec_digest="") -> ProfileResult   # pure
corroborate(findings, *, since=None, until=None, min_sources=2) -> list[Candidate]   # >= 2 sources per (entity_kind, entity)
write_findings(writer, rows, *, source, mark, **write_batch_kw)   # WriteRefused: a row of another source, or a foreign mark

# homelabnext.state
StateStore(path, *, schema_version=1, migrations=None, clock=time.time)   # atomic, versioned, quarantines corrupt files
    .get/.put/.update(key, fn)/.delete/.keys/.items
KeyedState(store, namespace="checks", clock=...)            # observe(key, ok), red_for(key), counter/incr, last_seen

# homelabnext.records   (agents write inbox/ only; operator movers live in records.decider, not re-exported)
Records(root, clock, *, agent=None).propose(note, *, body="", slug=None) -> Path
#   agent= binds requesting_agent (a note naming anyone else is refused); unbound, the caller sets it.
#   The real enforcement of decided/ is filesystem ownership, not this library.
Records.completion_request(related, body, *, agent=None, ...) -> Path   # related: decided/approved/<file>.md
RecordsReader(root).list(lane) / .read(lane, name) / .iter_notes(lane)
validate_note(note) / parse_note(text) / render_note(...)   # note schema: schemas/records/note.schema.json

# homelabnext.decide
load_spec(path) -> DecisionSpec ; Cascade(spec, tiers, scanner=None).decide(Item) -> Decision
lint_doc(doc) -> [(rule, detail)] ; lint_paths(paths, root=None) -> (n, [Problem])   # hnx decide lint (decide.lint)
ImpactScanner(tiers).scan(text) ; replay(records, cascade) -> ReplayReport ; gate(report, baseline=None, ...) -> GateResult
handle_decide(cascades, doc)                                 # the /v1/systemone adapter, framework-free
Cascade(spec, tiers, scanner, corroborators={name: fn})      # noise_gate specs: de-escalate only with a reference (K-08)
ModelTier(...).decide(item)                                  # schema-validated reply, retried once, then invalid -> escalate (A-04)
annotate(records, cascade) -> [records + decide_* columns]   # batch/ingest: records in == records out (K-13)
safety.check() -> [SpecResult]                               # hnx decide safety: REQUIRED safety specs pass their cases (K-15)

# homelabnext.golden
pins.run_eval(table, suites, factory, model_name=..., canary_factory=) ; pins.check_report(report, table, suites, *, require_live=False)   # hnx golden pins (G-11); canary_factory(role, binding) -> (completer, "live"|"fake")
load_suite(path) -> Suite ; run_suite(suite, completer, *, role=None, model_id="") -> Report ; score(output, expect)
agentic.run_task(suite, task, mode, completer, backend) -> Trace ; agentic.run_suites(suites, completer, backend_for, corpus, ...)   # Code Mode vs MCP mode (CM-6)
score_check(trace, check)                                    # trace scorers: broker_calls | denied_calls | ungranted_actions | turns
fakes.fake_report(suite_paths, *, fake="fence") ; agentic.check_report(stored, fresh)   # hnx golden codemode --check (scripted fake, fake broker world)
canary.run_canary(suite, completer, *, role=, model_id=, samples=) ; canary.findings(tool, arguments, task) ; canary.raw_findings(text, task)   # hnx golden canary (the egress canary)

# homelabnext.models   (docs/model-serving.md)
store.load(path) -> Store ; store.bindings_problems(store, table, engines=None) -> [str] ; store.check_disk(store, root) -> [str]
store.resolve_binding(store, model_id, *, engine=None, digest=None) -> (Entry | None, why)   # Entry.digest = sha256 of its sha256sum listing
serving.load_plan(path) -> Plan ; serving.render(plan) -> {"vllm_server/instances.yml": text}   # hnx models serving render|check

# homelabnext.network   (site model; pure, no network access)
load_site(path) -> dict ; validate(doc, registry) -> Report(.ok, .errors, .warnings)
build_ir(doc, registry) -> NetworkIR ; adapters.get("linux"|"dnsmasq"|"zonefile"|"unifi").render(ir) -> {path: text}

# homelabnext.compute   (guest model)
load_fleet(directory, zones: ZoneLookup, *, domain="example.internal", policies_path=None, keys_path=None) -> Fleet
open_site(path) -> (ZoneLookup, domain)                      # reads zones through network.load_site
validate(fleet) -> list[Problem] ; render(fleet, target) -> {path: text} ; plan(old_tree, new_tree) -> Plan
registry_hosts.fragment(fleet) / merge_into_registry(registry_doc, fragment)   # guests feed the registry

# homelabnext.customization
load_all(settings) ; discover(root, registry=None, roles_dir=None) -> Universe
lint(items, universe, today, enabled=None) -> list[Finding] ; build_plan(items, universe, today, enabled=None) -> dict
# invariant X-09 (plugins/x09_customizations.py) is registered through the homelabnext.invariants.checks entry point

# homelabnext.paths   (core; the one place that answers "where is schemas/?")
schemas_dir() / schema_file(*parts) / ocsf_dir() / profiles_dir() / examples_dir() / example_file(*parts)
resource_dir(kind) / resource_file(kind, *parts) / data_root() / source_root() / clear_cache()
# kind in {schemas, profiles, examples}.  Order: HNX_<KIND>_DIR, then HNX_DATA_DIR (a whole tree), then the
# wheel's homelabnext/_data/<kind>, then the checkout.  Each function takes env=, package_root=, source_root=
# for tests; ResourceNotFound lists every place tried.  No module under homelabnext/ may locate the data
# itself (tests/paths enforces it).  The wheel carries schemas/, profiles/ and examples/ as data, plus the
# conformance.protocols contracts runtime code imports; the rest of conformance/ (suites, fakes, targets),
# compose/, tools/ and docs/ stay in the source tree.

# homelabnext.agent   (extra: agent = PyYAML + jsonschema; hnx agent; docs/agent.md)
compile_profile(spec, library: PartsLibrary) -> dict     # MissingPartError / CeilingViolation / BudgetError / SpecError
check_ceiling(grants, ceiling) -> list[str]; check_budgets(budgets, cap=None) -> list[str]; verify_profile(profile, *, policy=None, lock=None) -> list[str]
verified_profile(profile, *, policy, lock) -> VerifiedProfile; load_verified_profile(path, policy, lock)  # UnverifiedProfile
# start_session / access_block / MemoryStore / select_knowledge / build_keyring take only a VerifiedProfile
assemble_pack(manifest, inputs) -> (pack, "sha256:...")  # pure; stable -> session -> volatile; status ready|deferred
validate_report(report, pack, pack_hash, manifest=None) -> list[str]
digest_of(obj) -> "sha256:..."                           # canonical JSON digest used everywhere
# homelabnext.grants  (core, dependency-free; the one definition of the broker tiers and the grant lookup)
TIERS; TIER_RANK; grant_for(manifest, actor, action) -> grant | None; tier_exceeds(tier, max_tier) -> bool
# homelabnext.broker  (reference evaluator for schemas/broker; default deny)
decide(manifest, request, approval=None, *, now=None) -> decision; request_digest(request); check_manifest_handlers(manifest, handlers)
# homelabnext.broker.service  (the reference broker service; hnx broker; docs/broker.md; ADR-0017)
BrokerService(state_dir, manifest=None, *, base_dir=, data_root=, handler_docs=(), bus=None, notifier=None,
              resolve_secret=None, clock=...)        # implements conformance.protocols.broker:Broker
BrokerService.from_manifest(path, state_dir, **kw) ; load_manifest(path) -> (manifest, handler_docs)  # ManifestError
validate_manifest(manifest, base_dir) -> (handler_docs, problems)   # schema, handler digests, lanes
.call/.submit(caller, action, params, *, target=None) ; .status/.run/.cancel(caller, request_id) ; .detail(caller, rid)
.approve/.deny(request_id, "issuer:subject", *, note=None) -> approval ; .pending() ; .audit() ; .audit_documents(**match)
# homelabnext.broker.lanes: Lane, write(lane, data_root, actor, params, now), LaneError(.reason, .outcome)
# homelabnext.broker.execute: run_handler(path, digest, *, params, run_dir, timeout_s, argv, env, secrets, resolve_secret,
#   max_output) -> ExecResult ; file_digest(path) ; ExecError(.reason) ; env_secret_resolver()
# homelabnext.broker.state: StateDir(root), FileApprovalStore(dir) (durable ApprovalStore), write_exclusive(path, data)
# homelabnext.workflows  (hnx workflows validate|run|digest|st2; docs/workflows.md; schemas/workflows)
validate_repo(paths=(), *, root=None, deploy=None) -> Report ; check_pack(doc, universe) -> [(rule, detail)]
run_fixture(pack, fixture, *, manifest, spec_labels=None, executor_factory=BrokerExecutor) -> RunResult ; pack_digest(doc)
# homelabnext.workflows.st2: render(binding, packs, *, pins, manifests, clean, tracked) -> Rendered(files, problems) ;
#   render_repo(root) ; drift(files, out_dir, base) ; write(files, out_dir) ; rule_criteria(trigger) ; cron_params(cron)
# homelabnext.workflows.st2_runtime: admit(*, pack, trigger, event|schedule, coalesce, kv) ; step(config, **params) ;
#   run_step(*, pack, actor, step, event, steps, calls, mode='shadow', risky, broker) ; schedule_event(id, fired_at)

# homelabnext.swap   (extra: swap = PyYAML + jsonschema; hnx swap; docs/swap.md; ADR-0005)
STEPS: tuple[str, ...]                  # declare, shadow-start, dual-write, parity-compare, soak, cutover,
                                        # rollback-window, decommission-check, close
class Backend: ...                      # conformance(role), shadow_start(), start_mirror(), parity(), apply_route(t),
                                        # verify_route(t), stop_old(), start_old(), decommission_scan() -> Outcome
ManualBackend(...)                      # gates satisfied by attestation files; the flip and the scan are real
LakeBackend(old, new, *, tables, registry_path, service, new_host, queries=(), sample=None, smoke=None, ...)
SwapRunner.create(record_path, backend, *, swap_id, capability, from_adapter, to_adapter, service, before, after,
                  plan=None, registry=None, clock=..., actor=...) -> SwapRunner
    .advance(dry_run=False, closure=None) -> AdvanceResult   # raises GateFailed when a gate refuses
    .rollback(reason) -> dict                                # RollbackRefused after decommission
    .status() / .record() / .note(text)
plan_flip(registry_doc, service, host=..., port=..., impl=..., version=...) -> FlipPlan ; flip_text(text, plan)
DualWriter(primary, secondary) ; Retired(...) ; scan(roots, retired, registry=..., allow=...) -> list[Finding]
# homelabnext.swap.record: new_record/load/save/problems/verify_evidence/dumps/head/verify_anchor (hash-chained
#   transition log with state digests, optional HMAC key via HNX_SWAP_CHAIN_KEY; schema platform/swap_record 1.1).
#   homelabnext.swap.events.step_events(record, *, source=None) -> list[event] turns the transition log into homelabnext.swap.step events (schema events/swap.step 1.1).

# homelabnext.parity   (core; no sub-command)
compare_tables(left, right, tables, *, sample=None, min_rows=0) -> ParityReport
compare_queries(left, right, queries: Sequence[ParityQuery]) -> ParityReport
compare_event_streams(old, new, EventRules(...)) / compare_notifications(old, new, NotifyRules(...)) -> ParityReport
schema_drift(left_table_info, right_table_info) -> list[Drift] ; diff_rows(left, right, RowRules(key=(...))) -> RowDiff
ParityReport(.ok, .checks, .merge(other), .summary(), .digest(), .to_dict())   # the digest goes into swap evidence

# homelabnext.conform   (hnx conform list|run|mutants|report; docs/conformance.md)
Suite(name, summary, protocol) ; @suite.check(id, summary, *, severity="must", requires=()) ; Mutant(factory, fails, description)
run(capability, binding_mapping, root=None) -> list[CheckResult]           # {"fake": True} or {"adapter": "pkg.mod:factory", ...}
run_capability(capability, target, root=None, *, only=None) -> CapabilityRun  # target: "fake" | "broken[:M]" | file | name
build_report(root=None, target="fake", ...) -> dict                          # capabilities_without_passing_test
CAPABILITIES (eighteen) / EXTENDED (backup, dns, edge, broker-tokens, orchestration-features, migration, log-pipeline) ; ConformError (misconfiguration, exit 2)
# the suites, Protocols and fakes live in conformance/ of the source tree (hnx conform --root DIR); an
# installed wheel lists the eighteen names and says "no suite" until pointed at a checkout.
# invariant X-10 (plugins/x10_conformance.py) is registered through the homelabnext.invariants.checks entry point.

# homelabnext.projects   (hnx projects; docs/projects.md; ADR-0020; contract conformance/protocols/projects.py)
ProjectStore(backend, *, records=callable->uids, clock=, new_uid=) ; MemoryBackend() ; MarkdownBackend(dir)
  .create(kind, title, *, project, parent, external_key, status, assignee, due, description) -> WorkItem
  .get(uid) / .list(*, kind, status, project, assignee, linked_to) / .update(uid, version, **fields)
  .close(uid, result, *, version) / .link(uid, target, relation) / .unlink(...) / .changes_since(cursor) -> ChangeSet
  .records() / .check() -> list[str]          # board rules over hand-edited files
markdown_store(dir, *, strategy=DIR) ; strategy_records(root) -> {uid, type, title, parent_uid, links}  # the strategy seam (ADR-0019 loader)
resolve_record(ref, root) (uid, display number or legacy code) ; events.change_event(change, origin=) -> homelabnext.project.changed
measures.completion_reading(items, mop, now=) (MOP only) ; pages.ProjectsSite (hnx status serve --projects DIR)
# homelabnext.projects.openproject: OpenProjectClient, load_config, discover, doctor, openproject_store(cfg),
#   sync_strategy(client, cfg, setup, records, apply=), ChangeFeed(backend, sink).poll/on_webhook, make_webhook_server, adopt
```

### 2.4 Swap, conformance and paths: how they fit

* **Contract first.** A swap is declared against a capability (`cap:<name>`); its first and second steps run
  the capability's conformance suite against the incumbent and the candidate (`hnx conform run`), so the
  same checks that prove a fake prove the real thing. A capability with no passing suite (invariant X-10) has
  nothing to prove a swap against.
* **Evidence is files.** Every step writes an evidence file under `<swap-id>.evidence/`; the record stores
  its hash, and `hnx swap record --verify` recomputes the chain (see docs/swap.md for what that does and
  does not prove). Parity reports enter as evidence by digest.
* **Events.** `homelabnext.swap.events.step_events` renders the record as `homelabnext.swap.step` events
  (steps 1..9 named as in the record; `events/swap.step` 1.1 added those names additively, 1.0 names stay
  valid). Publishing is the caller's job (the event bus is itself a capability).
* **Where data lives.** `homelabnext.paths` is the only locator; the swap record schema, the OCSF subsets
  and the minimal example lab are read through it, in a checkout and from an installed wheel alike.

## 3. Registry and naming

- Registry file: `services.yml` (the example lives at `examples/services.yml`), validated by
  `schemas/platform/service.json`. A service row has at least: `name` (logical id slug), `guest`,
  `ports` (named), `hostname`, `auth`, `health`, `metrics`, `backup`, `depends_on`, `version`,
  `impl` (current product), `replaced_by` (optional).
- Capability alias: `<capability>.svc.example.internal`, for example
  `lake-query.svc.example.internal`. The suffix is a registry setting (`domain:`), `example.internal`
  in everything public. Aliases are generated, never typed.
- Capability names (<!-- hnx:gen:fact:capability-count-word -->eighteen<!-- /hnx:gen -->, also the `hnx conform --list` output):
  <!-- hnx:gen:fact:capabilities -->`lake-query`, `lake-catalog`, `object-store`, `inference`, `fast-classifier`, `notify`, `cases`, `events`, `orchestration`, `broker`, `secrets`, `idp`, `records`, `detections`, `context`, `projects`, `codemode-executor`, `codemode-runner`<!-- /hnx:gen -->.
- Addresses in examples: `192.0.2.0/24` services, `198.51.100.0/24` management,
  `203.0.113.0/24` external, `2001:db8::/32` IPv6, MACs `00:00:5e:00:53:xx`.
- No library or role contains a default endpoint. An unresolvable capability raises the registry's
  `ResolutionError` (with the list of what was tried); the lake adapters, which take an endpoint
  from the caller, raise `homelabnext.lake.EndpointNotConfigured` when none was supplied; `tools/no_raw_endpoints.py` gates the tree (ADR-0002).
- Environment variables use the prefix `HNX_`. Endpoint overrides are `HNX_ENDPOINT_<NAME>` with
  the service name upper-cased and `-` replaced by `_`.

## 4. Logical ids

Grammar: `<kind>:<slug>`; `kind` is one of `svc cap det table role host note agent`; `slug` matches
`[a-z0-9][a-z0-9-]{0,62}`. Examples: `det:auth-failure-burst`, `cap:lake-query`,
`table:detection-findings`. A logical id never contains a scheme, address or engine rule number
(`viking://`, IPs and numeric rule ids are lint failures). W2's `homelabnext/ids/` is the
implementation and the `schemas/ids/` JSON Schema is the machine form; this section is the summary.

## 5. Schemas

```
schemas/<dir>/<name>.schema.json          the contract; "$id": "https://schemas.example.internal/homelabnext/<dir>/<name>/<major>.<minor>"
schemas/<dir>/examples/<name>.<n>.json     at least one valid example per schema
schemas/<dir>/negative/<name>.<n>.json     at least one example that MUST be rejected
```

Directories: <!-- hnx:gen:fact:schema-dirs -->`agent`, `broker`, `codemode`, `conform`, `events`, `ids`, `ocsf`, `platform`, `records`, `registers`, `status`, `strategy`, `workflows`<!-- /hnx:gen -->. A schema may also be named
`<name>.json` (`model_roles`, `decision_spec`, `service`) or `<class>.v1.json` (the OCSF subsets);
`tests/schemas/test_schema_contracts.py` pins the exact set.
JSON Schema draft 2020-12. Each schema file declares `title`, `description` and `$id`. Registers
that humans edit are YAML validated by the JSON Schema of the same name.

Every live schema and its current version (the last part of its `$id`), generated by
`hnx docs facts generate` and checked in `make gates` (a draft is `x-draft`: not frozen, it may
change until its ADR is accepted):

<!-- hnx:gen:fact:schema-versions -->
| schema (`$id` name) | version | file | status |
|---|---|---|---|
| `agent/context_manifest` | 1.2 | `schemas/agent/context_manifest.schema.json` | stable |
| `agent/golden_task` | 1.1 | `schemas/agent/golden_task.schema.json` | stable |
| `agent/handoff` | 1.0 | `schemas/agent/handoff.schema.json` | stable |
| `agent/injection_corpus` | 1.0 | `schemas/agent/injection_corpus.schema.json` | stable |
| `agent/pregate_output` | 1.0 | `schemas/agent/pregate_output.schema.json` | stable |
| `agent/profile` | 1.6 | `schemas/agent/profile.schema.json` | stable |
| `agent/prompt_template` | 1.0 | `schemas/agent/prompt_template.schema.json` | stable |
| `agent/report_result` | 1.1 | `schemas/agent/report_result.schema.json` | stable |
| `broker/approval` | 1.0 | `schemas/broker/approval.schema.json` | stable |
| `broker/audit` | 1.4 | `schemas/broker/audit.schema.json` | stable |
| `broker/decision` | 1.2 | `schemas/broker/decision.schema.json` | stable |
| `broker/handler` | 1.3 | `schemas/broker/handler.schema.json` | stable |
| `broker/manifest` | 1.8 | `schemas/broker/manifest.schema.json` | stable |
| `broker/request` | 1.0 | `schemas/broker/request.schema.json` | stable |
| `codemode/execution_request` | 1.0 | `schemas/codemode/execution_request.schema.json` | draft |
| `codemode/execution_result` | 1.0 | `schemas/codemode/execution_result.schema.json` | draft |
| `codemode/journal_step` | 1.0 | `schemas/codemode/journal_step.schema.json` | draft |
| `codemode/token` | 1.0 | `schemas/codemode/token.schema.json` | draft |
| `conform/capabilities` | 1.0 | `schemas/conform/capabilities.schema.json` | stable |
| `conform/target` | 1.0 | `schemas/conform/target.schema.json` | stable |
| `events/agent.activity` | 1.2 | `schemas/events/agent.activity.schema.json` | stable |
| `events/agent.job.failed` | 1.3 | `schemas/events/agent.job.failed.schema.json` | stable |
| `events/agent.job.finished` | 1.2 | `schemas/events/agent.job.finished.schema.json` | stable |
| `events/alert.created` | 1.2 | `schemas/events/alert.created.schema.json` | stable |
| `events/case.opened` | 1.2 | `schemas/events/case.opened.schema.json` | stable |
| `events/decision.requested` | 1.2 | `schemas/events/decision.requested.schema.json` | stable |
| `events/decision.returned` | 1.3 | `schemas/events/decision.returned.schema.json` | stable |
| `events/deploy.changed` | 1.2 | `schemas/events/deploy.changed.schema.json` | stable |
| `events/envelope` | 1.2 | `schemas/events/envelope.schema.json` | stable |
| `events/project.changed` | 1.2 | `schemas/events/project.changed.schema.json` | stable |
| `events/proposal.created` | 1.2 | `schemas/events/proposal.created.schema.json` | stable |
| `events/proposal.decided` | 1.2 | `schemas/events/proposal.decided.schema.json` | stable |
| `events/schedule.fired` | 1.2 | `schemas/events/schedule.fired.schema.json` | stable |
| `events/scope.denied` | 1.2 | `schemas/events/scope.denied.schema.json` | stable |
| `events/status.observed` | 1.2 | `schemas/events/status.observed.schema.json` | stable |
| `events/swap.step` | 1.3 | `schemas/events/swap.step.schema.json` | stable |
| `events/task.queued` | 1.2 | `schemas/events/task.queued.schema.json` | stable |
| `ids/common` | 1.0 | `schemas/ids/common.schema.json` | stable |
| `ids/logical-id` | 1.0 | `schemas/ids/logical-id.schema.json` | stable |
| `ocsf/authentication` | 1.1 | `schemas/ocsf/authentication.v1.json` | stable |
| `ocsf/detection_finding` | 1.1 | `schemas/ocsf/detection_finding.v1.json` | stable |
| `ocsf/dns_activity` | 1.1 | `schemas/ocsf/dns_activity.v1.json` | stable |
| `ocsf/network_activity` | 1.1 | `schemas/ocsf/network_activity.v1.json` | stable |
| `ocsf/novelty_finding` | 1.0 | `schemas/ocsf/novelty_finding.v1.json` | draft |
| `ocsf/vulnerability_finding` | 1.1 | `schemas/ocsf/vulnerability_finding.v1.json` | stable |
| `platform/agent_profile` | 1.2 | `schemas/platform/agent_profile.schema.json` | stable |
| `platform/baseline_set` | 1.2 | `schemas/platform/baseline_set.schema.json` | stable |
| `platform/broker_action` | 1.0 | `schemas/platform/broker_action.schema.json` | stable |
| `platform/capability` | 1.0 | `schemas/platform/capability.schema.json` | stable |
| `platform/customization` | 1.2 | `schemas/platform/customization.schema.json` | stable |
| `platform/export_manifest` | 1.0 | `schemas/platform/export_manifest.schema.json` | draft |
| `platform/guest` | 1.6 | `schemas/platform/guest.schema.json` | stable |
| `platform/interface` | 1.0 | `schemas/platform/interface.schema.json` | draft |
| `platform/lake_table` | 1.0 | `schemas/platform/lake_table.schema.json` | draft |
| `platform/mcp_server` | 1.3 | `schemas/platform/mcp_server.schema.json` | stable |
| `platform/model_roles` | 1.4 | `schemas/platform/model_roles.json` | stable |
| `platform/model_serving` | 1.0 | `schemas/platform/model_serving.schema.json` | stable |
| `platform/model_store` | 1.0 | `schemas/platform/model_store.schema.json` | stable |
| `platform/module` | 1.0 | `schemas/platform/module.schema.json` | draft |
| `platform/module_inventory` | 1.0 | `schemas/platform/module_inventory.schema.json` | draft |
| `platform/module_lock` | 1.0 | `schemas/platform/module_lock.schema.json` | draft |
| `platform/module_selection` | 1.0 | `schemas/platform/module_selection.schema.json` | draft |
| `platform/module_swap` | 1.0 | `schemas/platform/module_swap.schema.json` | draft |
| `platform/novelty_spec` | 1.0 | `schemas/platform/novelty_spec.schema.json` | draft |
| `platform/role_interface` | 1.0 | `schemas/platform/role_interface.schema.json` | stable |
| `platform/script_header` | 1.0 | `schemas/platform/script_header.schema.json` | stable |
| `platform/service` | 2.8 | `schemas/platform/service.json` | stable |
| `platform/site` | 1.6 | `schemas/platform/site.schema.json` | stable |
| `platform/slot` | 1.0 | `schemas/platform/slot.schema.json` | draft |
| `platform/swap_record` | 1.1 | `schemas/platform/swap_record.schema.json` | stable |
| `records/note` | 1.4 | `schemas/records/note.schema.json` | stable |
| `registers/decision_spec` | 1.3 | `schemas/registers/decision_spec.json` | stable |
| `registers/invariant` | 1.0 | `schemas/registers/invariant.schema.json` | stable |
| `registers/kanban_item` | 1.0 | `schemas/registers/kanban_item.schema.json` | stable |
| `registers/lesson` | 2.1 | `schemas/registers/lesson.schema.json` | stable |
| `registers/register_event` | 1.3 | `schemas/registers/register_event.schema.json` | stable |
| `registers/runbook` | 2.2 | `schemas/registers/runbook.schema.json` | stable |
| `status/agent_activity` | 1.0 | `schemas/status/agent_activity.schema.json` | stable |
| `status/agent_activity_detail` | 1.0 | `schemas/status/agent_activity_detail.schema.json` | stable |
| `status/agents` | 1.4 | `schemas/status/agents.schema.json` | stable |
| `status/last_run` | 1.0 | `schemas/status/last_run.schema.json` | stable |
| `status/observation` | 1.0 | `schemas/status/observation.schema.json` | stable |
| `status/orchestration_export` | 1.2 | `schemas/status/orchestration_export.schema.json` | stable |
| `status/roster` | 1.0 | `schemas/status/roster.schema.json` | stable |
| `status/views` | 1.10 | `schemas/status/views.schema.json` | stable |
| `strategy/doctrine` | 1.1 | `schemas/strategy/doctrine.schema.json` | stable |
| `strategy/measure` | 2.0 | `schemas/strategy/measure.schema.json` | stable |
| `strategy/objective` | 2.0 | `schemas/strategy/objective.schema.json` | stable |
| `strategy/requirement` | 2.0 | `schemas/strategy/requirement.schema.json` | stable |
| `strategy/rfi` | 2.0 | `schemas/strategy/rfi.schema.json` | stable |
| `strategy/strategy` | 2.0 | `schemas/strategy/strategy.schema.json` | stable |
| `workflows/deploy` | 1.0 | `schemas/workflows/deploy.schema.json` | stable |
| `workflows/pack` | 1.0 | `schemas/workflows/pack.schema.json` | stable |
| `workflows/stackstorm` | 1.1 | `schemas/workflows/stackstorm.schema.json` | stable |
<!-- /hnx:gen -->

## 6. Version policy

- Distribution version: SemVer, `0.x` until the first stable drop. The single source is
  `homelabnext/_version.py`; `CHANGELOG.md` must hold a section for it (`tools/check_changelog.py`).
- Schemas: the major version is in `$id` and, for versioned families, the filename
  (`<class>.v1.json`). Within a major version evolution is **additive only**: new optional
  properties, new enum values, relaxed bounds, a wider type. Every enum may grow within a major,
  so a consumer refuses or ignores a value it does not know rather than assume the set is closed.
  On an open object (no `additionalProperties: false`) a new optional property is accepted as
  additive although a document could have carried that key undeclared: an undeclared key of an
  open object carries no contract. Removing, renaming or tightening (a new `required`,
  `multipleOf`, pattern property, `then`/`else` beside an `if`, or schema for
  `additionalProperties`) is a new major, bumped in place (ADR-0001 decision 3): the earlier
  major's frozen copies stay under `schemas/_frozen/` and stored documents are migrated; there is
  no dual-write window. `tools/schema_check.py` enforces additivity within a major; a major bump
  is not checked against the earlier major.
- Python API: a name listed in section 2.1 follows SemVer once `1.0` ships; before that, a change
  to a listed signature needs a note in `CHANGELOG.md` under "Changed".
- Capability contracts: a conformance check is never removed; it may be added. A new check ships
  with a fake update in the same change.
- ADRs are append-only. A reversal is a new ADR that supersedes the old one.

## 7. Extending this page

Open an issue or pull request naming the section and the proposed text. Do not
edit this file from a feature branch of another task.
