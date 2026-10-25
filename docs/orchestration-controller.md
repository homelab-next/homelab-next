<!-- SPDX-License-Identifier: Apache-2.0 -->
# The LLM orchestrator as the `orchestration` capability

The maintainer's Go controller (the "LLM orchestrator", pinned here at commit `a52a1c4`) admits
whole agent sessions. Each job is one `hermes -z` subprocess, admitted against live engine load,
moved to another backend when it fails, and sent to cloud only when the failure is the backend's
fault. This page covers two things:

- how the controller is measured against the `orchestration` contract;
- how its model calls go through the [LLM gateway](llm-gateway.md) ([[llm-gateway]]).

The controller keeps the session scheduling. The gateway takes over request-level concerns:
roles, keys, limits and cloud egress.

## The adapter

`homelabnext.conform.adapters.llm_orchestrator:make` is a stdlib adapter for the controller's job
API (`internal/api/server.go:39-42`). The contract's job body is a Python callable, and the
controller runs only `hermes`. So a conformance run puts a stand-in on the controller's `PATH` as
`hermes`: `conformance/fakes/llm_orchestrator_hermes.py`. The stand-in calls back to a loopback
*handler host* inside the adapter, which runs the handler.

| Contract | Controller |
|---|---|
| `define(name, handler, retries=n)` | Writes the profile `<profiles_dir>/hnxconf-<run token>-<name>.yaml` (`local_only: true`, `max_attempts: n+1`), then `POST /admin/reload-profiles`. The handler stays in the handler host. |
| `submit(name, params, idempotency_key=k)` | `POST /jobs` with that `agent_key`, `idempotency_key: hnxconf-<run token>-<k>`, and a task description that holds one job line (`hnx-conform-job:<base64url JSON>`: the handler host URL, a token issued for this submit and its HMAC, the job and its parameters; the HMAC key never leaves the adapter, since `GET /jobs/{id}` shows the description to any caller, and the handler host runs only an issued token for its own job and parameters, with a bounded body). `201`/`200` gives the run id. `404` raises `UnknownJob`. |
| the job body | The controller runs `hermes -z PROMPT` (`internal/hermesagent/invoker.go:239-247`). The stand-in finds the job line and asks the handler host to run the handler; it posts only to the handler host's `/run` on IPv4 loopback and refuses any other callback (another scheme such as `file://`, host, userinfo or path). It prints the answer (exit 0) or the error (exit 1). |
| `wait(run_id)` | Polls `GET /jobs/{id}`. `done` maps to `succeeded`; `failed` and `budget_killed` map to `failed`. `result` is decoded from `response_body`; `error` is `local_failed_reason`. The timeout is at least `wait_floor` (60 s), because the controller admits on a 2 s tick (`cmd/controller/main.go:225`). |
| `cancel(run_id)` | `POST /jobs/{id}/cancel`. A `409` (no longer cancellable) reads the run back unchanged, which is what the contract expects for a finished run. |
| `RunStatus.attempts` | The `attempts` field, when the controller reports one. `a52a1c4` reports none, so the adapter falls back to the number of executions the handler host saw for that run. |
| `capacity()` (feature `admission`) | `GET /admin/backend-inflight` (`internal/api/server.go`, `WithBackendInFlight`, which serves `hermesagent.Policy.InFlightSnapshot`; the route landed after `a52a1c4`): `in_flight` summed over the backends, `holders` the union of their `reserved_runs`, `limit` `None` (the snapshot reports none). The adapter declares `admission` only when the route answers; a `404` means "no route" (the capacity checks skip), any other answer or none makes the run unmeasured. With no limit the checks judge a release by the run leaving `reserved_runs`, never by `in_flight`, which other traffic on a shared controller moves; and they cannot test capacity by its effect (admitting new runs into the freed slots), which they do wherever a limit is reported. With API authentication on, the route needs an admin token, which the adapter does not send. |
| `kill(run_id)`, `restart()` (test hook `fault-injection`) | Only on the recorded stand-in, which models the hermes process dying (`signal: killed`) and a controller restart (`ReconcileOrphans`). On a live controller the adapter cannot kill one job's worker or restart the service honestly, so it never declares the hook. |

The adapter never answers on the controller's behalf. It does not raise `UnknownJob` for a name it
was never given, and it does not resubmit a failed run itself.

Two target files ship with it:

- `orchestration-llm-orchestrator` is a running controller: `HNX_ENDPOINT_ORCHESTRATION` and
  `HNX_ORCHESTRATION_PROFILES_DIR`.
- `orchestration-llm-orchestrator-recorded` is the loopback stand-in of the job API
  (`conformance/fakes/llm_orchestrator_api.py`). Each shape in it cites the Go file and line it
  came from.

`tests/conform/test_conform_orchestration_controller.py` runs the whole suite through the adapter
on that stand-in, both as recorded and with the proposed fixes turned on.

## Holds: capacity is held only by live work

The contract requires that a slot, lease or token reservation lives only as long as the worker it
was granted to (clauses a-e in `conformance/protocols/orchestration.py`, ADR-0029). A run between
attempts (a failed attempt, a retry backing off or waiting for a backend) is live: liveness is the
orchestrator's record of the run's worker, never whether an attempt's process exists at that moment,
and `retrying-run-keeps-its-hold` checks that a retrying run stays `running` with its hold. Five
more MUST checks hold an implementation to the release side: `cancel-running-run-frees-capacity`,
`killed-worker-fails-run-and-frees-capacity`, `deadline-expiry-frees-capacity`,
`restart-reconciles-runs-and-capacity` and `capacity-returns-to-zero-after-churn`. Each needs
`admission`; the kill and restart ones also need `fault-injection`, and the deadline one
`deadline`. Each of the four that stop a run also requires that the stopped worker's result never
lands after its body returns. Each of the five ends, where a limit is reported, by requiring the
freed capacity to admit `limit` new runs promptly: a `capacity()` that reports free slots
admission still counts fails, whichever path leaked the slot. The cancel check also requires a
live, still-blocked run to keep its hold for two graces (a timer standing in for the release
fails). A restart must end
a run that was executing; it may not run it again, since its old worker may still be executing.
An implementation's `cancel_grace_s` may not exceed `MAX_CANCEL_GRACE_S` (10 s): a longer grace
would let "released when the body returned" pass for "released on cancel".

| Controller | Result |
|---|---|
| `a52a1c4` as recorded | No in-flight route, so no `admission`: all five skip (a missing product feature skips a check even when its hook is missing too). |
| the stand-in with the upstream in-flight route (`fixes: [backend-inflight]`) | The four that need no `deadline` pass. A cancel cancels the job's context, which kills the `hermes` process; a defer releases the slot on every exit path (`scheduler.go:409-435`); a restart runs `ReconcileOrphans` (`running` becomes `failed`, `admitted` becomes `queued`) and starts with empty counters. |
| a live controller with the route | `admission` is declared; the kill and restart checks are `untested` (the adapter has no honest hook), which fails the capability until a controller-side hook exists. `deadline-expiry-frees-capacity` skips: the API takes no per-run deadline. |

The stand-in models slots only. The live controller also keeps token-weighted reservations and
exclusive leases. The 2026-10-23 review found that its stale-reservation reaper returns the slot
but not the token reservation, and that an exclusive lease is never recorded as a reservation, so
`reserved_runs` does not show it. A live run of these checks, with a kill and restart hook on the
controller host, is what would prove those paths.

## Result: three MUST checks fail at `a52a1c4`

Live run on 2026-10-22: the controller built with Go 1.25, a dev config, the stand-in as `hermes`.
Result: `FAIL orchestration ... 11 executed`, with 8 passing.

| Check | What the controller does | Proposed fix |
|---|---|---|
| `unknown-job-raises` | It accepts an `agent_key` that has no profile, answers `201`, and queues an HTTP passthrough job. That job fails later with `primary-local: unreachable`. A typo in `agent_key` silently changes the dispatch path. | `0002`: `reject_unknown_agent_keys: true` makes the API answer `404 unknown agent_key` unless the request carries an explicit `request_body`. It is opt-in, because passthrough callers still exist. |
| `retries-until-success` | It attempts a run once. Its only requeues are the special cases (capacity kill, backend down), and each requeue creates a new run id. | `0003`: profile `max_attempts` re-runs the attempt chain under the same run id. It never retries after a cancel, a job deadline, a timeout ceiling or a turn cap. `GET /jobs/{id}` reports `attempts`. |
| `retries-are-bounded` | Same cause as `retries-until-success`. | `0003`. |

`0001` is not a contract fix, but the live run needs it. At `a52a1c4`, `main.go:160` reads the
lessons register from a fixed production path and exits if it is missing, so the controller cannot
start on a lab host. `0001` adds `lessons_path`/`runbooks_path` (the defaults are unchanged). The
as-is run worked around it by giving the controller a private mount namespace with a stub file.

The three patches apply in order with `git am` to `a52a1c4`. Each one has its own Go test
(`internal/config`, `internal/api/unknown_agent_test.go`, `internal/queue/max_attempts_test.go`,
`internal/api/attempts_test.go`). With all three applied, the same live run passes all 11 checks.
The patches are proposals: nothing was committed to the controller.

Other findings, not MUST failures:

- **Idempotency keys are global and never expire** (`internal/store/store.go:57-58`). A repeated
  key returns the first run even when the `agent_key` differs. The adapter therefore namespaces
  every key per run.
- **A submit cannot be held.** A cancel sent right after a submit races the next 2 s tick, so
  `cancel-before-start-never-runs` can in principle flake against a live controller.
- **No authentication**, and **no list or events endpoint**. Listing runs is now an optional
  feature of the contract (`list-runs`, below), which the adapter does not declare; events and
  authentication are not part of it.

### Running it live

```bash
# controller (with 0001 applied, or the as-is binary in a mount namespace with a stub register)
mkdir -p lab/bin lab/profiles lab/homes/local lab/homes/cloud
ln -s "$PWD/conformance/fakes/llm_orchestrator_hermes.py" lab/bin/hermes
cat > lab/controller.yaml <<'EOF'
db_path: lab/controller.db
http_addr: 127.0.0.1:18088                # no-raw-endpoint: allow a dev controller on loopback
lock_path: lab/gateway.lock
profiles_dir: lab/profiles
lessons_path: lab/lessons.yml          # "lessons: []" is enough
runbooks_path: lab/runbooks.yml
reject_unknown_agent_keys: true        # 0002
backends:
  local: {name: primary-local, base_url: "http://127.0.0.1:9", needs_interlock: false}  # no-raw-endpoint: allow a dead port on purpose
  cloud: {name: cloud-fallback, base_url: "http://127.0.0.1:9"}  # no-raw-endpoint: allow a dead port on purpose
hermes_local_home: lab/homes/local
hermes_cloud_home: lab/homes/cloud
hermes_agent_timeout_seconds: 60
EOF
PATH="$PWD/lab/bin:$PATH" ./controller -config lab/controller.yaml &

export HNX_ENDPOINT_ORCHESTRATION=http://127.0.0.1:18088  # no-raw-endpoint: allow the dev controller above
export HNX_ORCHESTRATION_PROFILES_DIR="$PWD/lab/profiles"
hnx conform run orchestration --target orchestration-llm-orchestrator
```

Both backends point at a dead loopback port on purpose. A profiled job never reaches them, because
the stand-in does not call a model. The passthrough path that an unknown `agent_key` falls into
fails the way it does in production when no backend answers.

## Model calls through the gateway

Today each controller backend is two things:

- a controller config entry under `backends` (the `local`, `local_fallback` and `additional[]` entries);
- a `HERMES_HOME` whose `config.yaml` names the engine URL and the engine's own model id
  (`model.base_url`, `model.default`).

That second part breaks ADR-0007: a backend address and a model id sit in an agent's home. With
the gateway, the home carries only the gateway URL and a **role alias**. The role table
(`schemas/platform/model_roles.json`) is the only place where a role becomes a backend and a model
id, and `hnx gen gateway render` (`homelabnext/generators/llm_gateway.py`) turns that table into the
gateway's config.

### Mapping

| Controller today | With the gateway | Where it is declared |
|---|---|---|
| backend `name` (`vllm-a`) | `svc:vllm-a`, a backend in the gateway spec (`locality: local`, `port`), bound by one or more roles | the gateway spec, and `bindings[].backend` in the role table |
| `HERMES_HOME/config.yaml` `model.default` = engine model id | `model.default` = the role alias (`main-reasoner`) | the role's `bindings[].model_id` holds the engine id |
| `model.base_url` = engine URL | `model.base_url` = `https://llm-gateway.example.internal/v1` | the registry (`llm-gateway` capability) |
| `model.api_key` (a placeholder today) | the agent's virtual key (for `profile:reader`: key `agent-reader`, secret `secret:llm-gateway/key-reader`) | the gateway's `keys.json`, one key per profile |
| `model.context_length` | the role's `max_context_tokens` | the role table |
| backend `max_context` (admission, `min_context` affinity) | must equal the bound role's `max_context_tokens` | `hnx gen gateway render --check` with a `controller:` block (Checks, below) |
| backend `base_url` (passthrough target, and the socket peer that progress-liveness matches, `internal/hermesagent/policy.go:262-265`) | the gateway URL, because the `hermes` sockets now go to the gateway. The passthrough path is then removed: non-agent callers go to the gateway directly. | controller config |
| backend `load_probe_urls`, `health_url` | **unchanged: they stay on the engine.** Admission must see engine KV load, and a gateway hides which engine is busy. | controller config |
| `hermes_cloud_home` (re-runs the whole session on Anthropic) | a cloud home whose `model.default` is a **cloud-allowed role**. The gateway holds the provider key. | role table, gateway spec `locality: cloud` |

Each local backend keeps its own home, so the controller still decides which backend a session
lands on. A home names the role that is bound only to that backend's `svc:` (one role per engine,
for example `main-reasoner-a` and `main-reasoner-b`), and `--check` refuses any other (Checks,
below). If two engines sat behind one role, the
gateway would pick per request, and a session could move between engines turn by turn. That
undoes the controller's admission, exclusive leases and context escalation.

Cloud for an agent stays the controller's session-level decision. The gateway's locality rule
(docs/llm-gateway.md) already refuses a cross-provider fallback on any role an agent uses. So the
only way an agent session reaches cloud is the controller re-running it on the cloud home, and only
when the profile is not `local_only`.

When the gateway is down, every attempt fails with `connection refused`. That is backend-
attributable: the controller marks the backend down (`internal/hermesagent/health.go:57`) and holds
local-only jobs queued until a probe succeeds. It does not fail them.

### Per-agent keys

`HERMES_HOME` is per backend, not per agent. A per-agent key therefore needs one of two things: an
environment variable that the controller sets per run from the profile, or a home per profile and
backend. **[verify]** whether hermes resolves `model.api_key` from the environment. Until then, the
first step is a backend-level key (one per home) with the same role limits, and per-agent keys
follow.

### Checks

Both are built. The worked example is `examples/llm-orchestrator-gateway/` (fictional, like every
example): a gateway spec with two engines, `svc:vllm-a` and `svc:vllm-b`; a role table with one
role per engine, `main-reasoner-a` and `main-reasoner-b`; an excerpt of the controller's config
(`controller.yaml`); one `HERMES_HOME` per local backend (`homes/vllm-a`, `homes/vllm-b`); and the
gateway config generated from them (`gateway/`). The repository had no controller config or home
of its own to read, so this example is the input. `make gateway-check` runs the check on it.

- **`hnx gen gateway render SPEC OUT --check` reads the controller's backend list** when the spec
  has a `controller:` block (`config:` names the controller's config file, and `homes:` maps each
  backend name to its `HERMES_HOME`). The backends are the `local` and `local_fallback`
  entries under `backends` and every entry of its `additional` list. Its `cloud` entry is not
  read: it is the session-level cloud re-run, which reaches the gateway through a cloud home's
  role, not as a gateway backend. The check fails when:
  - a backend `name` is not a `svc:` of the spec;
  - the backend's home `model.default` is not a role of the role table, or is a role that is not
    bound to that backend's `svc:` alone (a role bound to two engines would let the gateway move
    a session between them; see the paragraph after the mapping table);
  - the backend's `max_context` is missing or differs from that role's `max_context_tokens`;
  - a backend has no home, a home names no backend, or a backend is declared twice.

  `homelabnext/generators/agent_homes.py` (`controller_problems`) holds the rules. The tests are
  `tests/generators/test_agent_homes.py`, with a failing fixture that breaks each rule once
  (`tests/generators/fixtures/controller-backends/fail/`).
- **Invariant A-14: no agent home names an IP address or an engine model id.**
  `hnx gen gateway homes --roles ROLES [--store STORE] HOME...` fails on any `config.yaml` that
  names an IPv4 or IPv6 address, documentation ranges included, anywhere in the file, keys
  included. It also fails on an engine model id in any value (never a key, which is a field
  name), compared without case, alone or behind a provider prefix (`openai/<id>`) and with or
  without a `:tag` or `@quant` suffix. A missing `config.yaml` is a failure; one that is not
  UTF-8 or not YAML is *could not measure* (exit 100), neither a pass nor a finding. The fast
  invariants run covers it (`make invariants`, criterion A-14 of
  `examples/registers/invariants.yml`), over the example's homes. The pass and fail fixtures are
  in `tests/generators/fixtures/hermes-homes/`.

  *Engine model id* means an id the engine itself answers to:
  - each binding's `model_id` in the role table. It is the engine's `--served-model-name` and
    the id the gateway sends upstream ([model-serving.md](model-serving.md)), so a home that
    names it reaches the engine past the role table.
  - with `--store`, each store entry's `served_model_name` and its hub repository
    (`source.repo`), which an engine loads directly.

  A role alias is never one, even when it is spelled like one, because a home must name a role.
  A store entry's own key is not one either: no engine serves under that name. Addresses are found
  with the repository gate's own detection (`tools/no_raw_endpoints.py`'s IPv4 rule and the hosts
  of its URL rules, loaded once through `homelabnext/endpoint_gate.py`, the loader the
  customization lint shares) together with `ipaddress` over the file's words (split at
  whitespace, `=`, `@` and punctuation), which also catches IPv6. Outside a checkout the gate is
  not there: the word scan still runs, and the command warns that the scan is reduced. That gate exempts
  `0.0.0.0` and version-like dotted numbers, but a home has no reason to name either, so here
  they count.

## Additive `orchestration` contract features

These are not contract changes. Each one is an optional feature (ADR-0001: evolve additively),
clauses f-j of `conformance/protocols/orchestration.py`. A target that does not declare a feature
skips its checks, so the in-memory fake of another product and a StackStorm-backed adapter are
unaffected. The checks for the five features built here are the extended suite
`orchestration-features` (`conformance/suites/orchestration_features.py`). With them the
`orchestration` suite would have reached the 24-check ceiling. The in-memory fake implements every
feature. It has two local backends and one cloud backend, and a retry of a job that is not
local-only moves to a cloud backend that satisfies the job's constraints.

| Feature | Field / call | What the check proves |
|---|---|---|
| `priority` | `submit(..., priority: int)`, 1 = first | **Built**: `lower-priority-number-starts-first` (SHOULD). With every slot filled, a priority-9 run and a priority-1 run are queued, and one slot is freed: the priority-1 run starts first. Ordering can only be observed while a single slot is free, so the check needs `admission` and a reported limit, and it skips without one. Its defect (first come, first served) is pinned by `tests/conform/test_conform_orchestration_features.py`, because only a MUST can name a registered mutant. |
| `admission` | `capacity() -> (limit, in_flight, holders)` | **Built** (see "Holds" above): capacity is held only by live work and is released on success, failure, cancel, deadline, worker death and restart. |
| `deadline` | `submit(..., deadline_s: float)` | **Built in the contract and the fake** (`deadline-expiry-frees-capacity`): a run still unfinished at its deadline ends `failed`, its error names the deadline, and its capacity is released. The controller's API takes no per-run deadline, so the check skips there. |
| `shadow` | `submit(..., shadow: bool)`; `placements(run_id)` gives each attempt's lane | **Built**: `shadow-run-executes-only-on-the-shadow-lane` checks that every attempt of a shadow run, its retry included, runs on the `shadow` lane, and every attempt of an ordinary run on `real` (mutant `shadow-retry-on-real-lane`). `one-unfinished-shadow-run-per-job` checks that while a job has a queued or running shadow run, another shadow submit raises `ShadowRunPending`, the 429-equivalent. A repeated idempotency key still returns its run. Ordinary runs and other jobs' shadow runs are accepted, and so is a new shadow run once the first has finished (mutant `shadow-limit-counts-running-only`). |
| `constraints` | `define(..., constraints={"require_tags": [...], "min_context": int, "exclusive": bool})`; `backends()`, `placements(run_id)` | **Built**: `unsatisfiable-constraints-never-run` checks that a job whose tags or context no backend has is rejected (`ConstraintsUnsatisfiable`), or that its run stays queued or fails without executing (mutant `best-effort-placement`). `every-attempt-meets-the-constraints` checks every attempt, the retry included, against the tightest constraints the backends allow (mutant `retry-ignores-constraints`). `exclusive-run-has-its-backend-alone` checks that an exclusive run does not start beside another run on its backend, and that no other run starts beside it (mutant `exclusive-not-enforced`). |
| `local-only` | `define(..., local_only: bool)`; `backends()`, `placements(run_id)` | **Built**: `local-only-run-never-reruns-on-cloud`. A local-only run whose attempts fail is retried on local backends only, and its body never runs again, under its run id or a new one (mutant `local-only-escalates`). |
| `list-runs` | `runs(state=...)` | **Built**: `runs-lists-every-run-once-in-its-state`. Succeeded, failed after a retry, cancelled, queued and running runs each appear exactly once in their current state. A repeated key and a retry add no row, and `runs(state=s)` returns only runs in `s` (mutant `row-per-attempt`). |

Each MUST check has a mutant that it catches and no other check catches
(`orchestration-features` is in `ONLY_ITS_OWN` of `tests/conform/test_conform_mutants.py`).

The `llm_orchestrator` adapter declares `priority` and none of the others. The job API takes a
priority from 1 to 100 and admits the lowest number first, then submit order (`handlers.go:97-111`
and the scheduler's queue order, as the recorded stand-in models them). The adapter sends the
number it is given and refuses one outside that range. Its `capacity()` reports no limit, so the
priority check skips there. The job API reports neither the backend nor the lane an attempt ran
on, so it cannot show `shadow`, `constraints` or `local-only` being honoured, even though the
controller has shadow lanes and `local_only` profiles. It has no list route for `list-runs`. A
controller-side route that reports placements is what would let the adapter declare those
features.

`RunStatus.attempts` already exists in the contract. `0003` is what makes the controller fill it.
