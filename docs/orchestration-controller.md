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
| `submit(name, params, idempotency_key=k)` | `POST /jobs` with that `agent_key`, `idempotency_key: hnxconf-<run token>-<k>`, and a task description that holds one job line (`hnx-conform-job:<base64url JSON>`). `201`/`200` gives the run id. `404` raises `UnknownJob`. |
| the job body | The controller runs `hermes -z PROMPT` (`internal/hermesagent/invoker.go:239-247`). The stand-in finds the job line and asks the handler host to run the handler. It prints the answer (exit 0) or the error (exit 1). |
| `wait(run_id)` | Polls `GET /jobs/{id}`. `done` maps to `succeeded`; `failed` and `budget_killed` map to `failed`. `result` is decoded from `response_body`; `error` is `local_failed_reason`. The timeout is at least `wait_floor` (60 s), because the controller admits on a 2 s tick (`cmd/controller/main.go:225`). |
| `cancel(run_id)` | `POST /jobs/{id}/cancel`. A `409` (no longer cancellable) reads the run back unchanged, which is what the contract expects for a finished run. |
| `RunStatus.attempts` | The `attempts` field, when the controller reports one. `a52a1c4` reports none, so the adapter falls back to the number of executions the handler host saw for that run. |

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
- **No authentication**, and **no list or events endpoint**. Neither is part of this contract
  yet (see the proposed fields below).

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
| backend `max_context` (admission, `min_context` affinity) | must equal the bound role's `max_context_tokens` | proposed check below |
| backend `base_url` (passthrough target, and the socket peer that progress-liveness matches, `internal/hermesagent/policy.go:262-265`) | the gateway URL, because the `hermes` sockets now go to the gateway. The passthrough path is then removed: non-agent callers go to the gateway directly. | controller config |
| backend `load_probe_urls`, `health_url` | **unchanged: they stay on the engine.** Admission must see engine KV load, and a gateway hides which engine is busy. | controller config |
| `hermes_cloud_home` (re-runs the whole session on Anthropic) | a cloud home whose `model.default` is a **cloud-allowed role**. The gateway holds the provider key. | role table, gateway spec `locality: cloud` |

Each local backend keeps its own home, so the controller still decides which backend a session
lands on. A home names the role that is bound only to that backend's `svc:` (one role per engine,
for example `main-reasoner-a` and `main-reasoner-b`). If two engines sat behind one role, the
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

### Proposed checks (not built)

- `gen gateway --check` could also read the controller's backend list. It would fail when a
  backend `name` is not a `svc:` of the spec, when a home's `model.default` is not a role bound to
  that backend, or when `max_context` differs from the role's `max_context_tokens`.
- An invariant: no `HERMES_HOME/config.yaml` names an IP address or an engine model id.

## Proposed additive `orchestration` contract fields

These are not contract changes. Each would be an optional feature (ADR-0001: evolve additively),
so the in-memory fake and a StackStorm-backed adapter can skip the checks.

| Feature | Field / call | What a check would prove |
|---|---|---|
| `priority` | `submit(..., priority: int)`, 1 = first | Among queued runs, a lower number starts first (SHOULD: ordering can only be observed when a single slot is used). |
| `deadline` | `submit(..., deadline_s: float)` | A run still unfinished at its deadline ends `failed`, its error names the deadline, and it is not retried (the job deadline, LL-369). |
| `shadow` | `submit(..., shadow: bool)` | A shadow run uses the shadow lane and never the real one, and the controller allows one unfinished shadow run per job (`429` otherwise). |
| `constraints` | `define(..., constraints={"require_tags": [...], "min_context": int, "exclusive": bool})` | A run whose constraints no backend satisfies is rejected or stays queued, and does not run on a backend that violates them. |
| `local-only` | `define(..., local_only: bool)` | A local-only run that fails is never re-run on cloud. |
| `list-runs` | `runs(state=...)` | Every submitted run appears exactly once, in its current state. |

`RunStatus.attempts` already exists in the contract. `0003` is what makes the controller fill it.
