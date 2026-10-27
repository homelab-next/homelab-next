---
summary: The decision cascade (floor, small, large, llm, then a human) and the model roles it calls, with the guarantees each rule keeps.
summary_of: outline:sha256:0e1211da0b293aa8
---
# Decisions and models

How the decision cascade (`homelabnext.decide`) and the model roles it calls
(`homelabnext.registry.models`, `homelabnext.golden`) keep their guarantees. Every rule below has
a test; the gates run in `make check` and CI.

## The cascade

Tiers run in spec order (floor, small, large, llm) and a human is always the last stop. A tier
answers only at or above its threshold; a fault, a timeout, an abstention or an invalid answer
escalates. Impact can be raised, never lowered. Rules: `homelabnext/decide/cascade.py`.

| Guarantee | Mechanism | Checklist |
|---|---|---|
| Model output is validated | `ModelTier` checks every reply against `output_schema(labels)` (JSON Schema 2020-12); an invalid reply is retried once with the problems fed back, a second one is `invalid` and escalates | A-04 |
| Noise gates de-escalate only with corroboration | a spec's `noise_gate` names `deescalate` labels and `corroborators`; such an answer stands only when a corroborator (a deterministic check the caller supplies) returns evidence, and the decision carries `corroboration: <name>:<evidence>`; otherwise `uncorroborated`, escalate | K-08 |
| Classifiers never delete data | `decide.annotate.annotate(records, cascade)` returns every record, in order, unchanged, plus `decide_*` annotation columns; a column clash is refused before anything runs; an unclassifiable record is kept and marked `human` | K-13 |
| Required safety specs are live | `homelabnext/decide/safety_specs/`: `sensitive-content`, `hostile-content`, `purpose-consistency`, `disclosure-risk`, each `safety: true` with a keyword list and a case set; `hnx decide safety` runs them against deterministic fakes | K-15 |

The safety-spec fakes (`fake_tiers` in each case file) prove the specs and the cascade's raise-only
rules, not that a real model classifies well: the keyword floor is real, the model tiers are not.

## Model roles

Consumers name a role (`mdl:fast-classifier`); the role table maps it to bindings
(`schemas/platform/model_roles.json` 1.3). The reference table for CI is
`examples/model_roles.json`.

| Guarantee | Mechanism | Checklist |
|---|---|---|
| Serving config is what we think | `probe` reads `/v1/models`: the bound model id and, when the role declares `max_context_tokens`, the loaded context length (`loaded_context_length`, `max_model_len`, `context_length`, `max_context_length` or `meta.n_ctx`); unreported or different is a mismatch. `registry.serving.check_serving(resolver, notifier)` alerts through the state-diffed notifier (`model-serving/<role>`), once per change, with a registered recovery | K-14 |
| Rate and cost limits hold | role `limits` (`window_s`, `max_requests`, `max_tokens`, `max_cost`, `cost_per_1k_tokens`) or an agent profile's `budgets` become `registry.limits.Budget`s; `Limiter.wrap(chat, "mdl:<role>", "profile:<id>")` refuses an over-budget call with `Throttled` (a decision tier then escalates) and alerts once (`model-budget/<key>`), recovering once | G-10 |
| Models are pinned | every binding carries `version` and `digest: sha256:<hex>`; `hnx golden pins check` (`make models-check`) fails on an unpinned binding, a role nothing evaluates, or an evaluation report whose inputs (pins, golden suites, replay spec and gold set) changed since it was produced | G-11, K-12 |

Changing a model: edit the pin, run `make models-report` (deterministic fake, committed as
`examples/model_roles.eval.json`) and `make models-eval REGISTRY=...` (live, kept with the change),
then commit. CI re-runs the fake evaluation and fails if the stored report does not reproduce.
