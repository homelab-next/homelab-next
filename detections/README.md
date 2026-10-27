<!-- SPDX-License-Identifier: Apache-2.0 -->
# Detections as code

```
detections/
  sigma/<tactic>/<slug>.yml      Sigma-subset rule; file stem = slug; logical id = det:<slug>
  fixtures/<slug>/{must_fire,must_not_fire,evasion}/*.json   synthetic events only
  mappings/generic.yml           Sigma field -> event path
  det_map.yml                    GENERATED: det:<slug> <-> engine rule number
```

Rules: every rule needs >=1 `must_fire` and >=1 `must_not_fire` fixture (lint fails otherwise),
an ATT&CK technique tag (`attack.tNNNN[.NNN]`), and lives in a directory named after one of its
tactic tags. A rule's `status` is one of Sigma's (`stable`, `test`, `experimental`, `deprecated`,
`unsupported`); an `unsupported` (inert: it needs a field nothing sets yet) or `deprecated` rule
still runs its fixtures but is neither counted in `attack_coverage.json` nor compiled into an
engine bundle (`compile`). A fixture is the event as the engine sees it, after the pipeline: a
`labels.hnx_runtime` in one is the label the log pipeline set from the guest model, never one the
event arrived with (docs/log-pipeline.md). `evasion` fixtures document known-hard variants: the runner lists
whether each was caught, a miss is a reported gap, never a failure.

Engine rule numbers appear in `det_map.yml` and nowhere else. Charters, profiles, decision specs and
schedules say `det:<slug>`; `lint-ids` fails on a raw number. With no paths it scans the checkout
(skipping `tests/`, build output and hidden directories, where fixtures are bad on purpose); it runs
in `make detections` and CI, and invariant X-06 also checks that every `det:` id resolves in the map.

```
python -m homelabnext.detections lint | run | map [--check] | lint-ids [paths] | compile <generic|wazuh>
```

Backends implement `compile(rule, target) -> Artifact` (`adapters.py`). `generic` emits an
engine-neutral query; `wazuh` is an offline XML stub (SERVER: loading it into a manager and
`logtest` are not implemented here). Supported Sigma subset is documented in `sigma.py`; aggregations
are deliberately rejected. Fixtures contain synthetic data only; example rules are original works
built on well-known public technique ideas.
