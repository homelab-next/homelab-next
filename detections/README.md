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
tactic tags. `evasion` fixtures document known-hard variants: the runner lists whether each was
caught, a miss is a reported gap, never a failure.

Engine rule numbers appear in `det_map.yml` and nowhere else. Charters, profiles, decision specs and
schedules say `det:<slug>`; `lint-ids` fails on a raw number.

```
python -m homelabnext.detections lint | run | map [--check] | lint-ids [paths] | compile <generic|wazuh>
```

Backends implement `compile(rule, target) -> Artifact` (`adapters.py`). `generic` emits an
engine-neutral query; `wazuh` is an offline XML stub (SERVER: loading it into a manager and
`logtest` are not implemented here). Supported Sigma subset is documented in `sigma.py`; aggregations
are deliberately rejected. Fixtures contain synthetic data only; example rules are original works
built on well-known public technique ideas.
