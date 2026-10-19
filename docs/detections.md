<!-- SPDX-License-Identifier: Apache-2.0 -->
# Detections

Detections are authored in a Sigma subset, compiled to engine artefacts through adapters, and
referenced by logical id (`det:<slug>`) everywhere outside the compiled rule file. This page
covers the parts that are not already in ADR-0006; the layout and lint rules themselves are in
`homelabnext/detections/`.

## Layout

```
detections/
  sigma/<tactic>/<slug>.yml        one rule, Sigma subset
  fixtures/<slug>/{must_fire,must_not_fire,evasion}/*.json
  mappings/<backend>.yml           Sigma field name -> dotted path in the engine's event shape
  attack_snapshots/<backend>.yml   the engine's bundled ATT&CK ids (see below)
  det_map.yml                      det:<slug> -> engine rule number
  attack_coverage.json             GENERATED: ATT&CK coverage from passing fixtures (golden)
```

## ATT&CK coverage counts only tested rules (D-04)

`python -m homelabnext.detections coverage` derives the ATT&CK technique and tactic coverage from
the fixture runner, not from the tags alone: a rule counts only when it has must_fire and
must_not_fire fixtures and every one of them passes. A rule that misses a must_fire or fires on
benign input is listed under `uncounted` with the reason; evasion misses are listed as
`evasion_gaps` and never change coverage. The report is committed as the golden file
`detections/attack_coverage.json`; `coverage --check detections/attack_coverage.json` (in
`make detections` and CI) fails when it is not the one the current rules and fixtures produce, naming
each technique that appeared or lost its last passing rule. After changing a rule or a fixture,
regenerate it with `coverage --out detections/attack_coverage.json` and commit it.

## ATT&CK-id validation (P6.5)

A rule can cite an ATT&CK (sub-)technique that is newer than the target engine's bundled
ATT&CK database. The rule fires correctly, but the engine logs an "unknown technique" warning
on every alert, and a monitoring stack that reads engine logs for faults may read that as an
ongoing error on something that is actually healthy.

Rule: **tag the parent technique the engine knows and keep the newer sub-technique in the
rule description or in extra tags that do not cross the ATT&CK boundary.** The parent is
always known-safe (ATT&CK does not retire techniques without a tombstone); a brand-new
sub-technique may not land in an engine's bundle for months.

### Known-id snapshot files

Each adapter ships (or points at) a snapshot of the ATT&CK ids its engine knows:

- Default location is `detections/attack_snapshots/<backend>.yml`; the adapter resolves a
  different path by setting `known_ids_snapshot` on the backend class.
- The file format is engine-neutral - a YAML/JSON mapping, OR a plain-text file with
  `# key: value` header comments and one id per line. Three forms are supported so a backend
  that gets its ids out of a native tool can ship the tool's own output without a conversion
  step.

Required header fields (missing any one is a load error): `engine`, `engine_version`,
`attack_version`, `snapshot_date`. These are display/reproducibility - no comparison runs on
them. `technique_ids` is a list of ids in `T####` or `T####.###` form (`attack.` prefixes and
lower case are accepted on load).

YAML example (`attack_snapshots/wazuh.yml`):

```yaml
engine: wazuh
engine_version: 0.0.0-example
attack_version: v15.1-example
snapshot_date: 2026-10-15
technique_ids:
  - T1059
  - T1059.001
  - T1086
```

Plain-text equivalent (`attack_snapshots/wazuh.txt`):

```
# engine: wazuh
# engine_version: 0.0.0-example
# attack_version: v15.1-example
# snapshot_date: 2026-10-15
T1059
T1059.001
T1086
```

### The adapter hook

An adapter advertises its known ids by implementing one or both of:

```python
class KnownTechniques(Protocol):
    known_ids_snapshot: Path | str | None

    def known_technique_ids(self) -> frozenset[str]: ...
```

The included `WazuhStubBackend` loads the snapshot lazily and caches it by resolved path, so
one process can validate several trees in sequence without one tree's cache leaking to the
next.

An engine's known-id set is usually its own data: an engine with no in-process ATT&CK
database (the included `generic` backend) advertises nothing, and `validate-techniques`
reports "could not measure" rather than falsely passing.

### Running the check

```
python -m homelabnext.detections --root detections validate-techniques
python -m homelabnext.detections --root detections validate-techniques --suggest-parent
python -m homelabnext.detections --root detections validate-techniques \
    --backend wazuh --snapshot path/to/known.yml
```

Exit codes follow the fleet's invariants-runner convention (and this is wired through the
detections test suite):

| rc  | meaning |
|---  |---|
| 0   | every id in every rule's `attack.*` tags is in the engine's known set |
| 1   | one or more ids are not in the known set (fail) |
| 100 | no snapshot could be loaded for this backend (could not measure) |

`--suggest-parent` turns an unknown sub-technique whose parent IS known into a suggestion:

```
det:cloud-api-key-new-asn: ATT&CK id T1078.999 not in the engine's known set;
  parent T1078 IS known - tag the parent and keep T1078.999 in the description
  or extra tags
```

A bare technique that is unknown stays a hard error - there is no higher-level parent to fall
back to, and the fix is to update the engine's ATT&CK database (or the snapshot).

### Writing a test around it

```python
from homelabnext.detections import attack
from homelabnext.detections.sigma import load_rules

snap = attack.load_snapshot("detections/attack_snapshots/wazuh.yml")
problems = attack.validate_rules(load_rules("detections"), snap, suggest_parent=True)
assert problems == [], "\n".join(problems)
```

The validator duck-types on `det_id` and `attack_techniques`; call sites that already hold a
backend's `known_technique_ids()` set can pass that set directly instead of constructing a
snapshot.
