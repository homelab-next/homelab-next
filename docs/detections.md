---
summary: 'Detections as Sigma: layout, the Sigma lane on the engine (bindings, awaiting-source, engine fixtures), ATT&CK coverage, known-id snapshots, native rules.'
summary_of: outline:sha256:a7fe3ad2e5df6703
---
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
  mappings/generic.yml             Sigma field name -> dotted path in the fixtures' event shape
  mappings/<backend>.yml           optional: the same for one engine's decoded event shape
  attack_snapshots/<backend>.yml   the engine's bundled ATT&CK ids (see below)
  det_map.yml                      GENERATED: det:<slug> -> engine rule number
  attack_coverage.json             GENERATED: ATT&CK coverage from passing fixtures (golden)
```

`compile <backend>` maps field names with `mappings/<backend>.yml` when that file exists, and
otherwise with `mappings/generic.yml`, warning on stderr that the engine gets the generic field
paths. The fixture runner (`run`, `coverage`) always uses `mappings/generic.yml`: fixtures are
events in the generic shape. A rule a backend cannot express is named on stderr and left out of
the bundle, and `compile` exits 1; the rest of the bundle is still written.

`run` also drives the fixtures through each backend that can evaluate its own artefact (an
`evaluate(artifact, event)` method; today the `wazuh` backend, which reads a compiled rule as the
engine does: every `field` present and matching, a `negate` field present and not matching). The
rule is compiled with the generic field map for this, so the compiled form is tested and not the
engine's field names. A must_fire or must_not_fire fixture whose compiled result is not the
reference evaluator's is printed as `[DIVERGES]` and fails `run`; a rule the backend cannot
express is printed as `[not expressible]`. The backend emits case-insensitivity as scoped
`(?i:...)` groups, so an alternation of patterns is valid in Python's `re` as well as PCRE2.

`map --check` fails unless `det_map.yml` is exactly what `map` would write: every live rule has a
number, no number is shared by two rules, no live rule reuses a retired number, and every entry
is an integer. A hand edit that breaks any of these is caught in CI, not only on regeneration.

Every `attack.*` tag is lower-case and one of: a technique (`attack.tNNNN[.NNN]`), a group
(`attack.gNNNN`), software (`attack.sNNNN`), or an ATT&CK Enterprise tactic
(`homelabnext.detections.sigma.ATTACK_TACTICS`; Sigma spells them with underscores,
`attack.initial_access`). `lint` fails on any other `attack.*` tag, and only tactic names count
as tactics in `attack_coverage.json`. `lint` also fails on a file under `sigma/` that is not
`sigma/<tactic>/<slug>.yml`, which no gate would otherwise load.

## ATT&CK coverage counts only tested rules (D-04)

`python -m homelabnext.detections coverage` derives the ATT&CK technique and tactic coverage from
the fixture runner, not from the tags alone: a rule counts only when it has must_fire and
must_not_fire fixtures and every one of them passes. A rule that misses a must_fire or fires on
benign input is listed under `uncounted` with the reason; evasion misses are listed as
`evasion_gaps` and never change coverage. Under `backends`, each backend `run` drives through its
compiled artefact has its own count from the same fixtures (`rules_counted`, `techniques_covered`,
`must_fire` fired of total, `uncounted` with the reason, a rule it cannot express included), so the
top-level numbers are not read as an engine's coverage when its compiled rules would not fire. The report is committed as the golden file
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

An adapter advertises its known ids by implementing either: the `known_technique_ids()` method,
or only the `known_ids_snapshot` attribute (relative to the detections root, or absolute), which
`validate-techniques` then loads itself:

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

It runs in `make detections` and CI. Exit codes follow the fleet's invariants-runner convention
(and this is wired through the detections test suite):

| rc  | meaning |
|---  |---|
| 0   | every id in every rule's `attack.*` tags is in the engine's known set |
| 1   | one or more ids are not in the known set (fail) |
| 100 | no snapshot could be loaded for this backend: none advertised, or the named or advertised file is missing or malformed (could not measure) |

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

## Native rules (ADR-0006 decision 4, ADR-0049 decision 2)

A detection is Sigma unless Sigma cannot carry it. A native rule is the engine's own rule or decoder
file, with a stated reason from a closed list: `engine-correlation` (frequency, timeframe, same-field
or parent-rule chains), `decoder` (it reads a field only the engine's decoder produces),
`list-lookup` (an engine-side list) or `stock-override` (it changes the level of, or silences, a
rule the product ships; human-approve, and it names the stock rule ids it changes). The layout, in
a detections root (the SIEM module's, or the overlay module's for the lab's own rules):

```
native/index.yml                  the registry: schema, engine, range, one entry per file
native/rules/<name>.xml           the engine's rule files
native/decoders/<name>.xml        the engine's decoder files
native/native.baseline.json       the ratchet: {"count": N, "stock-override": M}
fixtures/<slug>/{must_fire,must_not_fire}/*.json   raw engine input: {event, location, format, rule_id}
```

`python -m homelabnext.detections lint --native` fails on a missing or unlisted reason, a det id a
Sigma rule also has, a rule number outside the module's range or declared twice, a fixture kind
missing, a `<location>` with regular-expression characters and no `type="pcre2"` (it loads clean and
never matches), and a count above the baseline (only a reviewed change raises it). `python -m
homelabnext.detections run --native --manager-url URL --ca FILE` (the account's password in
`HNX_MANAGER_API_PASSWORD`) sends every fixture through the manager's own rule tester
(`PUT /logtest`) and fails on a missed must-fire or a fired must-not-fire. The runner keeps itself under 240 requests a minute (the manager API refuses past 300 with 429) and, on a 429 anyway, waits `Retry-After` or backs off 2, 4, 8 ... seconds, five tries. Native fixtures are not
orphans to the Sigma lint. An entry whose events the rule tester cannot reach (a file-integrity event comes from the agent's own daemon, not as a log line) says `proof: live` and a `live_test` (the steps and the alert that proves it) instead of fixtures; the engine run skips it, and the post-deploy live test is its proof. Native rules count in the engine's own coverage only.

## The Sigma lane on the engine

A Sigma rule ships to the engine as compiled XML, loaded by the SIEM module beside its native rules
(modules/wazuh README, "The Sigma lane"). Three things make the compiled form a real rule rather
than a well-formed one:

**Logsource bindings.** `mappings/<backend>.yml` may carry a `logsources:` list. Each binding
matches Sigma logsource keys (`product`, `category`, `service`; the binding matching the most keys
wins), names ONE engine base its rules chain from (`parent`: `if_sid`, `if_group` or `decoded_as`;
a multi-valued `if_sid` beside a field condition matches nothing on the engine, so it is refused),
and maps Sigma field names to the decoder's (`fields`). With bindings present, a rule compiles only
through its binding's fields: a rule no binding names, or a Sigma field the binding does not map,
is not expressible and is named by `compile`, never passed through under its Sigma name. A field
written `raw:<template>` is matched on the raw line by the rule's one `<regex type="pcre2">`, the
template being a PCRE2 fragment with one `{}` for the value (`raw:"id\.resp_h":"{}"`); it is for a
value the decoder keeps only in a static field the engine will not match by pattern (an address
list), takes equals/contains/startswith/endswith, and is the engine's to prove (the compiled-form
evaluator refuses it).

```yaml
fields: {}
logsources:
  - name: sensor-http
    match: {product: zeek, service: http}
    parent: {if_sid: 900380}             # the site's native HTTP base classifier
    fields: {c-uri: uri, DestinationIp: 'raw:"id\.resp_h":"{}"'}
```

**Rules awaiting their source.** `hnx_source: awaiting-source` marks a rule ported and tested whose
telemetry is not collected yet (an endpoint class not enrolled). Its fixtures run, through the
reference evaluator and the compiled form, and `compile` compiles it (so a port the engine cannot
take fails now, not on enrolment day), but it is left out of the bundle and out of
`attack_coverage.json`. Removing the marker is the change that ships it; give it engine fixtures
from the real source in the same change.

**Engine fixtures.** `engine_fixtures/<slug>/{must_fire,must_not_fire}/*.json` hold raw engine
input in the native fixtures' shape (`event`, `location`, `format`) plus a `provenance` (where the
line came from: a lake row, a capture, and what was changed in it); the expected rule is the det
map's number, never one written in the file. `python -m homelabnext.detections run --engine
--manager-url URL --ca FILE --user NAME` (the password in `HNX_MANAGER_API_PASSWORD`) sends them
through the deployed manager's rule tester and fails on a missed must-fire, a fired must-not-fire,
and a deployed rule with no engine fixture of either kind: the binding's base, the sibling order
and the decoder's field names are only proved there. `lint` reports orphan engine fixtures and
malformed ones.

`map --base N` starts a new map's numbers at `N` (an existing map continues after its highest
number, live or retired); `compile <backend> --out FILE` writes the bundle to a file.
