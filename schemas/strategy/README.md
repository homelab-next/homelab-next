# schemas/strategy

The strategy-to-task records (`homelabnext.strategy`, `docs/strategy.md`). Each schema validates a
record **as loaded**: its front-matter plus its prose sections (`## Question`, `## Definition`,
...), with the sidecar events applied (reviews, readings, transitions). The examples are YAML
documents of that shape; the link rules, the lifecycle and the doctrine are checked in code
(`homelabnext/strategy/rules.py`), because they span records.

2.0 (ADR-0019): every record carries `uid` (a UUIDv7) and `type`, every link is a uid, and no
number is stored -- the one a record is shown with (`OO 1.2`, `PIR 2.1`) is computed from type,
`parent` and `order`. Which types a link may name (a parent, `supports`, `serves`, `raised_by`) is
the doctrine's `hierarchy` and `links`, checked in code. The 1.x baselines stay in
`schemas/_frozen/1.0/`; only `hnx records assign-uids` reads records of that form.

| Schema | Core idea |
|---|---|
| `strategy.schema.json` | the one strategy record (with its `uid`): `mission`, `intent`, `end_state` (sections), ranked `priorities`, `assumptions`, `constraints` of `{rule, owner}` |
| `objective.schema.json` | `type` SO/OO/TO/TT, `parent` (an objective's uid; none for an SO), `owner`; its measures name it as their parent; `active -> achieved / retired` |
| `measure.schema.json` | `type` MOP/MOE with the seven doctrine fields: `parent` (the objective's uid), `definition`, `source` (a typed binding: `invariant:`, `status:`, `records:`, `manual`, `none`), `target`, `confidence`, `thinness`; value + time are `value` events |
| `requirement.schema.json` | `type` CCIR/FFIR/PIR (a PIR may name a PIR `parent`): question, decision supported, consumer, cadence, LTIOV, SIRs, indicators, sources, tasked_to, acceptance, guardrails, `supports` (uids of SO/OO/TO, at least one) and `serves` (uids of CCIR/FFIR) |
| `rfi.schema.json` | `type` RFI: `raised_by` (the uid of a measure or requirement), `question`, `triage` (collection or production), `ltiov`; `open -> answered / expired / no-find` |
| `doctrine.schema.json` (1.1) | the doctrine policy (`doctrine.yml`): each mechanical rule with `enforce: error / warn / off` and its options, the default RFI LTIOV, the rules left to judgment, and (1.1) the record `hierarchy` and the `links` table |
