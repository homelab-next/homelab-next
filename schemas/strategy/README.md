# schemas/strategy

The strategy-to-task records (`homelabnext.strategy`, `docs/strategy.md`). Each schema validates a
record **as loaded**: its front-matter plus its prose sections (`## Question`, `## Definition`,
...), with the sidecar events applied (reviews, readings, transitions). The examples are YAML
documents of that shape; the link rules, the lifecycle and the doctrine are checked in code
(`homelabnext/strategy/rules.py`), because they span records.

| Schema | Core idea |
|---|---|
| `strategy.schema.json` | the one strategy record: `mission`, `intent`, `end_state` (sections), ranked `priorities`, `assumptions`, `constraints` of `{rule, owner}` |
| `objective.schema.json` | `SO-`/`OO-`/`TO-`/`TT-NNN`, `level`, `parent` (none for an SO), `owner`, `measures`; `active -> achieved / retired` |
| `measure.schema.json` | `MOP-`/`MOE-NNN` with the seven doctrine fields: `objective`, `definition`, `source` (a typed binding: `invariant:`, `status:`, `records:`, `manual`, `none`), `target`, `confidence`, `thinness`; value + time are `value` events |
| `requirement.schema.json` | `CCIR-`/`FFIR-`/`PIR-NNN`: question, decision supported, consumer, cadence, LTIOV, SIRs, indicators, sources, tasked_to, acceptance, guardrails, `supports` (SO/OO/TO, at least one) and `serves` (CCIR/FFIR) |
| `rfi.schema.json` | `RFI-NNN`: `raised_by` (a measure or requirement), `question`, `triage` (collection or production), `ltiov`; `open -> answered / expired / no-find` |
| `doctrine.schema.json` | the doctrine policy (`doctrine.yml`): each mechanical rule with `enforce: error / warn / off` and its options, the default RFI LTIOV, and the rules left to judgment |
