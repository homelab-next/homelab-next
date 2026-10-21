# schemas/records

`note.schema.json` validates the YAML frontmatter of a records note (the generalised "vault" note).
Examples and negatives are Markdown files whose frontmatter is validated.

Common fields: `type`, `title`, `requesting_agent` (`profile:` id), `created` (RFC 3339), optional
`related[]` (relative paths, no traversal) and `provenance`.

| `type` | extra required fields |
|---|---|
| `proposal` | `risk` (low/medium/high), `rollback` |
| `completion-request` | `related[]` non-empty, each `decided/approved/<file>.md` |
| `finding` | `area`, `severity` |
| `escalation` | `reason`, `to` (a role slug, not a person) |
| `task` | `assigned_to`, `done_when` (the observable completion condition), `expires` |
| `strategy-transition` (1.3) | `record` (the uid of an SO/OO/TO/TT/MOP/MOE/CCIR/FFIR/PIR/RFI record; 1.4, ADR-0019: a legacy numbered code still resolves through `aliases.yml`, with a warning), `from`, `to`, `reason` (it becomes the record's resolution). Applied only by `hnx strategy decide` (docs/strategy.md) |
| `strategy-rfi` (1.3) | `raised_by` (a measure or requirement id), `question`, `triage` (`collection` or `production`); optional `ltiov`, `tasked_to`. Creates an RFI record when `hnx strategy decide` applies it |
| `register-transition` (1.1; `retired_on` 1.2) | `record` (the uid of a lesson or runbook; 1.4, ADR-0019: a legacy `LL-`/`RB-` code still resolves through `aliases.yml`, with a warning), `from`, `to`, `reason`; optional `retired_by`, `incorporated_into`, `superseded_by`, `retired_on` (`on`, from 1.1, is not read: YAML 1.1 parses it as `true`, and a note with a non-string key is invalid). Applied only by `hnx registers decide` (docs/registers.md) |

Filename convention (checked by `tools/schema_check.py::check_note_filename`, not expressible in
JSON Schema): `<YYYY-MM-DD>-<requesting-agent>-<slug>.md`, date equal to `created`, agent equal to
the `requesting_agent` slug.

Lanes (documented here, enforced by the records library): `inbox/` is the only agent-writable lane;
`decided/approved|denied|completed/` belong to the decision maker. Completing an item is a note of
type `completion-request` whose `related` lists the approved files.
