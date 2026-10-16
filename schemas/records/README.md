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

Filename convention (checked by `tools/schema_check.py::check_note_filename`, not expressible in
JSON Schema): `<YYYY-MM-DD>-<requesting-agent>-<slug>.md`, date equal to `created`, agent equal to
the `requesting_agent` slug.

Lanes (documented here, enforced by the records library): `inbox/` is the only agent-writable lane;
`decided/approved|denied|completed/` belong to the decision maker. Completing an item is a note of
type `completion-request` whose `related` lists the approved files.
