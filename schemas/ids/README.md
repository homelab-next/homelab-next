# schemas/ids

Logical ids and shared definitions.

| File | `$id` | What |
|---|---|---|
| `logical-id.schema.json` | `.../ids/logical-id/1.0` | the id grammar as a JSON Schema; `$defs` has one definition per kind (`#/$defs/cap_id`, `svc_id`, `det_id`, `profile_id`, `persona_id`, `skill_id`, `mdl_id`, `memory_id`, `table_id`) |
| `common.schema.json` | `.../ids/common/1.0` | `$defs` only: `timestamp`, `date`, `slug`, `sha256`, `rel_path`, `severity` |

## Grammar

```
id    = kind ":" body                      max 128 characters
slug  = [a-z][a-z0-9]*(-[a-z0-9]+)*        max 64
ident = [a-z][a-z0-9]*(_[a-z0-9]+)*        max 64

cap:<slug>  svc:<slug>  det:<slug>  profile:<slug>  persona:<slug>  skill:<slug>  mdl:<slug>
memory:<slug>/<slug>        (scope/id)
table:<ident>.<ident>       (schema.name)
```

Product locators cannot be spelled: no `scheme://`, no dots or colons in slugs (so no IP
literals), and no run of four or more digits and no `rule`/`sid` followed by a digit (so no vendor
rule numbers). The engine rule number for `det:auth-failure-burst` lives in a generated adapter map,
never in a charter, profile, spec or schedule. The Python grammar (`homelabnext.ids`) and the schema
are generated from the same patterns and a property test checks they agree.

Reference another schema's definition with
`{"$ref": "https://schemas.example.internal/homelabnext/ids/logical-id/1.0#/$defs/cap_id"}`.

## Lint (`homelabnext.ids.lint`)

`lint_id` (strict, per id) and `scan_text` / `scan_document` (free text and parsed specs) report
`PRODUCT_URI` (`viking://` and other locators), `IP_LITERAL`, `RULE_NUMBER`, `GRAMMAR`.
Documentation-range addresses (RFC 5737 / 3849) are tolerated in prose, never inside an id.

Examples live in `examples/`, rejected documents in `negative/`.
