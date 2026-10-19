# Per-system SOP pages

Every service in the registry gets one operator page: what it does, how to use it, how to tell it
is healthy, how it fails, who it depends on, and which secret-store **names** it needs.
`docs/systems/_TEMPLATE.md` is the blank form; `docs/systems/<service>.md` are the pages for the
example fleet (fictional data only).

```
hnx docs systems generate examples/services.yml docs/systems   # create missing pages, refresh generated blocks
hnx docs systems check    examples/services.yml docs/systems   # exit 1 on a missing page, an orphan page or a stale block
hnx docs systems check    ... --require-complete               # also fail while any TODO(human) is left
hnx docs systems template                                       # print the blank page
```

## How a page is built

* Front-matter (YAML) carries the machine facts: `service`, `capability`, `impl`, `owner`, `host`,
  `port`, `protocol`, `health`, `backup_job`, `tags`, and a `status` (`draft` / `reviewed`) that
  people own.
* Nine fixed sections: what it does; inputs; outputs with formats; how to use it; how to verify it
  is healthy; failure modes; depends on / depended on by; credentials and access (secret-store
  names only, never values); source of truth.
* Machine-known facts sit in `<!-- hnx:gen:NAME -->` blocks that `generate` rewrites. Human text
  sits in `<!-- hnx:todo:NAME -->` blocks that `generate` never touches. Replace the
  `TODO(human)` line inside the block with prose.
* Links are relative (`lake-catalog.md`) and each also has a path-qualified wiki-link
  (`[[systems/lake-catalog|lake-catalog]]`), so `docs/` opens cleanly as an Obsidian vault
  ([docs/README.md](README.md)); the path matters because `docs/capabilities/` has pages of the
  same names.
* The `what` block links the service's capability reference page
  ([capabilities/](capabilities/README.md), built by `hnx docs capabilities generate`) when its
  capability is one of the conformance capabilities.

## The check

`check` fails (exit 1) when a registry row has no page, a page has no registry row (orphan), a page
is malformed or misnamed, or a generated block no longer matches the registry. It does not fail on
unfilled TODO blocks unless `--require-complete` is given; the count is always printed.
`tests/sop/` also pins the committed template and example pages to the generator output.
