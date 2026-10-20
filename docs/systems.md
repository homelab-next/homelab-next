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
  `port`, `protocol`, `health`, `backup_job`, `tags`, and the fields people own and regeneration
  keeps: `status` (`draft` / `reviewed`), `author` and `reviews` (see "Reviews" below).
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

## Reviews

Pages share the review model of the lesson and runbook records
([registers](registers.md#reviews), `homelabnext/reviews.py`): `author:` plus a `reviews:` list
of `{by, kind, role, date, verdict, digest, note}`, the broker's identity normalization, no
self-review, an adversarial review by a different agent than every check, and no agent identity
in a human slot. The policy is `examples/review-policy.yml` (`system-page`), read by `check`
when it exists (`--policy FILE`, or `--policy none`).

* `status: reviewed` needs, by default, an agent check, an adversarial agent review and a human
  approve, all current, and no `TODO(human)` left. `check` fails on a page that claims it without
  them and names the missing tier.
* A review is current while its `digest` matches the page's: `hnx reviews digest
  docs/systems/<service>.md`. The digest covers only what people wrote, the `hnx:todo` blocks and
  any human front-matter field, never the `hnx:gen` blocks, so `generate` (machine facts) keeps a
  review current and editing the prose drops it.
* Draft pages are listed as `info:` with the tiers `reviewed` would still need; they never fail.

The fourteen example pages are drafts with `reviews: []`; `tests/sop/fixtures/dns.reviewed.md`
is a fully reviewed page that proves the pass path.
