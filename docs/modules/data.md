---
summary: 'Module manifest reference: the data block and lifecycle safety (export, import, retention), and how config, credentials and identifiers are declared.'
summary_of: outline:sha256:2a34da2303850d2f
---
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Modules: data, lifecycle safety and configuration

> Part of [the module manifest](../modules.md) ([[modules]]), the draft for operator review
> ([ADR-0027](../adr/0027-feature-and-provider-modules.md), proposed).

## `data:` and lifecycle safety

Each owned dataset: `id`, `kind` (`lake-table` needs `table`; `object-prefix`, `records-prefix` and
`files` need `prefix`; `database` and `state` have neither), `via` (the requirement it lives in:
required for `lake-table`, `object-prefix` and `records-prefix`, and naming only a cap, and an
instance, the module requires or prefers; `files`, `database` and `state` live on the module's own
host), `export` and `import` (`{formats: [...], via: role}`), `retention`. Roots: a prefix is relative to the
slot instance it lives in; files and path defaults are relative to the module's data root on its host
(`/var/lib/hnx-modules/<id>/`); contributed files to the module directory.

A dataset may also declare its **TLP label** (ADR-0033 decision 3; [TLP labels](tlp.md#tlp-labels-adr-0033)):
`tlp`, one of `clear`, `green`, `amber`, `amber+strict`, `red` in its canonical spelling, is the
label of any item that arrives without one, taken from the provider's terms (a feed's licence, an
API's redistribution terms), never from the processing stage. A dataset that declares none is
`red` (decision 2), so the lab's own data needs no declaration. `honour_item_labels: true` lets an
item keep a label of its own that is looser than `tlp`; without it a looser item label is raised to
`tlp`, and a stricter one is always kept (`homelabnext.tlp.item_label`; an unreadable item label,
`null` included, is `red`; only an item whose label field is missing takes `tlp`).
`honour_item_labels` needs `tlp` beside it, and a fallback's `data` override never changes either.
Both sit under `data`, so any change to them, tightening included, is human-approve.
`homelabnext.modules.rules.dataset_label` reads the declaration.

- Removal exports first (`export_first`, default true); `false` needs a `discard_reason`. A removal
  deletes only the module's own namespaced data, never another module's (the namespaces cannot
  overlap).
- **Import validation** (follow-up 7, implemented as a library and a suite; no provider proves it
  yet): an export is a tree plus an export manifest (draft schema `platform/export_manifest` 1.0:
  slot, format, every file's path, size and sha256, and the totals; `manifest_sha256` is its digest
  over canonical JSON, what a swap record's `export_manifest_sha256` names). Each slot's `import_`
  MUST refuse, before changing anything:
  - a manifest path that traverses (`..`, absolute, backslash, control character), is not NFC, or
    repeats or crosses a file when compared case-insensitively (so a case-folding target cannot
    merge two entries);
  - a symbolic link or special file anywhere in the tree, the root included;
  - a file with a second hard link (an exporter writes fresh files, not a `cp -al` or
    `rsync --link-dest` tree);
  - an entry on another filesystem or a mount point inside the tree (read from
    `/proc/self/mountinfo`; an unreadable mount table refuses, so the check fails closed);
  - a missing or unlisted file (unlisted empty directories are allowed), a size or sha256 that
    differs, and a tree over its limits or the caller's tighter ones (`Limits.tighten`; the
    library's defaults are a backstop, and a provider sets its own for its slot).

  It never follows a link while reading. `homelabnext.modules.importcheck` implements it through
  one `O_NOFOLLOW` descriptor of the root: `check_tree` names the problems (at most 100) without
  reading content, and every file is opened from its parent's descriptor and re-checked on its
  own, so a file or directory swapped for a link after the check is refused. An importer stages
  before it applies: `copy_tree` streams a verified tree into a new directory, flushed to disk and
  renamed into place only when complete, and `read_tree` does the same in memory for small trees;
  `iter_tree` streams, so applying its files as they come would leave a partial import. The
  manifest is the outgoing provider's own claim: the check proves the tree is safe to read and is
  what the manifest says, not where it came from. The extended conformance suite `migration`
  (`conformance/protocols/migration.py`) states the MUST; five deliberately broken importers, one
  defect each, are each caught by exactly the check that names it. **No provider proves it yet**:
  no slot protocol has `export` and `import_` (below), so the suite runs only the reference
  importer, labelled as each stateful slot (a harness self-check), and the test's
  `MIGRATION_PROOF` table records, per stateful slot, what proves it, so a new stateful slot cannot
  arrive without that decision. The format-specific parse stays the slot's own suite.
- "Start empty" after a swap is a recorded decision with a reason (swap record 1.2).

Slot-level export/import (rule 3): each stateful slot's protocol gains `export(dest, fmt) ->
manifest` and `import_(src, manifest, limits=None)` (the shape of `conformance/protocols/migration.py`) in the slot's export formats with a MUST round-trip check; role interface 1.1
adds `tasks/import.yml`; X-07 becomes slot-keyed ("every selected provider of a stateful slot passes
that slot's round trip").

## `config:`, credentials and identifiers

- Types: `string`, `integer`, `boolean`, `duration_s`, `path`, `svc`, `secret`, `enum`. Defaults are
  fictional. A key named like a credential (`password`, `token`, `secret`, `key`, `credential`,
  `api_key`, `private_key`) **must** be `type: secret`, whose default is a `secret:<id>/...` name. A
  string default carries no `<scheme>:` reference in any case (`secret:`, `SECRET:`, `vault:`) and no
  address literal: a module that needs addresses requires a part of the site's
  [network scope](network-scope.md#the-network-scope) instead. A path default is relative, without `..`. An enum default is a string, one of its
  `values` (loader).
- `credentials[].holder`: `provider` (only the provider's roles read it), `consumers` (a template:
  the provider issues one credential **per consumer** at bind time, never shared, so a swap revokes
  exactly the outgoing provider's), `granted` (readable only by modules the overlay's
  `grants.secrets` names: the static-hosting deploy token, read only by the publish gate's identity).
- Client environment names are slot-named (`OBJECT_STORE_ENDPOINT`), mapped by the provider.
- `identifiers` (hostname, dns-name, vmid, ...) with `on_remove: release | keep | tombstone`; the
  loader refuses an identifier another selected module or the core holds, so a removal never
  releases a name someone else uses.
