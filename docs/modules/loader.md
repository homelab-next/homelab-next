---
summary: 'Module manifest reference: every rule the module loader checks over the manifests, the slot registry and a site''s selection.'
summary_of: outline:sha256:80931cf2149fd566
---
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Modules: what the loader checks

> Part of [the module manifest](../modules.md) ([[modules]]), the draft for operator review
> ([ADR-0027](../adr/0027-feature-and-provider-modules.md), proposed).

## What the loader checks

`homelabnext/modules/loader.py` (`hnx modules check [--overlay DIR] [--examples] [--site FILE]
[--running FILE] [--keyring FILE] [--mcp-catalog DIR] [--deploy] [--json]`; exit 0 clean, 1
problems, 2 a path that does not exist or an input that cannot be read, 100 an internal error)
discovers `<id>/module.yml` under the public
`modules/`, the fictional `examples/modules/` (`--examples`, a fixture root whose modules may omit
`roles/` and `playbooks/`; the report names the modules the exemption applied to) and an
overlay's `lab/modules/`. It refuses a manifest that cannot be read, a module directory or
`module.yml` that is a symbolic link, a manifest that names another id than its directory, a
reserved id, an id under two shipped roots and, from the overlay, an id that **shadows a shipped
one**. Each manifest is validated against `platform/module` before any rule reads it, and the
selection against `platform/module_selection`; the rules below then run with every input they
take (rows, units, privileged units, the role table), built by the loader from the contributed
files. A module with a problem is left out of the rules across manifests and of the site. With a
site, the selected modules' supply chain runs too (`homelabnext.modules.supply`; a fetched module
with no lock is refused).

**Every file is read the same way**: opened without blocking (a FIFO or a device is refused,
never waited on), a regular file only and not a hard link, at most 1 MB (a larger file is
refused, never skipped; one cap for every file, since none needs more: the largest example is
13 kB), YAML with duplicate keys and **aliases** refused, and a document nested too deeply
refused. A module's files may add up to 2 MB and the run's to 8 MB, refused once spent, and each
file is read and parsed once per run, so a planted tree cannot stall it; each
is a named problem against its module, the selection, the registry or the inventory (exit 1),
or, for an input named on the command line, a usage error (exit 2). Untrusted names (directory
names, ids) are printed quoted and escaped when they are not plain identifiers, so they cannot
carry a terminal escape, a line break or a CI workflow command. Whatever the loader did not check
(no site, no inventory, the kinds below it does not validate) and every input it took from the
repository's examples instead of the overlay (the role table, the core registry, an empty
public `modules/`) it prints as a note, never as a pass. `hnx modules render --site FILE [--network
FILE] --out DIR` (with `--overlay DIR`, the site and the network model default to the overlay's
`lab/modules.yml` and `lab/site.yml`) writes the footprint limits, the egress policy and the log
pipeline's TLP source table (`tlp-sources.json`: every selected module's datasets with their
declarations, [log pipeline](../log-pipeline.md#the-tlp-label)), only for a site that checks clean and
only into a new or empty directory (stale files from an earlier render never mix in; a file
there is a usage error); with `--json`, a generator's refusal is the output's `error`. The rules
(`homelabnext/modules/rules.py`):

1. **Per manifest**: id equals the directory and is not reserved; `origin: in-tree` exactly when the
   module is in the public `modules/` tree, and a core module only there; `replaced_by` is another
   module; every name is bound to the id (table above); code is own or shared-adapter; secrets in
   the own namespace; timers name own roles; every referenced role is contributed; agent rules
   (owned profile, prompts per lane, the real lane writing `<root>/<id>/` and the shadow lane
   `<root>/<id>-shadow/`, needs equal the spec's capabilities, tools on a needed slot or an own MCP
   record, no spec ceiling, a trigger names a consumed interface); criteria ids and evidence; fleet
   units (`fleet_units.validate`, namespaced, no root or opt-out, no direct paging); service rows
   (host roles, own status sources, public routes need auth, upstreams the module uses and never
   `secrets`); egress from own host roles; datasets `via` a cap and instance the module uses;
   fallback data naming an own dataset of that preference, in the fallback slot's export formats;
   interface schemas with the owner's `$id`; slot registry agreement (declared slots, provisional
   only without a contract, never for a privileged slot, migration iff stateful); enum defaults
   within values.
2. **Across manifests**: one owner per interface id (every version), no reference without a
   definition; every bound name belongs to the longest module id it is named under; unique names
   (the list above); no data prefix or records write prefix overlap; **no module id, and no
   feature or core module's service row, MCP server id, agent key, table or table namespace that
   is one of the core's own names**, and, per site, no provider instance named like a core service
   row whose capability it does not fill. The core's names are read from sources it already has,
   never from a list kept for this check: the reserved ids, the core registry's service rows
   (`services.yml`), the ids of the core MCP catalog (each record's `id`, else its file's stem, as
   the catalog's own loader takes it; an id that is not its file name, a record that is not a
   mapping, and a record-like file that is not `<id>.yml` are `registry` problems), the agent keys
   of the keyring's agent principals (`profile:<key>`, the generated map of every principal), the
   core's OCSF tables (`schemas/ocsf`) in their lake namespace (`ocsf`, which no module's own
   namespace may be), and the core's own notify pairs (`homelabnext.notify.core_pairs`, the one
   list the core registers its pairs from: no module may declare one of their problem or recovery
   titles, since the notifier keys pairs by problem title and a module taking one would change
   how the core's alert clears). With `--overlay`, the catalog (`lab/mcp/`) and the keyring
   (`lab/keyring/keyring.json`) are the overlay's: one that is missing is a `registry` problem
   unless it is given (`--mcp-catalog`, `--keyring`), never the repository's examples answering
   for a lab they do not describe. Without an overlay, the catalog beside the core registry
   (`mcp/`) and the example keyring are used, each said in a note, and a missing one is a note.
   The catalogs are read like any other input, at most 1,000 entries each. Exact names only: a
   lookalike with a core name as its prefix (`<core name>-tools`) is a module's own name, as a
   service row's is. The core's own fleet units are read from what installs them, never from a
   list kept for the check: every unit file a core role's tasks install (a `dest:` naming
   `hnx-<name>.service`, `.timer` or `.{{ item }}`, and `hnx-<prefix>-{{ ... }}.service`, a family
   with one unit per instance) and the units the core's generators write (the egress and mirror
   generators' `UNIT`), read from `ansible/roles` under `--root` (the pinned checkout). A module
   unit named like one of them is refused. A test scans every role file and the package for a
   unit name the loader does not read, so a role that installs one some other way fails the
   build. Without `ansible/roles` under the root the core's units are not read (a note; under
   `--deploy` a `registry` problem).
3. **Per site**: every selected module has a manifest (core included); each features, core and
   providers entry is a selected module of that kind and binds only agents it contributes; config
   values are declared keys, carry no site address, and a secret value is the module's own or
   granted; the scope block parses strictly, and every part a selected module requires is present
   and non-empty (an exclusion may be `[]`); required core slots
   selected (a provider, or an incumbent: a real slot, not also under `slots`, naming the core
   registry's primary row of that capability), or planned (a warning: a required core slot, in no
   other answer, with a real `review_by` that `--deploy` refuses once passed; never served); instances unique; every hard requirement and instance satisfied; fallbacks selected
   and datasets moved with their data override; service upstreams follow the fallback; pass-through
   only where allowed and formats meet; interfaces provided, on instances their providers require;
   grants for publish, egress (internet, authority services, external hosts), public routes and
   cross-module secrets; every agent lane bound to exactly one selected orchestration instance;
   placements complete for features and core modules alike, external and isolated roles on matching
   hosts; footprints times `count` over four dimensions, and every resource claim against the
   host's named resources with exclusivity; a host that references a guest record resolved
   (known, schema-valid, live or planned, with resources, named by one host) and each role placed
   on it against the guest's kind, size, capability and baselines; every lab host's own address
   private or in `scope.trusted.nets`
   ([hosts that are guests](selection.md#hosts-that-are-guests)); with the lab's own registry,
   every service row a selected module contributes appears in it identically as the site binds it
   (renamed to the instance, `version` from the product, `host` the placed guest), each difference
   named field by field
   ([registry rows](registry-rows.md)).
4. **Two-way, against what runs**: every contributed file, and every lifecycle playbook
   (`lifecycle.install|upgrade|remove.playbook`, what the apply path runs as root), exists, is a
   regular file inside the
   module (no symbolic link on the way, realpath containment) with a single link (a hard link
   could alias a file outside it), and is read only then. A contributed role is a **directory**,
   `roles/<name>` exactly (the apply path runs the module's roles from its `roles/`), reached
   through no symbolic link; the module's whole `roles/` tree holds only the contributed roles
   (any other entry is refused, a `README` or `.gitkeep` beside the roles included: a module
   ships only `roles/<name>/` directories there) and, walked without following
   anything, no symbolic link at any depth (a role runs as root, and a link can point at any file
   on the controller), no FIFO, socket or device, and no hard-linked file; a tree of more than
   5,000 entries or 12 levels is refused rather than cut short. Nothing under `roles/` is read.
   A fixture module (`--examples`) that ships no `roles/` keeps its exemption; one that ships it
   is walked the same way. What the check does **not** cover, and the apply path must: the
   check is a point-in-time walk of the checkout (run what was checked, from a staging copy, not
   the live tree), and Ansible also loads `library/`, `*_plugins/`, `collections/`,
   `group_vars/`, `host_vars/`, `ansible.cfg` and a `roles/` beside a playbook, none of which a
   module contributes, so the apply path must not run a playbook from a directory holding them;
   role content that reaches outside the module (a `meta` dependency by path, an
   `include_tasks: ../..`, an absolute `src`) is the review's and the tree digest's. The kinds with a record type are
   validated against it: MCP records (`platform/mcp_server`), service rows (`platform/service`),
   prompt templates (`agent/prompt_template`), lake tables (`platform/lake_table`), interface
   schemas (a JSON Schema in the owner's `$id` namespace), unit specs (the fleet_units rules) and
   Sigma detections; the others (docs, charters, agent specs, invariant files, roles, playbooks,
   conformance targets) are checked for containment only, and the report lists them. With an
   inventory of what runs (`--running`, the draft `platform/module_inventory` 1.0), every running
   unit, service row, MCP server, agent and table bound to a module id is declared by that
   module, which the site selects, and every declared one runs (a provider's row runs under the
   instance name the site gives it; a name bound to no module id is the core's and not judged
   here). With the inventory's optional `notify_pairs` (the running notifier's recovery pairs,
   each with the module it was loaded from; a pair with no module must be one of the core's own,
   `homelabnext.notify.core_pairs`, with the same recovery, or it runs but is no module's or the
   core's), the same holds
   for recovery pairs, compared by both titles: a running pair is declared by its module, which
   the site selects, with the same recovery title; every selected module's pair runs; and the
   notifier holds one pair per problem title, so a title runs once. Without `notify_pairs` the
   pairs are not compared, and the report says so. Per site, a problem title is declared once
   across the selected modules (the notifier keys its pairs by it, and `register_pair` refuses
   a second registration of a title with another recovery), and every title names one thing: a
   recovery is not its own problem's title, another pair's problem title or another pair's
   recovery. A title is one line of printable text without the characters that make two titles
   look alike (controls, no-break and other spaces, zero-width and bidirectional marks), in the
   manifest and the inventory alike. A kind the inventory names in `not_gathered` is not
   compared, and the report says so; one it merely leaves out is refused by the schema, never
   read as "nothing runs". The fleet units and the recovery pairs come from the hosts, and the
   agents from the running broker where the census asks one
   ([The loader at deploy time](loader-deploy.md#the-loader-at-deploy-time)). MCP servers are gathered when at
   least one host lists its installed client configurations, and tables when one host lists the
   lake catalog; otherwise a gathered inventory names them in `not_gathered`. Service rows are
   never gathered by name (a socket names no row): a gathered inventory names them in
   `not_gathered`, the loader judges each selected row by whether its placed host listens on its
   port, and only a hand-written inventory compares them by name.
