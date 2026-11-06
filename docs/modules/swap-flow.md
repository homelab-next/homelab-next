---
summary: 'Module manifest reference: how a module swap works end to end, the draft swap record 1.2, its evidence and the overlay''s gate.'
summary_of: outline:sha256:5d094505efc827bd
---
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Modules: how a swap works

> Part of [the module manifest](../modules.md) ([[modules]]), the draft for operator review
> ([ADR-0027](../adr/0027-feature-and-provider-modules.md), proposed).

## How a swap works, end to end

Swapping the `samples` object store from `example-object-store` to `other-object-store` (same shared
adapter, same instance name, same slot-named identifiers: the record keys on modules, never on
adapters or routes):

1. **Plan.** One selection line changes. The loader lists the dependants of `object-store/samples`
   (the external data collector and the sandbox require it; publishing reads through its interface;
   the lake requires the slot) **and core modules**, and opens a swap record 1.2.
2. **Conformance**: incumbent first, then candidate; data plane and field meanings.
3. **Dependants re-checked** against the candidate's version, features and formats; a dependant that
   no longer holds blocks the cutover. Fields whose meaning changes are recorded.
4. **Migration**: export from the incumbent in the slot's format, import into the candidate, with a
   boundary check (min, max, count across the cut), then dual-write and parity.
5. **Cutover and rollback window**: flip the binding; the instance name stays.
6. **Decommission**: the outgoing provider's issued credentials revoked, identifiers kept, released
   or tombstoned, `hnx decommission` plus the `contributions` plane (which takes a **module**
   target, not only a guest) clean. The `contributions` plane is specified, not implemented:
   `hnx decommission` has no such plane yet (see [follow-ups](follow-ups.md)).
7. **Close** with an ADR reference.

### Swap record 1.2 (draft: `platform/module_swap` 1.0)

What 1.2 adds to the record is the draft schema `platform/module_swap` 1.0, with its rules in
`homelabnext/modules/swap.py`; `platform/swap_record` stays 1.1 (its steps, gates and hash-chained
log are unchanged) until the ADR is accepted and the two are folded together. The swap kit
(`hnx swap`) still drives 1.1 records: no live swap has run through 1.2.

* **`dependants.report`**: one entry per selected module that requires or prefers a moving slot
  instance (a requirement naming another instance is not one; one naming none is), core modules
  included: `{module, kind, relation, slot, instance, checks: {features, formats}, verdict,
  reasons}`. Each check is `holds`, `fails` or `not-asked` against what the **incoming** provider
  offers for the slot; a failed requirement `blocks`, a failed preference `falls-back`.
  `dependants.blocked` lists the blocking modules, and a non-empty list refuses the cutover. The
  report is recomputed from the manifests and the site and compared, never trusted as written.
* **`route.selection_diff`**: `[{slot, instance, from, to}]`, exactly one line per moving slot
  instance from the outgoing to the incoming module, for a swap with no network route.
  `apply_selection_diff` is its cutover: it runs the cutover gate first, so only the record's
  checked diff is applied, and refuses a line that does not read `from`, so a diff cannot be
  applied twice or to another selection.
* **`legs`**: `[{instance, order}]`, every instance of the swap once, orders 1..n.
* The site checked against is the selection the swap **starts** from: each moving instance is
  served by the outgoing module there. `migration.format` is one both providers migrate the slot
  in, its import count equals the boundary count and it rejected nothing, and it never comes with
  `start_empty`; `credentials_revoked` names only the outgoing provider's credentials.
* Three gates: `module_swap_problems` (the record holds), `cutover_problems` (it holds, no
  dependant blocks, and the data either moved or the swap starts empty by decision) and
  `decommission_problems` (against the selection after the cutover: once the outgoing module
  serves nothing, every credential it issued is revoked; while it still serves another instance,
  its credentials stay, since revoking them would break that instance).

| Change from 1.1 | Why |
|---|---|
| `from_module`, `to_module` and `slots: [{slot, instance}]` replace `capability`, `from_adapter`, `to_adapter` | a swap is keyed on modules, slot and instance; one record links several slots (cases plus ioc-enrichment) |
| gate `modules-differ` replaces `adapters-differ`; an unchanged route is allowed | the same shared adapter and the same address are normal (the DNS swap kept its IPs) |
| `route` is one of `{endpoint: {host, port}}` or `{selection_diff}` | the scheduler cutover, a model-role rebind, a hosted static site and an engine behind an unchanged gateway have no network route |
| new step `migrate` between `shadow-start` and `dual-write` with evidence `migration: {export_manifest_sha256, import_result, boundary: {min, max, count}}` | export/import is gated, not prose |
| `start_empty: {reason, decided_by}` instead of `migration` | starting empty is a recorded decision |
| `dependants: {report, blocked: [...]}` gating `cutover`, including core modules | rule 2's promise |
| `meaning_changes: [{field, before, after}]` | a feed move changed what a rule id meant |
| `credentials_revoked: [secret:...]` gating `decommission-check` | the old provider's issued credentials go |
| `legs: [{instance, order}]` | the DNS swap's two-leg cutover across instances |
| `model_roles: [{slot: inference, instance, role, from, to, evaluation}]` | a model-role rebind is gated on the pinned evaluation of the new binding, its egress canary included |

`tests/schemas/test_module_swap.py` drives the swap above (the `samples` object store) through
these rules end to end: plan, re-check, migration, cutover onto `sites/full.yml`, decommission.

What the draft leaves out, on purpose: the contract version a dependant requires is the slot's,
not the provider's, so it is not re-checked; a dependant that reaches the slot only through an
interface is not seen (as in `rules.dependants`); one record migrates in one format, so a swap of
several slots that migrate in different formats is one record per format; a `holder: consumers`
credential is the template of the keys the store issues, so revoking it stands for those keys;
and `meaning_changes` is recorded, never checked.

* **`model_roles`**: the model roles a swap of the `inference` slot rebinds, one leg per role:
  `{slot: inference, instance, role: mdl:..., from, to, evaluation: {report, require_live}}`
  (`cap:inference`, written as the record writes every slot). `from` and `to` each name one binding
  of the role, as `{pin}` (the pin digest its canary entry records) or `{store_entry}` (a model
  store entry: the role's one binding serving that entry's model id and digest).
  `model_role_problems` checks the legs against `ModelEvidence`: the role table the swap starts
  from, the table after the rebind, the evaluation reports and the model store. Every role whose
  bindings differ between the two tables has exactly one leg (`mdl:x` and `x` are one role), no
  unchanged role has one, and a role only one table has is refused. The instance is one the swap
  moves; the old binding is one of the starting table's, the new one is the later table's and
  differs from it, the role's other bindings are unchanged, and the new binding resolves to a store
  entry. `from` is best named by `pin`, since an outgoing model may have left the store. `evaluation.report` is the digest
  (`homelabnext.golden.pins.report_digest`, canonical JSON) of the report for the table after the
  rebind. That report must be supplied and must pass `hnx golden pins check` against that table:
  it is not stale, so it was run for the new binding, and every binding has a canary entry, the new
  one included. How live is policy, held by the evidence and not the record:
  `ModelEvidence.require_live` (default on) checks it as `--require-live` and requires the store. A
  leg's `require_live: true` turns it on for that leg, and `false` waives nothing. With the policy
  off, the all-fake guard of `pins check` still applies, and the new binding's own entry must have
  run live unless the table after is the shipped example. `module_swap_problems` (and so the
  cutover gate and `apply_selection_diff`) takes the evidence as `models=`. A swap that moves the
  `inference` slot without it is refused, legs or none, because only the two tables show which
  roles it rebinds; so is a record with legs and no evidence. A malformed leg is refused by name.

  The new binding's backend is the instance the leg moves: `svc:<instance>`, the service row the
  incoming provider's row is renamed to at bind time (see the naming table). The rule reads the
  name; no manifest is consulted. A leg that rebinds a model onto any other backend is refused, and
  so is one that adds a binding on another backend beside the old one (a fallback included).

  **`hnx modules swap-check RECORD --site FILE --base REV | --ci-base`** builds the evidence from
  the repository rather than taking it from a caller (`homelabnext.modules.swap_evidence`), and
  **everything that vouches for the new model is read from the base commit, never from the
  change**: the role table before, the model store (`examples/model-serving/model_store.json`),
  the evaluation reports (`examples/model_roles.eval.json` and every `*.json` directly under
  `examples/model-evals/`, at most 64; a leg pins the one it means by digest) and the golden suites
  the report is checked with (`homelabnext/golden/examples/classifier_smoke.yml`). Each is a
  regular blob at the base, not a symbolic link and not over the loader's size cap. Only the table
  after comes from the working tree (`--roles`, default `examples/model_roles.json`; read like every
  loader input: no symbolic link on its path, the root included, a regular file, capped, opened
  without blocking). The base is resolved once to a commit (`git rev-parse --verify
  --end-of-options REV^{commit}`), so an option-like value or a tree is refused. Live evidence is
  required: that is policy, never the record's. The record validates against
  `platform/module_swap`, then `module_swap_problems` runs against the discovered manifests
  (`--examples`) and the site. An input it cannot read is exit 2, never "no change"; git that cannot
  run is exit 100. `--report` adds a report for a local run; CI never passes one. `--overlay` is
  refused: the evidence is read at the repository's fixed paths, so an overlay's swap is checked
  from the overlay's own checkout (`--root`) with its tables at those paths. `make swap-check
  RECORD=... SITE=... [BASE=...]` runs it; it is not part of `make gates`, because the tree holds no
  swap record of its own to check.

  **Vetting, then rebinding.** Since the base holds the evidence, a model reaches a role in two
  changes. The first adds its store entry and the live report for the proposed table (`make
  models-eval`, copied to `examples/model-evals/<name>.json`, a directory that does not exist yet: `homelabnext.modules.swap_evidence.EVALS` names it and the first vetting change creates it); `hnx modules review-tier` rates the
  store, the reports, the report directory and the golden suites human-approve, so a code owner
  reviews the vetting. The second changes the role table and adds the swap record. A change cannot
  vouch for itself: a store entry or a live report in the same change counts for nothing.

  **`hnx modules swap-gate --base REV | --ci-base`** (`make swap-gate`) is the CI gate. When the
  role table differs from the base's, at least one swap record added or changed under
  `examples/swaps/` (`swap_evidence.SWAPS`; the directory does not exist yet, the first role-table change creates it; JSON or YAML; untracked ones count, a record already on the base does not)
  must cover it: each must validate and its `model_roles` legs must hold against the base's
  evidence, live required, which also means a leg for every role the change rebinds. An unchanged
  table passes.

  **The overlay's gate: `hnx modules swap-gate --overlay DIR --base REV | --ci-base`.** `DIR` is
  the overlay checkout and the git root; the gate reads the same files under `lab/` with the
  repository's names: the role table `lab/model_roles.json`, the store
  `lab/model-serving/model_store.json`, the reports `lab/model_roles.eval.json` and
  `lab/model-evals/`, and the records `lab/swaps/` (`swap_evidence.OVERLAY`; the repository's
  paths are `swap_evidence.REPO` and read nothing from the overlay). The guarantees are the
  repository's: the evidence is the base commit's, the head table goes through the symlink-checked
  reader, a record must be added or changed in the change, and every unreadable input is exit 2.
  `--root` and `--roles` are refused with `--overlay` (the layout is fixed), and so is a
  `DIR` that is not a directory or is not the root of its git checkout
  (`git -C DIR rev-parse --show-toplevel` must be `DIR` resolved; a subdirectory is exit 2). The one difference is the golden suites: an overlay carries none,
  so the reports are checked with the installed package's
  (`homelabnext.golden.pins.DEFAULT_SUITES`), the code CI installs from the pinned commit, never a
  file of the change. The overlay template's `checks.yml` job `swap-gate` runs
  `hnx modules swap-gate --overlay . --ci-base` on every pull request and push, with the pinned
  `HNX_REF` (refused unless a full SHA), a refusal of an `hnx/` the change carries, a full-history
  checkout for the base, and no secret. `swap-check` still refuses `--overlay`. Two things for an
  operator: add `swap-gate` to the overlay's required status checks with the template's other
  jobs (a job no rule requires gates nothing), and the change that adds an overlay's **first**
  `lab/model_roles.json` cannot pass the gate (there is no base table to hold it against, so it
  exits 2): merge that one change by an owner override, after which every later change is gated.

  **Fields that are not the pin.** `ModelEvidence` compares roles by their pins (backend, model id,
  version, digest), which do not show a binding's `leaves_lab` (what `rules.cloud_roles` reads to
  require `grants.cloud_models`), a role's `fallback` (which it follows) or any other field. The
  gate therefore also compares each role both tables have field by field, pins aside (the role's
  own keys, and the keys each binding carries beside its pin, kept with that binding's pin, so a flag
  that moves to another binding is a change; a binding's `leaves_lab` counts as the rules read it,
  only `true`, so `false` and an absent key are the same). Every role that differs that way
  must be named in the new optional **`model_role_changes`** of a record in the change (`mdl:<role>`
  aliases; schema `platform/module_swap`); a record that rebinds or names other roles covers
  nothing for it, and a name whose role did not change is refused. A role with both a rebind and
  such a change needs its leg and its name. Names are not checked by `swap-check` (it sees no
  second table), only by the gate. Any role field counts (a `description` too), since the gate
  cannot tell which fields a future rule reads. A role present in only one table is refused as
  before. The module, site and migration rules are `swap-check`'s, which needs a site. A
  rebind within one provider module has no record type of its own, so for now any change to the
  example role table goes through a swap record.

  **What runs the gate.** The `--ci-base` rule is the package's (`homelabnext.gitbase.ci_base`;
  `tools/schema_check.py` re-exports it), so no CLI loads a file from the checkout to find its
  base. The package itself is still whatever is installed, and in a pull request's CI run that is
  the pull request's; so CI's `trusted-gates` job runs `review-tier` and `swap-gate` with **the
  base commit's own code**: a detached worktree of the base, imported with `python -P` (the
  checkout's own package never on the path, which the job asserts), reading the change only as data
  (`--root`). The ratchets that hold a change to the base run there too, the base's
  `tools/schema_check.py`, `product_name_lint.py`, `dup_check.py` and `register_ids.py check-lost`
  under `python -I` (the other jobs' copies are quick feedback a change can edit), and the
  regression-tests job judges fixes with the base's `tools/fix_has_test.py`. Nothing of the change runs before the gates: the job calls `actions/setup-python`
  directly rather than the checkout's `python-deps` action, calls the interpreter by the absolute
  path it reports, and installs pip and the checker's dependencies from the base's constraints and
  `pyproject.toml`. A base that cannot run a gate fails the job; the change's own code never stands
  in. A pull request run still takes the workflow file from the change, so this rests on
  `.github/workflows/ci.yml` being human-approve (it is governance), a review `main`'s ruleset does
  not yet require, until a ruleset requires the job from the default branch; the privileged
  pull-request trigger is never used.

  What none of this proves: a report's `live` is the claim of whoever ran it, now one a code owner
  reviewed, not one checked for provenance; and a library caller that assembles its own
  `ModelEvidence` is trusted with it.

`tests/schemas/test_module_swap_model_roles.py` drives one inference swap through these rules. It
rebinds `mdl:fast-classifier` from the shipped example's binding to a model-store entry and refuses:

- a report that is missing, not a report, or produced for the old binding;
- a fake canary entry where live is required, and a fake entry for the new binding in an otherwise
  live report;
- a changed role with no leg, a leg for an unchanged role, and a second leg for one role;
- a new binding on a backend the swap does not install;
- an unknown role, a malformed leg, and an unresolvable binding;
- an inference swap with no evidence.

Golden evaluations stand as conformance here. **Calibration refit is not enforced**: the record has
no field for it, and none is added until there is a refit artefact to check. A rebind that keeps
the provider module is not a module swap (gate `modules-differ`): `hnx golden pins check` alone
gates it. The swap kit (`hnx swap`) drives 1.1 records, which carry no `model_roles`, so the leg is
checked where the rest of 1.2 is, in these rules. Downtime migrations and derived-data rebuilds
remain open (below).
