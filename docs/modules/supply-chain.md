---
summary: 'Module manifest reference: placement and isolation of module code, and the supply chain of fetched modules (lock, digest, review).'
summary_of: outline:sha256:24318251d2813857
---
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Modules: placement, isolation and the supply chain

> Part of [the module manifest](../modules.md) ([[modules]]), the draft for operator review
> ([ADR-0027](../adr/0027-feature-and-provider-modules.md), proposed).

## Placement and isolation

`exposure: isolated` (the sandbox's detonation guest, the detonation engine) lands only on a host the
site marks `isolated: true`, and such a host carries only isolated roles: no route to the lab, no
egress. External roles land only on `kind: external` hosts and vice versa. The compute model of
external hosts (IaC, image bake, access, the one-way path) is deferred to the collector pilot.

## Supply chain

`origin` is `in-tree` (shipped here; reviewed by this repository's pull requests),
`{kind: git, url, commit}` (a full 40- or 64-hex commit; the URL has no `.` or `..` segment) or
`{kind: archive, url, sha256}`. `in-tree` is bound to where the manifest is: the loader refuses
`in-tree` outside the public `modules/` tree and a fetched origin inside it, so a copied
third-party module cannot call itself in-tree. **Reviews never live in a module** (a module author
could ship pre-stamped approvals); `author` is required.

**The lock, the tree digest and digest-keyed reviews** (follow-up 5): for a fetched module the
overlay keeps a lock, `lab/modules.lock` (draft schema `platform/module_lock` 1.0): per module id,
its `origin` (exactly the manifest's), its `tree` digest and the `reviews` of that tree.

- **The tree digest** (`homelabnext.modules.supply.tree_digest`, `hnx reviews digest <module
  dir>`) is `sha256:` over a `hnx-tree-v1` header and one line per regular file: its path, whether
  any executable bit is set, and its content digest, sorted by path. It does not cover empty
  directories, directory modes, ownership, times or other mode bits. A symbolic link, special file,
  hard-linked file or `.git` entry anywhere refuses it (fetch with `git archive`, or strip `.git`,
  before pinning: no review reads version-control metadata), and so does a tree over its limits
  (20 000 files, 2 GiB).
- **The reviews** have the shape of every other review (`homelabnext.reviews`), inline in the lock
  (a fetched module cannot hold reviews beside itself; sidecar event files are the alternative if
  several reviewers conflict on one file). Only a review naming the **full** pinned tree counts
  (a prefix, which a module author could grind for, is reported); reviews of an earlier tree stay as
  history and are ignored; a `changes` or `reject` verdict on the pinned tree vetoes it; the
  manifest's `author` never reviews their own module and may not be `unknown`.
- **The policy**: kinds `module-provider`, `module-feature` and `module-core`, state `locked`. The
  example policy asks an agent check, an independent agent audit and a human approve of every kind
  (flat, stricter than the per-field tier above: the digest covers a whole tree, not a change). A
  module of no known kind, or of a kind the policy leaves out or asks nothing of, is never loadable;
  a policy may leave the kinds out, so older policies still load.

`lock_problems` is the loader's check: every selected fetched module is pinned, its origin is the
lock's, its directory still has the pinned digest and its reviews meet the policy, so **unpinned,
changed or unreviewed means not loadable**; a module that changes needs a new pin and new reviews.
A module is in-tree only when its directory is under the public `modules/` tree, whatever its
manifest says; an in-tree module is never locked, and an entry for a module that is not selected is
refused. Like every review here, this is a consistency check over what the files claim, not
authentication: whoever can edit the lock can edit the pin and the reviews, so the lock is reviewed
by the overlay's own pull requests. The digest is a string, not a snapshot, so the loader loads from
a copy only it can write.
