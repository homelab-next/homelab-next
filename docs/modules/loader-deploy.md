---
summary: 'Module manifest reference: the module loader at deploy time, the census of what runs and the notify pairs a notifier records.'
summary_of: outline:sha256:7a3b02b840ae20d2
---
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Modules: the loader at deploy time

> Part of [the module manifest](../modules.md) ([[modules]]), the draft for operator review
> ([ADR-0027](../adr/0027-feature-and-provider-modules.md), proposed).

## The loader at deploy time

The private overlay's deploy workflow ([private overlay](../private-overlay.md#the-deploy-workflow-step-by-step))
runs the loader twice, and both always run:

1. **Before anything changes on a host**: `hnx modules check --root hnx --overlay . --deploy`, the
   check `make gates` runs, over the lab's own selection. A problem fails the step, and nothing
   after it runs: no tailnet join, no `site.yml`. `--deploy` needs `--overlay`, refuses
   `--examples`, and turns every input the overlay layout names and the lab lacks (the selection
   `lab/modules.yml`, the role table `lab/model_roles.json`, the core registry `lab/services.yml`,
   the MCP catalog `lab/mcp/` and the keyring) into a problem instead of the note an ad-hoc check
   prints: a deploy never checks the repository's examples in place of the lab. The slot registry
   is the pinned `hnx` checkout's own (`examples/modules/slots.yml`), never the overlay's
   (`--deploy` refuses `--slots`). With
   modules selected and no `lab/review-policy.yml`, the check says so: the supply chain then
   refuses every fetched module, so a lab of in-tree modules needs no policy, and one that fetches
   a module cannot load it without one.
2. **After the deploy**: the census of what runs, then the two-way check against it. The deploy
   step runs `ansible-playbook hnx/ansible/playbooks/module_census.yml` (role `module_census`,
   every host, read-only) into a fresh directory of the runner's, with `systemctl` pinned on the
   command line (an extra variable wins over the overlay's `group_vars`, so the overlay cannot
   point the census at a stand-in); `hnx modules gather DIR --out FILE` builds the inventory
   (`homelabnext.modules.census`), and `hnx modules check --deploy --running FILE` compares it.
   This is a verification, not a gate: the deploy has applied by then, and the failed run is the
   alarm. It runs after the deploy rather than before the next one because a unit the deploy
   installs runs only after it (checked before, every new unit would read "declared but not
   running"), and because drift between deploys is what a later check would see, not what this
   deploy did.

The private overlay's `checks.yml` runs the first check on every pull request too, with the pinned
`hnx` and no secret, so a problem shows on the pull request and not only when the operator
dispatches the deploy. The census needs the hosts, so it stays in the deploy.

**A lab that takes up no modules is an empty selection, never skipped.** With none of
`lab/modules.yml`, `lab/modules/` and `lab/modules.lock` present (a dangling link counts as
present, so a broken link never reads as "no modules"), `hnx` checks an empty selection: the site
rules and the supply chain have nothing to judge, the inputs that only judge selected modules (the
role table, the registry, the MCP catalog, the keyring) are notes instead of problems, and the
runtime check still runs, so every running unit of a module (a core module's included) is one the
site does not select. A unit whose name is no module's (`<id>` or `<id>-...`) must be one of the
core's own (read from its roles and generators, above), as for any selection: any other `hnx-*`
unit runs but is no module's or the core's, a problem. A unit the overlay's own roles install is
therefore a problem unless an overlay module declares it. A lab with some of the three but not the others is checked as one
that takes up modules: every missing input is a problem. The decision is `hnx`'s, never the
workflow's: the step that runs it has no condition of its own.

**What the census measures.** Only `hnx-*` services and timers, by design: a unit under any other
name (a package's own service, a unit the overlay names otherwise) is out of its scope, and the
loader never sees it. Two queries per host, both for `hnx-*` services and timers:
`systemctl list-unit-files --state=enabled` and `systemctl list-units --state=active`. A unit
counts as running when a host reports its unit file enabled **or** reports it active, so one that
runs without being enabled (static, `enabled-runtime`, linked, or started by another unit or by
`systemd-run` under a `hnx-` name) is counted while it is active; one that is neither at the moment
of the census is not. Template units and their instances (`hnx-<name>@...`) are left out and noted:
an instance is not a unit a manifest declares. **The census is a union across hosts**: a unit
counts when any host reports it, so a unit enabled on the wrong host satisfies the check for the
right one. The inventory carries no host, and a manifest declares no placement per unit to
compare one with; that is a known limit.

**Notify pairs.** A process that owns a notifier (`hnx broker serve`, `hnx status collect
--notify-topic`) given `--notify-pairs-dir DIR` (or `HNX_NOTIFY_PAIRS_DIR`) writes the pairs it
holds to `DIR/broker/pairs.json` or `DIR/status/pairs.json` (`homelabnext.notify.record`), when it
starts and after each registration, the whole set each time. The record also carries when it was
written (UTC), the host's boot id, and the writer's pid and start time.

- **Where it is written.** `DIR` and `DIR/<owner>` are opened once, never through a link at any
  step, and each must be owned by root or by the writing process's user and writable by no one
  else (group or other), or the process refuses to start. Every later step (the `flock` on the
  owner's directory itself, the temp file, the replace) is relative to that open directory, so a
  path swapped or a link planted after start cannot redirect a write, and there is no lock file to
  plant. **No role in this repository deploys the broker or the status hub**, so the operator
  makes the directories: `/var/lib/homelabnext/notify-pairs` owned by root, mode `0755`; and
  `broker` and `status` beneath it, each owned by that service's user (or root), mode `0755` (a
  process running as root creates its own). A unit that writes there names its own `DIR/<owner>`
  in `ReadWritePaths`.
- **When it fails.** The first write, at start, stops the process: one that cannot say what it
  holds is not started quietly. A later write that fails is logged; the pair is still held
  (alerting goes on), and the whole set is written again at the next registration or report until
  a write succeeds.
- **What it discloses.** The record is mode `0644`: it tells the host's local users which pairs,
  and which module ids, run there. Titles are code constants and manifest strings, not secrets.
- **Modules.** A pair carries the module it was loaded from only when its registrant names one
  (`register_pair(..., module=...)`); the notifier never guesses one. **Nothing in the core passes
  `module=` yet**: until a module loader registers a module's pairs with it, a module's pair seen
  running is bound to no module, and the loader reports it as no module's or the core's.

The census reads each owner's record at `/var/lib/homelabnext/notify-pairs`
(`module_census_pairs_dir`, a role default the overlay's deploy workflow pins on the command line,
so its inventory cannot repoint it; no glob) in one step, with the role's `notify_pairs_records` module, so
nothing can be swapped between a check and a read. No link is followed at any step; each directory
on the way must be writable by no one but its owner; the record must be a regular file of at most
256 KiB (a FIFO never blocks the read); otherwise the census fails. Beside each record the host
reports its boot id, its clock, and the start time now of the process the record names. `gather`
parses each record strictly, and **a record that no longer says what runs is noted and not
counted**:
- one written before the host's last boot, or where the boot cannot be told;
- a broker record whose process (that pid, with that start time) is not running: the broker is
  long-running, so its record counts however old it is while its process runs;
- a status record older than 900 s: `hnx status collect` is one pass per timer run, and every run
  rewrites its record, so 15 minutes outlasts a few missed runs of a timer that fires every few
  minutes. A status record says what the last pass held, not what a live process holds.

A process that stops leaves its file; the census, not the file, decides whether it still counts.
`gather` lists every pair a counted record holds, once (one title held with two recoveries, or for
two modules, is listed twice, which the loader refuses). With no counted record on any host,
`notify_pairs` is left out and the pairs are not compared: the census cannot tell "no notifier
records its pairs" from "no pair runs". When the core's own pairs were not read, the loader does
not judge a pair bound to no module and says so. A record is the owning service's word about its
own pairs, believed as a host's `systemctl` output is about its units.

**Binding and trust.** The gatherer binds nothing: a running name belongs to a module by its name
alone (`<id>` or `<id>-...`), the rule the loader applies to a hand-written inventory too, so no
stamp a host writes decides whose a unit is, and none exists. A host's only input is its
`systemctl` output, which reaches the runner as two JSON lists of lines and is parsed strictly: a
line that is not one `hnx-<name>.service` or `.timer` in the query's own shape (an active unit's
description is free text, but no control character) makes the census unreadable, and `gather`
fails (exit 2). The directory is the runner's, made empty for the run: `_hosts.json` lists every
host the play targeted, an unreachable one included, and a host that wrote no answer, an entry that
is no listed host's answer, an answer written for another host, a linked or non-regular file, or
one over 1 MB fails the gather too. The role refuses a host name that is not a plain name before it
writes anything. What a host reports is believed: a host whose root is compromised can hide a unit
or claim one, and no census read from the host itself can rule that out.

**The overlay runs the census.** The census play runs with the overlay's own Ansible configuration
and inventory (its `ansible.cfg` names the inventory, the vault client and the SSH host keys a
deploy needs, so the pinned checkout's cannot stand in for it). A hostile change to the overlay can
therefore leave a host out of the play, or shadow a plugin through its configuration and forge the
answers: the census is an alarm against drift and mistakes, not a gate against a hostile overlay,
which already has root on every host through `site.yml`. Review of the overlay itself (its
`ansible.cfg`, inventory and roles are its code owners') is what guards against that.

What the census gathers beyond units and notify pairs (agents, MCP servers, lake tables, service
rows) is on [its own page](census.md).
