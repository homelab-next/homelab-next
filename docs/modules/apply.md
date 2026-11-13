---
summary: 'Module manifest reference: the apply path, from a checked selection to the per-module inventory groups and the install and check playbooks.'
summary_of: outline:sha256:15dd3d7f60294405
---
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Modules: the apply path

> Part of [the module manifest](../modules.md) ([[modules]]), the draft for operator review
> ([ADR-0027](../adr/0027-feature-and-provider-modules.md), proposed).

## From a selection to Ansible

A module is a service, not a machine: the guest it runs on is a hand-written guest file
([compute model](../compute-model.md)), and the selection joins the two with one placement line
(`placement: {<host role>: <site host>}`, the site host referencing the guest:
[hosts that are guests](selection.md#hosts-that-are-guests)). The apply path turns a selection
that `hnx modules check` passed into what Ansible needs, with two renders that share one naming
rule (`homelabnext/modules/apply.py`), so they agree by construction:

| Render | Writes | Holds |
|---|---|---|
| `hnx guests render --target inventory --selection lab/modules.yml` | `hosts.yml` (and `host_vars/`, unchanged; `group_vars/` with `--group-vars`) | one group `mod_<module>_<host role>` per placed host role, `-` written `_` (module `web-app`, host role `server`: `mod_web_app_server`), holding the guest every placement of that role lands on; and one group `modhost_<site host>` per lab site host a module is placed on, holding the guest that site host references |
| `hnx modules render ... --out DIR` | `DIR/modules.yml`, `DIR/checks/<module>.yml` (beside `limits/`, `egress/`, `tlp-sources.json`) | the install playbook and one check playbook per placed module |

Both are pure functions of the files they read (ADR-0028): the same selection, manifests and
guests give the same bytes, and goldens pin them (`tests/modules/golden/apply/`). Neither is
committed; render them where the deploy runs.

**The inventory groups.** Each placement's site host must reference a guest
(`hosts.<name>.guest`) of the fleet being rendered: a stand-in host (`kind` and `capacity`, no
guest) is no machine Ansible can reach, so the render refuses it by name, as it refuses a guest
the fleet does not hold. A placement on an `external` stand-in host runs outside the lab and gets
no group. Two instances of one provider placed on two guests share their group (the roles are the
same; instance values come from the guests' variables). The render refuses a group name two
placements would share (`a-b`/`c` and `a`/`b-c` are both `mod_a_b_c`) and one equal to a group the
guest model already writes. Each lab site host with a placement is also a group,
`modhost_<site host>` (`-` written `_`; a site host name has no `_`, and `modhost_` never equals
a `mod_` group), the target of that host's limits play below; one guest referenced by two site
hosts is refused (one guest is one host). The inventory path checks the selection's schema only, not the module rules: run `hnx modules
check` first. `--selection` is for the `inventory` target only (`render` and
`plan`); a selection the schema refuses is exit 1, one that cannot be read exit 2. The inventory is
fleet-wide, so `--node` does not narrow it: render it once.

**The install playbook (`modules.yml`).** One play per placed host role of each selected module,
the modules in **install order**: each after every module that serves a slot it hard-requires
(`requires.capabilities`: the provider of the named instance, or of every instance of the slot
when the requirement names none), ties broken by id. A soft requirement (`prefers`) and an
incumbent order nothing, and a requirement cycle is refused, naming the modules in the cycle (not
those that only wait on it). The first play, on `localhost` and tagged `always`, fails unless
every module group the playbook targets holds a host: a play on a group the inventory lacks
(rendered without `--selection`, or from another selection) would otherwise be "no hosts
matched", and `ansible-playbook` would exit 0 having installed nothing.

Then, before any module, one **limits play** per site host that `limits/` renders (the
[footprint limits](../modules.md)), on `modhost_<site host>`, escalated, tagged `hnx_limits` and
the tag of every module placed on that host (so `--tags mod_<module>` installs its host's limits
first). It copies the host's role slices and its fleet units' `Slice=` drop-ins into
`/etc/systemd/system/` (0644; drop-in directories 0755) and runs `systemctl daemon-reload` only
when one changed, then installs `hnx-module-quota.sh` into `/usr/local/sbin/` (0755) and runs its
`--check`: exit 0 changes nothing, exit 3 (a cap is owed) runs the script once to cap and reserve
the owed data roots, and that run failing (exit 3 again: data in the way, a different size, a
symbolic link) fails the play, so no module role runs on a host whose caps could not be put in
place. Any other exit of `--check` fails too, and the limits plays are `any_errors_fatal`: a
host whose limits fail stops the whole run, so no module installs anywhere against a provider
whose host is not capped. A stuck cap (an image cap whose `disk_gb` changed, which is never
resized in place) therefore blocks every module on its host; `--skip-tags hnx_quota` (the two
quota tasks' own tag) is the explicit way past it while the data is moved. A module's data root
that already holds files on a guest without ZFS (a module deployed before its limits were
installed) is refused the same way: move the data out, or make the root its own ZFS dataset,
then rerun. A second run copies nothing, reloads nothing and only runs `--check` (`changed=0`);
under `ansible-playbook --check` the `--check` still runs (it is read-only) and an owed cap shows
as a change, while the apply is skipped. `--tags mod_<module>` installs that module's whole host's
limits and runs the quota script for every module's data root there, and `--skip-tags
mod_<module>` skips the limits play of each host it is on, other modules there included.
`daemon-reload` runs only when a unit changed: a run killed between the copy and the reload
leaves it owed (`systemctl daemon-reload` by hand), a cost accepted for an exact `changed=0`. The two
directories are play variables (`hnx_limits_unit_dir`, `hnx_limits_sbin_dir`), so a test can
point them elsewhere with `-e`. A slice limits only the services that join it (`Slice=`, or a
container's cgroup parent): a role that does not is not confined by it. A file of the limits
render that is not one of those three shapes is refused by the render. A module removed from a
host leaves its slice behind (`lifecycle.remove` is not rendered yet).

The egress policy (`egress/`) is rendered but **not installed** by `modules.yml`: see "What it
does not do yet" below.

Then, per host role, a play:

- targets exactly `mod_<module>_<host role>`, never a group a module names, so a module's roles
  reach only the guests the site placed it on (`role_lint` PB001 holds by construction; a play on
  `cap_notify` would also reach every other host serving the capability);
- escalates (`become: true`), as the baseline playbook does;
- runs the module's own preflight hooks for its roles first (`contributes.preflight`, as
  `pre_tasks`), then the roles the module lists for the host role (`requires.hosts[].roles`), each
  the role interface v1 `main` entry point ([role interface](../role-interface.md));
- is tagged `mod_<module>` only, so `--tags mod_web_app` installs one module (a group tag could
  equal another module's tag: module `a-b`'s is `mod_a_b`, and so is module `a`'s host role `b`).

A host role of kind `external` and one that lists no roles are written as comments (the loader
lands an external role only on an external host and only it there, so the inventory's skipped
external hosts and these comments agree), and a module
placed nowhere (a hosted or config-only provider) as `placed on no host`. A selection with no role
to apply is one play on `localhost` that does nothing (`ansible-playbook` refuses an empty
playbook). The module's own `lifecycle.install` playbook is not imported: its plays name their own
hosts, which is the site's placement to decide; so an install step a module expresses outside
the roles its host roles list is not applied. Role paths are written relative to `DIR`: the
render is not relocatable, so render into the directory the playbooks run from, and apply
straight after the check, from the same unchanged checkouts (no digest yet ties what was checked
to the role files Ansible reads). Every value written outside a quoted string (module ids, host
roles, groups, hooks, kind, version, role path segments) is held to its schema shape by the
render itself, and files are written as new files (mode 0600), never through a symbolic link. The render
names module ids, versions and the overlay's module paths: treat it as private.

**The check playbooks (`checks/<module>.yml`).** For one placed module, on each of its groups, the
`readiness` hook and then the `health` hook of every one of its roles (`include_role` with
`tasks_from`); both are read-only by the role interface contract. `--tags health` (or
`readiness`) runs one hook.

**Group variables.** The selection's `config` values and a module role's own variables (the ntfy
role's `ntfy_logical_id`, say) reach the roles through the overlay's group variables, one file
per module group (`mod_<module>_<host role>.yml`). `hnx guests render --target inventory
--group-vars DIR` carries every `<group>.yml` (or `.yaml`) of `DIR` into the render as
`group_vars/<group>.yml`, beside `hosts.yml`, where Ansible reads it for that inventory: nothing
to link by hand. Each must be a group the rendered inventory holds (or `all`), plain YAML holding
a mapping: a file for any other group (a typo, or a module no longer selected), a second file for
one group, an `ansible-vault` file (give secrets by reference, `secret:<name>`), a directory
(`group_vars/<group>/`) or a symbolic link is refused, so no variable is set on nothing silently.
The carried file starts with the render's header, so `--prune` removes it once its source is
gone; `plan` takes `--group-vars` too.

**What it does not do yet.** Install the egress policy (`egress/`: `hnx-egress.nft`, its service
and timer, the fleet units' drop-ins); it is rendered, and its README says how to install it by
hand. Installing it from `modules.yml` waits on a decision: it filters only sockets of processes
in a role slice and in the host's own network namespace, so a module that runs as a container on
a bridge network (ntfy) is not filtered at all, and a module with `egress: none` that does run in
its slice gets a chain that allows only DNS and its required slots and drops the rest (for ntfy,
which requires only `secrets`, read at deploy time by the controller, not by the guest: in effect
drop all). Its
unit starts before `network-pre.target` and requires every role slice, so a wrong policy can cut a
host off at boot. The options: install it as rendered (containers stay unfiltered, so a declared
`egress: none` would read as enforced when it is not); filter containers first, with `compose_app`
putting the container under its role slice and either `network_mode: host` or a stable bridge
name matched by `iifname` in a `forward` chain; give an `egress: none` container an
`internal: true` Docker network, which is not open to a module that publishes a port (ntfy does:
an internal network carries no published port, so it would need a second network, and egress
again); or install nothing for container roles and make the gap visible where the posture is
read (a `hnx modules check` warning, not only this page). A digest binding the inventory, the playbooks and the checked
selection and module trees together (the guard play catches only a missing group, not a stale
one); a walk of each role directory refusing links before it runs as root (the loader's
`roles/` walk is a point-in-time check of the checkout, so run from a staging copy). The selection's `config` values and the module's secrets reach the
roles only through the overlay's group and host variables (carried by `--group-vars`, never
generated); firewall
edges and backup membership stay in the guest file; `lifecycle.upgrade` and `lifecycle.remove`
are not rendered; a host role's `count` copies are not spread over several guests.

## Running it in an overlay

From the overlay root, with the pinned checkout at `hnx/` (the layout `hnx modules check --root hnx
--overlay .` already reads):

```sh
hnx modules check --root hnx --overlay . --deploy
hnx guests render lab/guests --site lab/site.yml --target inventory \
    --selection lab/modules.yml --group-vars group_vars --out build/inventory
hnx modules render --root hnx --overlay . --out build/modules
ansible-playbook -i build/inventory/hosts.yml build/modules/modules.yml
ansible-playbook -i build/inventory/hosts.yml build/modules/modules.yml   # changed=0
ansible-playbook -i build/inventory/hosts.yml build/modules/checks/<module>.yml
```

`hnx modules render` refuses a `--out` that is not new or empty, so remove `build/modules` before
re-rendering. The overlay's `ansible.cfg` names the core roles (`hnx/ansible/roles`), which a
module role may use (`compose_app`); a module's own roles are reached by path. After the apply, the
census and `hnx modules check --deploy --running` ([loader at deploy time](loader-deploy.md))
confirm that what runs is what the selection declares.
