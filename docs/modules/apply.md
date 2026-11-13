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
| `hnx guests render --target inventory --selection lab/modules.yml` | `hosts.yml` (and `host_vars/`, unchanged) | one group `mod_<module>_<host role>` per placed host role, `-` written `_` (module `web-app`, host role `server`: `mod_web_app_server`), holding the guest every placement of that role lands on |
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
guest model already writes. `--selection` is for the `inventory` target only (`render` and
`plan`); a selection the schema refuses is exit 1, one that cannot be read exit 2. The inventory is
fleet-wide, so `--node` does not narrow it: render it once.

**The install playbook (`modules.yml`).** One play per placed host role of each selected module,
the modules in **install order**: each after every module that serves a slot it hard-requires
(`requires.capabilities`: the provider of the named instance, or of every instance of the slot
when the requirement names none), ties broken by id. A soft requirement (`prefers`) and an
incumbent order nothing, and a requirement cycle is refused, naming the modules in it. A play:

- targets exactly `mod_<module>_<host role>`, never a group a module names, so a module's roles
  reach only the guests the site placed it on (`role_lint` PB001 holds by construction; a play on
  `cap_notify` would also reach every other host serving the capability);
- escalates (`become: true`), as the baseline playbook does;
- runs the module's own preflight hooks for its roles first (`contributes.preflight`, as
  `pre_tasks`), then the roles the module lists for the host role (`requires.hosts[].roles`), each
  the role interface v1 `main` entry point ([role interface](../role-interface.md));
- is tagged `mod_<module>` and `mod_<module>_<host role>`, so `--tags mod_web_app` installs one
  module.

A host role of kind `external` and one that lists no roles are written as comments, and a module
placed nowhere (a hosted or config-only provider) as `placed on no host`. A selection with no role
to apply is one play on `localhost` that does nothing (`ansible-playbook` refuses an empty
playbook). The module's own `lifecycle.install` playbook is not imported: its plays name their own
hosts, which is the site's placement to decide. Role paths are written relative to `DIR`, so the
render and the checkouts move together: render into the directory the playbooks run from.

**The check playbooks (`checks/<module>.yml`).** For one placed module, on each of its groups, the
`readiness` hook and then the `health` hook of every one of its roles (`include_role` with
`tasks_from`); both are read-only by the role interface contract. `--tags health` (or
`readiness`) runs one hook.

**What it does not do yet.** The selection's `config` values and the module's secrets reach the
roles only through the overlay's group and host variables (no generated variable file); firewall
edges and backup membership stay in the guest file; `lifecycle.upgrade` and `lifecycle.remove`
are not rendered; a host role's `count` copies are not spread over several guests.

## Running it in an overlay

From the overlay root, with the pinned checkout at `hnx/` (the layout `hnx modules check --root hnx
--overlay .` already reads):

```sh
hnx modules check --root hnx --overlay . --deploy
hnx guests render lab/guests --site lab/site.yml --target inventory \
    --selection lab/modules.yml --out build/inventory
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
