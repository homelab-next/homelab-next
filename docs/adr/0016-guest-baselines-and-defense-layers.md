---
summary: Guests name product-neutral defense baselines of controls in six layers; each control binds to a product role in one place.
---
# ADR-0016: Guest baselines and defense layers

- **Status:** proposed
- **Date:** 2026-10-20
- **Related:** ADR-0001, ADR-0004, ADR-0012, ADR-0013, `docs/compute-model.md`,
  `schemas/platform/baseline_set.schema.json` (1.0; 1.1 for decision 7; 1.2 for decision 8),
  `schemas/platform/guest.schema.json` (1.3), `homelabnext/compute/baselines.py`;
  decision 7 amended 2026-10-20 with the first bound products and 2026-10-21 with the rest;
  decision 8 added 2026-10-21

## Context

Every guest needs defenses (an endpoint agent for the SIEM, log forwarding, a vulnerability scan,
a host firewall, hardened SSH, backups that are restored in drills), and which ones it needs
depends on what it is: an edge-facing proxy needs more than a scratch lab VM. Kept as habit, the
list drifts: a guest created in a hurry gets none of them and nothing notices. At the same time
the products are not chosen yet (which SIEM agent, which network sensor, which scanner, which
remote-access gateway), and choosing them must not mean editing every guest file, or the guest
model would encode a product (against the swap discipline of ADR-0004 and ADR-0005).

## Decision

1. A **baseline set** (`_baselines.yml` beside the guest files, `baseline_set.schema.json` 1.0)
   holds a catalogue of generic **controls** and named **baselines** of controls. A baseline may
   `extends` others; resolution is a deterministic union (parents first, listed order, deduped).
2. Every control sits in exactly one **defense layer** from a closed set: identity, host, network,
   detection, data, recovery. Each carries a `verify` line, the observable that proves it is in
   place.
3. **Products are bound per control, in one place**: the control's `role`, the Ansible role that
   implements it, or `null` while no product is chosen. The inventory gains `baseline_<name>` and
   `control_<id>` groups; the `baseline-playbook` target applies each bound role to its
   `control_<id>` group and lists every unbound control as a commented block naming the guests
   that wait for it, never dropping one. Choosing a product is a one-line change to the set.
4. A guest declares `baseline.names` (guest schema 1.3, additive), optionally `add` and `remove`
   (each removal with a reason), or a `baseline.exemption` with a reason and review date, which
   mirrors `network.firewall_exemption`.
5. **When a baseline set exists, every guest (vm, lxc and physical host) must declare a baseline
   or an exemption**; `hnx guests validate` fails otherwise. Without a set nothing is required.
   The set is checked for unknown names, missing `extends` targets, cycles and baselines that
   resolve to nothing.
6. `hnx guests baselines` prints the guest x layer coverage matrix (`--json`, `--check`,
   `--require-bound`), and the status hub serves it as the Baselines page.
7. *(Amendment, baseline set 1.1.)* **A binding says how its role reaches a guest**: `apply:
   guest` (the default, and what every 1.0 control means) runs the role on each guest that needs
   the control, through `control_<id>`; `apply: central` with `group: cap_<x>` runs it **once on
   the central product host** and passes it `<role>_guests`, every guest that needs the control
   as `{id, name, fqdn, ip, zone}`, for that product to enroll. Software on the guest (an
   endpoint agent, a VPN client) is a guest binding; enrolment in a central product (a network
   sensor's monitored addresses, a scanner's targets) is a central one, because nothing is
   installed on the guest. `group` is required with `central` and refused with `guest`, and must
   be a known inventory group; `cap_sensor` and `cap_scanner` are added for the two central
   products. A central control whose group holds no guest of the model is reported (`NO HOST`
   in the playbook, `unplaced` in the coverage report) and fails `--require-bound`. The first
   bindings are the Wazuh agent (`siem-agent`, guest), Suricata (`network-sensor`, central),
   Greenbone (`vuln-scan`, central, the authenticated internal assessment) and Tailscale
   (`remote-access`, guest); the `tailscale-acl` target renders the tailnet policy from the site
   model (a tag per zone, admins on SSH, the site's zone-to-zone allows), so remote access
   follows the zones rather than hand-written policy.
   *(Addendum, 2026-10-21.)* Every control of the example catalogue is now bound, each to a
   first-version role with the same interface (`docs/compute-model.md`, "Bound products"): chrony,
   unattended-upgrades, an OpenSSH drop-in, sssd against the identity provider's LDAP outpost,
   nftables from the guest model's own `firewall_rules` (host-firewall and egress-filter share
   it), rsyslog over TLS, a CIS-lite hardening set, auditd, Lynis, Trivy, AIDE, rkhunter, ClamAV
   and etckeeper on the guest; restore drills centrally on the backup host (`cap_backup`, added
   beside `cap_sensor` and `cap_scanner`). Two controls are **verified, not applied**, because
   applying them is destructive or belongs elsewhere: disk-encryption (encryption happens at
   provisioning; the role reports data volumes without a crypt layer) and secrets-from-store (the
   repository's leak scanner runs over the guest's configuration directories). Six controls were
   added to the catalogue: host-audit, host-assessment (the verify of os-hardening),
   package-scan, file-integrity, rootkit-check and malware-scan, with a `container-host`
   baseline; then restart-required (needrestart, list-only, in `base` beside patching).
8. *(Amendment, baseline set 1.2.)* **A baseline may set the inputs of a control's role**: its
   `controls` list takes a control id or `{id, with}`, where `with` names inputs of the bound
   role's `meta/argument_specs.yml` main options without the role prefix. Their names and types
   come from that file, the one source of truth; a control's `settings` list may narrow which of
   them a baseline may set, and `with` on an unbound control is refused. Settings merge parent
   first through `extends`, so a baseline overrides what it extends (`sensitive` scans packages
   at MEDIUM where `server` says HIGH); two baselines that set one input differently are refused
   unless the later one extends the other, for the set and for each guest's names. A guest file
   carries no settings: a per-guest value is a one-guest baseline that extends the shared one, so
   every value is reviewed in the set. The `inventory` target writes the settings of per-guest
   controls as the role's prefixed host variables; a central control's enrolled rows carry them
   as `settings`; the coverage report and the Baselines page list every value that differs from
   the role's default.

## Consequences

Creating a guest without deciding its defenses is no longer possible once a lab has a set, and
an opt-out is a reviewed line with a reason rather than an omission. The coverage matrix shows
which rings of defense each guest has before any product is installed, and `--require-bound`
turns "we have not picked a SIEM agent yet" into a visible, checkable gap. Binding a product
touches one file and re-renders the playbook; swapping it later is the same edit.

Decision 7 keeps that one-line edit true for products that do not live on the guest: without
it, a sensor or scanner binding would have to install something pointless on every guest or
live outside the model. A central play carries the guest list in the rendered playbook, so the
list is reviewed in the same diff as the guest change that caused it. The roles are first
versions to be tuned on the real lab; their limits are listed in `docs/compute-model.md`
("Bound products").

It obliges us to keep the control catalogue generic (a control names a function, never a
product) and to keep `verify` lines honest; the model does not run them. The requirement is
conditional on the set existing, so a lab that never writes one gets no baseline enforcement:
this is deliberate, because a pre-1.3 tree must stay valid (ADR-0001's additive evolution), and
a missing set is visible to `hnx guests baselines --check`, which fails without one.

Decision 8 lets a baseline say "this kind of guest is scanned more strictly" without a second
rule language and without a value per guest file; the price is that the compute model reads the
roles' argument_specs (`HNX_ROLES_DIR`, or the checkout's `ansible/roles`), so a set with
settings cannot be checked where the roles are absent.

## Alternatives

- **Products in the guest file** (for example `siem: product-x`): every product choice or swap
  would touch every guest, and the guest model would stop being vendor-neutral.
- **Baselines from tags or capability groups**: implicit; a guest with the wrong tag silently
  gets fewer defenses, and there is no place to record why a guest is exempt.
- **Making `baseline` required in the schema**: breaks every existing tree (not additive) and
  cannot express "required only when a set defines what baselines exist".
- **Central products as a second, separate catalogue** (sensors and scanners outside
  `controls`): the coverage matrix would lose them, and "is this guest scanned" would have two
  sources. **Discovering enrolment at run time** from `groups['control_<id>']` inside the
  central play: works, but the enrolled list would not be visible in the rendered playbook or
  testable as a golden.
- **Settings in the guest file or in hand-written `group_vars`** (for decision 8): a value per
  guest repeats what a baseline means, and `group_vars/baseline_<name>.yml` would merge by
  Ansible's group precedence (alphabetical at one depth), not by `extends`, and nothing would
  check the keys. **A separate settings schema per control in the set**: a second copy of every
  role's inputs that drifts from the role.
- **Open-ended layers**: a free-text layer drifts into synonyms, and the coverage matrix would
  stop being comparable between guests and labs.
