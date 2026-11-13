# SPDX-License-Identifier: Apache-2.0
"""Ansible inventory grouped by capability (``cap_*``) with per-host variables from the model.

Playbooks target groups, never hosts (docs/role-interface.md section 5).  Every guest appears,
including manual ones and physical hosts, because configuration management applies to all.
With a baseline set, each guest is also in ``baseline_<name>`` for every baseline it resolves to
(``extends`` included) and ``control_<id>`` for every control it needs, and carries
``hnx_baselines`` / ``hnx_controls`` (the baseline-playbook target plays to those groups), and
the baseline settings (``with:``, baseline set 1.2) of its per-guest controls as the bound roles'
prefixed variables (``trivy_severity: "HIGH"``).

With a module selection (``--selection``, docs/modules/apply.md), each placed module host role is
also a group, ``mod_<module>_<host role>``, holding the guest its selection host references
(:func:`homelabnext.modules.apply.inventory_groups`); the ``hnx modules render`` playbooks target
those groups.  Without one the render is unchanged.

With ``--group-vars DIR`` (:func:`group_vars`), the overlay's group variable files (one
``<group>.yml`` per group, plain YAML) are carried into the render as ``group_vars/<group>.yml``,
next to ``hosts.yml``, where Ansible reads them; a file for a group the inventory does not hold is
refused, so a typo or a module no longer selected cannot set nothing silently.
"""

from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path

import yaml

from homelabnext import _yaml
from homelabnext.compute.baselines import resolve, role_vars
from homelabnext.compute.model import ComputeError, ComputeUnreadable, Fleet, Guest
from homelabnext.shapes import VAULT_BLOB

from ._text import HEADER, q, qlist
from .firewall_rules import resolve_addresses


def baseline_group(name: str) -> str:
    return "baseline_" + name.replace("-", "_")


def control_group(control: str) -> str:
    return "control_" + control.replace("-", "_")


def _fw_rules(fleet: Fleet, rule: dict, side: str) -> list[str]:
    """One row per address the rule names: a ``zone:`` with a ``subnet6`` is two rows of the same
    name, the IPv4 subnet's and the IPv6 prefix's."""
    out = []
    for addr in resolve_addresses(fleet, rule[side]):
        row = {"name": rule["name"], "proto": rule["proto"]}
        if rule.get("ports"):
            row["ports"] = rule["ports"]
        row[side] = addr or "any"
        out.append("{" + ", ".join(f"{k}: {q(v)}" for k, v in row.items()) + "}")
    return out


def firewall_vars(fleet: Fleet, g: Guest) -> list[str]:
    """``hnx_firewall``: the guest's firewall rules with zones resolved to subnets (and to the
    zone's IPv6 prefix as a second row of the same name, where it has one)."""
    L = ["hnx_firewall:", f"  policy_out: {q(g.policy_out)}"]
    for key, rules, side in (
        ("inbound_allow", g.firewall_rules, "source"),
        ("outbound_allow", g.outbound_rules, "dest"),
    ):
        if not rules:
            L.append(f"  {key}: []")
            continue
        L.append(f"  {key}:")
        L += [f"    - {row}" for r in rules for row in _fw_rules(fleet, dict(r), side)]
    return L


def host_vars(fleet: Fleet, g: Guest) -> str:
    v: dict[str, object] = {
        "ansible_host": g.ip,
        "hnx_guest_id": g.id,
        "hnx_kind": g.kind,
        "hnx_provisioning": g.provisioning,
        "hnx_zone": g.zone,
        "hnx_node": g.node,
        "hnx_capability": g.capability,
        "hnx_owner": g.owners["primary"],
        "hnx_backup_policy": g.backup_policy,
    }
    if g.cloudinit.get("user"):
        v["ansible_user"] = g.cloudinit["user"]
    if g.vmid is not None:
        v["hnx_vmid"] = g.vmid
    if g.owners.get("oncall"):
        v["hnx_oncall"] = g.owners["oncall"]
    if g.backup.get("export_hook"):
        v["hnx_export_hook"] = g.backup["export_hook"]
    L = [f"# {HEADER}"]
    for k in sorted(v):
        L.append(f"{k}: {q(v[k])}")
    L.append(f"hnx_tags: {qlist(sorted(g.tags))}")
    L += firewall_vars(fleet, g)
    if fleet.baselines is not None:
        r = resolve(g, fleet.baselines)
        L.append(f"hnx_baselines: {qlist(list(r.baselines))}")
        L.append(f"hnx_controls: {qlist(list(r.controls))}")
        if r.exemption:
            L.append(f"hnx_baseline_exemption: {q(r.exemption['reason'])}")
        settings = role_vars(fleet.baselines, r)
        if settings:
            L.append("# baseline settings (with:) of the controls applied on this guest")
            L += [f"{k}: {json.dumps(v, sort_keys=True)}" for k, v in sorted(settings.items())]
    return "\n".join(L) + "\n"


def module_groups(fleet: Fleet, selection: dict, taken: frozenset[str]) -> dict[str, list[str]]:
    """The selection's ``mod_*`` groups over this fleet's guests (a guest id -> its fqdn); a
    placement the inventory cannot hold is a :class:`ComputeError` naming it."""
    from homelabnext.modules.apply import ApplyError, inventory_groups

    by_id = {g.id: fleet.fqdn(g) for g in fleet.guests}
    try:
        return inventory_groups(selection, by_id.get, taken)
    except ApplyError as exc:
        raise ComputeError(f"--selection: {exc}") from None


def hosts_yml(fleet: Fleet, selection: dict | None = None) -> str:
    guests = fleet.sorted()
    groups: dict[str, list[str]] = {}
    for g in guests:
        for grp in g.groups:
            groups.setdefault(grp, []).append(fleet.fqdn(g))
        for t in g.tags:
            groups.setdefault(f"tag_{t.replace('-', '_')}", []).append(fleet.fqdn(g))
        if fleet.baselines is not None:
            r = resolve(g, fleet.baselines)
            for b in r.baselines:
                groups.setdefault(baseline_group(b), []).append(fleet.fqdn(g))
            for c in r.controls:
                groups.setdefault(control_group(c), []).append(fleet.fqdn(g))
    if selection is not None:
        groups.update(module_groups(fleet, selection, frozenset(groups)))
    L = [f"# {HEADER}", "all:", "  children:", "    guests:", "      hosts:"]
    L += [f"        {fleet.fqdn(g)}:" for g in guests]
    for grp in sorted(groups):
        L += [f"    {grp}:", "      hosts:"]
        L += [f"        {h}:" for h in sorted(groups[grp])]
    return "\n".join(L) + "\n"


def render(fleet: Fleet, selection: dict | None = None) -> dict[str, str]:
    out = {"hosts.yml": hosts_yml(fleet, selection)}
    for g in fleet.sorted():
        out[f"host_vars/{fleet.fqdn(g)}.yml"] = host_vars(fleet, g)
    return out


#: a group variable file the render carries: an Ansible group name, ``.yml`` or ``.yaml``
_GROUP_VARS_FILE = re.compile(r"(?P<group>[A-Za-z_][A-Za-z0-9_]*)\.ya?ml\Z")
#: the largest group variable file carried (a typo'd path must not pull in a disk image)
GROUP_VARS_MAX = 1 << 20


def _read_regular(path: Path) -> str:
    """A regular file's text, opened without following a link (refused, not followed)."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise ComputeUnreadable(f"--group-vars {path}: {exc.strerror}") from None
    with os.fdopen(fd, "rb") as fh:
        if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
            raise ComputeUnreadable(f"--group-vars {path}: not a regular file")
        data = fh.read(GROUP_VARS_MAX + 1)
    if len(data) > GROUP_VARS_MAX:
        raise ComputeUnreadable(f"--group-vars {path}: larger than {GROUP_VARS_MAX} bytes")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise ComputeUnreadable(f"--group-vars {path}: not UTF-8 text") from None


def group_vars(directory: str | Path, hosts_yml_text: str) -> dict[str, str]:
    """``group_vars/<group>.yml`` for every ``<group>.yml`` (or ``.yaml``) in ``directory``, each
    a group of the rendered inventory (``hosts_yml_text``) or ``all``.  The content is carried as
    written, after a header naming it generated (so ``--prune`` knows it); it must be plain YAML
    holding a mapping (an ``ansible-vault`` file is refused: secrets reach roles by reference).
    Unreadable input is :class:`ComputeUnreadable` (exit 2); a file for a group the inventory
    does not hold, two files for one group or a non-mapping is :class:`ComputeError` (exit 1)."""
    d = Path(directory)
    if d.is_symlink() or not d.is_dir():
        raise ComputeUnreadable(f"--group-vars {d}: not a directory")
    inv = _yaml.safe_load(hosts_yml_text)
    groups = {"all", *inv["all"]["children"]}
    out: dict[str, str] = {}
    problems: list[str] = []
    for entry in sorted(d.iterdir()):
        if entry.name.startswith("."):
            continue
        m = _GROUP_VARS_FILE.match(entry.name)
        if m is None:
            problems.append(
                f"{entry.name}: not <group>.yml (a group_vars/<group>/ directory is not carried)"
            )
            continue
        group = m["group"]
        text = _read_regular(entry)
        if re.match(VAULT_BLOB, text.lstrip()):
            problems.append(
                f"{entry.name}: an ansible-vault file (give secrets by reference, secret:<name>)"
            )
            continue
        try:
            # a key given twice is refused: one of the two would be set silently
            doc = yaml.load(text, Loader=_yaml.UniqueKeyLoader)
        except yaml.YAMLError as exc:
            mark = getattr(exc, "problem_mark", None)
            where = f" at line {mark.line + 1}" if mark else ""
            raise ComputeUnreadable(f"--group-vars {entry}: not valid YAML{where}") from None
        if doc is not None and not isinstance(doc, dict):
            problems.append(f"{entry.name}: not a mapping of variables")
            continue
        if group not in groups:
            problems.append(f"{entry.name}: {group} is no group of this inventory")
            continue
        rel = f"group_vars/{group}.yml"
        if rel in out:
            problems.append(f"{entry.name}: a second file for group {group}")
            continue
        out[rel] = f"# {HEADER}\n# carried from --group-vars: {entry.name}\n{text}"
        if not text.endswith("\n"):
            out[rel] += "\n"
    if problems:
        raise ComputeError("--group-vars: " + "; ".join(problems))
    return out
