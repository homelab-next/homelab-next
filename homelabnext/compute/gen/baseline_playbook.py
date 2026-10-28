# SPDX-License-Identifier: Apache-2.0
"""An Ansible playbook that applies each defense control's role to the guests that need it.

One play per control, by layer (identity, host, network, detection, data, recovery) then id.  A
control applied per guest (``apply: guest``, the default) targets the ``control_<id>`` inventory
group (the ``inventory`` target writes it).  A control applied centrally (``apply: central``,
ADR-0016 decision 7) targets its ``group``, the central product host, once, and passes the role
``<role>_guests``: every guest that needs the control as ``{id, name, fqdn, ip, zone}``, sorted
by id, which the product enrolls (a sensor's monitored addresses, a scanner's targets); a guest
that names other addresses it sends from (``network.extra_addresses``, guest 1.6) carries them as
``extra_addresses: [...]`` after ``ip``, so a sensor counts them as its own, and its zone's IPv4
``subnet`` after ``zone`` (and its IPv6 ``subnet6``, site 1.4, when the zone gives one), so the
role can hold each one to the guest's own zone as validation did; a guest whose baselines set
inputs of that role (``with:``, baseline set 1.2) carries them as ``settings: {<role>_<input>:
value}`` in its row.  A per-guest control's settings are host
variables (the ``inventory`` target writes them), so its play names only the role.

A control whose ``role`` is null has no product yet: it is written as a commented block that names
the guests waiting for it, never dropped.  A control no guest needs is listed as such.  The
product is chosen in one place, the control's ``role`` in the baseline set (ADR-0016).

With no baseline set, or no control bound to a role, the file is one play on ``localhost`` that
gathers no facts and has no tasks, with the reason as a comment: a valid playbook that does
nothing, since ``ansible-playbook`` refuses a file with no play.
"""

from __future__ import annotations

import json

from homelabnext.compute.baselines import APPLY_CENTRAL, LAYERS, coverage, resolve
from homelabnext.compute.model import Fleet

from ._text import HEADER, q, qlist
from .inventory import control_group

FILE = "baseline.yml"

#: what stands in for the plays when there are none: ``ansible-playbook`` refuses an empty list
#: ("A playbook must contain at least one play"), so a fleet with nothing to apply gets one play
#: on the control node that does nothing and gathers nothing
NO_OP = ["- name: no baseline control to apply", "  hosts: localhost", "  gather_facts: false"]


def enrolled(fleet: Fleet, guest_ids: list[str], control: str | None = None) -> list[dict]:
    """What a central role receives for each guest: id, name, fqdn, ip and zone, sorted by id;
    ``extra_addresses`` and the zone's ``subnet`` (and ``subnet6``, when it has one) when the
    guest names extra addresses; and
    ``settings`` (the guest's baseline settings of ``control`` as role variables) when its
    baselines set any."""
    by_id = {g.id: g for g in fleet.guests}
    out: list[dict] = []
    for g in sorted((by_id[i] for i in guest_ids), key=lambda x: x.id):
        row: dict = {"id": g.id, "name": g.name, "fqdn": fleet.fqdn(g), "ip": g.ip}
        if g.extra_addresses:
            row["extra_addresses"] = list(g.extra_addresses)
        row["zone"] = g.zone
        if g.extra_addresses:
            zone = fleet.zone(g)
            row["subnet"] = zone.subnet
            if zone.subnet6 is not None:
                row["subnet6"] = zone.subnet6
        if control and fleet.baselines is not None:
            role = fleet.baselines.role(control)
            mine = resolve(g, fleet.baselines).settings.get(control, {})
            if role and mine:
                row["settings"] = {f"{role}_{k}": v for k, v in sorted(mine.items())}
        out.append(row)
    return out


def _flow(row: dict) -> str:
    return (
        "{"
        + ", ".join(
            f"{k}: {json.dumps(v, sort_keys=True) if isinstance(v, dict | list) else q(v)}"
            for k, v in row.items()
        )
        + "}"
    )


def render(fleet: Fleet) -> dict[str, str]:
    L = [f"# {HEADER}"]
    bs = fleet.baselines
    if bs is None:
        L += ["# no baseline set (_baselines.yml): nothing to apply", *NO_OP]
        return {FILE: "\n".join(L) + "\n"}
    report = coverage(fleet.sorted(), bs)
    L += [
        "# Applies each defense control's role to its control_<id> inventory group, or, for a",
        "# central control, once to its product host's group with the guests to enroll.",
        "# Bind a product by setting the control's `role` in the baseline set.",
    ]
    plays = 0
    for layer in LAYERS:
        ctrls = [c for c in bs.ordered_controls() if bs.layer(c) == layer]
        if not ctrls:
            continue
        L += ["", f"# ---- layer: {layer}"]
        for c in ctrls:
            info = report["controls"][c]
            needed = info["needed_by"]
            role = info["role"]
            central = info["apply"] == APPLY_CENTRAL
            name = f"control {c} ({layer}, central)" if central else f"control {c} ({layer})"
            hosts = info["group"] if central else control_group(c)
            if not needed:
                L.append(f"# {name}: needed by no guest; nothing to apply")
                continue
            if role is None:
                L += [
                    f"# {name}: NOT BOUND to a product yet; set `role` in the baseline set.",
                    f"#   needed by: {', '.join(g.removeprefix('guest:') for g in needed)}",
                    f"#   verify: {info['verify']}",
                    f"# - name: {q(name)}",
                    f"#   hosts: {hosts}",
                    "#   roles: [<role>]",
                ]
                continue
            plays += 1
            L += [
                f"- name: {q(name)}",
                f"  hosts: {hosts}",
                f"  tags: {qlist([control_group(c), f'layer_{layer}'])}",
                f"  # verify: {info['verify']}",
            ]
            if central:
                if c in report["unplaced"]:
                    L.append(
                        f"  # NO HOST: no guest of the model is in {hosts}; this play is a no-op"
                    )
                L += [
                    "  # enrolls each guest that needs the control on the central product host",
                    "  roles:",
                    f"    - role: {role}",
                    f"      {role}_guests:",
                ]
                L += [f"        - {_flow(row)}" for row in enrolled(fleet, needed, c)]
            else:
                if any(c in resolve(g, bs).settings for g in fleet.guests):
                    L.append(
                        "  # baseline settings (with:) are host variables (the inventory target)"
                    )
                L += ["  roles:", f"    - role: {role}"]
    if not plays:
        L += ["", "# no control is bound to a role yet", *NO_OP]
    return {FILE: "\n".join(L) + "\n"}
