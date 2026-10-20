# SPDX-License-Identifier: Apache-2.0
"""An Ansible playbook that applies each defense control's role to the guests that need it.

One play per control, by layer (identity, host, network, detection, data, recovery) then id,
targeting the ``control_<id>`` inventory group (the ``inventory`` target writes it).  A control
whose ``role`` is null has no product yet: it is written as a commented block that names the
guests waiting for it, never dropped.  A control no guest needs is listed as such.  The product
is chosen in one place, the control's ``role`` in the baseline set (ADR-0016).
"""

from __future__ import annotations

from homelabnext.compute.baselines import LAYERS, coverage
from homelabnext.compute.model import Fleet

from ._text import HEADER, q, qlist
from .inventory import control_group

FILE = "baseline.yml"


def render(fleet: Fleet) -> dict[str, str]:
    L = [f"# {HEADER}"]
    bs = fleet.baselines
    if bs is None:
        L += ["# no baseline set (_baselines.yml): nothing to apply", "[]"]
        return {FILE: "\n".join(L) + "\n"}
    report = coverage(fleet.sorted(), bs)
    L += [
        "# Applies each defense control's role to its control_<id> inventory group.",
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
            name = f"control {c} ({layer})"
            if not needed:
                L.append(f"# {name}: needed by no guest; nothing to apply")
                continue
            if role is None:
                L += [
                    f"# {name}: NOT BOUND to a product yet; set `role` in the baseline set.",
                    f"#   needed by: {', '.join(g.removeprefix('guest:') for g in needed)}",
                    f"#   verify: {info['verify']}",
                    f"# - name: {q(name)}",
                    f"#   hosts: {control_group(c)}",
                    "#   roles: [<role>]",
                ]
                continue
            plays += 1
            L += [
                f"- name: {q(name)}",
                f"  hosts: {control_group(c)}",
                f"  tags: {qlist([control_group(c), f'layer_{layer}'])}",
                f"  # verify: {info['verify']}",
                "  roles:",
                f"    - role: {role}",
            ]
    if not plays:
        L += ["", "# no control is bound to a role yet", "[]"]
    return {FILE: "\n".join(L) + "\n"}
