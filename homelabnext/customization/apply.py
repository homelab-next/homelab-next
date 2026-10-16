# SPDX-License-Identifier: Apache-2.0
"""The applier: customizations in, a PLAN and a resolved view out.

Hard rules, enforced here and covered by tests:

* The applier never edits a core file. It writes nothing at all except an explicit output file
  chosen by the caller, and refuses an output path inside a core directory.
* Only the five sanctioned extension points exist (variable override, role hook, template
  overlay, registry patch, opt-in host profile). Anything else cannot even be expressed: the
  schema rejects it before the applier sees it.
* Fail closed: a customization with any lint error is excluded from the resolved view and the
  plan reports it; a conflict excludes every customization involved.
* A registry patch is applied to a COPY of the registry and the result must pass the service
  schema and the registry's semantic checks, or the patch is rejected.
* Deterministic: order is (kind rank, id); the same inputs give a byte-identical plan.
"""

from __future__ import annotations

import copy
import hashlib
from datetime import date
from pathlib import Path
from typing import Any

from .lint import lint
from .model import Customization, Finding, extension_points, sort_key
from .resolve import active, detect_conflicts, resolve_hosts
from .universe import Universe

__all__ = ["PLAN_SCHEMA", "build_plan", "write_plan"]

PLAN_SCHEMA = "hnx.customization.plan/1"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _registry_problems(doc: dict[str, Any]) -> list[str]:
    from homelabnext.registry.model import schema_problems, semantic_problems

    probs = schema_problems(doc)
    return probs if probs else semantic_problems(doc)


def build_plan(
    items: list[Customization],
    universe: Universe,
    today: date,
    enabled: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    enabled = enabled or {}
    findings = lint(items, universe, today, enabled)
    errors = [f for f in findings if f.severity == "error"]
    # Fail closed: drop every customization named by any error.
    bad_ids: set[str] = set()
    for f in errors:
        bad_ids.update(f.customization.split(","))
    for c in items:
        if c.schema_errors:
            bad_ids.add(c.id)
    live = [c for c in active(items, enabled) if c.id not in bad_ids and not c.schema_errors]
    live.sort(key=sort_key)

    role_vars: dict[str, dict[str, Any]] = {}
    hooks: dict[str, dict[str, dict[str, list[str]]]] = {}
    overlays: dict[str, dict[str, list[dict[str, str]]]] = {}
    profiles: dict[str, dict[str, Any]] = {}
    registry_changes: list[dict[str, Any]] = []
    plan_items: list[dict[str, Any]] = []
    patched = copy.deepcopy(universe.registry) if universe.registry is not None else None
    extra: list[Finding] = []

    for c in live:
        a = c.action
        hosts = sorted(resolve_hosts(c, universe, enabled))
        entry: dict[str, Any] = {
            "id": c.id,
            "kind": c.kind,
            "origin": c.origin,
            "owner": c.doc["owner"],
            "review_by": c.doc["review_by"],
            "applies_to": {"hosts": hosts, "scope": c.scope},
            "extension_points": extension_points(c),
            "changes": [],
        }
        if c.kind == "override":
            for var, val in sorted(a["vars"].items()):
                role_vars.setdefault(a["role"], {})[var] = val
                entry["changes"].append({"set_var": f"{a['role']}.{var}", "value": val})
        elif c.kind == "hook":
            f = str((c.base / a["tasks_file"]).relative_to(c.base))
            hooks.setdefault(a["role"], {}).setdefault(a["entry_point"], {}).setdefault(
                a["phase"], []
            ).append(f"{c.id}:{f}")
            entry["changes"].append(
                {"hook": f"{a['role']}.{a['entry_point']}", "phase": a["phase"], "tasks": f}
            )
        elif c.kind == "patch-overlay":
            ov = c.base / a["overlay"]
            overlays.setdefault(a["role"], {}).setdefault(a["template"], []).append(
                {"id": c.id, "mode": a["mode"], "overlay": a["overlay"], "sha256": _sha(ov)}
            )
            entry["changes"].append(
                {
                    "overlay_template": f"{a['role']}/{a['template']}",
                    "mode": a["mode"],
                    "sha256": _sha(ov),
                }
            )
        elif c.kind == "profile":
            p = profiles.setdefault(a["profile"], {"hosts": set(), "tasks": [], "vars": {}})
            p["hosts"] |= set(hosts)
            p["tasks"] += [{"id": c.id, "name": t["name"], "file": t["file"]} for t in a["tasks"]]
            p["vars"].update(a.get("vars", {}))
            entry["changes"].append({"add_profile_tasks": a["profile"], "count": len(a["tasks"])})
        elif c.kind == "registry-patch":
            if patched is None:
                extra.append(
                    Finding("CU004", "error", c.id, "no registry loaded to validate the patch")
                )
                continue
            trial = copy.deepcopy(patched)
            row = trial["services"][a["service"]]
            before = {k: row.get(k) for k in a["set"]}
            row.update(a["set"])
            probs = _registry_problems(trial)
            if probs:
                for pr in probs:
                    extra.append(Finding("CU004", "error", c.id, f"patched registry invalid: {pr}"))
                continue
            patched = trial
            for k in sorted(a["set"]):
                registry_changes.append(
                    {
                        "id": c.id,
                        "service": a["service"],
                        "field": k,
                        "before": before[k],
                        "after": a["set"][k],
                    }
                )
                entry["changes"].append(
                    {"registry": f"{a['service']}.{k}", "before": before[k], "after": a["set"][k]}
                )
        plan_items.append(entry)

    rejected_ids = {f.customization for f in extra}
    plan_items = [p for p in plan_items if p["id"] not in rejected_ids]
    findings = sorted(
        [*findings, *extra],
        key=lambda f: (f.severity != "error", f.customization, f.code, f.message),
    )
    inactive = sorted(c.id for c in items if c.optional and c.id not in enabled)
    return {
        "schema": PLAN_SCHEMA,
        "date": today.isoformat(),
        "ok": not any(f.severity == "error" for f in findings),
        "items": plan_items,
        "inactive_optional": inactive,
        "findings": [f.as_dict() for f in findings],
        "conflicts": [
            {"extension_point": cf.extension_point, "ids": list(cf.ids)}
            for cf in detect_conflicts(
                active([c for c in items if not c.schema_errors], enabled), universe, enabled
            )
        ],
        "resolved": {
            "role_vars": {r: dict(sorted(v.items())) for r, v in sorted(role_vars.items())},
            "hooks": hooks,
            "template_overlays": overlays,
            "profiles": {
                n: {**p, "hosts": sorted(p["hosts"])} for n, p in sorted(profiles.items())
            },
            "registry_changes": registry_changes,
        },
    }


def write_plan(plan: dict[str, Any], out: Path, universe: Universe) -> None:
    """The only write the applier performs, and only where the caller says, never into core."""
    import json

    real = out.resolve()
    for root in universe.core_roots:
        if real == root or root in real.parents:
            raise PermissionError(f"refusing to write {out}: inside core directory {root.name}/")
    out.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
