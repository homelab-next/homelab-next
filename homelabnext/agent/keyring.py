# SPDX-License-Identifier: Apache-2.0
"""The keyring: one generated map of access, and the check that it has not drifted (M-12).

What the keyring is.  ADR-0002 lists "keyring rows" among the outputs generated from the
registry, and checklist M-11 asks that "every principal is in the keyring with grants by level
and denials".  Nothing hand-written holds that map, so here it is a **generated document** whose
only inputs are the sources that already decide access:

* the service registry (``services.yml``): services, their capability aliases, MCP servers,
  hosts, zones and which zones may connect (``clients``, dependencies);
* the compiled agent profiles (``agent/profile``): each agent's grants, tier, data tier and
  memory scopes, each verified against the ceiling ``policy`` and the ``lock`` of reviewed
  digests the sources file names (:func:`~homelabnext.agent.compiler.verified_profile`), so an
  edited profile is refused whether or not its digest was recomputed;
* optionally the broker manifest (``broker/manifest``): which profile may request which action
  at which tier, and who may approve.

Principals: every profile (``kind: agent``), every profile the broker grants actions to without
a compiled profile in the set (``kind: agent``, ``profile: null``), every broker approver
(``kind: human`` or ``agent``) and every registry zone (``kind: network``).  Each row lists
grants with a level and, where the registry knows it, the endpoint; and the explicit denials.

The sources file (YAML, paths relative to it)::

    registry: ../services.yml
    profiles: [../../schemas/agent/examples/profile.reader.json, ...]   # globs allowed
    policy: policy.yml        # ceiling policy (hnx agent verify --policy); needed with profiles
    lock: lock.yml            # reviewed digests {profiles: {<id>: <digest>}}; needed with profiles
    broker: ../../schemas/broker/examples/manifest.example.json         # optional
    out: keyring.json

``hnx agent keyring build SOURCES`` writes ``out``; ``hnx agent keyring check SOURCES``
regenerates it and fails on any difference (``make keyring-check``, part of ``make check``).
The keyring is never edited by hand: change a source and rebuild.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from .access import principal_access, reachable_services
from .compiler import (
    CeilingPolicy,
    VerifiedProfile,
    lock_from_mapping,
    require_verified,
    verified_profile,
)
from .digest import digest_of
from .errors import SpecError
from .readers import ToolClasses, default_classes

KEYRING_VERSION = 1


#: the tiers whose rows are in the keyring (ADR-0039 decision 2): a retiring or legacy row is
#: in no principal's grants or denials
KEYRING_TIERS = ("primary", "eval")


def _zones(registry: Any) -> list[dict]:
    rows = []
    listed = registry.rows(*KEYRING_TIERS)
    for zone in sorted(registry.zones):
        reach = {s.name for s in reachable_services(registry, zone, with_eval=True)}
        rows.append(
            {
                "principal": f"zone:{zone}",
                "kind": "network",
                "grants": [
                    {
                        "resource": f"svc:{s.name}",
                        "kind": "service",
                        "level": "connect",
                        # a primary by its capability alias, an eval row by its row name
                        "endpoint": registry.address_of(s),
                    }
                    for s in listed
                    if s.name in reach
                ],
                "denials": [
                    {"resource": f"svc:{s.name}", "reason": "zone not a client (default deny)"}
                    for s in listed
                    if s.name not in reach
                ],
            }
        )
    return rows


def build_keyring(
    registry: Any,
    profiles: Iterable[VerifiedProfile],
    *,
    broker: Mapping[str, Any] | None = None,
    classes: ToolClasses | None = None,
) -> dict:
    """The keyring document generated from its sources (pure; deterministic).  Every profile is
    a :class:`~homelabnext.agent.compiler.VerifiedProfile`."""
    classes = classes or default_classes()
    by_id: dict[str, VerifiedProfile] = {}
    for p in profiles:
        pid = require_verified(p, "the keyring")["id"]
        if pid in by_id:
            raise SpecError(f"{pid}: profile given twice")
        by_id[pid] = p
    rows: list[dict] = []
    for pid, p in sorted(by_id.items()):
        row = principal_access(pid, registry, profile=p, broker=broker, classes=classes)
        row.update(
            profile=p["digest"],
            broker_tier=(p.get("grants") or {}).get("tier"),
            data_tier=p.get("data_tier"),
            reads_untrusted=p.get("reads_untrusted", True),
            memory_scopes=sorted(p.get("memory_scopes") or []),
        )
        rows.append(row)
    for pid in sorted({g["profile"] for g in (broker or {}).get("grants", [])} - set(by_id)):
        row = principal_access(pid, registry, broker=broker, classes=classes)
        row.update(profile=None)
        rows.append(row)
    if broker:
        for a in sorted(broker.get("approvers", []), key=lambda a: (a["issuer"], a["subject"])):
            rows.append(
                {
                    "principal": f"{a['issuer']}:{a['subject']}",
                    "kind": a.get("kind", "human"),
                    "grants": [
                        {
                            "resource": f"approve:{broker['manifest_id']}",
                            "kind": "broker-approval",
                            "level": "privileged",
                        }
                    ],
                    "denials": [],
                }
            )
    rows += _zones(registry)
    rows.sort(key=lambda r: (r["kind"], r["principal"]))
    return {
        "keyring_version": KEYRING_VERSION,
        "generated_from": {
            "registry": registry.digest,
            "profiles": {pid: p["digest"] for pid, p in sorted(by_id.items())},
            "broker": digest_of(broker) if broker else None,
            "classes": digest_of(classes.table),
        },
        "principals": rows,
    }


def render_keyring(doc: Mapping[str, Any]) -> str:
    return json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _load(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".json":
        return json.loads(text)
    import yaml

    return yaml.safe_load(text)


def load_sources(path: str | Path, classes: ToolClasses | None = None) -> dict:
    """Resolve a sources file: ``{registry, profiles, policy, lock, broker, out}`` (paths relative
    to it); each profile is verified against ``policy`` and ``lock``."""
    from homelabnext.registry import load as load_registry

    path = Path(path)
    base = path.resolve().parent
    doc = _load(path) or {}
    if not isinstance(doc, Mapping) or not doc.get("registry") or not doc.get("out"):
        raise SpecError(f"{path}: needs 'registry' and 'out' (and usually 'profiles')")
    files: list[Path] = []
    for pattern in doc.get("profiles") or []:
        hits = sorted(base.glob(pattern)) if any(c in pattern for c in "*?[") else [base / pattern]
        if not hits or not all(h.is_file() for h in hits):
            raise SpecError(f"{path}: profiles entry {pattern!r} names no file")
        files += hits
    profiles = []
    if files:
        if not doc.get("policy") or not doc.get("lock"):
            raise SpecError(
                f"{path}: profiles are verified against a ceiling 'policy' and a 'lock' of "
                "reviewed digests; name both"
            )
        policy = CeilingPolicy.from_mapping(_load(base / doc["policy"]) or {}, str(doc["policy"]))
        lock = lock_from_mapping(_load(base / doc["lock"]), str(doc["lock"]))
        profiles = [
            verified_profile(_load(f), policy=policy, lock=lock, classes=classes) for f in files
        ]
    return {
        "registry": load_registry(base / doc["registry"]),
        "profiles": profiles,
        "broker": _load(base / doc["broker"]) if doc.get("broker") else None,
        "out": base / doc["out"],
    }


def build_from_sources(path: str | Path, classes: ToolClasses | None = None) -> tuple[str, Path]:
    src = load_sources(path, classes)
    doc = build_keyring(src["registry"], src["profiles"], broker=src["broker"], classes=classes)
    return render_keyring(doc), src["out"]


def drift(expected: str, actual: str | None) -> list[str]:
    """Human-readable differences between the generated keyring and the committed one."""
    if actual is None:
        return ["the keyring file does not exist (run: hnx agent keyring build SOURCES)"]
    if expected == actual:
        return []
    try:
        want, have = json.loads(expected), json.loads(actual)
    except ValueError:
        return ["the committed keyring is not valid JSON"]
    out = []
    if want.get("generated_from") != have.get("generated_from"):
        out.append("generated_from differs: a source changed since the keyring was built")
    w = {r["principal"]: r for r in want.get("principals", [])}
    h = {r.get("principal"): r for r in have.get("principals", []) if isinstance(r, dict)}
    out += [f"principal {p} missing from the keyring" for p in sorted(set(w) - set(h))]
    out += [f"principal {p} is in the keyring but in no source" for p in sorted(set(h) - set(w))]
    out += [
        f"principal {p} differs from its sources" for p in sorted(set(w) & set(h)) if w[p] != h[p]
    ]
    return out or ["formatting differs from the generator's output"]
