# SPDX-License-Identifier: Apache-2.0
"""The planes.  Each is a read-only probe ``(Target, Adapters) -> Result`` registered by name.

Order matters only for ``claimed``: the dedicated file planes (inventory, playbooks, iac) record
the paths they reported so the generic ``live-refs`` plane does not report them twice.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Callable
from pathlib import PurePosixPath
from typing import Any

import yaml

from .adapters import Adapters, SnapshotList
from .model import Result, Status, Target, Unreachable

Probe = Callable[[Target, Adapters], Result]
PLANES: dict[str, Probe] = {}

# A mention in these is history, not live config: a human decides, the audit does not fail.
NARRATIVE_SUFFIXES = (".md", ".rst", ".txt", ".adoc")
HISTORY_PARTS = ("adr", "history", "handovers", "evidence", "changelog", "archive")
COMMENT_PREFIXES = ("#", "//", ";", "--", "<!--")


def plane(name: str) -> Callable[[Probe], Probe]:
    def deco(fn: Probe) -> Probe:
        PLANES[name] = fn
        return fn

    return deco


def _skip(name: str, why: str) -> Result:
    return Result(name, Status.SKIP, why)


def _verdict(name: str, hits: list[str], clean: str, remnant: str) -> Result:
    return (
        Result(name, Status.REMNANT, remnant, hits) if hits else Result(name, Status.CLEAN, clean)
    )


def _parts(rel: str) -> list[str]:
    return [p.lower() for p in PurePosixPath(rel).parts]


# ---------------------------------------------------------------- file planes


def _is_inventory(rel: str) -> bool:
    parts = _parts(rel)
    return any(p in ("inventory", "inventories", "host_vars", "group_vars") for p in parts[:-1])


@plane("inventory")
def inventory(t: Target, a: Adapters) -> Result:
    if a.tree is None:
        return _skip("inventory", "no source tree configured")
    hits: list[str] = []
    for rel, text in a.tree.files():
        if not _is_inventory(rel):
            continue
        stem = PurePosixPath(rel).stem
        if "host_vars" in _parts(rel) and stem.lower() == t.name.lower():
            hits.append(f"{rel}: host_vars file for the guest")
            a.claimed.add(rel)
            continue
        for no, line in enumerate(text.splitlines(), 1):
            if t.matches(line):
                hits.append(f"{rel}:{no}: {line.strip()[:100]}")
                a.claimed.add(rel)
    return _verdict("inventory", hits, "no inventory or host_vars entry", "still in the inventory")


def _plays(text: str) -> list[dict] | None:
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError:
        return None
    return [p for p in doc if isinstance(p, dict)] if isinstance(doc, list) else None


def _host_tokens(value: Any) -> list[str]:
    items = value if isinstance(value, list) else [value]
    return [tok for i in items for tok in re.split(r"[:,]", str(i)) if tok]


@plane("playbooks")
def playbooks(t: Target, a: Adapters) -> Result:
    """Plays that target the guest, and imports in the deploy chain that no longer resolve."""
    if a.tree is None:
        return _skip("playbooks", "no source tree configured")
    files = dict(a.tree.files())
    importers: dict[str, list[str]] = {}
    broken: list[tuple[str, str]] = []
    pbs: dict[str, list[dict]] = {}
    for rel, text in files.items():
        if not rel.endswith((".yml", ".yaml")) or _is_inventory(rel) or "tasks" in _parts(rel):
            continue
        plays = _plays(text)
        if plays is None or not any("hosts" in p or "import_playbook" in p for p in plays):
            continue
        pbs[rel] = plays
        for p in plays:
            if "import_playbook" in p:
                target = posixpath.normpath(
                    posixpath.join(posixpath.dirname(rel), str(p["import_playbook"]))
                )
                importers.setdefault(target, []).append(rel)
                if target not in files:
                    broken.append((rel, str(p["import_playbook"])))
    hits: list[str] = []
    for rel, plays in pbs.items():
        for p in plays:
            if any(tok.lower() == t.name.lower() for tok in _host_tokens(p.get("hosts", ""))):
                via = importers.get(rel)
                note = f" (imported by {', '.join(sorted(via))})" if via else " (in no chain)"
                hits.append(f"{rel}: play targets the guest{note}")
                a.claimed.add(rel)
    for rel, imp in broken:
        if t.matches(imp) or t.matches(rel):
            hits.append(f"{rel}: import_playbook {imp!r} does not resolve")
            a.claimed.add(rel)
    res = _verdict("playbooks", hits, "no play targets the guest", "playbook(s) still target it")
    other = [
        f"{r}: import_playbook {i!r} does not resolve" for r, i in broken if r not in a.claimed
    ]
    if other and res.status is Status.CLEAN:
        return Result("playbooks", Status.INFO, "broken imports unrelated to the guest", other)
    return res


def _blocks(rel: str, text: str) -> list[str]:
    """Terraform files are split per top-level block so two resources in one file stay apart."""
    if rel.endswith(".tf"):
        parts = re.split(r"(?m)^(?=resource\s|module\s|data\s)", text)
        return [p for p in parts if p.strip()]
    return [text]


@plane("iac")
def iac(t: Target, a: Adapters) -> Result:
    """IaC definitions.  A vmid that is now another live resource's is INFO: never delete by id."""
    if a.tree is None:
        return _skip("iac", "no source tree configured")
    hits: list[str] = []
    reused: list[str] = []
    for rel, text in a.tree.files():
        if not rel.endswith((".tf", ".tfvars", ".yml", ".yaml", ".json", ".hcl")):
            continue
        if _is_inventory(rel) or ("playbook" in rel.lower()):
            continue
        for block in _blocks(rel, text):
            named = t.matches(block)
            if named:
                hits.append(f"{rel}: defines/mentions {named!r}")
                a.claimed.add(rel)
            elif t.vmid is not None and re.search(rf"(?m)\bvmid\"?\s*[=:]\s*\"?{t.vmid}\b", block):
                reused.append(f"{rel}: vmid {t.vmid} belongs to a different live resource")
    if hits:
        res = Result("iac", Status.REMNANT, "still defined in IaC", hits)
        res.items += [f"INFO {r}" for r in reused]
        return res
    if reused:
        return Result(
            "iac",
            Status.INFO,
            "no definition by name; the vmid was reused. Do NOT delete by id alone",
            reused,
        )
    return Result("iac", Status.CLEAN, "no IaC definition")


def _classify(rel: str, line: str) -> str:
    parts = _parts(rel)
    if rel.lower().endswith(NARRATIVE_SUFFIXES) or any(
        p.startswith(h) for p in parts for h in HISTORY_PARTS
    ):
        return "narrative"
    if line.lstrip().startswith(COMMENT_PREFIXES):
        return "comment"
    return "live"


@plane("live-refs")
def live_refs(t: Target, a: Adapters) -> Result:
    """Everything else that names the guest.  Live config fails; comments/narrative need a look."""
    if a.tree is None:
        return _skip("live-refs", "no source tree configured")
    live: list[str] = []
    soft: list[str] = []
    for rel, text in a.tree.files():
        if rel in a.claimed:
            continue
        for no, line in enumerate(text.splitlines(), 1):
            if not t.matches(line):
                continue
            kind = _classify(rel, line)
            (live if kind == "live" else soft).append(f"{rel}:{no}: [{kind}] {line.strip()[:100]}")
    if live:
        return Result("live-refs", Status.REMNANT, "live code/config still names it", live + soft)
    if soft:
        return Result(
            "live-refs", Status.REVIEW, "only comments or narrative docs mention it", soft
        )
    return Result("live-refs", Status.CLEAN, "no code, config or doc names it")


# ---------------------------------------------------------------- hypervisor planes


def _hv(name: str, a: Adapters, t: Target, fn: Callable[[Any], Result]) -> Result:
    if a.hypervisor is None:
        return _skip(name, "no hypervisor adapter configured")
    if t.vmid is None:
        return _skip(name, "no vmid given; cannot probe the hypervisor")
    try:
        return fn(a.hypervisor)
    except Unreachable as exc:
        return _skip(name, f"unreachable: {exc}")


@plane("hv-config")
def hv_config(t: Target, a: Adapters) -> Result:
    def probe(hv: Any) -> Result:
        cfg = hv.guest_config(t.vmid)
        if cfg is None:
            return Result("hv-config", Status.CLEAN, f"no guest config for vmid {t.vmid}")
        return Result("hv-config", Status.REMNANT, "guest config still exists", [f"vmid {t.vmid}"])

    return _hv("hv-config", a, t, probe)


@plane("hv-firewall")
def hv_firewall(t: Target, a: Adapters) -> Result:
    return _hv(
        "hv-firewall",
        a,
        t,
        lambda hv: _verdict(
            "hv-firewall",
            hv.firewall_files(t.vmid),
            "no per-guest firewall file",
            "dead firewall file",
        ),
    )


@plane("hv-volumes")
def hv_volumes(t: Target, a: Adapters) -> Result:
    return _hv(
        "hv-volumes",
        a,
        t,
        lambda hv: _verdict(
            "hv-volumes", hv.volumes(t.vmid), "no disks or volumes left", "orphan disk(s)/volume(s)"
        ),
    )


@plane("hv-backup")
def hv_backup(t: Target, a: Adapters) -> Result:
    return _hv(
        "hv-backup",
        a,
        t,
        lambda hv: _verdict(
            "hv-backup",
            [j.get("id", "?") for j in hv.backup_jobs() if t.vmid in j.get("vmids", [])],
            "in no backup job",
            "still a member of backup job(s)",
        ),
    )


@plane("hv-ha")
def hv_ha(t: Target, a: Adapters) -> Result:
    return _hv(
        "hv-ha",
        a,
        t,
        lambda hv: _verdict(
            "hv-ha",
            [s for s in hv.ha_resources() if re.fullmatch(rf"(vm|ct):{t.vmid}", s)],
            "not an HA resource",
            "still an HA resource",
        ),
    )


# ---------------------------------------------------------------- roster planes


def _roster(name: str, ad: SnapshotList | None, t: Target, clean: str, bad: str) -> Result:
    if ad is None:
        return _skip(name, "no adapter configured")
    try:
        entries = ad.entries()
    except Unreachable as exc:
        return _skip(name, f"unreachable: {exc}")
    hits = [str(e) for e in entries if t.matches(str(e))]
    return _verdict(name, hits, clean, bad)


@plane("siem-roster")
def siem_roster(t: Target, a: Adapters) -> Result:
    return _roster(
        "siem-roster", a.siem, t, "no telemetry agent registered", "agent still registered"
    )


@plane("monitoring")
def monitoring(t: Target, a: Adapters) -> Result:
    return _roster(
        "monitoring", a.monitoring, t, "no monitoring target", "still a monitoring target"
    )


@plane("secret-names")
def secret_names(t: Target, a: Adapters) -> Result:
    """Secret-store variable NAMES only.  ``app-core`` also matches ``app_core_password``."""
    if a.secrets is None:
        return _skip("secret-names", "no adapter configured")
    try:
        names = [str(n) for n in a.secrets.entries()]
    except Unreachable as exc:
        return _skip("secret-names", f"unreachable: {exc}")
    keys = {t.name.lower().replace("-", "_")}
    hits = [n for n in names if any(k in n.lower().replace("-", "_") for k in keys)]
    return _verdict("secret-names", hits, "no secret named for it", "secret name(s) remain")


@plane("dns")
def dns(t: Target, a: Adapters) -> Result:
    return _roster("dns", a.dns, t, "no DNS record", "DNS record(s) remain")


@plane("proxy")
def proxy(t: Target, a: Adapters) -> Result:
    return _roster("proxy", a.proxy, t, "no proxy route", "proxy route(s) remain")


@plane("dhcp")
def dhcp(t: Target, a: Adapters) -> Result:
    return _roster("dhcp", a.dhcp, t, "no DHCP reservation", "DHCP reservation(s) remain")


# What to do about a non-clean plane.  `plan` prints these; nothing here executes.
ACTIONS: dict[str, str] = {
    "inventory": "remove the host from inventory and delete its host_vars file",
    "playbooks": "drop the play (or retarget it) and remove it from the deploy chain imports",
    "iac": "remove the IaC definition; confirm the vmid is unowned before touching anything by id",
    "live-refs": "update live config and code; leave history and comments to a human decision",
    "hv-config": "destroy the guest on the hypervisor (after the backups are confirmed)",
    "hv-firewall": "delete the per-guest firewall file",
    "hv-volumes": "free the orphan disks/volumes after verifying no other guest uses them",
    "hv-backup": "remove the guest from the backup job(s)",
    "hv-ha": "remove the HA resource",
    "siem-roster": "remove the agent from the telemetry roster and revoke its key",
    "monitoring": "remove the scrape/probe target and its alert rules",
    "secret-names": "delete the secret entries by name in the secret store (values are never read)",
    "dns": "delete the DNS records and aliases",
    "proxy": "delete the proxy/edge routes",
    "dhcp": "release the DHCP reservation",
}
