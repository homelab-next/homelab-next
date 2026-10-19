# SPDX-License-Identifier: Apache-2.0
"""Customization lint. Every rule has a stable code.

====== ======== =============================================================================
code   severity meaning
====== ======== =============================================================================
CU001  error    schema violation (missing reason / owner / review_by, bad shape, unknown kind)
CU002  error    duplicate customization id (a local file may not silently shadow a shipped one)
CU003  error    raw endpoint (IP literal, host:port, URL with port) in the file or a referenced file
CU004  error    unknown extension point (role, template, variable, entry point, service, field)
CU005  error    scope selector does not resolve in the deployment
CU006  error    referenced file missing, absolute, escapes its directory, or points into core
CU007  error    dates: not a real date, review_by before created, or horizon too long
CU008  error    expired: review_by is in the past
CU009  warning  expires within 14 days
CU010  error    contract reference does not resolve
CU011  error    conflict: two customizations claim one extension point on overlapping scope
CU012  error    file unreadable or not parseable
CU013  error    enablement names an unknown customization, a non-optional one, or unknown hosts
CU014  warning  upstream is accepted: retire this after upgrading
CU015  error    maintained_upstream: true outside the project's own shipped profiles directory
====== ======== =============================================================================
"""

from __future__ import annotations

import importlib.util
import re
import sys
from datetime import date
from pathlib import Path
from typing import Any

from .model import (
    EXPIRY_WARN_DAYS,
    MAX_HORIZON_DAYS,
    Customization,
    Finding,
    parse_date,
)
from .resolve import active, detect_conflicts
from .universe import Universe

__all__ = ["RULES", "endpoint_hits", "lint"]

RULES = {
    "CU001": "schema violation",
    "CU002": "duplicate id",
    "CU003": "raw endpoint",
    "CU004": "unknown extension point",
    "CU005": "unresolved scope selector",
    "CU006": "bad file reference",
    "CU007": "bad dates",
    "CU008": "expired",
    "CU009": "expiring soon",
    "CU010": "unresolved contract",
    "CU011": "conflict",
    "CU012": "unreadable",
    "CU013": "bad enablement",
    "CU014": "upstream accepted, retire",
    "CU015": "maintained_upstream outside shipped profiles",
}

_scan_text = None


def _tools_path() -> Path | None:
    """tools/no_raw_endpoints.py of a verified checkout, else None (see homelabnext.paths)."""
    from homelabnext import paths

    try:
        return paths.checkout_tool("no_raw_endpoints.py", feature="custom lint")
    except paths.NotACheckout:
        return None


def _load_scanner():
    """Reuse the repository gate's own detection (tools/no_raw_endpoints.py) so a customization
    can never pass lint and then fail CI. Falls back to a smaller built-in matcher when the
    tools directory is not shipped (installed wheel)."""
    global _scan_text
    if _scan_text is not None:
        return _scan_text
    tools = _tools_path()
    if tools is not None:
        spec = importlib.util.spec_from_file_location("hnx_no_raw_endpoints", tools)
        assert spec and spec.loader
        mod = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = mod  # dataclasses need the module registered
        spec.loader.exec_module(mod)
        _scan_text = lambda text: [f.text for f in mod.scan_text("x", text)]  # noqa: E731
    else:
        rx = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|://[^\s/:]+:\d+|\blocalhost:\d+")
        _scan_text = lambda text: [m.group(0) for m in rx.finditer(text)]  # noqa: E731
    return _scan_text


def endpoint_hits(text: str) -> list[str]:
    return _load_scanner()(text)


def _strings(obj: Any):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield str(k)
            yield from _strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _strings(v)


def _referenced_files(c: Customization) -> list[str]:
    a = c.action
    if c.kind == "hook":
        return [a["tasks_file"]]
    if c.kind == "patch-overlay":
        return [a["overlay"]]
    if c.kind == "profile":
        return [t["file"] for t in a["tasks"]]
    return []


def _check_files(c: Customization, u: Universe, out: list[Finding]) -> None:
    base = c.base.resolve()
    for rel in _referenced_files(c):
        p = c.base / rel
        try:
            real = p.resolve(strict=True)
        except OSError:
            out.append(Finding("CU006", "error", c.id, f"{rel}: file does not exist"))
            continue
        if not real.is_file():
            out.append(Finding("CU006", "error", c.id, f"{rel}: not a regular file"))
        elif base != real and base not in real.parents:
            out.append(Finding("CU006", "error", c.id, f"{rel}: resolves outside {base.name}/"))
        elif any(r == real or r in real.parents for r in u.core_roots):
            out.append(Finding("CU006", "error", c.id, f"{rel}: points into core files"))
        else:
            for hit in endpoint_hits(real.read_text(encoding="utf-8", errors="replace")):
                out.append(Finding("CU003", "error", c.id, f"{rel}: raw endpoint {hit!r}"))


def _check_dates(c: Customization, today: date, out: list[Finding]) -> None:
    exempt = c.upstream_maintained
    if "review_by" not in c.doc:
        if not exempt:
            out.append(
                Finding(
                    "CU007",
                    "error",
                    c.id,
                    "review_by is required; only maintained_upstream profiles shipped "
                    "with the project may omit it",
                )
            )
        return
    created, review = parse_date(c.doc["created"]), parse_date(c.doc["review_by"])
    if created is None or review is None:
        out.append(Finding("CU007", "error", c.id, "created and review_by must be real dates"))
        return
    if review < created:
        out.append(Finding("CU007", "error", c.id, "review_by is before created"))
    elif not exempt and (review - created).days > MAX_HORIZON_DAYS:
        out.append(
            Finding(
                "CU007",
                "error",
                c.id,
                f"review_by is more than {MAX_HORIZON_DAYS} days after created; "
                "a customization that effectively never expires is not owned",
            )
        )
    if exempt:
        return  # shipped and maintained by the project itself: never expires
    if review < today:
        out.append(
            Finding("CU008", "error", c.id, f"expired on {review}; renew, upstream or retire")
        )
    elif (review - today).days <= EXPIRY_WARN_DAYS:
        out.append(
            Finding("CU009", "warning", c.id, f"expires in {(review - today).days} days ({review})")
        )


def _check_scope(c: Customization, u: Universe, out: list[Finding]) -> None:
    s = c.scope
    pairs = (
        ("capabilities", u.capabilities, "capability"),
        ("services", None if u.services is None else {f"svc:{x}" for x in u.services}, "service"),
        ("roles", None if u.roles is None else set(u.roles), "role"),
        ("hosts", u.hosts, "host"),
    )
    for key, known, noun in pairs:
        if known is None:
            continue
        for sel in s.get(key, []):
            if sel not in known:
                out.append(
                    Finding("CU005", "error", c.id, f"scope {noun} {sel!r} does not resolve")
                )


def _check_extension_point(c: Customization, u: Universe, out: list[Finding]) -> None:
    a, k = c.action, c.kind

    def bad(msg: str) -> None:
        out.append(Finding("CU004", "error", c.id, msg))

    if k in ("override", "hook", "patch-overlay") and u.roles is not None:
        role = a["role"]
        if role not in u.roles:
            return bad(f"unknown role {role!r}")
        if k == "override":
            for v in a["vars"]:
                if not v.startswith(f"{role}_"):
                    bad(f"variable {v!r} lacks the role prefix {role}_")
                elif v not in u.roles[role]:
                    bad(f"variable {v!r} is not defined in the defaults of role {role!r}")
        if k == "patch-overlay" and a["template"] not in u.role_templates.get(role, set()):
            bad(f"role {role!r} has no template {a['template']!r}")
    if k == "registry-patch" and u.registry is not None:
        svc = u.registry.get("services", {}).get(a["service"])
        if svc is None:
            return bad(f"unknown registry service {a['service']!r}")
        for f in a["set"]:
            if f in ("host", "capability"):
                bad(f"registry field {f!r} is structural; change it in the registry, not here")
    if k == "profile" and not a.get("tasks"):
        bad("a profile must add at least one task")


def _check_contract(c: Customization, u: Universe, out: list[Finding]) -> None:
    ref = c.doc["contract"]
    known: set[str] | None
    if ref.startswith("cap:"):
        known = u.capabilities
    elif ref.startswith("adr:"):
        known, ref = u.adr_slugs, ref[4:]
    else:
        known = u.schema_ids
    if known is not None and ref not in known:
        out.append(
            Finding("CU010", "error", c.id, f"contract {c.doc['contract']!r} does not resolve")
        )


def lint(
    items: list[Customization],
    universe: Universe,
    today: date,
    enabled: dict[str, list[str]] | None = None,
) -> list[Finding]:
    """All findings for a set of customizations, in a stable order."""
    enabled = enabled or {}
    out: list[Finding] = []
    seen: dict[str, Customization] = {}
    for c in items:
        for e in c.schema_errors:
            out.append(Finding("CU001", "error", c.id, e))
        if c.id in seen:
            out.append(
                Finding(
                    "CU002", "error", c.id, f"also defined in {seen[c.id].path}; ids are unique"
                )
            )
        seen.setdefault(c.id, c)
    valid = [c for c in items if not c.schema_errors]
    live = {c.id for c in active(valid, enabled)}
    for c in valid:
        if c.doc.get("maintained_upstream") is True and c.origin != "public":
            out.append(
                Finding(
                    "CU015",
                    "error",
                    c.id,
                    "maintained_upstream: true is only valid for profiles shipped with the "
                    "project; an overlay customization must carry a review_by and expire",
                )
            )
        _check_dates(c, today, out)
        for s in _strings(c.doc):
            for hit in endpoint_hits(s):
                out.append(Finding("CU003", "error", c.id, f"raw endpoint {hit!r}"))
        _check_files(c, universe, out)
        _check_contract(c, universe, out)
        _check_extension_point(c, universe, out)
        if c.id in live or not c.optional:
            _check_scope(c, universe, out)
        if c.doc["upstream"] == "accepted":
            out.append(
                Finding(
                    "CU014", "warning", c.id, "upstream accepted: retire after the next upgrade"
                )
            )
    for cid, hosts in sorted(enabled.items()):
        c = seen.get(cid)
        if c is None:
            out.append(
                Finding("CU013", "error", cid, "enabled but no such customization is loaded")
            )
            continue
        if not c.optional:
            out.append(Finding("CU013", "error", cid, "enabled, but it is not optional"))
        known = universe.hosts
        for h in hosts if known is not None else []:
            if h not in known:
                out.append(Finding("CU013", "error", cid, f"enabled for unknown host {h!r}"))
    if not any(f.code == "CU001" for f in out):
        for cf in detect_conflicts(active(valid, enabled), universe, enabled):
            out.append(Finding("CU011", "error", ",".join(cf.ids), str(cf)))
    return _dedupe(out)


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen, out = set(), []
    for f in findings:
        key = (f.code, f.customization, f.message)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return sorted(out, key=lambda f: (f.severity != "error", f.customization, f.code, f.message))
