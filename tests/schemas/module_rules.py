# SPDX-License-Identifier: Apache-2.0
"""The module loader's rules (docs/modules.md, "What the loader checks"), as plain functions over
manifests, the slot registry draft and a site selection.

There is no loader yet (ADR-0027 is proposed).  This is the specification in executable form for
the contract tests: ``tests/schemas/test_module_1_0.py`` applies it to the fictional examples and
shows each rule refusing a planted defect.  Each function returns a list of problem strings.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

Doc = dict[str, Any]

RECORD_ROOTS = ("findings", "state", "proposals", "memory")
SHARED_ADAPTERS = "homelabnext.conform.adapters."
PRIVILEGED_SHARED_CONFIG = {"cap:edge", "cap:idp"}
STATIC_HOSTING = "cap:static-hosting"


def us(mid: str) -> str:
    return mid.replace("-", "_")


def _named(name: str, mid: str, sep: str = "-") -> bool:
    base = mid if sep == "-" else us(mid)
    return name == base or name.startswith(base + sep)


def _roles(doc: Doc) -> set[str]:
    return {"role:" + Path(e["file"]).name for e in doc.get("contributes", {}).get("roles", [])}


def _agents(doc: Doc) -> list[Doc]:
    return doc.get("contributes", {}).get("agents", [])


def _own_write_prefix(p: str, mid: str) -> bool:
    parts = p.split("/")
    return len(parts) >= 3 and parts[0] in RECORD_ROOTS and parts[1] in (mid, mid + "-shadow")


def module_problems(doc: Doc, mod_dir: Path, slots: dict[str, Doc], load) -> list[str]:
    """Rules one manifest must meet on its own (``load(path)`` reads a contributed YAML file)."""
    mid, out = doc["id"], []
    if doc["id"] != mod_dir.name:
        out.append(f"id {mid} is not the directory name {mod_dir.name}")
    if doc.get("replaced_by") == mid:
        out.append("replaced_by names the module itself")
    roles = _roles(doc)
    for r in roles:
        if not _named(r[5:], mid, "_"):
            out.append(f"{r}: a role name starts with {us(mid)}")
    refs = [r for h in doc["requires"].get("hosts", []) for r in h.get("roles", [])]
    refs += [p["role"] for p in doc.get("contributes", {}).get("preflight", [])]
    for ds in doc.get("data", []):
        refs += [ds["export"]["via"], ds["import"]["via"]]
    for e in doc.get("provides", {}).get("slots", {}).values():
        if "migration" in e:
            refs += [e["migration"]["export"], e["migration"]["import"]]
    for job in doc.get("contributes", {}).get("scheduler_jobs", []):
        if "timer" in job:
            refs.append("role:" + job["timer"].split(":", 1)[1].split("/", 1)[0])
    out += [f"{r}: names a role the module does not contribute" for r in sorted(set(refs) - roles)]
    # code is the module's own (or a shared conformance adapter)
    own = f"hnx_modules.{us(mid)}."
    for slot, e in doc.get("provides", {}).get("slots", {}).items():
        if not (e["adapter"].startswith(own) or e["adapter"].startswith(SHARED_ADAPTERS)):
            out.append(
                f"provides.slots.{slot}.adapter: not the module's own code or a shared adapter"
            )
    for c in doc.get("control_plane", []):
        if not c["reader"].startswith(own):
            out.append("control_plane reader: not the module's own code")
    eps = doc.get("contributes", {}).get("entry_points", [])
    for ep in eps:
        if not ep["object"].startswith(own):
            out.append(f"entry point {ep['name']}: not the module's own package")
        if not _named(ep["name"], mid, "_"):
            out.append(f"entry point {ep['name']}: name starts with {us(mid)}")
    # secrets in the module's own namespace
    secrets = [c["secret"] for c in doc.get("credentials", [])]
    secrets += [
        k["default"]
        for k in doc.get("config", {}).values()
        if k["type"] == "secret" and "default" in k
    ]
    for s in secrets:
        if not s.startswith(f"secret:{mid}/"):
            out.append(f"{s}: a secret is in the module's own namespace secret:{mid}/")
    # data, tables and prefixes bound to the module
    for ds in doc.get("data", []):
        if "table" in ds and ds["table"].split(":", 1)[1].split(".")[0] != us(mid):
            out.append(f"data {ds['id']}: table namespace is {us(mid)}")
        p = ds.get("prefix")
        if p and ds["kind"] == "records-prefix" and not _own_write_prefix(p, mid):
            out.append(f"data {ds['id']}: records prefix is <root>/{mid}/")
        if p and ds["kind"] != "records-prefix" and not p.startswith(mid + "/"):
            out.append(f"data {ds['id']}: prefix starts with {mid}/")
    for i in doc.get("provides", {}).get("interfaces", []):
        p = i["via"].get("prefix")
        if p and not p.startswith(mid + "/"):
            out.append(f"interface {i['interface']}: prefix starts with {mid}/")
    # config defaults
    for k, spec in doc.get("config", {}).items():
        if spec["type"] == "enum" and "default" in spec and spec["default"] not in spec["values"]:
            out.append(f"config {k}: enum default is not one of its values")
    # agents: owned ids, lanes, scopes, the spec as the one source
    for a in _agents(doc):
        key = a["key"]
        if not _named(key, mid):
            out.append(f"agent {key}: key starts with {mid}")
        if a["profile"] != "profile:" + key:
            out.append(f"agent {key}: profile is profile:{key} (owned by the module)")
        lanes = {k for k in ("real", "shadow") if k in a["lanes"]}
        if set(a["prompts"]) != lanes:
            out.append(f"agent {key}: one prompt per lane")
        if a["lanes"]["production"] not in lanes:
            out.append(f"agent {key}: the production lane is declared")
        for lane in lanes:
            for w in a["lanes"][lane]["writes"]:
                if not _own_write_prefix(w, mid):
                    out.append(
                        f"agent {key}: lane {lane} writes {w} outside <root>/{mid}[-shadow]/"
                    )
        for n in a.get("needs", []):
            if n["access"] == "write":
                for s in n["scope"]:
                    if not _own_write_prefix(s, mid):
                        out.append(f"agent {key}: write scope {s} outside <root>/{mid}/")
        spec = load(mod_dir / a["spec"])
        if "ceiling" in spec:
            out.append(f"agent {key}: a module spec carries no ceiling")
        if spec.get("id") != a["profile"]:
            out.append(f"agent {key}: spec id is the agent's profile")
        if set(spec.get("capabilities", [])) != {n["cap"] for n in a.get("needs", [])}:
            out.append(f"agent {key}: needs name exactly the spec's capabilities")
        trig = a.get("trigger", {}).get("interface")
        if trig and trig not in _consumed_interfaces(doc):
            out.append(f"agent {key}: triggers on an interface the module does not consume")
    # detections, MCP records, criteria, service rows, units
    c = doc.get("contributes", {})
    for e in c.get("detections", []):
        det = load(mod_dir / e["file"]).get("det", "")
        if not _named(det.removeprefix("det:"), mid):
            out.append(f"{e['file']}: det id starts with {mid}")
    for e in c.get("mcp_servers", []):
        rec = load(mod_dir / e["file"])
        if not _named(rec["id"], mid):
            out.append(f"{e['file']}: MCP record id starts with {mid}")
        if rec.get("capabilities") and doc["kind"] != "provider":
            out.append(f"{e['file']}: only a provider's MCP record fronts a slot")
    plugins = {ep["name"] for ep in eps if ep["group"] == "homelabnext.invariants.checks"}
    for e in c.get("invariants", []):
        for cr in load(mod_dir / e["file"])["criteria"]:
            out += [f"criterion {cr.get('id')}: {p}" for p in criterion_problems(cr, mid, plugins)]
    hosts = {h["role"] for h in doc["requires"].get("hosts", [])}
    declared = set()
    for e in c.get("services", []):
        for name, row in load(mod_dir / e["file"])["services"].items():
            ok = (
                name in doc.get("provides", {}).get("slots", {})
                if doc["kind"] == "provider"
                else _named(name, mid)
            )
            if not ok:
                out.append(
                    f"service {name}: a provider's row is keyed by its slot, any other's starts with {mid}"
                )
            if row["host"] not in hosts:
                out.append(f"service {name}: host is one of the module's host roles")
            if row.get("public_hostname") and row.get("auth", "none") == "none":
                out.append(f"service {name}: a public route needs auth")
            for s in row.get("status_sources", []):
                if not _named(s["id"], mid):
                    out.append(f"status source {s['id']}: starts with {mid}")
                declared.add("status:" + s["id"])
    for s in set(c.get("status_sources", [])) - declared:
        out.append(f"{s}: not declared by the module's own service rows")
    for job in c.get("scheduler_jobs", []):
        if "file" in job:
            out += unit_problems(load(mod_dir / job["file"]), mid)
    # slot registry: declared slots, provisional only without a contract, privileged never
    for r in doc["requires"].get("capabilities", []) + doc.get("prefers", {}).get(
        "capabilities", []
    ):
        out += _slot_ref_problems(r["cap"], r.get("provisional", False), slots, "requirement")
    for slot, e in doc.get("provides", {}).get("slots", {}).items():
        out += _slot_ref_problems("cap:" + slot, e.get("provisional", False), slots, "provider")
        desc = slots.get(slot, {})
        if desc.get("stateful") and "migration" not in e:
            out.append(f"provides.slots.{slot}: a stateful slot carries a migration")
        if not desc.get("stateful") and "migration" in e:
            out.append(f"provides.slots.{slot}: a stateless slot carries no migration")
        if "migration" in e and not set(e["migration"]["formats"]) <= set(
            desc.get("export_formats", [])
        ):
            out.append(f"provides.slots.{slot}: migration formats are the slot's export formats")
    for sc_ in c.get("shared_config", []):
        if sc_["target"] in PRIVILEGED_SHARED_CONFIG:
            out.append(
                f"shared_config {sc_['target']}: needs an overlay grant (grants.shared_config)"
            )
    return out


def _consumed_interfaces(doc: Doc) -> set[str]:
    return {
        r["interface"]
        for r in doc["requires"].get("interfaces", [])
        + doc.get("prefers", {}).get("interfaces", [])
    }


def _slot_ref_problems(cap: str, provisional: bool, slots: dict[str, Doc], what: str) -> list[str]:
    name = cap.removeprefix("cap:")
    if name not in slots:
        return [f"{cap}: no such slot in the slot registry (a typo is not a new slot)"]
    d = slots[name]
    if provisional and d.get("contract"):
        return [f"{cap}: {what} is provisional on a slot that has a contract"]
    if provisional and d.get("privileged"):
        return [f"{cap}: a privileged slot is never provisional"]
    if not provisional and not d.get("contract"):
        return [f"{cap}: the slot has no contract, so the {what} is provisional"]
    return []


def criterion_problems(cr: Doc, mid: str, plugins: set[str]) -> list[str]:
    out = []
    if not re.fullmatch(re.escape(mid) + r"/[a-z][a-z0-9]*(?:-[a-z0-9]+)*", str(cr.get("id", ""))):
        out.append(f"id is {mid}/<slug> (registers/invariant 1.1)")
    if len(str(cr.get("statement", ""))) < 10 or len(str(cr.get("remediation", ""))) < 10:
        out.append("statement and remediation are sentences")
    ev = cr.get("evidence")
    if ev not in ("auto", "plugin", "manual"):
        out.append("evidence is auto, plugin or manual")
    if ev == "plugin" and cr.get("plugin") not in plugins:
        out.append("a plugin criterion names one of the module's own entry points")
    if ev == "auto" and not cr.get("observable"):
        out.append("an auto criterion has an observable command")
    if ev == "manual" and cr.get("status") not in ("untested", "pass", "fail", "deferred"):
        out.append("a manual criterion carries a status")
    if cr.get("status") == "deferred" and not cr.get("note"):
        out.append("a deferred criterion says why")
    return out


def unit_problems(entries: list[Doc], mid: str) -> list[str]:
    from homelabnext.generators.fleet_units import FleetUnitsError, validate

    out = []
    try:
        validate(entries)
    except FleetUnitsError as exc:
        out.append(f"fleet_units: {exc}")
    for e in entries:
        n = e.get("name", "")
        if not _named(n, mid):
            out.append(f"unit {n}: name starts with {mid}")
        if e.get("run_as_root") or e.get("user") == "root" or e.get("hardening_opt_out"):
            out.append(f"unit {n}: root or a hardening opt-out needs an overlay grant")
        if e.get("pages_directly"):
            out.append(f"unit {n}: pages only through notify (L-03), never directly")
    return out


def tree_problems(mods: dict[str, Doc]) -> list[str]:
    """Rules across every available manifest (selected or not)."""
    out: list[str] = []
    defs: dict[tuple[str, str], list[str]] = {}
    for m in mods.values():
        for i in m.get("interfaces", []):
            defs.setdefault((i["id"], i["version"]), []).append(m["id"])
    out += [f"interface {k}: defined by {v}, one owner only" for k, v in defs.items() if len(v) > 1]
    for m in mods.values():
        used = [(i["interface"], i["version"]) for i in m.get("provides", {}).get("interfaces", [])]
        used += [
            (r["interface"], r["version"])
            for r in m["requires"].get("interfaces", [])
            + m.get("prefers", {}).get("interfaces", [])
        ]
        out += [f"{m['id']}: interface {k} has no owner" for k in used if k not in defs]
    seen: dict[str, str] = {}
    for m in mods.values():
        names = [a["key"] for a in _agents(m)] + [a["profile"] for a in _agents(m)]
        names += ["table:" + d["table"] for d in m.get("data", []) if "table" in d]
        names += [f"prefix:{d['prefix']}" for d in m.get("data", []) if "prefix" in d]
        for n in names:
            if n in seen and seen[n] != m["id"]:
                out.append(f"{n}: claimed by {seen[n]} and {m['id']}")
            seen.setdefault(n, m["id"])
    prefixes = [
        (d["prefix"], m["id"]) for m in mods.values() for d in m.get("data", []) if "prefix" in d
    ]
    for a, ma in prefixes:
        for b, mb in prefixes:
            if ma != mb and a != b and b.startswith(a):
                out.append(f"prefix {a} ({ma}) contains {b} ({mb})")
    return out


def reaches(m: Doc, cap: str) -> bool:
    caps = [r["cap"] for r in m["requires"].get("capabilities", [])]
    for p in m.get("prefers", {}).get("capabilities", []):
        caps += [p["cap"], p["fallback"].get("to", "")]
    return cap in caps


def selected(site: Doc, mods: dict[str, Doc]) -> dict[str, Doc]:
    """Every module a site runs: its providers, its features and every core module."""
    names = {c["provider"] for v in site["slots"].values() if isinstance(v, list) for c in v}
    names |= set(site.get("features", {}))
    names |= {n for n, m in mods.items() if m["kind"] == "core"}
    missing = sorted(n for n in names if n not in mods)
    if missing:
        raise KeyError(f"selected modules without a manifest: {missing}")
    return {n: mods[n] for n in sorted(names)}


def chosen(site: Doc) -> dict[str, list[Doc]]:
    return {"cap:" + s: c for s, c in site["slots"].items() if isinstance(c, list)}


def site_problems(site: Doc, mods: dict[str, Doc], slots: dict[str, Doc]) -> list[str]:
    out: list[str] = []
    try:
        sel = selected(site, mods)
    except KeyError as exc:
        return [str(exc)]
    ch = chosen(site)
    grants = site.get("grants", {})
    for slot, d in slots.items():
        if d.get("required_in_core") and "cap:" + slot not in ch:
            out.append(f"{slot}: a required core slot has no provider")
    for cap, cs in ch.items():
        insts = [c["instance"] for c in cs]
        if len(insts) != len(set(insts)):
            out.append(f"{cap}: an instance is selected twice")
        for c in cs:
            if cap.removeprefix("cap:") not in sel[c["provider"]].get("provides", {}).get(
                "slots", {}
            ):
                out.append(f"{cap}: {c['provider']} does not fill it")
    empty = {"cap:" + s: v for s, v in site["slots"].items() if not isinstance(v, list)}
    for cap, how in empty.items():
        if how == "pass-through":
            out += _pass_through_problems(cap, ch, sel, slots)
    for m in sel.values():
        for r in m["requires"].get("capabilities", []):
            if r["cap"] not in ch:
                out.append(f"{m['id']}: requires {r['cap']}, which the site does not select")
            elif r.get("instance") and r["instance"] not in {c["instance"] for c in ch[r["cap"]]}:
                out.append(f"{m['id']}: requires instance {r['instance']} of {r['cap']}")
        for p in m.get("prefers", {}).get("capabilities", []):
            to = p["fallback"].get("to")
            if p["cap"] not in ch and to and to not in ch:
                out.append(
                    f"{m['id']}: falls back from {p['cap']} to {to}, which is not selected either"
                )
        for ds in m.get("data", []):
            via = ds.get("via", {}).get("cap")
            if via and via not in ch:
                pref = next(
                    (p for p in m.get("prefers", {}).get("capabilities", []) if p["cap"] == via),
                    None,
                )
                moved = pref and pref["fallback"].get("to") in ch
                over = pref and any(
                    x["dataset"] == ds["id"] for x in pref["fallback"].get("data", [])
                )
                if not (moved and over):
                    out.append(
                        f"{m['id']}: dataset {ds['id']} lives in {via}, unselected, with no fallback data"
                    )
        if reaches(m, STATIC_HOSTING) and m["id"] not in grants.get("publish", []):
            out.append(f"{m['id']}: reaches {STATIC_HOSTING} without the overlay's publish grant")
        eg = m.get("egress", "none")
        for e in eg if isinstance(eg, list) else []:
            if "internet" in e["to"] and e["host"] not in grants.get("egress", {}).get(m["id"], []):
                out.append(f"{m['id']}: host {e['host']} egresses to the internet without a grant")
        for a in _agents(m):
            bind = site.get("features" if m["kind"] == "feature" else "core", {}).get(m["id"], {})
            lanes = bind.get("agents", {}).get(a["key"], {}).get("lanes", {})
            want = {k for k in ("real", "shadow") if k in a["lanes"]}
            if set(lanes) != want:
                out.append(f"{a['key']}: each lane is bound to exactly one orchestration instance")
            orch = {c["instance"] for c in ch.get("cap:orchestration", [])}
            out += [
                f"{a['key']}: lane {k} bound to unselected instance {v}"
                for k, v in lanes.items()
                if v not in orch
            ]
    readable = {
        c["secret"]
        for m in sel.values()
        for c in m.get("credentials", [])
        if c["holder"] == "granted"
    }
    for reader, names in grants.get("secrets", {}).items():
        for n in names:
            owner = n.removeprefix("secret:").split("/", 1)[0]
            if n not in readable and owner != reader:
                out.append(f"grants.secrets: {reader} may not read {n} (not a granted credential)")
    out += _interface_problems(sel, mods)
    out += placement_problems(site, sel)
    return out


def _pass_through_problems(cap, ch, sel, slots) -> list[str]:
    d = slots.get(cap.removeprefix("cap:"), {})
    if not d.get("pass_through"):
        return [f"{cap}: the slot may not be pass-through"]

    def fmts(stage, side):
        out = []
        for s, desc in slots.items():
            if desc.get("stage") == stage and "cap:" + s in ch:
                f = set()
                for c in ch["cap:" + s]:
                    f |= {
                        x["format"]
                        for x in sel[c["provider"]]["provides"]["slots"][s].get("formats", [])
                    }
                f &= set(desc.get("formats", {}).get(side, []))
                out.append((s, f))
        return out

    up, down = fmts(d["stage"] - 1, "out"), fmts(d["stage"] + 1, "in")
    mine = set(d.get("formats", {}).get("out", []))
    down = [(s, f) for s, f in down if mine & set(slots[s].get("formats", {}).get("in", []))]
    probs = []
    for su, fu in up:
        for sd, _fd in down:
            if not fu & set(slots[sd]["formats"]["in"]):
                probs.append(
                    f"{cap}: pass-through, but {su} out {sorted(fu)} meets nothing {sd} reads"
                )
    if not up:
        probs.append(f"{cap}: pass-through with no upstream stage selected")
    return probs


def _interface_problems(sel, mods) -> list[str]:
    out = []
    provided = {
        (i["interface"], i["version"]): m["id"]
        for m in sel.values()
        for i in m.get("provides", {}).get("interfaces", [])
    }
    for m in sel.values():
        for r in m["requires"].get("interfaces", []):
            if (r["interface"], r["version"]) not in provided:
                out.append(
                    f"{m['id']}: requires interface {r['interface']}, which no selected module provides"
                )
        for i in m.get("provides", {}).get("interfaces", []):
            cap, inst = i["via"].get("cap"), i["via"].get("instance")
            req = [r for r in m["requires"].get("capabilities", []) if r["cap"] == cap]
            if cap and not req:
                out.append(
                    f"{m['id']}: interface {i['interface']} is carried on {cap}, which it does not require"
                )
            if inst and req and all(r.get("instance") != inst for r in req):
                out.append(
                    f"{m['id']}: interface {i['interface']} instance {inst} is not the one it requires"
                )
    return out


def _placed(site, sel):
    """(module, instance, host role, footprint, site host) for everything placed."""
    rows = []
    for cs in site["slots"].values():
        for c in cs if isinstance(cs, list) else []:
            for role, host in c.get("placement", {}).items():
                rows.append((c["provider"], c["instance"], role, host))
    for name, f in site.get("features", {}).items():
        for role, host in f.get("placement", {}).items():
            rows.append((name, None, role, host))
    out = []
    for mod, inst, role, host in sorted(set(rows), key=str):
        h = next((x for x in sel[mod]["requires"].get("hosts", []) if x["role"] == role), None)
        out.append((mod, inst, role, h, host))
    return out


def placement_problems(site: Doc, sel: dict[str, Doc]) -> list[str]:
    out = []
    placed = _placed(site, sel)
    for mod, _inst, role, h, host in placed:
        if h is None:
            out.append(f"{mod}: placement names {role}, not one of its host roles")
            continue
        sh = site["hosts"].get(host)
        if sh is None:
            out.append(f"{mod}: placed on unknown host {host}")
            continue
        if (h["kind"] == "external") != (sh["kind"] == "external"):
            out.append(
                f"{mod}/{role}: an external role lands only on an external host, and only it does"
            )
        if (h["exposure"] == "isolated") != bool(sh.get("isolated")):
            out.append(
                f"{mod}/{role}: an isolated role lands only on an isolated host, and only it does"
            )
    want = {}
    for cs in site["slots"].values():
        for c in cs if isinstance(cs, list) else []:
            want[(c["provider"], c["instance"])] = {
                x["role"] for x in sel[c["provider"]]["requires"].get("hosts", [])
            }
    for name in site.get("features", {}):
        want[(name, None)] = {x["role"] for x in sel[name]["requires"].get("hosts", [])}
    got: dict[tuple, set] = {}
    for mod, inst, role, _, _ in placed:
        got.setdefault((mod, inst), set()).add(role)
    for k, roles in want.items():
        if roles and got.get(k, set()) != roles:
            out.append(f"{k[0]} ({k[1] or 'feature'}): every host role is placed exactly once")
    return out + footprint_problems(site, placed)


def footprint_problems(site: Doc, placed) -> list[str]:
    """Every footprint on a host, summed over cpu, memory, disk and GPU memory, fits the host's
    capacity less its headroom; exclusive resources fit the host's named resources of that kind."""
    out = []
    use: dict[str, dict[str, float]] = {}
    excl: dict[str, dict[str, int]] = {}
    for _, _, _, h, host in placed:
        if h is None or host not in site["hosts"]:
            continue
        fp = h["footprint"]
        u = use.setdefault(host, {})
        for dim in ("cpu", "memory_mb", "disk_gb", "gpu_memory_mb"):
            u[dim] = u.get(dim, 0) + fp.get(dim, 0)
        for r in fp.get("resources", []):
            if r["exclusive"]:
                excl.setdefault(host, {})[r["kind"]] = excl.get(host, {}).get(r["kind"], 0) + 1
    for host, u in use.items():
        sh = site["hosts"][host]
        cap = dict(sh["capacity"])
        cap["memory_mb"] -= sh.get("headroom", {}).get("memory_mb", 0)
        for dim, v in u.items():
            if v > cap.get(dim, 0):
                out.append(f"{host}: {dim} {v} exceeds {cap.get(dim, 0)}")
        have = [r["kind"] for r in sh.get("resources", [])]
        for kind, n in excl.get(host, {}).items():
            if n > have.count(kind):
                out.append(f"{host}: {n} exclusive {kind} wanted, {have.count(kind)} named")
    return out


def dependants(slot: str, mods: dict[str, Doc], site: Doc | None = None) -> dict[str, str]:
    """Who a swap of ``slot`` must re-check: module id -> requires | prefers (the core included)."""
    out = {}
    for m in mods.values():
        if site is not None and m["id"] not in selected(site, mods):
            continue
        if any(r["cap"] == slot for r in m["requires"].get("capabilities", [])):
            out[m["id"]] = "requires"
        elif any(p["cap"] == slot for p in m.get("prefers", {}).get("capabilities", [])):
            out[m["id"]] = "prefers"
    return out
