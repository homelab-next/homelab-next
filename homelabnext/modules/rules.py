# SPDX-License-Identifier: Apache-2.0
"""The module loader's rules (docs/modules.md, "What the loader checks"), as plain functions over
manifests, the slot registry draft and a site selection.

:mod:`homelabnext.modules.loader` discovers the manifests and runs these with every input they
take (``hnx modules check``); ``tests/schemas/test_module_1_0.py`` shows each rule refusing a
planted defect.  Each function returns a list of problem strings, and assumes schema-valid
documents (the loader validates every manifest and selection first).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from homelabnext import paths, tlp
from homelabnext.modules.scope import (
    ScopeMissing,
    address_literals,
    manifest_scope_problems,
    scope_networks,
    scope_problems,
)

Doc = dict[str, Any]

RECORD_ROOTS = ("findings", "state", "proposals", "memory")


def public_module_roots() -> tuple[Path, ...]:
    """Where an in-tree module lives: the public ``modules/`` tree of this source checkout.

    An overlay's ``lab/modules/`` is never in-tree, and neither is ``examples/modules/`` (the
    fictional examples are never available to a site; the contract tests pass that root
    explicitly).  Outside a checkout (an installed wheel) there is no public tree to trust, so
    this raises :class:`homelabnext.paths.NotACheckout` rather than guess a path."""
    root = paths.checkout_root()
    if root is None:
        raise paths.NotACheckout(
            "the module rules' in-tree root is the checkout's modules/ (pass public_roots)"
        )
    return (root / "modules",)


#: slots whose service a module reaches only with an overlay grant (besides privileged slots)
AUTHORITY_SLOTS = ("broker", "secrets", "idp", "edge", "remote-admin", "mcp-catalog")
#: the site section that binds a module's agents and config, by kind
SECTION = {"feature": "features", "core": "core", "provider": "providers"}
SHARED_ADAPTERS = "homelabnext.conform.adapters."
PRIVILEGED_SHARED_CONFIG = {"cap:edge", "cap:idp"}
#: slots a service row may name as an upstream only with grants.upstreams (an authority behind a
#: route: the broker, the identity provider, remote administration)
GRANTED_UPSTREAMS = ("broker", "idp", "remote-admin")
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


def _own_write_prefix(p: str, mid: str, lane: str | None = None) -> bool:
    """A records write under the module's own namespace: the real lane writes <root>/<id>/, the
    shadow lane <root>/<id>-shadow/, and a lane-less write (a write scope, a records-prefix
    dataset) either."""
    parts = p.split("/")
    own = {"real": (mid,), "shadow": (mid + "-shadow",)}.get(lane, (mid, mid + "-shadow"))
    return len(parts) >= 3 and parts[0] in RECORD_ROOTS and parts[1] in own


def _caps(doc: Doc) -> list[Doc]:
    """Every capability requirement and preference (each with cap, maybe instance)."""
    return doc["requires"].get("capabilities", []) + doc.get("prefers", {}).get("capabilities", [])


def _hosts(doc: Doc) -> dict[str, Doc]:
    return {h["role"]: h for h in doc["requires"].get("hosts", [])}


def _egress(doc: Doc) -> list[Doc]:
    eg = doc.get("egress", "none")
    return eg if isinstance(eg, list) else []


def _mcp_ids(doc: Doc, mod_dir: Path, load) -> set[str]:
    out = set()
    for e in doc.get("contributes", {}).get("mcp_servers", []):
        try:
            out.add(load(mod_dir / e["file"])["id"])
        except Exception:  # an unreadable record fails where module_problems loads it
            continue
    return out


def _units(doc: Doc, mod_dir: Path, load) -> set[str]:
    """The unit names of the module's fleet_units specs (its scheduler_jobs files)."""
    return {
        u.get("name", "")
        for job in doc.get("contributes", {}).get("scheduler_jobs", [])
        if "file" in job
        for u in load(mod_dir / job["file"])
    }


def privileged_unit(e: Doc) -> bool:
    """A unit that runs as root or opts out of hardening: allowed only with grants.units.  A
    numeric ``user: "0"`` is not tested here: the fleet_units validator, which the module rules
    run on every unit (:func:`unit_problems`), refuses a root user (``root`` or ``0``) without
    ``run_as_root``, so such a unit carries the flag this reads."""
    return bool(e.get("run_as_root") or e.get("user") == "root" or e.get("hardening_opt_out"))


def _privileged_units(doc: Doc, mod_dir: Path, load) -> set[str]:
    """The names of the module's units that need grants.units (:func:`privileged_unit`)."""
    return {
        u.get("name", "")
        for job in doc.get("contributes", {}).get("scheduler_jobs", [])
        if "file" in job
        for u in load(mod_dir / job["file"])
        if privileged_unit(u)
    }


def cloud_roles(roles: dict[str, Doc]) -> set[str]:
    """The role table's roles (``mdl:<role>``) a prompt can leave the lab through: a binding marked
    ``leaves_lab``, on the role itself or anywhere down its fallback chain."""
    direct = {
        name
        for name, r in roles.items()
        if any(b.get("leaves_lab") is True for b in r.get("bindings", []))
    }
    out = set()
    for name in roles:
        seen, cur = set(), name
        while cur in roles and cur not in seen:
            seen.add(cur)
            if cur in direct:
                out.add("mdl:" + name)
                break
            cur = str(roles[cur].get("fallback", "")).removeprefix("mdl:")
    return out


def _rows(doc: Doc, mod_dir: Path, load) -> dict[str, Doc]:
    rows: dict[str, Doc] = {}
    for e in doc.get("contributes", {}).get("services", []):
        rows.update(load(mod_dir / e["file"])["services"])
    return rows


def module_problems(
    doc: Doc,
    mod_dir: Path,
    slots: dict[str, Doc],
    load,
    public_roots: tuple[Path, ...] | None = None,
) -> list[str]:
    """Rules one manifest must meet on its own (``load(path)`` reads a contributed YAML file).

    ``public_roots`` are the directories an in-tree module lives directly under (default:
    :func:`public_module_roots`, the checkout's ``modules/``)."""
    if public_roots is None:
        public_roots = public_module_roots()
    mid, out = doc["id"], []
    if doc["id"] != mod_dir.name:
        out.append(f"id {mid} is not the directory name {mod_dir.name}")
    in_public = mod_dir.resolve().parent in {r.resolve() for r in public_roots}
    origin = doc["origin"]["kind"]
    if origin == "in-tree" and not in_public:
        out.append("origin in-tree: the module is not in the public modules/ tree")
    if origin != "in-tree" and in_public:
        out.append(f"origin {origin}: a module in the public modules/ tree is in-tree")
    if doc["kind"] == "core" and not in_public:
        out.append("kind core: a core module lives in the public modules/ tree")
    if doc.get("replaced_by") == mid:
        out.append("replaced_by names the module itself")
    out += manifest_scope_problems(doc)
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
    # data, tables and prefixes bound to the module; via names a cap and instance it uses
    caps = _caps(doc)
    for ds in doc.get("data", []):
        via = ds.get("via")
        if via:
            entries = [r for r in caps if r["cap"] == via["cap"]]
            if not entries:
                out.append(
                    f"data {ds['id']}: via {via['cap']}, which it neither requires nor prefers"
                )
            elif via.get("instance") and all(r.get("instance") != via["instance"] for r in entries):
                out.append(
                    f"data {ds['id']}: via instance {via['instance']}, which it does not require"
                )
            elif not via.get("instance") and any(r.get("instance") for r in entries):
                out.append(f"data {ds['id']}: via names the instance it requires")
        if "table" in ds and ds["table"].split(":", 1)[1].split(".")[0] != us(mid):
            out.append(f"data {ds['id']}: table namespace is {us(mid)}")
        p = ds.get("prefix")
        if p and ds["kind"] == "records-prefix" and not _own_write_prefix(p, mid):
            out.append(f"data {ds['id']}: records prefix is <root>/{mid}/")
        if p and ds["kind"] != "records-prefix" and not p.startswith(mid + "/"):
            out.append(f"data {ds['id']}: prefix starts with {mid}/")
    data_ids = {ds["id"]: ds for ds in doc.get("data", [])}
    for pref in doc.get("prefers", {}).get("capabilities", []):
        fb = pref["fallback"]
        to = fb.get("to", "").removeprefix("cap:")
        for x in fb.get("data", []):
            ds = data_ids.get(x["dataset"])
            if ds is None:
                out.append(f"fallback of {pref['cap']}: dataset {x['dataset']} does not exist")
            elif ds.get("via", {}).get("cap") != pref["cap"]:
                out.append(f"fallback of {pref['cap']}: dataset {x['dataset']} does not live in it")
            allowed = set(slots.get(to, {}).get("export_formats", []))
            if not set(x.get("formats", [])) <= allowed:
                out.append(
                    f"fallback of {pref['cap']}: dataset {x['dataset']} formats are not "
                    f"{fb.get('to')}'s export formats {sorted(allowed)}"
                )
    for i in doc.get("provides", {}).get("interfaces", []):
        p = i["via"].get("prefix")
        if p and not p.startswith(mid + "/"):
            out.append(f"interface {i['interface']}: prefix starts with {mid}/")
    # Gate ownership is per id (every version): the module whose gate checks an interface marks
    # its consuming entry gate: true, owns the definition (gate: true) and never provides it.
    provided_ids = {i["interface"] for i in doc.get("provides", {}).get("interfaces", [])}
    defs = doc.get("interfaces", [])
    gated = _gated_interfaces(doc)
    gate_ids = {i["id"] for i in defs if i.get("gate") is True}
    for iid in sorted(gated - {i["id"] for i in defs}):
        out.append(
            f"interface {iid}: consumed with gate: true but not defined here; "
            "the module whose gate checks an interface owns it"
        )
    for i in defs:  # every version of a gate interface is marked, whatever the order
        if i.get("gate") is True:
            continue
        if i["id"] in gated:
            out.append(
                f"interface {i['id']} {i['version']}: consumed with gate: true, so its "
                "definition says gate: true"
            )
        elif i["id"] in gate_ids:
            out.append(
                f"interface {i['id']} {i['version']}: another version is a gate, so every "
                "version says gate: true"
            )
    for iid in sorted(gate_ids):
        if iid not in gated:
            out.append(
                f"interface {iid}: a gate interface; its owner requires or prefers it "
                "with gate: true"
            )
        if iid in provided_ids:
            out.append(
                f"interface {iid}: a gate interface its owner also provides; a producer "
                "never defines what its own output is checked against"
            )
    for i in defs:
        if "schema" in i:
            try:
                sid = str(load(mod_dir / i["schema"]).get("$id", ""))
            except Exception as exc:
                out.append(f"interface {i['id']}: schema unreadable ({exc.__class__.__name__})")
                continue
            if f"/modules/{mid}/" not in sid:
                out.append(f"interface {i['id']}: schema $id is in .../modules/{mid}/")
    # egress from the module's own host roles
    hosts = _hosts(doc)
    for e in _egress(doc):
        if e["host"] not in hosts:
            out.append(f"egress host {e['host']}: not one of the module's host roles")
    # config defaults
    for k, spec in doc.get("config", {}).items():
        if spec["type"] == "enum" and "default" in spec and spec["default"] not in spec["values"]:
            out.append(f"config {k}: enum default is not one of its values")
    # agents: owned ids, lanes, scopes, tools, the spec as the one source
    mcp_ids = _mcp_ids(doc, mod_dir, load)
    for a in _agents(doc):
        key = a["key"]
        if not _named(key, mid):
            out.append(f"agent {key}: key starts with {mid}")
        if a["profile"] != "profile:" + key:
            out.append(f"agent {key}: profile is profile:{key} (owned by the module)")
        lanes = {k for k in ("real", "shadow") if k in a["lanes"]}
        if set(a["prompts"]) != lanes:
            out.append(f"agent {key}: one prompt per lane")
        if a["lanes"].get("production", "real") not in lanes:
            out.append(f"agent {key}: the production lane is declared")
        for lane in lanes:
            own = mid if lane == "real" else mid + "-shadow"
            for w in a["lanes"][lane]["writes"]:
                if not _own_write_prefix(w, mid, lane):
                    out.append(f"agent {key}: lane {lane} writes {w} outside <root>/{own}/")
        needed = {n["cap"].removeprefix("cap:") for n in a.get("needs", [])}
        for t in a.get("tools", []):
            if t.split(".", 1)[0] not in needed | mcp_ids:
                out.append(
                    f"agent {key}: tool {t} is not on a slot it needs or one of the module's MCP records"
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
        # the agent's model role is one the module requires, so the site's model rules (the
        # cloud-model grant above all) cover the agent's prompts too
        required_roles = {r["role"] for r in doc["requires"].get("model_roles", [])}
        role = spec.get("model_role")
        if role is not None and (not isinstance(role, str) or role not in required_roles):
            out.append(
                f"agent {key}: model role {role!s} is not one of the module's requires.model_roles"
            )
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
    out += broker_rule_problems(doc, mod_dir, load)
    plugins = {ep["name"] for ep in eps if ep["group"] == "homelabnext.invariants.checks"}
    for e in c.get("invariants", []):
        for cr in load(mod_dir / e["file"])["criteria"]:
            out += [f"criterion {cr.get('id')}: {p}" for p in criterion_problems(cr, mid, plugins)]
    declared = set()
    instances = {r["instance"] for r in caps if r.get("instance")}
    reachable = {r["cap"].removeprefix("cap:") for r in caps}
    reachable |= {
        p["fallback"]["to"].removeprefix("cap:")
        for p in doc.get("prefers", {}).get("capabilities", [])
        if "to" in p["fallback"]
    }
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
            for u in row.get("upstreams", []):
                if u == "secrets":
                    out.append(
                        f"service {name}: upstream secrets: secrets are read by name, never an upstream"
                    )
                elif u not in reachable | instances:
                    out.append(
                        f"service {name}: upstream {u} is neither a slot it requires or prefers nor an instance it requires"
                    )
            for s in row.get("status_sources", []):
                if not _named(s["id"], mid):
                    out.append(f"status source {s['id']}: starts with {mid}")
                declared.add("status:" + s["id"])
    listed = set(c.get("status_sources", []))
    for s in sorted(listed - declared):
        out.append(f"{s}: not declared by the module's own service rows")
    for s in sorted(declared - listed):
        out.append(f"{s}: declared on a service row but not listed in contributes.status_sources")
    for job in c.get("scheduler_jobs", []):
        if "file" in job:
            out += unit_problems(load(mod_dir / job["file"]), mid)
    # slot registry: declared slots, provisional only without a contract, privileged never
    for r in caps:
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
    # edge or idp shared_config, root or opt-out units and broker, idp or remote-admin upstreams
    # are site rules: each needs the overlay's grant (site_problems), never a manifest's word
    return out


def broker_rule_problems(doc: Doc, mod_dir: Path, load) -> list[str]:
    """Actors act only through the broker (checklist G-13, ADR-0030), for what a module
    contributes.  A module contributes no authority (ADR-0027, "contributes (never authority)"):
    its effects are contributed as broker actions (the broker manifest and handlers), never as an
    MCP tool or a grant.  So a contributed MCP record has no acting tool (a ``broker_only``
    class) and declares no ``acts_via`` at all (``broker`` is only the broker's own front;
    ``direct`` is an exception only the overlay's own catalog and ceiling policy make), and a
    contributed agent's spec holds no acting grant: no acting MCP server (the broker's front
    included), no acting capability (``cap:broker`` included) and no acting tier.  The overlay
    that selects the module may grant its agent the broker in its own ceiling policy and spec."""
    from homelabnext.agent.readers import broker_problems, default_classes
    from homelabnext.mcp import servers

    c = doc.get("contributes", {})
    if not c.get("mcp_servers") and not c.get("agents"):
        return []
    classes = default_classes()
    only = set(classes.broker_only)
    records: dict[str, Doc] = {}
    out: list[str] = []
    for e in c.get("mcp_servers", []):
        rec = load(mod_dir / e["file"])
        records[rec["id"]] = rec
        acting = sorted(
            str(t.get("name")) for t in rec.get("tools") or () if set(t.get("classes") or ()) & only
        )
        if acting:
            out.append(
                f"{e['file']}: MCP record tool(s) {', '.join(acting)} act: a module contributes "
                "no authority (ADR-0027); its effects are broker actions, never an MCP tool"
            )
        if "acts_via" in rec:
            out.append(
                f"{e['file']}: MCP record declares acts_via: a module's record never does (broker "
                "is only the broker's own front; a direct exception is only the overlay's)"
            )
        # its classes are floored as the catalog check floors them: a run_command classed read
        # is an acting tool declared down, not a reading one
        out += servers.floor_problems(rec, e["file"], only)

    def acts(sid: str) -> bool:
        return any(set(t.get("classes") or ()) & only for t in records[sid].get("tools") or ())

    for a in _agents(doc):
        key = a["key"]
        spec = load(mod_dir / a["spec"])
        who = str(spec.get("id"))
        mcp = [m for m in spec.get("mcp") or [] if m not in records]
        caps = list(spec.get("capabilities") or [])
        grants = {"mcp": mcp, "capabilities": caps, "tier": spec.get("tier")}
        out += [f"agent {key}: {p}" for p in broker_problems(grants, classes, who)]
        for m in sorted(set(mcp)):
            if set(classes.classify("mcp", m) or ()) & only and not broker_problems(
                {"mcp": [m]}, classes, who
            ):
                out.append(f"agent {key}: spec grants acting MCP server {m!r}: a module grants "
                           "its own agent no acting tool (ADR-0027)")  # fmt: skip
        if "cap:broker" in caps:
            out.append(f"agent {key}: spec holds cap:broker: a module grants its own agent no "
                       "acting capability (ADR-0027)")  # fmt: skip
        tier = classes.classify("tiers", str(spec.get("tier"))) if spec.get("tier") else None
        if tier and set(tier) & only and "cap:broker" in caps:
            out.append(f"agent {key}: spec holds an acting tier: a module grants its own agent "
                       "no acting tier (ADR-0027)")  # fmt: skip
        for sid in sorted({m for m in spec.get("mcp") or [] if m in records and acts(m)}):
            out.append(f"agent {key}: spec grants the module's acting MCP record {sid}")
        for t in a.get("tools", []):
            sid, _, name = t.partition(".")
            rec = records.get(sid)
            if rec is not None and any(
                x.get("name") == name and set(x.get("classes") or ()) & only
                for x in rec.get("tools") or ()
            ):
                out.append(f"agent {key}: tool {t} acts: a module's agent holds no acting tool")
    return out


def _consumed_interfaces(doc: Doc) -> set[str]:
    return {
        r["interface"]
        for r in doc["requires"].get("interfaces", [])
        + doc.get("prefers", {}).get("interfaces", [])
    }


def _gated_interfaces(doc: Doc) -> set[str]:
    """The interface ids this module consumes with gate: true (its gate checks every item).
    Tolerates a malformed manifest (the schema reports it): odd entries are skipped."""
    out: set[str] = set()
    for part in ("requires", "prefers"):
        block = doc.get(part) if isinstance(doc, dict) else None
        entries = block.get("interfaces") if isinstance(block, dict) else None
        for r in entries if isinstance(entries, list) else []:
            if (
                isinstance(r, dict)
                and r.get("gate") is True
                and isinstance(r.get("interface"), str)
            ):
                out.add(r["interface"])
    return out


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
        if e.get("pages_directly"):
            out.append(f"unit {n}: pages only through notify (L-03), never directly")
    return out


def _owner(name: str, ids: set[str], sep: str) -> str | None:
    """The module a bound name belongs to: the LONGEST module id it is named under, so module
    ``external`` cannot claim ``external_collector_edge`` from ``external-collector``."""
    hits = [i for i in ids if _named(name, i, sep)]
    return max(hits, key=len) if hits else None


def _bound_names(m: Doc, mod_dir: Path | None, load) -> list[tuple[str, str, str]]:
    """(kind, name, separator) for every name the module binds to its id ('' = not id-bound)."""
    c = m.get("contributes", {})
    out = [("role", r[5:], "_") for r in sorted(_roles(m))]
    out += [("entry point", e["name"], "_") for e in c.get("entry_points", [])]
    out += [("agent", a["key"], "-") for a in _agents(m)]
    out += [("profile", a["profile"], "") for a in _agents(m)]
    out += [("status source", s.removeprefix("status:"), "-") for s in c.get("status_sources", [])]
    out += [("table", d["table"], "") for d in m.get("data", []) if "table" in d]
    out += [("identifier", f"{i['kind']}/{i['name']}", "") for i in m.get("identifiers", [])]
    if mod_dir is None or load is None:
        return out
    for e in c.get("mcp_servers", []):
        out.append(("MCP record", load(mod_dir / e["file"])["id"], "-"))
    for e in c.get("detections", []):
        out.append(
            ("det id", str(load(mod_dir / e["file"]).get("det", "")).removeprefix("det:"), "-")
        )
    for job in c.get("scheduler_jobs", []):
        if "file" in job:
            out += [("unit", u.get("name", ""), "-") for u in load(mod_dir / job["file"])]
    rows = _rows(m, mod_dir, load)
    listed = {s.removeprefix("status:") for s in c.get("status_sources", [])}
    out += [
        ("status source", src["id"], "-")
        for row in rows.values()
        for src in row.get("status_sources", [])
        if src["id"] not in listed
    ]
    if m["kind"] != "provider":  # a provider's row is keyed by its slot, renamed to the instance
        out += [("service row", n, "-") for n in rows]
    return out


def _write_prefixes(m: Doc) -> set[str]:
    out = {d["prefix"] for d in m.get("data", []) if d.get("kind") == "records-prefix"}
    for a in _agents(m):
        for lane in ("real", "shadow"):
            out |= set(a["lanes"].get(lane, {}).get("writes", []))
        for n in a.get("needs", []):
            if n["access"] == "write":
                out |= {s for s in n["scope"] if not s.startswith("table:")}
    return out


def tree_problems(
    mods: dict[str, Doc], dirs: dict[str, Path] | None = None, load=None
) -> list[str]:
    """Rules across every available manifest (selected or not).  With ``dirs`` (module id ->
    directory) and ``load``, names held in contributed files (MCP ids, det ids, units, rows) are
    compared too."""
    out: list[str] = []
    owners: dict[str, set[str]] = {}
    versions: dict[str, set[str]] = {}
    for m in mods.values():
        for i in m.get("interfaces", []):
            owners.setdefault(i["id"], set()).add(m["id"])
            versions.setdefault(i["id"], set()).add(i["version"])
    out += [
        f"interface {k}: defined by {sorted(v)}, one owner per id (every version)"
        for k, v in owners.items()
        if len(v) > 1
    ]
    # per id, every version: an id is a gate when any version says so, and marked only when all do
    all_defs = [i for m in mods.values() for i in m.get("interfaces", [])]
    gate_defs = {i["id"] for i in all_defs if i.get("gate") is True}
    unmarked = {i["id"] for i in all_defs if i.get("gate") is not True}
    out += [
        f"interface {k}: gate: true on some versions only; every version of a gate says it"
        for k in sorted(gate_defs & unmarked)
    ]
    for m in mods.values():  # gate ownership across manifests (per id, every version)
        for iid in sorted(_gated_interfaces(m)):
            others = sorted(owners.get(iid, set()) - {m["id"]})
            if others:
                out.append(f"{m['id']}: gates on interface {iid}, which {others} defines")
            elif iid in owners and iid in unmarked:
                out.append(
                    f"{m['id']}: gates on interface {iid}, whose definition lacks gate: true"
                )
        for i in m.get("provides", {}).get("interfaces", []):
            if i["interface"] in gate_defs and m["id"] in owners.get(i["interface"], set()):
                out.append(f"{m['id']}: provides interface {i['interface']}, a gate it owns")
    for m in mods.values():
        used = [(i["interface"], i["version"]) for i in m.get("provides", {}).get("interfaces", [])]
        used += [
            (r["interface"], r["version"])
            for r in m["requires"].get("interfaces", [])
            + m.get("prefers", {}).get("interfaces", [])
        ]
        out += [
            f"{m['id']}: interface {k[0]} {k[1]} has no owner"
            for k in used
            if k[1] not in versions.get(k[0], set())
        ]
    ids = set(mods)
    seen: dict[tuple[str, str], str] = {}
    for m in mods.values():
        d = (dirs or {}).get(m["id"])
        try:
            names = _bound_names(m, d, load if d else None)
        except Exception as exc:
            out.append(f"{m['id']}: a contributed file is unreadable ({exc.__class__.__name__})")
            names = _bound_names(m, None, None)
        names += [("prefix", f"{x['prefix']}", "") for x in m.get("data", []) if "prefix" in x]
        for kind, n, sep in names:
            if sep:
                own = _owner(n, ids, sep)
                if own and own != m["id"]:
                    out.append(f"{kind} {n}: named under module {own}, not {m['id']}")
            if (kind, n) in seen and seen[(kind, n)] != m["id"]:
                out.append(f"{kind} {n}: claimed by {seen[(kind, n)]} and {m['id']}")
            seen.setdefault((kind, n), m["id"])
    prefixes = [
        (d["prefix"], m["id"]) for m in mods.values() for d in m.get("data", []) if "prefix" in d
    ]
    for a, ma in prefixes:
        for b, mb in prefixes:
            if ma != mb and a != b and b.startswith(a):
                out.append(f"prefix {a} ({ma}) contains {b} ({mb})")
    writes = [(p, m["id"]) for m in mods.values() for p in sorted(_write_prefixes(m))]
    for a, ma in writes:
        for b, mb in writes:
            if ma < mb and (a.startswith(b) or b.startswith(a)):
                out.append(f"write prefix {a} ({ma}) overlaps {b} ({mb})")
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


def lab_namespace_problems(site: Doc, mods: dict[str, Doc]) -> list[str]:
    """The selection's ``lab_table_namespaces`` (the lake namespaces that are the lab's own): a
    namespace listed twice, the core's (:data:`homelabnext.lake.tables.CORE_NAMESPACE`) or a
    module id's (the id with ``-`` read as ``_``, any module in ``mods``) is refused: listing one
    would let a table there pass as the lab's, never judged as the module's or the core's."""
    from homelabnext.lake.tables import CORE_NAMESPACE

    out: list[str] = []
    seen: set[str] = set()
    owners = {us(mid): mid for mid in mods}
    for entry in site.get("lab_table_namespaces") or []:
        ns = entry.get("namespace") if isinstance(entry, dict) else None
        if not isinstance(ns, str):
            continue  # the schema reports it
        where = f"lab_table_namespaces: {ns}"
        if ns in seen:
            out.append(f"{where} is listed twice")
        seen.add(ns)
        if ns == CORE_NAMESPACE:
            out.append(f"{where} is the core's namespace, never the lab's")
        elif ns in owners:
            out.append(f"{where} is module {owners[ns]}'s namespace, never the lab's")
    return out


def site_problems(
    site: Doc,
    mods: dict[str, Doc],
    slots: dict[str, Doc],
    *,
    rows: dict[str, dict[str, Doc]],
    units: dict[str, set[str]],
    privileged_units: dict[str, set[str]],
    roles: dict[str, Doc],
    known: dict[str, Doc] | None = None,
) -> list[str]:
    """Rules a site's selection must meet.  ``rows`` (module id -> its contributed service rows):
    public routes need grants.public_routes, upstreams follow the fallback, and an upstream that
    reaches the broker, idp or remote-admin (directly, through a fallback or through an
    instance) needs grants.upstreams.  ``units`` (module id -> its unit names) and
    ``privileged_units`` (the ones that run as root or opt out of hardening): such a unit needs
    grants.units.  ``roles`` (the model role table's ``roles``): a module that requires a role
    whose prompts can leave the lab needs grants.cloud_models.  All four are required, so no rule
    is skipped for want of an input (a module with none passes an empty mapping); the loader will
    pass them.  ``known`` is every module the tree holds, those that failed validation included
    (default ``mods``): a lab namespace may name none of them."""
    # first: a selected module that failed validation stops the rest, not this
    out = lab_namespace_problems(site, mods if known is None else known)
    try:
        sel = selected(site, mods)
    except KeyError as exc:
        return [*out, str(exc)]
    ch = chosen(site)
    grants = site.get("grants", {})
    out += _binding_problems(site, mods, sel)
    out += _grant_problems(grants, sel, rows, units, privileged_units, roles, ch, slots)
    out += _config_problems(site, sel, grants)
    out += scope_problems(site)
    for m in sel.values():
        for need in m["requires"].get("scope", []):
            try:
                scope_networks(site, m, need["part"])
            except ScopeMissing:
                out.append(
                    f"{m['id']}: requires scope.{need['part']}, which the site leaves missing, "
                    "empty or unusable (its reader fails closed)"
                )
    authority = {s for s, d in slots.items() if d.get("privileged")} | set(AUTHORITY_SLOTS)
    authority |= {c["instance"] for cap, cs in ch.items() if cap[4:] in authority for c in cs}
    #: registry services an egress svc: target can name: every selected slot, every instance, and
    #: the rows of the selected feature and core modules
    services = {cap[4:] for cap in ch} | {c["instance"] for cs in ch.values() for c in cs}
    services |= {n for mid, rs in rows.items() if mid in sel for n in rs}
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
        granted = grants.get("egress", {}).get(m["id"], {})
        if not isinstance(
            granted, dict
        ):  # the 1-role-list shape: refused by the schema, no grant here
            out.append(f"grants.egress.{m['id']}: names {{<role>: [targets]}}, not a list of roles")
            granted = {}
        for e in _egress(m):
            for t in e["to"]:
                needs = t == "internet" or t.removeprefix("svc:") in authority
                if needs and t not in granted.get(e["host"], []):
                    out.append(f"{m['id']}: host {e['host']} egresses to {t} without a grant")
                if t.startswith("svc:") and not _is_service(t[4:], services):
                    out.append(f"{m['id']}: host {e['host']} egresses to {t}, which is no service")
        for role, h in _hosts(m).items():
            if h["kind"] == "external" and "external" not in granted.get(role, []):
                out.append(
                    f"{m['id']}: host role {role} is external (outside the lab) without an egress grant"
                )
            if (
                h.get("exposure") == "internet-facing"
                and h["kind"] != "external"
                and role not in grants.get("internet_facing", {}).get(m["id"], [])
            ):
                out.append(
                    f"{m['id']}: host role {role} is internet-facing inside the lab without grants.internet_facing"
                )
        for name, row in rows.get(m["id"], {}).items():
            if row.get("public_hostname") and name not in grants.get("public_routes", {}).get(
                m["id"], []
            ):
                out.append(f"{m['id']}: service {name} is public without grants.public_routes")
            out += _upstream_problems(m, name, row, ch, slots, grants)
        for u in sorted(privileged_units.get(m["id"], set())):
            if u not in grants.get("units", {}).get(m["id"], []):
                out.append(
                    f"{m['id']}: unit {u} runs as root or opts out of hardening without grants.units"
                )
        for sc_ in m.get("contributes", {}).get("shared_config", []):
            t = sc_["target"]
            if t in PRIVILEGED_SHARED_CONFIG and t not in grants.get("shared_config", {}).get(
                m["id"], []
            ):
                out.append(f"{m['id']}: shared_config {t} without grants.shared_config")
        cloud = cloud_roles(roles)
        for r in m["requires"].get("model_roles", []):
            if r["role"] in cloud and r["role"] not in grants.get("cloud_models", {}).get(
                m["id"], []
            ):
                out.append(
                    f"{m['id']}: requires {r['role']}, whose prompts can leave the lab (a "
                    "binding marked leaves_lab), without grants.cloud_models"
                )
        for a in _agents(m):
            bind = site.get(SECTION[m["kind"]], {}).get(m["id"], {})
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


def _is_service(name: str, services: set[str]) -> bool:
    """A registry service the site has: a selected slot or instance, or a selected module's row
    (``svc:secret`` for ``svc:secrets`` is refused)."""
    return name in services


def _grant_problems(
    grants: Doc,
    sel: dict[str, Doc],
    rows: dict[str, dict[str, Doc]],
    units: dict[str, set[str]],
    privileged: dict[str, set[str]],
    model_roles: dict[str, Doc],
    ch: dict[str, list[Doc]],
    slots: dict[str, Doc],
) -> list[str]:
    """Every grant names a selected module and only what that module uses: an egress target its
    entry lists (or external for an external role), an internet-facing role inside the lab, a
    public row (with ``rows``), static hosting it reaches, a granted credential of a selected
    module.  A grant waiting for a role, row or target to appear would switch it on with a
    module upgrade or a placement line nobody reads as a grant."""
    out: list[str] = []

    def stale(where: str, why: str) -> None:
        out.append(f"grants.{where}: {why}; remove the grant")

    for kind in (
        "egress",
        "internet_facing",
        "public_routes",
        "secrets",
        "units",
        "shared_config",
        "upstreams",
        "cloud_models",
    ):
        for mid in grants.get(kind, {}):
            if mid not in sel:
                stale(f"{kind}.{mid}", "the module is not selected")
    for mid, roles in grants.get("egress", {}).items():
        m = sel.get(mid)
        if m is None or not isinstance(roles, dict):
            continue  # unselected (above) or the old list shape (site_problems reports it)
        hosts = _hosts(m)
        for role, targets in roles.items():
            if role not in hosts:
                stale(f"egress.{mid}.{role}", "not one of the module's host roles")
                continue
            used = {t for e in _egress(m) if e["host"] == role for t in e["to"]}
            if hosts[role]["kind"] == "external":
                used.add("external")
            for t in targets:
                if t not in used:
                    stale(f"egress.{mid}.{role}", f"{t} is granted but not used")
    for mid, roles in grants.get("internet_facing", {}).items():
        hosts = _hosts(sel[mid]) if mid in sel else None
        for role in roles if hosts is not None else []:
            h = hosts.get(role)
            if h is None:
                stale(f"internet_facing.{mid}.{role}", "not one of the module's host roles")
            elif h.get("exposure") != "internet-facing" or h["kind"] == "external":
                stale(
                    f"internet_facing.{mid}.{role}",
                    "the role is not an internet-facing role inside the lab",
                )
    for mid, names in grants.get("public_routes", {}).items():
        if mid not in sel:
            continue
        mine = rows.get(mid, {})
        for n in names:
            if n not in mine:
                stale(f"public_routes.{mid}.{n}", "not one of the module's service rows")
            elif not mine[n].get("public_hostname"):
                stale(f"public_routes.{mid}.{n}", "the row has no public_hostname")
    for mid in grants.get("publish", []):
        if mid not in sel:
            stale(f"publish.{mid}", "the module is not selected")
        elif not reaches(sel[mid], STATIC_HOSTING):
            stale(f"publish.{mid}", f"the module does not reach {STATIC_HOSTING}")
    owners = {c["secret"]: m["id"] for m in sel.values() for c in m.get("credentials", [])}
    for mid, names in grants.get("secrets", {}).items():
        for n in names if mid in sel else []:
            if n.startswith(f"secret:{mid}/"):
                stale(f"secrets.{mid}", f"{n} is the module's own secret, which needs no grant")
            elif n not in owners:
                stale(f"secrets.{mid}", f"{n} is no selected module's credential")
    for mid, names in grants.get("units", {}).items():
        if mid in sel:
            for n in names:
                if n not in units.get(mid, set()):
                    stale(f"units.{mid}.{n}", "not one of the module's units")
                elif n not in privileged.get(mid, set()):
                    stale(
                        f"units.{mid}.{n}",
                        "the unit neither runs as root nor opts out of hardening",
                    )
    for mid, targets in grants.get("shared_config", {}).items():
        if mid in sel:
            declared = {
                x["target"] for x in sel[mid].get("contributes", {}).get("shared_config", [])
            }
            for t in targets:
                if t not in declared:
                    stale(f"shared_config.{mid}", f"the module declares no shared_config for {t}")
    for mid, caps in grants.get("upstreams", {}).items():
        if mid not in sel:
            continue
        # what the rows reach as traffic goes (through a fallback, through an instance)
        used = {
            "cap:" + a
            for row in rows.get(mid, {}).values()
            for u in row.get("upstreams", [])
            for a in _resolved_upstream(sel[mid], u, ch, slots) & set(GRANTED_UPSTREAMS)
        }
        for c in caps:
            if c not in used:
                stale(f"upstreams.{mid}", f"no service row of the module reaches {c[4:]}")
    for mid, wanted in grants.get("cloud_models", {}).items():
        if mid not in sel:
            continue
        required = {r["role"] for r in sel[mid]["requires"].get("model_roles", [])}
        cloud = cloud_roles(model_roles)
        for r in wanted:
            if r not in required:
                stale(f"cloud_models.{mid}", f"the module does not require {r}")
            elif r not in cloud:
                stale(f"cloud_models.{mid}", f"{r} has no binding that leaves the lab")
    return out


def _binding_problems(site: Doc, mods: dict[str, Doc], sel: dict[str, Doc]) -> list[str]:
    """Each features/core/providers entry names a selected module of that kind, and binds only
    agents the module contributes."""
    out = []
    for kind, sec in SECTION.items():
        for mid, b in site.get(sec, {}).items():
            m = sel.get(mid) or mods.get(mid)
            if m is None:
                out.append(f"{sec}.{mid}: no such module")
                continue
            if m["kind"] != kind:
                out.append(f"{sec}.{mid}: a {m['kind']} module is bound under {SECTION[m['kind']]}")
            if mid not in sel:
                out.append(f"{sec}.{mid}: the module is not selected")
            keys = {a["key"] for a in _agents(m)}
            for k in sorted(set(b.get("agents", {})) - keys):
                out.append(f"{sec}.{mid}.agents.{k}: the module contributes no such agent")
    return out


#: the config keys of a publication's TLP (ADR-0033 decision 9): ``tlp_allowed`` above
#: ``clear`` needs ``audience: community`` and a named ``access_control`` beside it
TLP_ALLOWED, AUDIENCE, ACCESS_CONTROL = "tlp_allowed", "audience", "access_control"


#: access controls that name nothing: a placeholder is not a control (compared lower-cased, with
#: spaces, dots, dashes and slashes removed).  A deny-list is the honest limit here: the selection
#: has no record of the community's access control to check the name against
PLACEHOLDER_CONTROLS = frozenset(
    {"", "none", "na", "nil", "null", "no", "x", "xx", "xxx", "tbd", "todo", "fixme", "unknown",
     "public", "open", "anyone", "everyone", "nobody", "noauth", "n", "y", "yes", "true",
     "false", "dash", "placeholder", "changeme", "example"}
)  # fmt: skip


def _placeholder(control: Any) -> bool:
    if not isinstance(control, str):
        return True
    squashed = re.sub(r"[\s./_-]+", "", control).lower()
    return squashed in PLACEHOLDER_CONTROLS or len(re.findall(r"[A-Za-z]", control)) < 3


def _green_problems(where: str, spec: Doc, cfg: Doc) -> list[str]:
    """``green`` is not public (ADR-0033 decision 9): a block whose ``tlp_allowed`` (its value,
    else the manifest's default) is ``green`` must declare the publication's audience as a
    community and name the access control that restricts it (not a placeholder:
    :data:`PLACEHOLDER_CONTROLS`), each by its value or the manifest's default.  Anything above
    ``green`` (``amber``, ``amber+strict``, ``red``, and a value that does not read, which is
    ``red``) is refused outright: no audience or control lets a publication out at that label."""
    if TLP_ALLOWED not in spec:
        return []

    def value(k: str) -> Any:
        return cfg[k] if k in cfg else spec.get(k, {}).get("default")

    label = tlp.read(value(TLP_ALLOWED))
    if label == tlp.Label.CLEAR:
        return []
    if label > tlp.Label.GREEN:
        return [
            f"{where}.config.{TLP_ALLOWED}: {label} is never published (ADR-0033 decision 9): "
            "the most a publication may carry is green, for a named community"
        ]
    audience, control = value(AUDIENCE), value(ACCESS_CONTROL)
    missing = []
    if audience != "community":
        missing.append(f"{AUDIENCE}: community (not {audience!r})")
    if _placeholder(control):
        missing.append(f"{ACCESS_CONTROL} naming what restricts it to that community")
    if not missing:
        return []
    return [
        f"{where}.config.{TLP_ALLOWED}: {label} is not public (ADR-0033 decision 9): it needs "
        + " and ".join(missing)
    ]


def _config_problems(site: Doc, sel: dict[str, Doc], grants: Doc) -> list[str]:
    """A selection's config values: declared keys only, no address literal (the scope block is the
    one place for addresses), a secret-typed value is a secret in the module's own namespace
    or one granted to it in grants.secrets (the same rule as a manifest default, so an overlay
    value cannot read another module's secret), and a publication above ``clear`` names its
    community audience and access control (:func:`_green_problems`)."""
    places = [
        (f"{sec}.{mid}", mid, b.get("config", {}))
        for sec in SECTION.values()
        for mid, b in site.get(sec, {}).items()
    ]
    places += [
        (f"slots.{s}.{c['instance']}", c["provider"], c.get("config", {}))
        for s, cs in site["slots"].items()
        if isinstance(cs, list)
        for c in cs
    ]
    out = []
    for where, mid, cfg in places:
        spec = sel.get(mid, {}).get("config", {})
        out += _green_problems(where, spec, cfg)
        for k, v in cfg.items():
            if k not in spec:
                out.append(f"{where}.config.{k}: the module declares no such key")
                continue
            literal = None
            # not scanned: integer, duration_s and boolean keys.  Their value is a number by
            # schema, and any integer of 2**24 or more is also an IPv4 address (a byte count of
            # 170000000 reads as one in 10/8), so scanning them would refuse ordinary sizes; a module
            # that reads an address out of an integer key is a defect in that module
            # (docs/modules.md, "The network scope")
            if spec[k]["type"] not in ("integer", "duration_s", "boolean"):
                text = str(v) if isinstance(v, int) and not isinstance(v, bool) else v
                literal = address_literals(text) if isinstance(text, str) else None
            if literal:
                out.append(
                    f"{where}.config.{k}: an address literal ({literal[0]}): a lab address "
                    "belongs in the selection's scope block, which the module requires; an "
                    "external endpoint (a resolver, an NTP server) is a hostname or a svc: "
                    "reference"
                )
                continue
            secretish = isinstance(v, str) and v.lower().startswith("secret:")
            if spec[k]["type"] != "secret":
                if secretish:
                    out.append(f"{where}.config.{k}: a secret reference in a non-secret key")
                continue
            if not (isinstance(v, str) and v.startswith("secret:")):
                out.append(f"{where}.config.{k}: a secret key's value is a secret name")
            elif not v.startswith(f"secret:{mid}/") and v not in grants.get("secrets", {}).get(
                mid, []
            ):
                out.append(f"{where}.config.{k}: {v} is not {mid}'s own and not granted to it")
    return out


def _fallback_to(m: Doc, slot: str) -> str | None:
    """The ``cap:`` a module falls back to when the site leaves its preferred ``slot`` out."""
    pref = next(
        (p for p in m.get("prefers", {}).get("capabilities", []) if p["cap"] == "cap:" + slot),
        None,
    )
    return pref["fallback"].get("to") if pref else None


def _resolved_upstream(m: Doc, u: str, ch, slots) -> set[str]:
    """The slots a row's upstream ``u`` reaches on this site, as traffic goes: a selected slot
    itself; an unselected preferred slot, its fallback slot when that is selected; an instance,
    every slot it fills."""
    if u in slots:
        if "cap:" + u in ch:
            return {u}
        to = _fallback_to(m, u)
        return {to[4:]} if to and to in ch else set()
    return {cap[4:] for cap, cs in ch.items() for c in cs if c["instance"] == u}


def _upstream_problems(m: Doc, name: str, row: Doc, ch, slots, grants: Doc) -> list[str]:
    """A row's upstream follows the module's fallback: a preferred slot the site does not select
    resolves to its fallback slot, which must be selected; an instance must be selected.  A
    broker, idp or remote-admin upstream needs grants.upstreams, judged by what the upstream
    reaches as traffic goes (:func:`_resolved_upstream`: the slot, its fallback, an instance)."""
    out = []
    selected_instances = {c["instance"] for cs in ch.values() for c in cs}
    granted = grants.get("upstreams", {}).get(m["id"], [])
    for u in row.get("upstreams", []):
        for authority in sorted(_resolved_upstream(m, u, ch, slots) & set(GRANTED_UPSTREAMS)):
            if "cap:" + authority not in granted:
                out.append(
                    f"{m['id']}: service {name} upstream {u} reaches {authority} without "
                    "grants.upstreams"
                )
        if u in slots:
            if "cap:" + u in ch:
                continue
            to = _fallback_to(m, u)
            if not (to and to in ch):
                out.append(
                    f"{m['id']}: service {name} upstream {u} is not selected, nor a fallback for it"
                )
        elif u not in selected_instances:
            out.append(f"{m['id']}: service {name} upstream {u} is not a selected instance")
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
    for sec in ("features", "core"):
        for name, f in site.get(sec, {}).items():
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
        if (h.get("exposure", "internal") == "isolated") != bool(sh.get("isolated")):
            out.append(
                f"{mod}/{role}: an isolated role lands only on an isolated host, and only it does"
            )
    want = {}
    for cs in site["slots"].values():
        for c in cs if isinstance(cs, list) else []:
            want[(c["provider"], c["instance"])] = {
                x["role"] for x in sel[c["provider"]]["requires"].get("hosts", [])
            }
    for name, m in sel.items():
        if m["kind"] != "provider":  # features and every core module, selected or not by name
            want[(name, None)] = {x["role"] for x in m["requires"].get("hosts", [])}
    got: dict[tuple, set] = {}
    for mod, inst, role, _, _ in placed:
        got.setdefault((mod, inst), set()).add(role)
    for k, roles in want.items():
        if roles and got.get(k, set()) != roles:
            out.append(
                f"{k[0]} ({k[1] or sel[k[0]]['kind']}): every host role is placed exactly once"
            )
    return out + footprint_problems(site, placed)


def footprint_problems(site: Doc, placed) -> list[str]:
    """Every footprint on a host, times its role's count, summed over cpu, memory, disk and GPU
    memory, fits the host's capacity less its headroom.  Every resource claim names a kind the
    host has; an exclusive claim takes one named resource to itself, and the shared claims of
    that kind need one left over."""
    out = []
    use: dict[str, dict[str, float]] = {}
    claims: dict[str, dict[str, list[bool]]] = {}
    for _, _, _, h, host in placed:
        if h is None or host not in site["hosts"]:
            continue
        fp, n = h["footprint"], h.get("count", 1)
        u = use.setdefault(host, {})
        for dim in ("cpu", "memory_mb", "disk_gb", "gpu_memory_mb"):
            u[dim] = u.get(dim, 0) + n * fp.get(dim, 0)
        for r in fp.get("resources", []):
            claims.setdefault(host, {}).setdefault(r["kind"], []).extend([r["exclusive"]] * n)
    for host, u in use.items():
        sh = site["hosts"][host]
        cap = dict(sh["capacity"])
        cap["memory_mb"] -= sh.get("headroom", {}).get("memory_mb", 0)
        for dim, v in u.items():
            if v > cap.get(dim, 0):
                out.append(f"{host}: {dim} {v} exceeds {cap.get(dim, 0)}")
        have = [r["kind"] for r in sh.get("resources", [])]
        for kind, cl in claims.get(host, {}).items():
            n, shared, named = cl.count(True), cl.count(False), have.count(kind)
            if not named:
                out.append(f"{host}: no {kind} named, {len(cl)} claim(s) on one")
            elif n > named:
                out.append(f"{host}: {n} exclusive {kind} wanted, {named} named")
            elif shared and n >= named:
                out.append(
                    f"{host}: {shared} shared {kind} claim(s), but every {kind} is held exclusively"
                )
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


def dataset_label(ds: dict[str, Any]) -> tuple[tlp.Label, bool]:
    """A dataset's declared TLP label and whether its items' own labels are honoured when looser
    (ADR-0033 decision 3): ``red`` and never honoured when it declares none (decision 2), since
    ``honour_item_labels`` applies only beside a declaration. The schema has already held ``tlp``
    to a canonical label; :func:`homelabnext.tlp.parse` still refuses anything else.
    """
    if "tlp" not in ds:
        return tlp.Label.RED, False
    return tlp.parse(ds["tlp"]), ds.get("honour_item_labels") is True
