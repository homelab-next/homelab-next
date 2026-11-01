# SPDX-License-Identifier: Apache-2.0
"""What an agent may reach, derived from its compiled profile and the registry (checklist M-14).

One derivation feeds two consumers, so they cannot disagree:

* the **keyring** (:mod:`homelabnext.agent.keyring`, M-12): every principal's grants by level
  and its denials, generated from the sources;
* the **access block** that :func:`start_session` puts into every session's context pack as a
  stable section named ``access``, so an agent starts knowing what it may use, through which
  registry alias, from where it runs, and that everything else is denied.

:func:`start_session` also adds the reserved stable ``terms`` section
(:mod:`homelabnext.agent.terms`): the project's vocabulary and authorized scope.

Levels.  A grant's level is the worst of its capability classes (``tool_classes.yml``):
``read``/``codemode`` -> read, ``record-write``/``file-write`` -> write,
``exec``/``egress``/``send`` -> execute, ``credential`` -> privileged (:data:`CLASS_LEVEL`,
one entry per class of the table).  A grant the table does not classify is listed as
``unclassified`` (never assumed harmless).  Broker actions carry their own tier.

Denials are explicit: every registry capability, MCP server and broker action the principal does
not hold is listed, so a probe (M-13) can test the denial as well as the grant.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from homelabnext.grants import TIER_RANK

from .compiler import VerifiedProfile, require_verified
from .digest import digest_of
from .errors import SpecError
from .pack import assemble_pack
from .readers import ToolClasses, default_classes
from .terms import TERMS_SECTION, terms_section

ACCESS_SECTION = "access"
LEVELS = ("read", "write", "execute", "privileged")
CLASS_LEVEL = {
    "read": "read",
    "record-write": "write",
    "file-write": "write",
    "egress": "execute",
    "send": "execute",
    "exec": "execute",
    "credential": "privileged",
    "codemode": "read",  # searches and describes granted actions; running one is codemode.execute
}
_LEVEL_RANK = {lv: i for i, lv in enumerate(LEVELS)}


def level_of(classes: Iterable[str] | None) -> str:
    """The level of a grant from its capability classes (worst wins)."""
    if not classes:
        return "unclassified"
    levels = [CLASS_LEVEL.get(c, "privileged") for c in classes]
    return max(levels, key=_LEVEL_RANK.__getitem__)


def _mcp_service(registry: Any, name: str):
    for svc in registry.sorted_services():
        if (svc.mcp and svc.mcp.get("name") == name) or svc.capability == name:
            return svc
    return None


def _cap_service(registry: Any, cap_id: str):
    return registry.by_capability(cap_id.split(":", 1)[1]) if ":" in cap_id else None


def reachable_services(registry: Any, zone: str) -> list[Any]:
    """Services a host in ``zone`` may connect to: same zone, a listed client zone, or a
    dependency of a service in the zone (``upstreams``)."""
    in_zone = [s for s in registry.sorted_services() if registry.host_of(s).zone == zone]
    called = {u for s in in_zone for u in s.upstreams}
    return [
        s
        for s in registry.sorted_services()
        if registry.host_of(s).zone == zone or zone in s.clients or s.capability in called
    ]


def _broker_grants(broker: Mapping[str, Any] | None, principal: str) -> dict[str, dict]:
    """``{action: {level, approval}}`` the broker manifest grants ``principal``."""
    if not broker:
        return {}
    actions = {a["action"]: a for a in broker.get("actions", [])}
    out: dict[str, dict] = {}
    for g in broker.get("grants", []):
        if g.get("profile") != principal:
            continue
        cap = TIER_RANK.get(g.get("max_tier", "read"), 0)
        for name in g.get("actions", []):
            a = actions.get(name)
            if a is None or TIER_RANK.get(a["tier"], 99) > cap:
                continue  # the broker itself refuses these (handler-missing / tier-exceeds-grant)
            out[name] = {"level": a["tier"], "approval": bool(a.get("requires_approval"))}
    return out


def principal_access(
    principal: str,
    registry: Any,
    *,
    profile: Mapping[str, Any] | None = None,
    broker: Mapping[str, Any] | None = None,
    classes: ToolClasses | None = None,
) -> dict:
    """Grants (with level and registry endpoint) and denials of one agent principal."""
    classes = classes or default_classes()
    grants: list[dict] = []
    granted: set[str] = set()
    pg = (profile or {}).get("grants") or {}
    for cap in pg.get("capabilities", []):
        svc = _cap_service(registry, cap)
        grants.append(
            {
                "resource": cap,
                "kind": "capability",
                "level": level_of(classes.classify("capabilities", cap)),
                "endpoint": registry.alias(svc.capability) if svc else None,
            }
        )
        granted.add(cap)
    for name in pg.get("mcp", []):
        svc = _mcp_service(registry, name)
        endpoint = None
        if svc:
            endpoint = registry.alias(svc.capability)
            if svc.mcp:
                endpoint += svc.mcp.get("path", "/mcp")
        grants.append(
            {
                "resource": f"mcp:{name}",
                "kind": "mcp",
                "level": level_of(classes.classify("mcp", name)),
                "endpoint": endpoint,
            }
        )
        granted.add(f"mcp:{name}")
    for action, g in sorted(_broker_grants(broker, principal).items()):
        grants.append(
            {
                "resource": f"action:{action}",
                "kind": "broker-action",
                "level": g["level"],
                "approval": g["approval"],
            }
        )
        granted.add(f"action:{action}")

    known: set[str] = set()
    for svc in registry.sorted_services():
        known.add(f"cap:{svc.capability}")
        if svc.mcp:
            known.add(f"mcp:{svc.mcp['name']}")
    for a in (broker or {}).get("actions", []):
        known.add(f"action:{a['action']}")
    denials = [
        {"resource": r, "reason": "not granted (default deny)"} for r in sorted(known - granted)
    ]
    grants.sort(key=lambda g: (_LEVEL_RANK.get(g["level"], len(LEVELS)), g["resource"]))
    return {"principal": principal, "kind": "agent", "grants": grants, "denials": denials}


def _runs_on(registry: Any, runs_on: str | None) -> Any:
    if runs_on is None:
        svc = registry.by_capability("agent-runtime")
        if svc is None:
            raise SpecError("no runs_on host given and the registry has no agent-runtime service")
        runs_on = svc.host
    host = registry.hosts.get(runs_on)
    if host is None:
        raise SpecError(f"runs_on host {runs_on!r} is not in the registry")
    return host


def access_block(
    profile: VerifiedProfile,
    registry: Any,
    *,
    runs_on: str | None = None,
    broker: Mapping[str, Any] | None = None,
    classes: ToolClasses | None = None,
) -> dict:
    """The structured access block for ``profile`` (a
    :class:`~homelabnext.agent.compiler.VerifiedProfile`) running on registry host ``runs_on``
    (default: the host of the registry's ``agent-runtime`` service)."""
    require_verified(profile, "access_block")
    host = _runs_on(registry, runs_on)
    access = principal_access(
        profile["id"], registry, profile=profile, broker=broker, classes=classes
    )
    return {
        "principal": profile["id"],
        "profile_digest": profile["digest"],
        "registry_digest": registry.digest,
        "broker": digest_of(broker) if broker else None,
        "runs_on": {"host": host.name, "zone": host.zone},
        "model_role": profile.get("model_role"),
        "data_tier": profile.get("data_tier"),
        "reads_untrusted": profile.get("reads_untrusted", True),
        "broker_tier": (profile.get("grants") or {}).get("tier"),
        "memory_scopes": sorted(profile.get("memory_scopes") or []),
        "budgets": dict(sorted((profile.get("budgets") or {}).items())),
        "grants": access["grants"],
        "denials": access["denials"],
        "reachable": sorted(
            registry.alias(s.capability) for s in reachable_services(registry, host.zone)
        ),
        "default": "deny",
    }


def render_access_block(block: Mapping[str, Any]) -> str:
    """Deterministic text of an access block (the ``access`` section of a session's pack)."""
    rt = block["runs_on"]
    lines = [
        f"You are {block['principal']}, running on {rt['host']} (zone {rt['zone']}).",
        "Anything not listed under 'may' is denied: the broker and the network refuse it.",
        f"model role: {block['model_role']}",
        f"data tier: {block['data_tier']}",
        f"reads untrusted content: {'yes' if block['reads_untrusted'] else 'no'}",
        f"broker tier: {block['broker_tier']}",
        f"memory scopes (your own memory only): {', '.join(block['memory_scopes']) or 'none'}",
        "budgets: " + ", ".join(f"{k}={v}" for k, v in block["budgets"].items()),
        "may:",
    ]
    for g in block["grants"]:
        via = ""
        if g["kind"] == "broker-action":
            via = " through the broker" + (", needs approval" if g.get("approval") else "")
        elif g.get("endpoint"):
            via = f" via {g['endpoint']}"
        else:
            via = " (no registry service)"
        lines.append(f"- {g['level']}: {g['resource']}{via}")
    if not block["grants"]:
        lines.append("- nothing")
    lines.append("may not (denied):")
    lines += [f"- {d['resource']}" for d in block["denials"]] or ["- (nothing else is known)"]
    lines.append(f"reachable from zone {rt['zone']}: {', '.join(block['reachable']) or 'none'}")
    lines.append(f"profile {block['profile_digest']}, registry {block['registry_digest']}")
    return "\n".join(lines)


def session_problems(manifest: Mapping[str, Any], profile: Mapping[str, Any]) -> list[str]:
    """Why ``manifest`` may not feed a session of ``profile`` (empty: it may).

    The manifest is bound to a persona and the profile declares what the agent may hold, so the
    two are only both in hand here (and in ``hnx agent lint``, for the profiles a manifest names):

    * the profile's persona is the manifest's, and a manifest that names its ``profiles`` names
      this one;
    * an actor (``reads_untrusted: false``) is never given a ``source: input`` section, the raw
      content a reader exists to turn into validated structured output (G-03/G-04);
    * every manifest tool is an MCP server the profile is granted, so the pack never lists a tool
      its own access block denies;
    * every manifest memory scope is one of the profile's own ``memory_scopes``.
    """
    pid = profile.get("id")
    problems: list[str] = []
    if manifest.get("persona") != profile.get("persona"):
        problems.append(
            f"manifest persona {manifest.get('persona')!r} is not the profile's "
            f"{profile.get('persona')!r}"
        )
    named = manifest.get("profiles")
    if named is not None and pid not in named:
        problems.append(f"the manifest names profiles {sorted(named)}, not {pid}")
    if profile.get("reads_untrusted", True) is False:
        raw = sorted(s["name"] for s in manifest.get("sections", []) if s.get("source") == "input")
        if raw:
            problems.append(
                f"{pid} declares reads_untrusted: false, but the manifest feeds it untrusted "
                f"input sections {raw}: an actor gets a reader's validated output, not raw input"
            )
    granted = set((profile.get("grants") or {}).get("mcp") or [])
    extra = sorted(set(manifest.get("tools") or []) - granted)
    if extra:
        problems.append(f"manifest tools {extra} are not MCP servers {pid} is granted")
    scopes = set(profile.get("memory_scopes") or [])
    wider = sorted(set(manifest.get("memory_scopes") or []) - scopes)
    if wider:
        problems.append(f"manifest memory scopes {wider} are not {pid}'s memory_scopes")
    return problems


def start_session(
    manifest: Mapping[str, Any],
    inputs: Mapping[str, Any],
    profile: VerifiedProfile,
    registry: Any,
    *,
    runs_on: str | None = None,
    broker: Mapping[str, Any] | None = None,
    classes: ToolClasses | None = None,
    denylist: Iterable[str] | None = None,
    knowledge: Any = None,
) -> tuple[dict, str]:
    """Assemble a session's context pack with the profile's access block and the project's terms
    (:mod:`homelabnext.agent.terms`) as stable sections.

    ``profile`` is a :class:`~homelabnext.agent.compiler.VerifiedProfile` (verified against the
    ceiling policy and the lock of reviewed digests); a dict is refused, digested or not.

    ``knowledge``: the profile's :class:`~homelabnext.agent.knowledge.Selection`; it must have
    been selected for this very profile (id and digest), and goes into the volatile tier.

    The sections are named ``access`` and ``terms`` and are reserved: a manifest that defines
    either is refused, so a manifest cannot replace or remove what the agent is told about its
    access and about the project's terms and scope.  :func:`session_problems` must find nothing
    (the persona is the manifest's, the manifest names this profile if it names any, and the
    tools and memory scopes fit).  Stable content is never cut, so a block that does not fit
    ``budget_chars`` defers the pack instead of being truncated.
    """
    require_verified(profile, "start_session")
    for s in manifest.get("sections", []):
        if s.get("name") == ACCESS_SECTION:
            raise SpecError(f"section name {ACCESS_SECTION!r} is reserved for the access block")
        if s.get("name") == TERMS_SECTION:
            raise SpecError(f"section name {TERMS_SECTION!r} is reserved for the project's terms")
    problems = session_problems(manifest, profile)
    if problems:
        raise SpecError("; ".join(problems))
    if knowledge is not None and (knowledge.profile, knowledge.profile_digest) != (
        profile["id"],
        profile["digest"],
    ):
        raise SpecError(
            f"knowledge was selected for {knowledge.profile} {knowledge.profile_digest}, "
            f"not this profile {profile['id']} {profile['digest']}"
        )
    text = render_access_block(
        access_block(profile, registry, runs_on=runs_on, broker=broker, classes=classes)
    )
    section = {
        "name": ACCESS_SECTION,
        "tier": "stable",
        "source": "static",
        "required": True,
        "max_chars": len(text),
        "text": text,
    }
    session_manifest = {**manifest, "sections": [*manifest["sections"], section, terms_section()]}
    return assemble_pack(session_manifest, inputs, denylist=denylist, knowledge=knowledge)
