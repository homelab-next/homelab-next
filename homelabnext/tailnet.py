# SPDX-License-Identifier: Apache-2.0
"""The deploy's tailnet access: which zones the CI deploy tag may reach, on which ports.

Pure functions over plain data, shared by the site model (:mod:`homelabnext.network.validate`,
``hnx site validate``) and the guest model (:func:`homelabnext.compute.zones.site_deploy`, read
by the ``tailscale-acl`` target), so the one rule set is written once and the compute model still
never imports the site-model package (the same split as :mod:`homelabnext.power`).

The site declares (1.2)::

    tailnet:
      deploy:
        tag: tag:ci-deploy              # optional; the tag the deploy's ephemeral key carries
        owners: [autogroup:admin]       # who may mint keys for the tag (tagOwners)
        zones: [mgmt, data]             # site zones whose tailnet nodes it reaches on SSH (22)
        exceptions:                     # anything beyond SSH, each with its reason
          - {zones: [mgmt], ports: [9443], reason: "..."}

SSH (TCP 22) to the listed zones is the whole default.  These are errors: a destination that is
not a zone of the site (``*``, ``any``, ``autogroup:...`` included: there is no wildcard
destination); a zone listed twice; an exception without a reason, for a zone the deploy does not
reach, or for port 22 (already allowed); a tag that is a zone tag (``tag:zone-...``, which the
nodes advertise) or that owns itself; no owner.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

DEFAULT_TAG = "tag:ci-deploy"
SSH = 22
#: the tag prefix the ``tailscale_node`` role advertises per zone (``tag:zone-<zone>``)
ZONE_TAG_PREFIX = "tag:zone-"
ANY_PORT = "*"
TAG_RE = re.compile(r"^tag:[a-z0-9][a-z0-9-]{0,62}\Z")
OWNER_RE = re.compile(
    r"^(autogroup:(admin|owner|it-admin|network-admin)|group:[a-z0-9][a-z0-9-]*|tag:[a-z0-9][a-z0-9-]{0,62})\Z"
)
WILDCARDS = frozenset({"*", "any"})
MIN_REASON = 10


def _zone_ids(doc: Mapping[str, Any]) -> list[str]:
    return [str(z["id"]) for z in doc.get("zones") or [] if isinstance(z, Mapping) and z.get("id")]


def deploy_problems(doc: Mapping[str, Any]) -> list[str]:
    """Problems of the site's ``tailnet.deploy`` declaration (none when it has none)."""
    tailnet = doc.get("tailnet")
    if tailnet is None:
        return []
    if not isinstance(tailnet, Mapping):
        return ["tailnet: must be a mapping"]
    dep = tailnet.get("deploy")
    if dep is None:
        return []
    w = "tailnet.deploy"
    if not isinstance(dep, Mapping):
        return [f"{w}: must be a mapping"]
    out: list[str] = []
    known = set(_zone_ids(doc))
    tag = dep.get("tag", DEFAULT_TAG)
    if not isinstance(tag, str) or not TAG_RE.match(tag):
        out.append(f"{w}.tag: {tag!r} is not a tag (tag:<a-z0-9->)")
    elif tag.startswith(ZONE_TAG_PREFIX):
        out.append(f"{w}.tag: {tag!r} is a zone tag; the deploy needs a tag of its own")
    owners = dep.get("owners")
    if not isinstance(owners, list) or not owners:
        out.append(f"{w}.owners: name who may mint keys for the tag (e.g. [autogroup:admin])")
    else:
        for o in owners:
            if not isinstance(o, str) or not OWNER_RE.match(o):
                out.append(f"{w}.owners: {o!r} is not an autogroup:, group: or tag: owner")
            elif o == tag:
                out.append(f"{w}.owners: the tag {tag!r} cannot own itself")
    zones = dep.get("zones")
    if not isinstance(zones, list) or not zones:
        out.append(f"{w}.zones: list the zones the deploy reaches (no wildcard)")
        zones = []
    seen: set[str] = set()
    for z in zones:
        if not isinstance(z, str) or z in WILDCARDS or ":" in z:
            out.append(
                f"{w}.zones: {z!r} is a wildcard or not a zone id; list each zone the deploy "
                "reaches by its id"
            )
        elif z not in known:
            out.append(f"{w}.zones: {z!r} is not a zone of the site")
        elif z in seen:
            out.append(f"{w}.zones: {z!r} listed twice")
        seen.add(str(z))
    for i, e in enumerate(dep.get("exceptions") or []):
        where = f"{w}.exceptions[{i}]"
        if not isinstance(e, Mapping):
            out.append(f"{where}: must be {{zones, ports, reason}}")
            continue
        reason = e.get("reason")
        if not isinstance(reason, str) or len(reason.strip()) < MIN_REASON:
            out.append(f"{where}: a port beyond SSH needs a reason (why the deploy needs it)")
        ez = e.get("zones")
        if not isinstance(ez, list) or not ez:
            out.append(f"{where}.zones: name the deploy zones the exception applies to")
        else:
            for z in ez:
                if z not in seen or z in WILDCARDS:
                    out.append(f"{where}.zones: {z!r} is not one of {w}.zones")
        ports = e.get("ports")
        if ports == ANY_PORT:
            continue
        if not isinstance(ports, list) or not ports:
            out.append(f"{where}.ports: list the ports, or '*' (every port) with its reason")
            continue
        for p in ports:
            if not isinstance(p, int) or isinstance(p, bool) or not 1 <= p <= 65535:
                out.append(f"{where}.ports: {p!r} is not a port")
            elif p == SSH:
                out.append(f"{where}.ports: 22 is the default; an exception is for other ports")
    return out


def site_deploy(doc: Mapping[str, Any]) -> dict[str, Any] | None:
    """The deploy access as plain data, or None when the site declares none: ``tag``,
    ``owners``, ``zones`` and ``exceptions`` (each ``{zones, ports, reason}``; ``ports`` is a
    sorted tuple, or ``"*"``).  Assumes :func:`deploy_problems` found nothing."""
    dep = (doc.get("tailnet") or {}).get("deploy") if isinstance(doc, Mapping) else None
    if not isinstance(dep, Mapping):
        return None
    return {
        "tag": dep.get("tag", DEFAULT_TAG),
        "owners": tuple(dep["owners"]),
        "zones": tuple(dep["zones"]),
        "exceptions": tuple(
            {
                "zones": tuple(e["zones"]),
                "ports": ANY_PORT if e["ports"] == ANY_PORT else tuple(sorted(e["ports"])),
                "reason": str(e["reason"]).strip(),
            }
            for e in dep.get("exceptions") or []
        ),
    }
