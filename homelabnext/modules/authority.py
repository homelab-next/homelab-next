# SPDX-License-Identifier: Apache-2.0
"""The authority slots, written once (docs/modules.md, "What the loader checks").

The manifest and selection schema generator (:mod:`homelabnext.schemas.module_manifest`) and the
loader's rules (:mod:`homelabnext.modules.rules`) both read these, so a trust root added here is
an authority everywhere at once.  The slot registry (``examples/modules/slots.yml``) carries the
same facts as its ``authority`` and ``granted_upstream`` flags; :func:`slot_flag_problems`
refuses a registry whose flags disagree with this module, so the flag and the list stay one fact
(the same arrangement as the egress list and the ``egress`` flag).  A registry cannot loosen the
platform's rules by dropping a flag: the rules read these constants, and the disagreement is a
problem.
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "AUTHORITY_SLOTS",
    "GRANTED_UPSTREAMS",
    "NEVER_SHARED",
    "SHARED_CONFIG_GRANTS",
    "slot_flag_problems",
]

#: slots whose service a module reaches only through its owner or an overlay grant: a module
#: agent is never granted one directly (``needs``), and each is an authority for the site rules
AUTHORITY_SLOTS = ("broker", "secrets", "idp", "edge", "remote-admin", "mcp-catalog")
#: shared components whose configuration a module can never merge into (no grant opens these)
NEVER_SHARED = (
    "secrets",
    "broker",
    "mcp-catalog",
    "records",
    "orchestration",
    "codemode-executor",  # a merged key could widen the sandbox's egress or environment
    "codemode-runner",  # a merged key could widen a token's actions or the relay's endpoint
)
#: authority slots a module may configure only with grants.shared_config: every authority slot
#: that is not closed to shared configuration altogether
SHARED_CONFIG_GRANTS = tuple(s for s in AUTHORITY_SLOTS if s not in NEVER_SHARED)
#: authority slots a service row may name as an upstream only with grants.upstreams (an authority
#: behind a route); secrets is read by name, never an upstream, and edge and mcp-catalog are
#: never behind a module's route
GRANTED_UPSTREAMS = ("broker", "idp", "remote-admin")

#: registry flag -> the slots this module says carry it
_FLAGS = {
    "authority": ("an authority", AUTHORITY_SLOTS),
    "granted_upstream": ("a granted-upstream", GRANTED_UPSTREAMS),
}


def slot_flag_problems(slots: dict[str, Any]) -> list[str]:
    """A problem for each registry entry whose ``authority`` or ``granted_upstream`` flag
    disagrees with this module, either way: a flagged slot the rules do not know would be
    treated as ordinary, and an unflagged authority slot would read as ordinary to anyone
    reading the registry."""
    out = []
    for name in sorted(slots, key=str):
        for flag, (what, names) in _FLAGS.items():
            flagged = slots[name].get(flag) is True
            if flagged and name not in names:
                out.append(
                    f"{name}: flagged {flag} in the slot registry, but "
                    f"homelabnext.modules.authority does not list it (the rules would treat it "
                    "as ordinary)"
                )
            elif name in names and not flagged:
                out.append(
                    f"{name}: {what} slot "
                    "(homelabnext.modules.authority), but the slot registry does not flag it"
                )
    return out
