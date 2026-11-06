# SPDX-License-Identifier: Apache-2.0
"""Shared fakes for the agent tests: an in-memory parts library and a canonical spec/manifest."""

import copy

from homelabnext.agent import PartsLibrary
from homelabnext.ids import MappingResolver

PARTS = {
    "persona:analyst": "You analyse findings and cite sources.",
    "skill:summarise": "Summarise in five bullets.",
    "skill:triage": "Rank findings by severity.",
    "cap:lake-query": "Read-only lake queries.",
    "cap:records-propose": "Write proposals.",
}


def library(parts=None) -> PartsLibrary:
    parts = PARTS if parts is None else parts
    resolver = MappingResolver("fake", {k: f"mem/{k}" for k in parts})
    return PartsLibrary(resolver, lambda loc: parts[loc[len("mem/") :]], source="fake-library")


def spec() -> dict:
    return copy.deepcopy(
        {
            "id": "profile:reader",
            "persona": "persona:analyst",
            "skills": ["skill:triage", "skill:summarise"],
            "capabilities": ["cap:lake-query"],
            "model_role": "mdl:fast-classifier",
            "mcp": ["lake"],
            "tier": "read",
            "ceiling": {
                "mcp": ["lake", "records"],
                "capabilities": ["cap:lake-query", "cap:records-propose"],
                "tier": "write",
                "budgets": {
                    "max_input_tokens": 64000,
                    "max_output_tokens": 4000,
                    "max_runtime_s": 900,
                    "max_tool_calls": 40,
                },
            },
            "memory_scopes": ["analyst"],
            "data_tier": "local-only",
            "budget_mode": "enforce",
            "budgets": {
                "max_input_tokens": 32000,
                "max_output_tokens": 2000,
                "max_runtime_s": 600,
                "max_tool_calls": 20,
            },
        }
    )


def manifest() -> dict:
    return {
        "id": "reader-pack",
        "persona": "persona:analyst",
        "skills": ["skill:summarise", "skill:triage"],
        "tools": ["lake"],
        "pregates": [{"id": "pipeline-health", "required": True, "max_age_s": 900}],
        "memory_scopes": ["analyst"],
        "delimiter": "=====",
        "must_cite": ["findings"],
        "budget_chars": 4000,
        "sections": [
            {
                "name": "charter",
                "tier": "stable",
                "source": "static",
                "required": True,
                "max_chars": 800,
                "text": "You are a read-only analyst. Cite every claim.",
            },
            {
                "name": "rules",
                "tier": "stable",
                "source": "static",
                "required": True,
                "max_chars": 800,
                "text": "Never act; only report.",
            },
            {
                "name": "memory",
                "tier": "session",
                "source": "input",
                "required": False,
                "max_chars": 600,
            },
            {
                "name": "findings",
                "tier": "volatile",
                "source": "input",
                "required": True,
                "max_chars": 2000,
            },
        ],
    }


GATE_OK = {
    "gate": "pipeline-health",
    "status": "ok",
    "observed_at": "2026-01-15T10:00:00Z",
    "sources": [{"name": "auth-events", "age_s": 42}],
}


def inputs() -> dict:
    return {
        "sections": {"findings": "f1: 3 failed logins", "memory": "no known scanners"},
        "pregates": {"pipeline-health": copy.deepcopy(GATE_OK)},
    }


def _ceilings(profiles) -> dict:
    """Policy entries attesting each compiled profile as it stands (its stored ceiling, data
    tier, model role and TLP ceiling): the policy owner's review, faked for the tests."""
    entries = {}
    for p in profiles:
        entry = {**p["ceiling"], "data_tier": p["data_tier"], "model_role": p["model_role"]}
        if p.get("tlp_ceiling"):
            entry["tlp_ceiling"] = p["tlp_ceiling"]
        entries[p["id"]] = entry
    return entries


def policy_for(*profiles):
    """A ceiling policy attesting ``profiles`` (:func:`_ceilings`)."""
    from homelabnext.agent import CeilingPolicy

    return CeilingPolicy(_ceilings(profiles), source="test-policy")


def lock_for(*profiles) -> dict:
    """The lock of reviewed digests pinning each compiled profile."""
    return {p["id"]: p["digest"] for p in profiles}


def verified(profile, classes=None):
    """``profile`` verified against :func:`policy_for` and :func:`lock_for` of itself."""
    from homelabnext.agent import verified_profile

    return verified_profile(
        profile, policy=policy_for(profile), lock=lock_for(profile), classes=classes
    )


def write_policy_lock(directory, *profiles) -> tuple:
    """``(policy path, lock path)`` files for the CLI, attesting and pinning ``profiles``."""
    import json
    from pathlib import Path

    policy, lock = Path(directory) / "policy.json", Path(directory) / "lock.json"
    policy.write_text(json.dumps({"ceilings": _ceilings(profiles)}), encoding="utf-8")
    lock.write_text(json.dumps({"profiles": lock_for(*profiles)}), encoding="utf-8")
    return policy, lock


def canonical_pack() -> tuple:
    """``(pack, hash)`` of :func:`manifest` and :func:`inputs`: the pack a checked memory write
    that cites nothing passes (ADR-0037 decision 7)."""
    from homelabnext.agent import assemble_pack

    return assemble_pack(manifest(), inputs())


def uid(n: int) -> str:
    """A canonical record uid (UUIDv7) numbered ``n``."""
    return f"01900000-0000-7000-8000-{n:012x}"


def digest(n: int) -> str:
    """A content digest numbered ``n``."""
    return f"sha256:{n:064x}"


def item(n: int, label: str | None = None) -> dict:
    """Input item ``n`` (``uid(n)``, ``digest(n)``) with the caller's ``label``."""
    return {"uid": uid(n), "digest": digest(n), **({"tlp": label} if label else {})}


def labelled_manifest(static: str | None = "green") -> dict:
    """:func:`manifest` without its pre-gate (a pre-gate section is always red) and with its
    static sections labelled ``static`` (absent: red)."""
    m = manifest()
    m["pregates"] = []
    for s in m["sections"]:
        if s["source"] == "static" and static is not None:
            s["tlp"] = static
    return m


def labelled_pack(findings=(), memory=(), *, static="green", stored=None, **kw) -> tuple:
    """``(pack, hash)`` of :func:`labelled_manifest` with input items: ``findings`` and ``memory``
    are lists of items (:func:`item`).  ``stored`` maps uid to its stored label (by default each
    item's own label, or red), the resolved uid map the assembler checks."""
    from homelabnext.agent import assemble_pack

    items = {"findings": list(findings), "memory": list(memory)}
    if stored is None:
        stored = {it["uid"]: it.get("tlp", "red") for group in items.values() for it in group}
    inp = {
        "sections": {"findings": "f1: 3 failed logins", "memory": "no known scanners"},
        "items": {k: v for k, v in items.items() if v},
    }
    return assemble_pack(labelled_manifest(static), inp, resolved_uids=stored, **kw)


def write(store, profile, updates, **kw):
    """A memory write as the history tests (ADR-0037 PR 1) make it, now that a write is checked
    against its pack or is an unchecked platform write (PR 2): a batch naming only the profile's
    platform scopes is written ``unchecked``; any other is checked against
    :func:`canonical_pack`.  A caller that passes ``pack`` or ``unchecked`` itself is passed
    through unchanged."""
    if "pack" in kw or "unchecked" in kw:
        return store.apply_updates(profile, updates, **kw)
    platform = set(profile.get("platform_scopes") or ())
    scopes = (
        {u.get("scope") for u in updates if isinstance(u, dict)}
        if isinstance(updates, list)
        else set()
    )
    if scopes and scopes <= platform:
        return store.apply_updates(profile, updates, unchecked=True, **kw)
    pack, digest = canonical_pack()
    return store.apply_updates(profile, updates, pack=pack, pack_hash=digest, **kw)
