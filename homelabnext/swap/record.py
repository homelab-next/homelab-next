# SPDX-License-Identifier: Apache-2.0
"""The swap record: schema, hash-chained transition log, semantic checks, atomic persistence.

``schemas/platform/swap_record.schema.json`` fixes the shape. Rules that JSON Schema cannot say
live in :func:`record_problems`:

* the nine steps appear in procedure order and the passed steps are a prefix;
* ``current_step`` is the first step that has not passed (while the swap is active);
* ``transitions`` are numbered 1..n and hash-chained: each hash covers the previous hash and the
  transition, including ``state``, the digest of the steps, route, status, rollback and closure
  as they were when the transition was written;
* the steps agree with the log: exactly one ``step-passed`` transition per passed step, in
  procedure order, at the step's ``finished_at``, naming the step's evidence; a failed step has
  a ``gate-failed`` transition; ``closed`` and ``rolled_back`` have their transitions; and the
  last transition's ``state`` is the digest of the record as it stands;
* ``route.flipped`` is true exactly when the ``cutover`` step has passed and the swap has not
  been rolled back;
* a swap cannot be rolled back after ``decommission-check`` passed, and cannot close before it.

What this guarantees, and what it does not:

* An **unkeyed** chain (plain sha256) detects accidental damage and an edit by someone who does
  not recompute the hashes.  Anyone who can write the file can recompute every hash, so it is
  not tamper-proof on its own.
* A **keyed** chain (``chain.alg: hmac-sha256``; key from ``key=`` or ``HNX_SWAP_CHAIN_KEY``)
  cannot be recomputed without the key.  When a key is configured, an unkeyed record is refused,
  so the chain cannot be downgraded.
* Neither detects a record replaced by a consistent *older* copy of itself (the tail truncated
  and the steps rewound with it).  For that, store :func:`head` somewhere the record's writer
  cannot rewrite (a ticket, a commit, the event bus) and check it with :func:`verify_anchor`.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from homelabnext.paths import schema_file, schemas_dir

RECORD_VERSION = "1.0"
STEPS = (
    "declare",
    "shadow-start",
    "dual-write",
    "parity-compare",
    "soak",
    "cutover",
    "rollback-window",
    "decommission-check",
    "close",
)
GENESIS = "sha256:" + "0" * 64
KEY_ENV = "HNX_SWAP_CHAIN_KEY"
_STATE_FIELDS = ("status", "current_step", "route", "steps", "rollback", "closure")


class RecordError(Exception):
    """The record is unreadable, invalid or inconsistent."""

    def __init__(self, message: str, problems: Sequence[str] = ()):
        self.problems = list(problems)
        super().__init__(message + "".join(f"\n  - {p}" for p in self.problems))


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_text(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def stamp(dt: Any) -> str:
    """RFC 3339 UTC text for an aware datetime (the only form the schema accepts)."""
    from datetime import UTC

    if dt.tzinfo is None:
        raise ValueError("naive datetime: pass an aware (UTC) clock")
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_stamp(text: str) -> Any:
    from datetime import datetime

    return datetime.fromisoformat(text.replace("Z", "+00:00"))


# ---------------------------------------------------------------- transitions
def chain_key(key: bytes | str | None = None) -> bytes | None:
    """The HMAC key: ``key`` if given, else ``$HNX_SWAP_CHAIN_KEY``, else None (unkeyed)."""
    if key is None:
        key = os.environ.get(KEY_ENV) or None
    if isinstance(key, str):
        key = key.encode("utf-8")
    return key or None


def state_digest(doc: Mapping[str, Any]) -> str:
    """Digest of the parts of the record a transition vouches for."""
    return sha256_text(canonical({k: doc.get(k) for k in _STATE_FIELDS}))


def chain_hash(prev: str, t: Mapping[str, Any], key: bytes | None = None) -> str:
    fields = ("seq", "at", "event", "step", "actor", "note", "state")
    body = {k: t[k] for k in fields if k in t}
    text = prev + canonical(body)
    if key is None:
        return sha256_text(text)
    return "sha256:" + hmac.new(key, text.encode("utf-8"), hashlib.sha256).hexdigest()


def _doc_key(doc: Mapping[str, Any], key: bytes | str | None) -> bytes | None:
    keyed = (doc.get("chain") or {}).get("alg") == "hmac-sha256"
    k = chain_key(key)
    if keyed and k is None:
        raise RecordError(f"swap record is HMAC-chained; set {KEY_ENV} or pass key=")
    return k if keyed else None


def append_transition(
    doc: dict[str, Any],
    *,
    at: str,
    event: str,
    step: str | None,
    actor: str,
    note: str = "",
    key: bytes | str | None = None,
) -> dict[str, Any]:
    """Append one transition; call it after the step/route/status change it records."""
    trans = doc["transitions"]
    prev = trans[-1]["hash"] if trans else GENESIS
    t: dict[str, Any] = {
        "seq": len(trans) + 1,
        "at": at,
        "event": event,
        "step": step,
        "actor": actor,
        "note": note[:500],
        "prev": prev,
        "state": state_digest(doc),
    }
    t["hash"] = chain_hash(prev, t, _doc_key(doc, key))
    trans.append(t)
    doc["updated_at"] = at
    return t


def head(doc: Mapping[str, Any]) -> dict[str, Any]:
    """``{seq, hash}`` of the last transition: the value to anchor outside the record."""
    t = doc["transitions"][-1]
    return {"seq": t["seq"], "hash": t["hash"]}


def verify_anchor(doc: Mapping[str, Any], anchor: Mapping[str, Any]) -> list[str]:
    """Problems if the anchored head (from :func:`head`) is not in this record's chain.

    The record may have grown since the anchor was taken; it may not have lost or rewritten the
    anchored transition or anything before it (those change its hash).
    """
    seq, want = int(anchor["seq"]), anchor["hash"]
    trans = doc["transitions"]
    if seq > len(trans):
        return [f"anchor: record has {len(trans)} transitions, anchored head is seq {seq}"]
    if trans[seq - 1]["hash"] != want:
        return [f"anchor: transition {seq} hash differs from the anchored head (rewritten)"]
    return []


def new_record(
    *,
    swap_id: str,
    capability: str,
    from_adapter: str,
    to_adapter: str,
    service: str,
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    now: str,
    actor: str,
    plan: Mapping[str, Any] | None = None,
    registry: str | None = None,
    key: bytes | str | None = None,
) -> dict[str, Any]:
    """A new record.  With a chain key (``key=`` or ``$HNX_SWAP_CHAIN_KEY``) the chain is keyed."""
    p = {
        "soak_hours": 168,
        "rollback_window_hours": 168,
        "max_divergences": 0,
        "min_parity_rows": 1,
    }
    p.update(plan or {})
    route: dict[str, Any] = {"before": dict(before), "after": dict(after), "flipped": False}
    if registry:
        route["registry"] = registry
    doc: dict[str, Any] = {
        "record_version": RECORD_VERSION,
        "swap_id": swap_id,
        "capability": capability,
        "from_adapter": from_adapter,
        "to_adapter": to_adapter,
        "service": service,
        "status": "active",
        "current_step": STEPS[0],
        "created_at": now,
        "updated_at": now,
        "plan": p,
        "route": route,
        "steps": [
            {"name": s, "status": "pending", "attempts": 0, "evidence": [], "gates": []}
            for s in STEPS
        ],
        "transitions": [],
        "rollback": None,
        "closure": None,
    }
    if chain_key(key) is not None:
        doc["chain"] = {"alg": "hmac-sha256"}
    append_transition(
        doc,
        at=now,
        event="declared",
        step=None,
        actor=actor,
        note=f"{from_adapter} -> {to_adapter}",
        key=key,
    )
    return doc


# ---------------------------------------------------------------- validation
_VALIDATOR = None


def _validator():
    global _VALIDATOR
    if _VALIDATOR is None:
        from jsonschema import Draft202012Validator
        from referencing import Registry, Resource
        from referencing.jsonschema import DRAFT202012

        reg: Registry = Registry()
        for p in sorted(schemas_dir().rglob("*.json")):
            if "_frozen" in p.parts:
                continue
            d = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(d, dict) and "$id" in d:
                reg = reg.with_resource(
                    d["$id"], Resource.from_contents(d, default_specification=DRAFT202012)
                )
        schema = json.loads(schema_path().read_text(encoding="utf-8"))
        _VALIDATOR = Draft202012Validator(schema, registry=reg)
    return _VALIDATOR


def schema_path() -> Path:
    return schema_file("platform", "swap_record.schema.json")


def schema_problems(doc: Any) -> list[str]:
    out = []
    for err in sorted(
        _validator().iter_errors(doc), key=lambda e: [str(p) for p in e.absolute_path]
    ):
        where = "/".join(str(p) for p in err.absolute_path) or "$"
        out.append(f"schema: {where}: {err.message[:200]}")
    return out


def record_problems(doc: Mapping[str, Any], *, key: bytes | str | None = None) -> list[str]:
    """Semantic checks. Assumes the schema already passed.

    ``key`` (or ``$HNX_SWAP_CHAIN_KEY``) verifies a keyed chain; when a key is configured an
    unkeyed record is a problem, so a keyed chain cannot be downgraded by dropping ``chain``.
    """
    out: list[str] = []
    steps = doc["steps"]
    if [s["name"] for s in steps] != list(STEPS):
        out.append("steps are not the nine procedure steps in order")
        return out
    status = [s["status"] for s in steps]
    n_passed = sum(1 for s in status if s == "passed")
    if status[:n_passed] != ["passed"] * n_passed:
        out.append("passed steps are not a prefix of the procedure")
    st = doc["status"]
    first_open = next((s["name"] for s in steps if s["status"] != "passed"), None)
    if st == "active" and doc["current_step"] != first_open:
        out.append(
            f"current_step is {doc['current_step']!r}, first unfinished step is {first_open!r}"
        )
    if st == "closed" and n_passed != len(STEPS):
        out.append("a closed swap must have all nine steps passed")
    passed = {s["name"] for s in steps if s["status"] == "passed"}
    flipped = doc["route"]["flipped"]
    if st == "rolled_back":
        if flipped:
            out.append("a rolled-back swap must not be flipped")
        rb = doc["rollback"]
        if rb and "decommission-check" in passed:
            out.append("rollback is not allowed after decommission-check passed")
    elif flipped != ("cutover" in passed):
        cut = next(s for s in steps if s["name"] == "cutover")
        # a cutover whose revert failed is flipped-but-failed: legal, and only rollback can leave it
        if not (flipped and cut["status"] == "failed"):
            out.append(f"route.flipped is {flipped} but cutover passed is {'cutover' in passed}")
    if st == "closed" and "decommission-check" not in passed:
        out.append("closed without decommission-check")
    out += _chain_problems(doc, key)
    out += _log_problems(doc)
    return out


def _chain_problems(doc: Mapping[str, Any], key: bytes | str | None) -> list[str]:
    out: list[str] = []
    keyed = (doc.get("chain") or {}).get("alg") == "hmac-sha256"
    k = chain_key(key)
    if keyed and k is None:
        return [f"transitions: the chain is HMAC-keyed; set {KEY_ENV} (or pass key=) to verify it"]
    if k is not None and not keyed:
        out.append("transitions: a chain key is configured but this record's chain is unkeyed")
    prev = GENESIS
    seen_state = False
    for i, t in enumerate(doc["transitions"], 1):
        if t["seq"] != i:
            out.append(f"transition {i}: seq is {t['seq']}")
        if t["prev"] != prev:
            out.append(f"transition {i}: prev hash does not link to transition {i - 1}")
        if t["hash"] != chain_hash(t["prev"], t, k if keyed else None):
            out.append(f"transition {i}: hash does not match its content (edited?)")
        if seen_state and "state" not in t:
            out.append(f"transition {i}: state digest missing after earlier transitions had one")
        seen_state = seen_state or "state" in t
        prev = t["hash"]
    if doc["transitions"] and doc["transitions"][0]["event"] != "declared":
        out.append("first transition must be 'declared'")
    if doc["updated_at"] != doc["transitions"][-1]["at"]:
        out.append("updated_at is not the time of the last transition")
    last = doc["transitions"][-1]
    if "state" in last and last["state"] != state_digest(doc):
        out.append(
            "steps/route/status differ from the state the last transition recorded "
            "(edited after the fact, or transitions removed)"
        )
    return out


def _log_problems(doc: Mapping[str, Any]) -> list[str]:
    """The steps, route and status must be the ones the transition log says happened."""
    out: list[str] = []
    trans = doc["transitions"]
    steps = {s["name"]: s for s in doc["steps"]}
    passed = [s["name"] for s in doc["steps"] if s["status"] == "passed"]
    logged = [t for t in trans if t["event"] == "step-passed"]
    if [t["step"] for t in logged] != passed:
        out.append(
            f"step-passed transitions {[t['step'] for t in logged]} do not match the passed "
            f"steps {passed}"
        )
    else:
        for t in logged:
            s = steps[t["step"]]
            if s.get("finished_at") != t["at"]:
                out.append(
                    f"{s['name']}: finished_at is not the time of its step-passed transition"
                )
            if t["note"] not in [e["summary"][:500] for e in s["evidence"]]:
                out.append(f"{s['name']}: step-passed transition names no evidence of the step")
    failed_logged = {t["step"] for t in trans if t["event"] == "gate-failed"}
    for s in doc["steps"]:
        if s["status"] == "failed" and s["name"] not in failed_logged:
            out.append(f"{s['name']}: failed, but no gate-failed transition records it")
    events = [t["event"] for t in trans]
    st = doc["status"]
    for status, event in (("closed", "closed"), ("rolled_back", "rolled-back")):
        if (st == status) != (event in events):
            where = "present" if event in events else "absent"
            out.append(f"status is {st} but a {event!r} transition is {where}")
    if st != "active" and events and events[-1] not in ("closed", "rolled-back", "note"):
        out.append(f"status is {st} but the last transition is {events[-1]!r}")
    return out


def problems(doc: Any, *, key: bytes | str | None = None) -> list[str]:
    p = schema_problems(doc)
    return p or record_problems(doc, key=key)


def validate(doc: Any, *, key: bytes | str | None = None) -> None:
    p = problems(doc, key=key)
    if p:
        raise RecordError("invalid swap record", p)


def verify_evidence(doc: Mapping[str, Any], evidence_dir: str | Path) -> list[str]:
    """Recompute every evidence hash; returns the problems (empty = all artefacts intact)."""
    base = Path(evidence_dir)
    out = []
    for s in doc["steps"]:
        for e in s["evidence"]:
            p = base / e["ref"]
            if not p.is_file():
                out.append(f"{s['name']}: evidence {e['ref']} is missing")
            elif sha256_file(p) != e["sha256"]:
                out.append(f"{s['name']}: evidence {e['ref']} does not match its recorded hash")
    return out


# ---------------------------------------------------------------- persistence
def load(path: str | Path, *, key: bytes | str | None = None) -> dict[str, Any]:
    p = Path(path)
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except OSError as exc:
        raise RecordError(f"cannot read swap record {p}: {exc}") from exc
    except ValueError as exc:
        raise RecordError(f"swap record {p} is not valid JSON: {exc}") from exc
    validate(doc, key=key)
    return doc


def dumps(doc: Mapping[str, Any]) -> str:
    return json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def save(path: str | Path, doc: Mapping[str, Any], *, key: bytes | str | None = None) -> None:
    """Validate, then write atomically (temp file + rename): a crash leaves the old record."""
    validate(doc, key=key)
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=p.name + ".", suffix=".tmp", dir=p.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(dumps(doc))
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, p)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def clone(doc: Mapping[str, Any]) -> dict[str, Any]:
    return copy.deepcopy(dict(doc))
