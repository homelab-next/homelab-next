# SPDX-License-Identifier: Apache-2.0
"""The swap record: schema, hash-chained transition log, semantic checks, atomic persistence.

``schemas/platform/swap_record.schema.json`` fixes the shape. Rules that JSON Schema cannot say
live in :func:`record_problems`:

* the nine steps appear in procedure order and the passed steps are a prefix;
* ``current_step`` is the first step that has not passed (while the swap is active);
* ``transitions`` are numbered 1..n and hash-chained, so editing or removing a past entry is
  detectable (:func:`record_problems` recomputes every hash);
* ``route.flipped`` is true exactly when the ``cutover`` step has passed and the swap has not
  been rolled back;
* a swap cannot be rolled back after ``decommission-check`` passed, and cannot close before it.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
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
def chain_hash(prev: str, t: Mapping[str, Any]) -> str:
    body = {k: t[k] for k in ("seq", "at", "event", "step", "actor", "note")}
    return sha256_text(prev + canonical(body))


def append_transition(
    doc: dict[str, Any], *, at: str, event: str, step: str | None, actor: str, note: str = ""
) -> dict[str, Any]:
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
    }
    t["hash"] = chain_hash(prev, t)
    trans.append(t)
    doc["updated_at"] = at
    return t


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
) -> dict[str, Any]:
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
    append_transition(
        doc,
        at=now,
        event="declared",
        step=None,
        actor=actor,
        note=f"{from_adapter} -> {to_adapter}",
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
        for p in sorted((REPO_ROOT / "schemas").rglob("*.json")):
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
    return REPO_ROOT / "schemas" / "platform" / "swap_record.schema.json"


def schema_problems(doc: Any) -> list[str]:
    out = []
    for err in sorted(
        _validator().iter_errors(doc), key=lambda e: [str(p) for p in e.absolute_path]
    ):
        where = "/".join(str(p) for p in err.absolute_path) or "$"
        out.append(f"schema: {where}: {err.message[:200]}")
    return out


def record_problems(doc: Mapping[str, Any]) -> list[str]:
    """Semantic checks. Assumes the schema already passed."""
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
    # transition chain
    prev = GENESIS
    for i, t in enumerate(doc["transitions"], 1):
        if t["seq"] != i:
            out.append(f"transition {i}: seq is {t['seq']}")
        if t["prev"] != prev:
            out.append(f"transition {i}: prev hash does not link to transition {i - 1}")
        if t["hash"] != chain_hash(t["prev"], t):
            out.append(f"transition {i}: hash does not match its content (edited?)")
        prev = t["hash"]
    if doc["transitions"] and doc["transitions"][0]["event"] != "declared":
        out.append("first transition must be 'declared'")
    if doc["updated_at"] != doc["transitions"][-1]["at"]:
        out.append("updated_at is not the time of the last transition")
    return out


def problems(doc: Any) -> list[str]:
    p = schema_problems(doc)
    return p or record_problems(doc)


def validate(doc: Any) -> None:
    p = problems(doc)
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
def load(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except OSError as exc:
        raise RecordError(f"cannot read swap record {p}: {exc}") from exc
    except ValueError as exc:
        raise RecordError(f"swap record {p} is not valid JSON: {exc}") from exc
    validate(doc)
    return doc


def dumps(doc: Mapping[str, Any]) -> str:
    return json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def save(path: str | Path, doc: Mapping[str, Any]) -> None:
    """Validate, then write atomically (temp file + rename): a crash leaves the old record."""
    validate(doc)
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
