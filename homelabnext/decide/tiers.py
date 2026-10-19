# SPDX-License-Identifier: Apache-2.0
"""Tier building blocks.

A tier looks at an :class:`Item` and returns a :class:`TierAnswer` (a label with a confidence),
abstains (label ``None``), or raises.  The cascade, not the tier, decides what an answer is worth.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

from homelabnext.registry.models import ChatResult

from .spec import IMPACTS


class TierTimeout(Exception):
    """The tier did not answer in time."""


class TierError(Exception):
    """The tier failed (backend error, unparseable reply, ...)."""


@dataclass(frozen=True)
class Item:
    id: str
    text: str
    impact: str = "low"  # impact declared by the requester
    fields: dict = field(default_factory=dict)


@dataclass(frozen=True)
class TierAnswer:
    label: str | None  # None = abstain
    confidence: float = 0.0
    impact: str | None = None  # impact this tier proposes (can only raise the running impact)
    rationale: str = ""


class Tier(Protocol):
    name: str

    def decide(self, item: Item) -> TierAnswer: ...


class CallableTier:
    """Wrap a plain function as a tier (the deterministic script tier is usually one)."""

    def __init__(self, name: str, fn: Callable[[Item], TierAnswer], *, deterministic: bool = False):
        self.name = name
        self.fn = fn
        self.deterministic = deterministic

    def decide(self, item: Item) -> TierAnswer:
        return self.fn(item)


def regex_floor(rules: list[tuple[str, str]], name: str = "floor") -> CallableTier:
    """Deterministic floor: first matching ``(pattern, label)`` wins with confidence 1.0."""
    compiled = [(re.compile(p, re.IGNORECASE), label) for p, label in rules]

    def fn(item: Item) -> TierAnswer:
        for rx, label in compiled:
            if rx.search(item.text):
                return TierAnswer(label, 1.0, rationale=f"matched {rx.pattern!r}")
        return TierAnswer(None)

    return CallableTier(name, fn, deterministic=True)


ChatFn = Callable[[list[dict]], ChatResult]


class TierInvalidOutput(TierError):
    """The model's reply failed the output schema, on the first try and on the one retry."""


def output_schema(labels: tuple[str, ...]) -> dict:
    """The JSON Schema (2020-12) every :class:`ModelTier` reply must satisfy (checklist A-04)."""
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "label": {"enum": list(labels)},
            "confidence": {"type": "number", "minimum": 0, "maximum": 1},
            "impact": {"enum": list(IMPACTS)},
            "rationale": {"type": "string", "maxLength": 2000},
        },
        "required": ["label", "confidence"],
        "additionalProperties": False,
    }


def validate_output(doc: Any, labels: tuple[str, ...]) -> list[str]:
    """Problems with one decoded reply against :func:`output_schema` (empty = valid).

    Hand-written so the cascade needs no schema library at run time; ``tests/decide`` proves it
    agrees with ``jsonschema`` on the declared schema.
    """
    if not isinstance(doc, dict):
        return ["reply is not a JSON object"]
    p: list[str] = []
    for key in ("label", "confidence"):
        if key not in doc:
            p.append(f"{key}: required")
    extra = sorted(set(doc) - {"label", "confidence", "impact", "rationale"})
    if extra:
        p.append(f"unexpected keys {extra}")
    if "label" in doc and doc["label"] not in labels:
        p.append(f"label {doc['label']!r} not in {list(labels)}")
    if "confidence" in doc:
        c = doc["confidence"]
        if isinstance(c, bool) or not isinstance(c, (int, float)) or not 0 <= c <= 1:
            p.append(f"confidence {c!r} is not a number in 0..1")
    if "impact" in doc and doc["impact"] not in IMPACTS:
        p.append(f"impact {doc['impact']!r} not in {list(IMPACTS)}")
    if "rationale" in doc and (
        not isinstance(doc["rationale"], str) or len(doc["rationale"]) > 2000
    ):
        p.append("rationale must be a string of at most 2000 characters")
    return p


class ModelTier:
    """A tier that asks a model and expects ``{"label", "confidence", "impact"?}`` JSON back.

    Every reply is validated against :func:`output_schema` before it is used (A-04).  An invalid
    reply (not JSON, or not schema-valid) is retried **once**, with the problems fed back; a second
    invalid reply raises :class:`TierInvalidOutput`, which the cascade records as ``invalid`` and
    escalates.  Unvalidated output never reaches the cascade.

    The reported confidence is the model's stated confidence, lowered to the mean token
    probability when the backend returns logprobs (a model cannot be more sure than its tokens).
    """

    #: invalid replies tolerated before escalating: one retry, never more
    RETRIES = 1

    def __init__(
        self, name: str, chat: ChatFn, question_set: tuple[str, ...], labels: tuple[str, ...]
    ):
        self.name = name
        self.chat = chat
        self.question_set = question_set
        self.labels = labels
        self.schema = output_schema(labels)

    def messages(self, item: Item) -> list[dict]:
        qs = "\n".join(f"- {q}" for q in self.question_set)
        system = (
            "You are a classifier. Answer the questions about the text, then reply with one JSON "
            f'object: {{"label": one of {list(self.labels)}, "confidence": 0..1, '
            '"impact": optional one of low|medium|high|critical}.\n' + qs
        )
        return [{"role": "system", "content": system}, {"role": "user", "content": item.text}]

    @staticmethod
    def _parse(text: str) -> tuple[Any, list[str]]:
        try:
            return json.loads(text), []
        except ValueError:
            return None, [f"reply is not JSON: {text[:80]!r}"]

    def decide(self, item: Item) -> TierAnswer:
        msgs = self.messages(item)
        problems: list[str] = []
        for attempt in range(self.RETRIES + 1):
            if attempt:
                msgs = [
                    *msgs,
                    {
                        "role": "user",
                        "content": "Your previous reply was invalid ("
                        + "; ".join(problems)
                        + "). Reply with exactly one JSON object matching the schema.",
                    },
                ]
            res = self.chat(msgs)
            doc, problems = self._parse(res.text)
            if not problems:
                problems = validate_output(doc, self.labels)
            if problems:
                continue
            conf = float(doc["confidence"])
            mp = res.mean_prob
            if mp is not None:
                conf = min(conf, mp)
            note = "; valid after one retry" if attempt else ""
            return TierAnswer(
                doc["label"], conf, doc.get("impact"), str(doc.get("rationale", "")) + note
            )
        raise TierInvalidOutput(
            f"invalid output after {self.RETRIES + 1} attempts: " + "; ".join(problems)
        )
