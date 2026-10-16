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


class ModelTier:
    """A tier that asks a model and expects ``{"label", "confidence", "impact"?}`` JSON back.

    The reported confidence is the model's stated confidence, lowered to the mean token
    probability when the backend returns logprobs (a model cannot be more sure than its tokens).
    """

    def __init__(
        self, name: str, chat: ChatFn, question_set: tuple[str, ...], labels: tuple[str, ...]
    ):
        self.name = name
        self.chat = chat
        self.question_set = question_set
        self.labels = labels

    def messages(self, item: Item) -> list[dict]:
        qs = "\n".join(f"- {q}" for q in self.question_set)
        system = (
            "You are a classifier. Answer the questions about the text, then reply with one JSON "
            f'object: {{"label": one of {list(self.labels)}, "confidence": 0..1, '
            '"impact": optional one of low|medium|high|critical}.\n' + qs
        )
        return [{"role": "system", "content": system}, {"role": "user", "content": item.text}]

    def decide(self, item: Item) -> TierAnswer:
        res = self.chat(self.messages(item))
        try:
            doc: Any = json.loads(res.text)
            label = doc["label"]
            conf = float(doc["confidence"])
        except (ValueError, KeyError, TypeError) as exc:
            raise TierError(f"unparseable model reply: {res.text[:80]!r}") from exc
        mp = res.mean_prob
        if mp is not None:
            conf = min(conf, mp)
        return TierAnswer(label, conf, doc.get("impact"), str(doc.get("rationale", "")))
