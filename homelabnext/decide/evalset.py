# SPDX-License-Identifier: Apache-2.0
"""Synthetic gold set and simulated tiers: a deterministic evaluation harness.

Everything is generated from a hash of ``(seed, index)``, never from ``random``, so the set (and
therefore the coverage number in the tests) is identical on every machine and Python version.
The simulated classifiers know fixed phrase lists, which makes the cascade's behaviour exactly
predictable: the floor catches explicit markers, the small tier knows common paraphrases, the
large tier also knows the hard ones, and the ambiguous remainder reaches a human.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from pathlib import Path

from .cascade import Cascade
from .impact_scan import ImpactScanner
from .replay import Record
from .spec import DecisionSpec, load_spec
from .tiers import CallableTier, Item, TierAnswer, regex_floor

EXAMPLES = Path(__file__).resolve().parent / "examples"

VERBS = ["Upgrade", "Reconfigure", "Migrate", "Patch", "Reindex", "Resize"]
OBJECTS = ["the reporting service", "the queue workers", "the ingest pipeline", "the cache tier"]
ACCEPT_MEDIUM = [
    "the change can be reverted by redeploying the previous build",
    "previous version is restored from the snapshot taken first",
]
REJECT_MEDIUM = [
    "there is no way back once this is applied",
    "no recovery step was prepared",
]
ACCEPT_HARD = ["the undo path is described in the appendix"]
REJECT_HARD = ["recovery was deferred to a later ticket"]
AMBIGUOUS = ["the usual process applies", "see the team wiki for details", "as discussed earlier"]
IMPACT_PHRASES = [
    ("", "low"),
    ("This touches the production database.", "high"),
    ("A firewall rule is added.", "medium"),
    ("The job will wipe all data in the staging area.", "critical"),
]


def _u(seed: int, i: int, k: int) -> float:
    h = hashlib.sha256(f"{seed}:{i}:{k}".encode()).digest()
    return int.from_bytes(h[:8], "big") / 2**64


def _pick(seq: list[str], u: float) -> str:
    return seq[min(int(u * len(seq)), len(seq) - 1)]


def generate_gold_set(n: int = 200, seed: int = 7) -> list[Record]:
    out: list[Record] = []
    for i in range(n):
        accept = _u(seed, i, 1) < 0.55
        gold = "accept" if accept else "reject"
        bucket = _u(seed, i, 0)
        change = f"{_pick(VERBS, _u(seed, i, 2))} {_pick(OBJECTS, _u(seed, i, 3))}."
        if bucket < 0.40:
            tail = "ROLLBACK-PLAN: revert the commit." if accept else "NO-ROLLBACK."
        elif bucket < 0.75:
            tail = _pick(ACCEPT_MEDIUM if accept else REJECT_MEDIUM, _u(seed, i, 4)) + "."
        elif bucket < 0.90:
            tail = _pick(ACCEPT_HARD if accept else REJECT_HARD, _u(seed, i, 4)) + "."
        else:
            tail = _pick(AMBIGUOUS, _u(seed, i, 4)) + "."
        phrase, gold_impact = IMPACT_PHRASES[
            int(_u(seed, i, 5) * 4) % 4 if _u(seed, i, 6) < 0.3 else 0
        ]
        text = " ".join(x for x in (change, phrase, tail) if x)
        out.append(Record(f"syn-{i:04d}", Item(f"syn-{i:04d}", text), gold, gold_impact))
    return out


class PhraseTier:
    """Simulated classifier: confident on phrases it knows, a weak guess otherwise."""

    def __init__(self, name: str, known: dict[str, str], conf_hit: float = 0.95, conf_miss=0.6):
        self.name = name
        self.known = {k.lower(): v for k, v in known.items()}
        self.conf_hit = conf_hit
        self.conf_miss = conf_miss

    def decide(self, item: Item) -> TierAnswer:
        low = item.text.lower()
        for phrase, label in self.known.items():
            if phrase in low:
                return TierAnswer(label, self.conf_hit, rationale=f"knows {phrase!r}")
        h = hashlib.sha256(item.id.encode()).digest()[0]
        return TierAnswer("accept" if h % 2 else "reject", self.conf_miss, rationale="guess")


def _phrases(accept: list[str], reject: list[str]) -> dict[str, str]:
    return {**dict.fromkeys(accept, "accept"), **dict.fromkeys(reject, "reject")}


def demo_cascade(
    spec: DecisionSpec | None = None,
    *,
    clock: Callable[[], float] | None = None,
    small: object | None = None,
) -> Cascade:
    spec = spec or load_spec(EXAMPLES / "decision_spec.yml")
    floor = regex_floor([(r"no-rollback", "reject"), (r"rollback-plan", "accept")])
    tiers = {
        "floor": floor,
        "small": small or PhraseTier("small", _phrases(ACCEPT_MEDIUM, REJECT_MEDIUM)),
        "large": PhraseTier(
            "large",
            _phrases(ACCEPT_MEDIUM + ACCEPT_HARD, REJECT_MEDIUM + REJECT_HARD),
            conf_hit=0.93,
            conf_miss=0.55,
        ),
    }
    scanner = ImpactScanner.load(EXAMPLES / "impact_keywords.yml")
    kw = {"clock": clock} if clock else {}
    return Cascade(spec, tiers, scanner, **kw)  # type: ignore[arg-type]


__all__ = ["CallableTier", "PhraseTier", "demo_cascade", "generate_gold_set"]
