# SPDX-License-Identifier: Apache-2.0
"""Deterministic impact scan: an Aho-Corasick keyword matcher over a tiered keyword list.

The keyword file (YAML) maps impact tiers to keywords::

    version: 1
    tiers:
      critical: [wipe all data, disable audit logging]
      high: [production database]
      medium: [firewall rule]

The matcher is case-insensitive and, by default, only reports matches that sit on word
boundaries.  One pass over the text finds every keyword (a trie with failure links), so cost is
linear in the text length no matter how long the list is.  Pure Python, no dependencies.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .spec import IMPACTS, impact_rank


@dataclass(frozen=True)
class Hit:
    keyword: str
    tier: str
    start: int
    end: int


@dataclass(frozen=True)
class ScanResult:
    tier: str | None  # highest tier hit, None when nothing matched
    hits: tuple[Hit, ...]

    @property
    def keywords(self) -> tuple[str, ...]:
        return tuple(sorted({h.keyword for h in self.hits}))


class AhoCorasick:
    def __init__(self, patterns: dict[str, str]):
        """``patterns``: keyword -> tier name.  Keywords are matched lower-cased."""
        self._next: list[dict[str, int]] = [{}]
        self._fail: list[int] = [0]
        self._out: list[list[str]] = [[]]
        self.tier_of: dict[str, str] = {}
        for kw, tier in patterns.items():
            key = kw.lower()
            if not key.strip():
                raise ValueError("empty keyword")
            if key in self.tier_of and impact_rank(self.tier_of[key]) >= impact_rank(tier):
                continue  # a keyword listed in two tiers counts at the higher one
            self.tier_of[key] = tier
            self._add(key)
        self._build()

    def _add(self, key: str) -> None:
        node = 0
        for ch in key:
            nxt = self._next[node].get(ch)
            if nxt is None:
                self._next.append({})
                self._fail.append(0)
                self._out.append([])
                nxt = len(self._next) - 1
                self._next[node][ch] = nxt
            node = nxt
        if key not in self._out[node]:
            self._out[node].append(key)

    def _build(self) -> None:
        q: deque[int] = deque(self._next[0].values())
        while q:
            node = q.popleft()
            for ch, child in self._next[node].items():
                f = self._fail[node]
                while f and ch not in self._next[f]:
                    f = self._fail[f]
                link = self._next[f].get(ch, 0)
                self._fail[child] = 0 if link == child else link
                self._out[child] = self._out[child] + self._out[self._fail[child]]
                q.append(child)

    def find_all(self, text: str) -> list[tuple[int, int, str]]:
        """Every (start, end, keyword) occurrence in lower-cased ``text``; end is exclusive."""
        found: list[tuple[int, int, str]] = []
        node = 0
        low = text.lower()
        for i, ch in enumerate(low):
            while node and ch not in self._next[node]:
                node = self._fail[node]
            node = self._next[node].get(ch, 0)
            for kw in self._out[node]:
                found.append((i + 1 - len(kw), i + 1, kw))
        return sorted(found)


def _is_word(ch: str) -> bool:
    return ch.isalnum() or ch == "_"


class ImpactScanner:
    def __init__(self, tiers: dict[str, list[str]], *, whole_words: bool = True):
        patterns: dict[str, str] = {}
        for tier, words in tiers.items():
            if tier not in IMPACTS:
                raise ValueError(f"unknown impact tier {tier!r}; expected one of {IMPACTS}")
            for w in words:
                key = str(w).lower()
                if key not in patterns or impact_rank(tier) > impact_rank(patterns[key]):
                    patterns[key] = tier
        self.whole_words = whole_words
        self._ac = AhoCorasick(patterns)

    @classmethod
    def from_dict(cls, doc: Any, **kw: Any) -> ImpactScanner:
        if not isinstance(doc, dict) or not isinstance(doc.get("tiers"), dict):
            raise ValueError("keyword file needs a 'tiers' mapping")
        return cls({k: list(v) for k, v in doc["tiers"].items()}, **kw)

    @classmethod
    def load(cls, path: str | Path, **kw: Any) -> ImpactScanner:
        import yaml

        return cls.from_dict(yaml.safe_load(Path(path).read_text(encoding="utf-8")), **kw)

    def scan(self, text: str) -> ScanResult:
        hits: list[Hit] = []
        for start, end, kw in self._ac.find_all(text):
            if self.whole_words:
                if start > 0 and _is_word(text[start - 1]) and _is_word(kw[0]):
                    continue
                if end < len(text) and _is_word(text[end]) and _is_word(kw[-1]):
                    continue
            hits.append(Hit(kw, self._ac.tier_of[kw], start, end))
        top = max((h.tier for h in hits), key=impact_rank, default=None)
        return ScanResult(top, tuple(hits))
