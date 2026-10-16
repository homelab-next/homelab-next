# SPDX-License-Identifier: Apache-2.0
import hashlib

import pytest

from homelabnext.decide import AhoCorasick, ImpactScanner
from homelabnext.decide.evalset import EXAMPLES

WORDS = ["he", "she", "his", "hers", "ab", "abc", "bc", "c", "aaa", "aa"]


def brute(text, words):
    low = text.lower()
    out = []
    for w in words:
        i = low.find(w)
        while i != -1:
            out.append((i, i + len(w), w))
            i = low.find(w, i + 1)
    return sorted(out)


def test_matches_naive_search_on_generated_texts():
    ac = AhoCorasick(dict.fromkeys(WORDS, "low"))
    alphabet = "abchse "
    for i in range(300):
        h = hashlib.sha256(str(i).encode()).digest()
        text = "".join(alphabet[b % len(alphabet)] for b in h)
        assert ac.find_all(text) == brute(text, WORDS), text


def test_classic_overlaps_and_suffix_outputs():
    ac = AhoCorasick({"he": "low", "she": "low", "hers": "low", "his": "low"})
    assert [m[2] for m in ac.find_all("ushers")] == ["she", "he", "hers"]


def test_scanner_tiers_whole_words_and_case():
    sc = ImpactScanner.load(EXAMPLES / "impact_keywords.yml")
    res = sc.scan("Please WIPE ALL DATA, then add a firewall rule.")
    assert res.tier == "critical" and res.keywords == ("firewall rule", "wipe all data")
    assert sc.scan("touches the production database").tier == "high"
    assert sc.scan("a harmless note").tier is None
    assert ImpactScanner({"high": ["rule"]}).scan("a rulebook").tier is None  # inside a word
    assert ImpactScanner({"high": ["rule"]}, whole_words=False).scan("a rulebook").tier == "high"


def test_keyword_in_two_tiers_counts_at_the_higher():
    sc = ImpactScanner({"low": ["restart"], "high": ["restart"]})
    assert sc.scan("restart now").tier == "high"
    sc = ImpactScanner({"high": ["restart"], "low": ["restart"]})
    assert sc.scan("restart now").tier == "high"


def test_bad_keyword_lists_are_refused():
    with pytest.raises(ValueError, match="unknown impact tier"):
        ImpactScanner({"catastrophic": ["x"]})
    with pytest.raises(ValueError, match="empty keyword"):
        ImpactScanner({"low": [" "]})
    with pytest.raises(ValueError, match="tiers"):
        ImpactScanner.from_dict({"version": 1})
