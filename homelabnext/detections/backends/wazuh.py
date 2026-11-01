# SPDX-License-Identifier: Apache-2.0
"""Wazuh-style XML stub backend. Emits well-formed rule XML; deploys nothing.

Expressible subset: a conjunction of selections, each with ONE alternative,
optionally negated (single-field selections only). Anything else raises
``UnsupportedConstruct`` - author a native rule with a stated reason.
The logical id is preserved as an XML comment; the engine number comes only
from ``Target.det_map`` (the generated map), never from the rule file.

Case-insensitivity is a scoped group, ``(?i:...)``, never a bare ``(?i)``: an alternation of
bare-flag patterns is refused by Python's ``re`` and only works in PCRE2 by its looser rule.
:meth:`WazuhStubBackend.evaluate` runs a compiled rule against an event, as the engine reads
it (every ``field`` must be present and match, a ``negate`` field must be present and not
match), so the fixture runner proves the compiled form fires where the rule does.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from xml.sax.saxutils import escape, quoteattr

from .. import attack
from ..adapters import Artifact, MissingEngineId, Target, UnsupportedConstruct, register
from ..sigma import Matcher, Rule, _lookup

_LEVEL = {"informational": 3, "low": 5, "medium": 8, "high": 12, "critical": 15}


def _rx(m: Matcher, value) -> str:
    v = re.escape(str(value))
    if m.op == "equals":
        return f"(?i:^{v.replace(chr(92) + '*', '.*').replace(chr(92) + '?', '.')}$)"
    if m.op == "contains":
        return f"(?i:{v})"
    if m.op == "startswith":
        return f"(?i:^{v})"
    if m.op == "endswith":
        return f"(?i:{v}$)"
    return str(value)  # re


def _field_elems(m: Matcher, tgt: Target, negate: bool) -> list[str]:
    if m.field is None or m.op == "null":
        raise UnsupportedConstruct("keyword / null matchers need a native rule")
    name = tgt.field_mapping.get(m.field, m.field)
    neg = ' negate="yes"' if negate else ""
    pats = [_rx(m, v) for v in m.values]
    if m.match_all and len(pats) > 1:
        if negate:
            raise UnsupportedConstruct("negated 'all' needs a native rule")
        return [f'<field name={quoteattr(name)} type="pcre2">{escape(p)}</field>' for p in pats]
    pat = pats[0] if len(pats) == 1 else "|".join(f"(?:{p})" for p in pats)
    return [f'<field name={quoteattr(name)} type="pcre2"{neg}>{escape(pat)}</field>']


def _terms(ast: tuple) -> list[tuple[str, bool]]:
    k = ast[0]
    if k == "sel":
        return [(ast[1], False)]
    if k == "not" and ast[1][0] == "sel":
        return [(ast[1][1], True)]
    if k == "and":
        return [t for a in ast[1] for t in _terms(a)]
    raise UnsupportedConstruct("condition is not a conjunction of (negated) selections")


class WazuhStubBackend:
    """Wazuh-style stub. ``known_ids_snapshot`` is the default snapshot path RELATIVE to the
    detections root; callers can also set an absolute path or ``None``. ``known_technique_ids``
    loads the snapshot lazily and caches the frozen set so repeated calls are free.
    """

    name = "wazuh"
    known_ids_snapshot: Path | str | None = Path("attack_snapshots/wazuh.yml")

    def __init__(self, known_ids_snapshot: Path | str | None = None):
        if known_ids_snapshot is not None:
            self.known_ids_snapshot = known_ids_snapshot
        # Cache is keyed on the resolved snapshot path so a module-registered singleton can be
        # driven against several roots in a test suite without one call's cached result leaking
        # into another's.
        self._cache: dict[Path, frozenset[str]] = {}

    def known_technique_ids(self, root: Path | str | None = None) -> frozenset[str]:
        """Return the engine's known ATT&CK ids. ``root`` is the detections root the backend's
        relative snapshot path resolves against; absolute snapshot paths ignore it.

        An empty set is returned when the snapshot file does not exist - the caller then
        reads that as "the engine has not advertised a known set", which is distinguishable
        from "the engine advertised an empty set" at the type level by the snapshot's own
        schema (which refuses an empty id list).
        """
        if self.known_ids_snapshot is None:
            return frozenset()
        path = Path(self.known_ids_snapshot)
        if not path.is_absolute() and root is not None:
            path = Path(root) / path
        resolved = path.resolve() if path.exists() else path
        cached = self._cache.get(resolved)
        if cached is not None:
            return cached
        if not path.exists():
            return frozenset()
        snap = attack.load_snapshot(path)
        self._cache[resolved] = snap.technique_ids
        return snap.technique_ids

    def compile(self, rule: Rule, target: Target) -> Artifact:
        if rule.det_id not in target.det_map:
            raise MissingEngineId(rule.det_id)
        num = target.det_map[rule.det_id]
        fields: list[str] = []
        for sel, neg in _terms(rule.condition):
            alts = rule.selections[sel]
            if len(alts) != 1:
                raise UnsupportedConstruct(f"selection {sel!r} is an OR of maps")
            if neg and len(alts[0]) != 1:
                raise UnsupportedConstruct(f"negated selection {sel!r} has several fields")
            for m in alts[0]:
                fields += _field_elems(m, target, neg)
        group = target.options.get("if_group", "hnx_generic")
        lines = [
            f"<!-- {rule.det_id} -->",
            f'<rule id="{num}" level="{_LEVEL[rule.level]}">',
            f"  <if_group>{escape(group)}</if_group>",
        ]
        lines += [f"  {f}" for f in fields]
        lines.append(f"  <description>{escape(rule.title)}</description>")
        techs = rule.attack_techniques
        if techs:
            lines.append("  <mitre>" + "".join(f"<id>{t}</id>" for t in techs) + "</mitre>")
        lines.append("</rule>")
        return Artifact(rule.det_id, self.name, "application/xml", "\n".join(lines) + "\n")

    @staticmethod
    def evaluate(artifact: Artifact, event: dict) -> bool:
        """Whether the compiled rule matches ``event`` (field names as the artefact names them).

        Each ``field`` holds only when the event has the field and the pattern matches one of
        its values; a ``negate="yes"`` field holds only when the field is present and the
        pattern matches none of them, since the engine skips a rule whose field is missing.
        Patterns run under Python's ``re``, which agrees with PCRE2 on what this backend emits
        (escaped literals, ``.*``, anchors, scoped ``(?i:...)``); a rule's own ``|re`` value is
        the one place they could differ.
        """
        rule = ET.fromstring(artifact.content)
        for f in rule.findall("field"):
            values = [v for v in _lookup(event, f.get("name", "")) if v is not None]
            if not values:
                return False
            hit = any(re.search(f.text or "", str(v), re.DOTALL) for v in values)
            if hit == (f.get("negate") == "yes"):
                return False
        return True

    @staticmethod
    def bundle(artifacts: list[Artifact]) -> str:
        body = "\n".join(a.content.rstrip("\n") for a in artifacts)
        indented = "\n".join("  " + ln if ln else ln for ln in body.splitlines())
        return f'<group name="homelabnext,">\n{indented}\n</group>\n'


register(WazuhStubBackend())
