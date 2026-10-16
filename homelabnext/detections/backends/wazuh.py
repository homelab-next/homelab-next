# SPDX-License-Identifier: Apache-2.0
"""Wazuh-style XML stub backend. Emits well-formed rule XML; deploys nothing.

Expressible subset: a conjunction of selections, each with ONE alternative,
optionally negated (single-field selections only). Anything else raises
``UnsupportedConstruct`` - author a native rule with a stated reason.
The logical id is preserved as an XML comment; the engine number comes only
from ``Target.det_map`` (the generated map), never from the rule file.
"""

from __future__ import annotations

import re
from xml.sax.saxutils import escape, quoteattr

from ..adapters import Artifact, MissingEngineId, Target, UnsupportedConstruct, register
from ..sigma import Matcher, Rule

_LEVEL = {"informational": 3, "low": 5, "medium": 8, "high": 12, "critical": 15}


def _rx(m: Matcher, value) -> str:
    v = re.escape(str(value))
    if m.op == "equals":
        return f"(?i)^{v.replace(chr(92) + '*', '.*').replace(chr(92) + '?', '.')}$"
    if m.op == "contains":
        return f"(?i){v}"
    if m.op == "startswith":
        return f"(?i)^{v}"
    if m.op == "endswith":
        return f"(?i){v}$"
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
    name = "wazuh"

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
    def bundle(artifacts: list[Artifact]) -> str:
        body = "\n".join(a.content.rstrip("\n") for a in artifacts)
        indented = "\n".join("  " + ln if ln else ln for ln in body.splitlines())
        return f'<group name="homelabnext,">\n{indented}\n</group>\n'


register(WazuhStubBackend())
