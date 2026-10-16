# SPDX-License-Identifier: Apache-2.0
"""Lint rules: product locators must not leak into logical ids or specs.

Rules (codes):

``PRODUCT_URI``   a ``scheme://`` locator such as ``viking://``
``IP_LITERAL``    an IPv4/IPv6 literal (documentation ranges allowed only by
                  :func:`scan_text` with ``allow_documentation=True``; never in an id)
``RULE_NUMBER``   a vendor rule/signature number (digit run >= 4 or ``rule``/``sid`` + digit)
``GRAMMAR``       not a valid logical id at all
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from .grammar import BODY_PATTERNS, FORBIDDEN_RE, IdError, parse

_URI_RE = re.compile(r"\b[A-Za-z][A-Za-z0-9+.-]*://")
_V4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.]*\w)")
_V6_RE = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])")
_RULE_CTX_RE = re.compile(
    r"\b(?:rule[ _-]?(?:id|number|no\.?)?|sid|signature[ _-]?id)\b[\s:=#\"'-]*\d{4,}",
    re.IGNORECASE,
)
_ID_START_RE = re.compile(r"^(?:" + "|".join(BODY_PATTERNS) + r"):")

_DOC_NETS = [
    ipaddress.ip_network(n)
    for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
]


@dataclass(frozen=True)
class Violation:
    code: str
    message: str
    where: str = ""

    def __str__(self) -> str:
        loc = f"{self.where}: " if self.where else ""
        return f"{loc}{self.code}: {self.message}"


def _is_doc_ip(token: str) -> bool:
    try:
        ip = ipaddress.ip_address(token)
    except ValueError:
        return False
    return any(ip in net for net in _DOC_NETS)


def _ip_tokens(text: str) -> Iterator[str]:
    for rx in (_V4_RE, _V6_RE):
        for m in rx.finditer(text):
            tok = m.group(0)
            try:
                ipaddress.ip_address(tok)
            except ValueError:
                continue
            yield tok


def lint_id(text: str, where: str = "") -> list[Violation]:
    """All violations for one candidate logical id (empty list = clean)."""
    out: list[Violation] = []
    if not isinstance(text, str):
        return [Violation("GRAMMAR", "logical id must be a string", where)]
    if _URI_RE.search(text):
        out.append(Violation("PRODUCT_URI", f"product locator in id: {text!r}", where))
    if any(True for _ in _ip_tokens(text)) or any(True for _ in _ip_tokens(text.partition(":")[2])):
        out.append(Violation("IP_LITERAL", f"IP literal in id: {text!r}", where))
    if FORBIDDEN_RE.search(text):
        out.append(Violation("RULE_NUMBER", f"rule-number-like digits in id: {text!r}", where))
    try:
        parse(text)
    except IdError as exc:
        if exc.code == "GRAMMAR":
            out.append(Violation("GRAMMAR", str(exc), where))
    return out


def scan_text(text: str, where: str = "", allow_documentation: bool = True) -> list[Violation]:
    """Scan free text (charters, specs, schedules) for product locators."""
    out: list[Violation] = []
    for m in _URI_RE.finditer(text):
        if m.group(0).lower().startswith("viking://"):
            out.append(Violation("PRODUCT_URI", "viking:// URI", where))
    for tok in _ip_tokens(text):
        if allow_documentation and _is_doc_ip(tok):
            continue
        out.append(Violation("IP_LITERAL", f"IP literal {tok}", where))
    for m in _RULE_CTX_RE.finditer(text):
        out.append(Violation("RULE_NUMBER", f"vendor rule number: {m.group(0).strip()!r}", where))
    return out


def scan_document(obj: Any, where: str = "$", allow_documentation: bool = True) -> list[Violation]:
    """Walk a parsed JSON/YAML document.

    Strings that start like a logical id are linted as ids (strict, no IPs at
    all); every other string is scanned as free text.
    """
    out: list[Violation] = []
    if isinstance(obj, str):
        if _ID_START_RE.match(obj) and " " not in obj:
            out.extend(lint_id(obj, where))
        else:
            out.extend(scan_text(obj, where, allow_documentation))
    elif isinstance(obj, dict):
        for k, v in obj.items():
            out.extend(scan_document(v, f"{where}.{k}", allow_documentation))
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            out.extend(scan_document(v, f"{where}[{i}]", allow_documentation))
    return out
