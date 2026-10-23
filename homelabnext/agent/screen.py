# SPDX-License-Identifier: Apache-2.0
"""Prompt screener: redact secrets and PII from untrusted text before it enters a context pack.

What is redacted, by type (the type is part of the replacement):

=============== ==========================================================================
``private-key`` a PEM/OpenSSH private key block, header to footer (or to the end of the text)
``jwt``         a JSON web token
``token``       vendor credentials recognisable by shape: AWS access key ids, GitHub, GitLab,
                Slack, Google, npm, Hugging Face, Stripe-style and ``sk-`` API keys, and the
                credential of an ``Authorization:`` header (Bearer, Basic, Digest, Token,
                ApiKey, ...)
``secret``      the *value* of a password/secret/token/api-key style key (``key=value``,
                ``key: value``, JSON and YAML, a quoted value with spaces in it, ``DB_PASS=``,
                ``--password value``, "the password is ..."), a ``Cookie:``/``Set-Cookie:``
                header's value, and the password in a ``scheme://user:password@host`` URL
``denylist``    any term from a caller-supplied deny-list (literal word or ``re:`` regex)
``card``        a payment card number: 13-19 digits, a known issuer prefix and a valid Luhn digit
``email``       every e-mail address, documentation domains included
``national-id`` US SSN shape (``ddd-dd-dddd`` outside the never-issued ranges), UK NINO shape,
                and any id after a keyword such as *SSN*, *passport number*, *tax id*
``ip``          every IPv4/IPv6 address (documentation ranges included); private, loopback,
                link-local and CGNAT ranges only while ``redact_private_ips`` is on (default)
``phone``       international ``+CC ...`` numbers, North American ``(ddd) ddd-dddd`` shapes,
                and digits after a keyword such as *phone*, *tel*, *mobile*
=============== ==========================================================================

The rule for reserved and documentation values (``example.org`` mail, the RFC 5737 TEST-NET ranges,
``2001:db8::/32``, 555-01xx numbers) is: **they are redacted**.  The screener cannot tell a test
fixture from a real value in somebody else's content, and redacting a placeholder costs nothing.
Values that are *not* redacted, because they are not identifying and models need them: version
numbers (a dotted quad after ``v``/``version``), dates and times, UUIDs, hashes and commit ids in
prose (a long hex value is redacted only as the value of a secret key), CVE and ATT&CK ids,
ports, sizes, and numbers failing the card or SSN rules.  MAC addresses and host names are not
in scope; a deployment that needs them redacted puts them on the deny-list.

Replacements are typed and stable within one :class:`Screener` (one pack): the same value gives
the same ``[REDACTED:<type>:<n>]`` everywhere, and different values of a type get different
numbers in order of first appearance, so the model can still reason about co-reference ("the
same address appears in both alerts") without seeing the value.  Values are compared normalised
(e-mail case-folded, phone and card by digits, addresses canonicalised).

Detection is regex plus validators; overlapping candidates are resolved by type priority (the
order of the table), then position, then length.  It runs twice: on the text as given, and on a
folded view in which format characters (Unicode category Cf: zero-width space, joiners, BOM, soft
hyphen) are removed and every other character is NFKC-normalised (full-width and other Unicode
digits become ASCII), so ``alice<ZWSP>@corp`` or a full-width address is found.  The redacted
spans are the union of both passes, mapped back to the original text, with overlapping spans
merged; folding can join a value to its neighbour and break a boundary, so the folded pass only
ever adds to what the plain pass finds.  Shapes shared with the publishing leak scanner come from
:mod:`homelabnext.shapes`; unlike that scanner, nothing here exempts placeholders.
"""

from __future__ import annotations

import bisect
import ipaddress
import re
import unicodedata
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from homelabnext import shapes

TYPES = (
    "private-key",
    "jwt",
    "token",
    "secret",
    "denylist",
    "card",
    "email",
    "national-id",
    "ip",
    "phone",
)
_PRIORITY = {t: i for i, t in enumerate(TYPES)}
LABEL_RE = re.compile(r"\[REDACTED:(?P<type>[a-z-]+):(?P<n>\d+)\]")

# Ranges that ``redact_private_ips=False`` leaves in place: RFC 1918, CGNAT, loopback, link-local,
# "this network", and IPv6 loopback, unspecified, unique-local and link-local.  The IPv4 ranges
# are written as (integer, prefix) so this file holds no address literal for the leak scanner.
_PRIVATE_NETS = (
    ipaddress.ip_network((10 << 24, 8)),
    ipaddress.ip_network((172 << 24 | 16 << 16, 12)),
    ipaddress.ip_network((192 << 24 | 168 << 16, 16)),
    ipaddress.ip_network((100 << 24 | 64 << 16, 10)),
    ipaddress.ip_network((127 << 24, 8)),
    ipaddress.ip_network((169 << 24 | 254 << 16, 16)),
    ipaddress.ip_network((0, 8)),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network((0xFC << 120, 7)),
    ipaddress.ip_network((0xFE80 << 112, 10)),
)


@dataclass(frozen=True)
class _Rule:
    type: str
    regex: re.Pattern[str]
    group: str | int = 0  # the part of the match that is redacted
    accept: Callable[[re.Match[str], str], bool] | None = None
    # search again from the last key-like run of the redacted value, not the end of the match:
    # a keyed value can end in the next key ("pw=secret: <value>", "password=<value>secret:
    # <value>"), which a match running on to the end would consume.  Only that last run can
    # start a key whose value lies past this one, so each character is rescanned at most once.
    rescan: bool = False


@dataclass(frozen=True)
class Redaction:
    """One redacted span of the input (offsets into the original text)."""

    type: str
    start: int
    end: int
    label: str


# ---------------------------------------------------------------- validators
def _luhn(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


_CARD_PREFIX_RE = re.compile(
    r"^(?:4|5[1-5]|2(?:2[2-9]|[3-6]\d|7[01]|720)|3[47]|3(?:0[0-5]|[68])|35|6(?:011|5|4[4-9]))"
)


def _is_card(m: re.Match[str], _text: str) -> bool:
    digits = re.sub(r"\D", "", m.group(0))
    seps = set(re.findall(r"[ -]", m.group(0)))
    return (
        13 <= len(digits) <= 19
        and len(seps) <= 1
        and bool(_CARD_PREFIX_RE.match(digits))
        and _luhn(digits)
    )


def _digits_between(lo: int, hi: int) -> Callable[[re.Match[str], str], bool]:
    def accept(m: re.Match[str], _text: str) -> bool:
        return lo <= len(re.sub(r"\D", "", m.group("v"))) <= hi

    return accept


def _min_digits(n: int) -> Callable[[re.Match[str], str], bool]:
    def accept(m: re.Match[str], _text: str) -> bool:
        return len(re.findall(r"\d", m.group("v"))) >= n

    return accept


# key names that contain a secret word but hold a count, a limit or a location
_NOT_SECRET_KEY_RE = re.compile(
    r"(?i)(?:tokens|tokenizer|_?count|_?ttl|_?len|_?length|_?limit|_?max|_?min|_?size|timeout"
    r"|_?type|_?url|_?uri|_?path|_?file|_?dir|_?name|_?endpoint|_?expiry|_?expires(?:_at)?"
    r"|_?policy|_?rotation|_?days)$"
)
_NOT_SECRET_VALUE_RE = re.compile(
    r"(?i)^(?:true|false|null|none|nil|yes|no|on|off|required|optional|redacted|\*+"
    r"|\[REDACTED:[a-z-]+:\d+\].*)$|^(?:\$|\{|<|%\()"
)


def _is_keyed_secret(m: re.Match[str], _text: str) -> bool:
    if _NOT_SECRET_KEY_RE.search(m.group("k")):
        return False
    return not _NOT_SECRET_VALUE_RE.search(m.group("v"))


def _is_prose_secret(m: re.Match[str], _text: str) -> bool:
    v = m.group("v")
    # "the password was changed": a plain lower-case word after prose is not a credential
    return not (_NOT_SECRET_VALUE_RE.search(v) or re.fullmatch(r"[a-z]+", v))


def _private(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if addr.version == 6 and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return any(addr.version == n.version and addr in n for n in _PRIVATE_NETS)


def _fold(text: str) -> tuple[str, list[int] | None]:
    """The text detection runs on, and for each of its characters the index in ``text`` it came
    from (None when it is ``text`` itself): Cf characters dropped, the rest NFKC-normalised."""
    if text.isascii():
        return text, None
    out: list[str] = []
    where: list[int] = []
    for i, c in enumerate(text):
        if c.isascii():
            out.append(c)
            where.append(i)
            continue
        if unicodedata.category(c) == "Cf":
            continue
        for n in unicodedata.normalize("NFKC", c):
            out.append(n)
            where.append(i)
    where.append(len(text))
    return "".join(out), where


# ---------------------------------------------------------------- rules
_KEY_WORDS = (
    r"passw(?:or)?d|passwd|pwd|passphrase|secret|token|api[_-]?key|apikey|access[_-]?key"
    r"|private[_-]?key|auth[_-]?key|credential|client[_-]?secret|session[_-]?key"
    # short words only as a whole part of the key (DB_PASS, db.pw, session-id; not bypass, pwm)
    r"|(?<![a-z0-9])(?:pass|pw|sessid|session[_-]?id|cookie)(?![a-z0-9])"
)


# The key of a key=value rule: the whole run of key characters, matched once from its start
# (one start per run, possessive, so nothing backtracks into it), with a lookahead that the run
# holds a key word.  ``[\w.-]*`` on both sides of the key word backtracked cubically over a run
# such as "token.token.token..." (a crafted 2 KB line took seconds); a bound on the key made it
# linear but let a key word more than the bound before the separator hide the value.  The
# lookahead scans each run once, so every rule stays linear in the length of the text, however
# long the key.  (The key word is tested in the pattern rather than after the match: a match
# refused afterwards would have consumed a later, real key in the same text.)
_KEY = rf"(?<![\w.-])(?=[\w.-]*?(?:{_KEY_WORDS}))[\w.-]++"
_FLAG_KEY = rf"(?=[\w-]*?(?:{_KEY_WORDS}))[\w-]++"


def _ascii_bounds(rx: str) -> str:
    """``rx`` with its word classes and boundaries made ASCII: ``\\w`` is ``[A-Za-z0-9_]``,
    ``\\d`` is ``[0-9]``, ``\\W``/``\\D`` their complements and ``\\b`` an ASCII boundary
    (``(?a:\\b)``).  Python's are Unicode, so a value glued to a CJK, Thai or Cyrillic letter
    (``用户alice@corp.com已登录``) had no boundary and was not found.  ``\\s`` stays Unicode
    (a value still ends at a no-break or ideographic space), which is why the whole pattern is
    not compiled with ``re.ASCII``."""
    out: list[str] = []
    i, in_class = 0, False
    while i < len(rx):
        c = rx[i]
        if c == "\\" and i + 1 < len(rx):
            nxt = rx[i + 1]
            if nxt == "w":
                out.append("A-Za-z0-9_" if in_class else "[A-Za-z0-9_]")
            elif nxt == "d":
                out.append("0-9" if in_class else "[0-9]")
            elif nxt == "W" and not in_class:
                out.append("[^A-Za-z0-9_]")
            elif nxt == "D" and not in_class:
                out.append("[^0-9]")
            elif nxt == "b" and not in_class:
                out.append("(?a:\\b)")
            else:
                out.append(rx[i : i + 2])
            i += 2
            continue
        if c == "[" and not in_class:
            in_class = True
            out.append(c)
            i += 1
            if rx[i : i + 1] == "^":
                out.append("^")
                i += 1
            if rx[i : i + 1] == "]":  # a leading "]" is a member
                out.append("]")
                i += 1
            continue
        if c == "]" and in_class:
            in_class = False
        out.append(c)
        i += 1
    return "".join(out)


def _r(
    type_: str, rx: str, group: str | int = 0, accept=None, flags: int = 0, rescan: bool = False
) -> _Rule:
    return _Rule(type_, re.compile(_ascii_bounds(rx), flags), group, accept, rescan)


def _matches(rule: _Rule, text: str) -> Iterable[re.Match[str]]:
    if not rule.rescan:
        yield from rule.regex.finditer(text)
        return
    pos = 0
    while (m := rule.regex.search(text, pos)) is not None:
        yield m
        end = m.end(rule.group)
        while end > m.start(rule.group) and text[end - 1] in ":=>\"'":
            end -= 1
        start = end
        while start > m.start(rule.group) and (
            text[start - 1] in "._-" or (text[start - 1].isascii() and text[start - 1].isalnum())
        ):
            start -= 1
        pos = max(start, m.start() + 1) if start < end else m.end()


_RULES: tuple[_Rule, ...] = (
    _r(
        "private-key",
        shapes.PRIVATE_KEY_HEADER + r".*?(?:-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----|\Z)",
        flags=re.S,
    ),
    _r("jwt", shapes.JWT),
    _r("token", shapes.AWS_ACCESS_KEY),
    _r("token", shapes.GITHUB_TOKEN),
    _r("token", shapes.SLACK_TOKEN),
    _r("token", shapes.GOOGLE_KEY),
    _r("token", r"\bglpat-[A-Za-z0-9_-]{20,}"),
    _r("token", r"\bnpm_[A-Za-z0-9]{36}\b"),
    _r("token", r"\bhf_[A-Za-z0-9]{30,}\b"),
    _r("token", r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}"),
    _r("token", r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}"),
    _r("token", r"(?i)\bbearer\s+(?P<v>[A-Za-z0-9._~+/=-]{16,})", "v"),
    # Authorization: <scheme> <credential> (header, JSON or YAML); Digest's parameters to the end
    _r(
        "token",
        r"(?i)\b(?:proxy-)?authorization[\"']?\s*[:=]\s*[\"']?"
        r"(?:basic|bearer|token|apikey|api-key|key|negotiate|ntlm|aws4-hmac-sha256)\s+"
        r"(?P<v>[A-Za-z0-9._~+/=:,-]{3,})",
        "v",
    ),
    _r(
        "token",
        r"(?i)\b(?:proxy-)?authorization[\"']?\s*[:=]\s*[\"']?digest\s+(?P<v>[^\r\n]+)",
        "v",
    ),
    # Cookie: a=b; c=d / Set-Cookie: id=...; Path=/ -- the whole header value
    _r(
        "secret",
        r"(?im)(?:^|(?<=[\"'\s]))(?P<k>(?:set-)?cookie)[\"']?[ \t]*:[ \t]*[\"']?"
        r"(?P<v>[^\r\n\"']*=[^\r\n\"']*)",
        "v",
        _is_keyed_secret,
    ),
    # user:password@ in a URL
    _r("secret", r"(?i)[a-z][a-z0-9+.-]{0,31}://[^\s:/@]+:(?P<v>[^\s@/]+)@", "v"),
    # "key": "a quoted value", key: 'with spaces in it' (the whole quoted value)
    _r(
        "secret",
        rf"(?i)(?P<k>{_KEY})[\"']?\s*(?:[:=]|=>)\s*"
        r"(?P<q>[\"'])(?P<v>(?:(?!(?P=q))[^\r\n\\]|\\.){1,512})(?P=q)",
        "v",
        _is_keyed_secret,
    ),
    # key=value, key: value, "key": "value", key => value
    _r(
        "secret",
        rf"(?i)(?P<k>{_KEY})[\"']?\s*(?:[:=]|=>)\s*[\"']?"
        rf"(?P<v>[^\s\"',;)}}\]]{{3,}})",
        "v",
        _is_keyed_secret,
        rescan=True,
    ),
    # --password value / --api-key=value
    _r(
        "secret",
        rf"(?i)(?<![\w-])--?(?P<k>{_FLAG_KEY})[ =](?P<v>[^\s\"']{{3,}})",
        "v",
        _is_keyed_secret,
        rescan=True,
    ),
    # "the password is X" / "pin was X"
    _r(
        "secret",
        r"(?i)\b(?:password|passphrase|passcode|pwd)\s+(?:is|was)\s*:?\s+[\"']?"
        r"(?P<v>[^\s\"',;)]+?)(?=[\"'.,;)]?(?:\s|$))",
        "v",
        _is_prose_secret,
    ),
    _r(
        "card",
        r"(?<![\w.-])\d(?:[ -]?\d){12,18}(?![\w-]|\.\d)",
        accept=_is_card,
    ),
    _r("email", r"(?<![\w.+-])" + shapes.EMAIL),
    _r(
        "national-id",
        r"(?<![\w-])(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?![\w-])",
    ),
    _r("national-id", r"(?<![\w-])[A-Z]{2} ?\d{2} ?\d{2} ?\d{2} ?[A-D](?![\w-])"),
    _r(
        "national-id",
        r"(?i)\b(?:ssn|social security(?: number| no\.?)?|national (?:id|insurance)"
        r"(?: number| no\.?)?|nino|passport(?: number| no\.?)?|tax id|id number|personal id)"
        r"\b\W{0,4}(?P<v>[A-Z0-9][A-Z0-9-]{4,16}[A-Z0-9]|\d{2,4}(?: \d{2,4}){1,4})(?![\w-])",
        "v",
        _min_digits(4),
    ),
    _r(
        "phone",
        r"(?<![\w+])(?P<v>\+\d{1,3}(?:[ .-]?\(?\d{1,4}\)?){2,5})(?![\w-]|\.\d)",
        "v",
        _digits_between(8, 15),
    ),
    _r(
        "phone",
        r"(?<![\w.+-])(?P<v>(?:\(\d{3}\)[ .-]?|\d{3}[ .-])\d{3}[ .-]\d{4})(?![\w-]|\.\d)",
        "v",
        _digits_between(10, 10),
    ),
    _r(
        "phone",
        r"(?i)\b(?:phone|telephone|tel|mobile|cell|fax|whatsapp|sms)\b\.?[\s:#-]{0,4}"
        r"(?:no\.?\s*|number\s*)?(?P<v>\+?\d[\d ().-]{5,}\d)(?![\w-])",
        "v",
        _digits_between(7, 15),
    ),
)
_IPV4_RE = re.compile(_ascii_bounds(r"(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?![\w]|\.\d)"))
_IPV6_RE = re.compile(
    _ascii_bounds(
        # with an embedded IPv4 tail first (::ffff:a.b.c.d is one address, not "::ffff:a" and a rest)
        r"(?<![\w:.])(?:(?:[0-9A-Fa-f]{0,4}:){2,6}\d{1,3}(?:\.\d{1,3}){3}(?![\w.:])"
        r"|(?:(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}"
        r"|(?=[0-9A-Fa-f:]*::)[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7})(?![\w:]|\.\d))"
    )
)


class Screener:
    """Redacts one pack's untrusted text; holds the label table, so use one per pack.

    ``denylist`` is an iterable of deny-list lines (the leak scanner's format: a literal term per
    line, or ``re:<regex>``); ``types`` limits which types are redacted (default: all).
    """

    def __init__(
        self,
        *,
        redact_private_ips: bool = True,
        denylist: Iterable[str] | None = None,
        types: Iterable[str] | None = None,
    ) -> None:
        self.redact_private_ips = bool(redact_private_ips)
        lines = list(denylist or [])
        self._deny = [rx for _, rx in shapes.compile_denylist(lines)]
        self.denylist_terms = len(self._deny)
        self.types = tuple(t for t in TYPES if types is None or t in set(types))
        unknown = set(types or ()) - set(TYPES)
        if unknown:
            raise ValueError(f"unknown redaction types {sorted(unknown)}; known: {list(TYPES)}")
        self._labels: dict[tuple[str, str], str] = {}
        self._counts: dict[str, int] = {}
        self.redactions: dict[str, int] = {}

    # -- detection
    def find(self, text: str) -> list[tuple[int, int, str, str]]:
        """Non-overlapping ``(start, end, type, normalised value)`` spans of ``text``, by
        position: the union of the plain and the folded pass, overlaps merged (module doc)."""
        plain = self._find(text)
        folded, where = _fold(text)
        if where is None:
            return plain
        # (start, end, priority, pass, type, value): pass 0 is the plain text, 1 the folded view
        spans = [(s, e, _PRIORITY[t], 0, t, v) for s, e, t, v in plain]
        spans += [
            (where[s], where[e - 1] + 1, _PRIORITY[t], 1, t, v) for s, e, t, v in self._find(folded)
        ]
        out: list[tuple[int, int, str, str]] = []
        rank: list[tuple[int, int]] = []  # (priority, pass) of the span each out entry labels
        for s, e, pri, src, t, v in sorted(spans, key=lambda x: (x[0], -x[1], x[2], x[3])):
            if out and s < out[-1][1]:
                ps, pe, pt, pv = out[-1]
                # one span covering both; it keeps the label of the higher-priority type, and of
                # the plain pass on a tie, so one address keeps one label (an e-mail address next to a
                # trade mark sign folds to the address plus "tm")
                if (pri, src) < rank[-1]:
                    pt, pv, rank[-1] = t, v, (pri, src)
                out[-1] = (ps, max(pe, e), pt, pv)
                continue
            out.append((s, e, t, v))
            rank.append((pri, src))
        return out

    def _find(self, text: str) -> list[tuple[int, int, str, str]]:
        cands: list[tuple[int, int, int, str, str]] = []
        on = set(self.types)

        def add(type_: str, start: int, end: int, value: str) -> None:
            if type_ in on and end > start:
                cands.append((_PRIORITY[type_], start, end, type_, value))

        for rule in _RULES:
            if rule.type not in on:
                continue
            for m in _matches(rule, text):
                if rule.accept is not None and not rule.accept(m, text):
                    continue
                s, e = m.span(rule.group)
                add(rule.type, s, e, _normalise(rule.type, m.group(rule.group)))
        for rx in self._deny:
            for m in rx.finditer(text):
                add("denylist", m.start(), m.end(), m.group(0).casefold())
        for m in _IPV4_RE.finditer(text):
            self._ip(m, text, add)
        for m in _IPV6_RE.finditer(text):
            self._ip(m, text, add)

        # Candidates are taken by priority; chosen spans never overlap, so they are kept sorted
        # and each candidate is checked against its neighbours only (a scan of every chosen span
        # was quadratic).  A candidate that overlaps a higher-priority span is not dropped: the
        # parts of it no chosen span covers are redacted under its own label, so nothing a rule
        # found stays in clear because another rule matched next to it ("password=4111 1111
        # 1111 1111": the secret takes "4111", the card the rest).  The cost is over-redaction,
        # such as the host of an e-mail address whose local part is a token.  A label already
        # in the text ("[REDACTED:secret:1]") is taken first and never redacted again, so
        # screening screened text changes nothing.
        chosen: list[tuple[int, int, str, str]] = [
            (m.start(), m.end(), "", "") for m in LABEL_RE.finditer(text)
        ]
        starts: list[int] = [c[0] for c in chosen]

        def put(s: int, e: int, t: str, v: str) -> None:
            i = bisect.bisect_left(starts, s)
            starts.insert(i, s)
            chosen.insert(i, (s, e, t, v))

        for _, s, e, t, v in sorted(cands, key=lambda c: (c[0], c[1], -(c[2] - c[1]))):
            i = bisect.bisect_right(starts, s)
            if i and chosen[i - 1][1] > s:
                i -= 1  # the chosen span that covers s
            pieces: list[tuple[int, int]] = []
            pos = s
            while i < len(chosen) and chosen[i][0] < e:
                cs, ce = chosen[i][0], chosen[i][1]
                if cs > pos:
                    pieces.append((pos, cs))
                pos = max(pos, ce)
                i += 1
            if pos < e:
                pieces.append((pos, e))
            for ps, pe in pieces:
                put(ps, pe, t, v)
        return [c for c in chosen if c[2]]  # the labels already in the text are not spans

    def _ip(self, m: re.Match[str], text: str, add: Callable[[str, int, int, str], None]) -> None:
        raw = m.group(0)
        try:
            addr = ipaddress.ip_address(raw)
        except ValueError:
            return
        if addr.version == 4:
            if any(len(o) > 1 and o.startswith("0") for o in raw.split(".")):
                return  # zero-padded octets: a date or version, not an address
            # the context ends at the address: a short window keeps this linear (a search of
            # the whole prefix per address was quadratic); longer padding only redacts more
            ctx = shapes.VERSION_CONTEXT_RE.search(text[max(0, m.start() - 32) : m.start()])
            # the leak scanner's version context, except a lone "=": "src=<address>" is a value
            if ctx and ctx.group(0).strip() != "=":
                return
        else:
            groups = [g for g in raw.split(":") if g]
            if len(groups) < 2 and not addr.is_loopback:
                return  # "a::b"-ish prose and bare "::"
            if all(g.isalpha() for g in groups):
                return  # Foo::Bar, dead::beef style text
        if not self.redact_private_ips and _private(addr):
            return
        add("ip", m.start(), m.end(), str(addr))

    # -- redaction
    def label(self, type_: str, value: str) -> str:
        key = (type_, value)
        if key not in self._labels:
            self._counts[type_] = self._counts.get(type_, 0) + 1
            self._labels[key] = f"[REDACTED:{type_}:{self._counts[type_]}]"
        return self._labels[key]

    def screen(self, text: str) -> tuple[str, list[Redaction]]:
        """Return the redacted text and what was redacted (offsets into ``text``)."""
        out: list[str] = []
        done: list[Redaction] = []
        pos = 0
        chain: set[str] = set()  # labels of the run of adjacent spans ending at pos
        for s, e, t, v in self.find(text):
            lab = self.label(t, v)
            out += [text[pos:s], lab]
            done.append(Redaction(t, s, e, lab))
            if s != pos or not done[:-1]:
                chain = set()
            if lab not in chain:  # a value split by another span is counted once
                self.redactions[t] = self.redactions.get(t, 0) + 1
                chain.add(lab)
            pos = e
        out.append(text[pos:])
        return "".join(out), done

    def summary(self) -> dict[str, Any]:
        """What the pack records: settings and counts, never a value or a deny-list term."""
        return {
            "enabled": True,
            "redact_private_ips": self.redact_private_ips,
            "denylist_terms": self.denylist_terms,
            "redactions": dict(sorted(self.redactions.items())),
            "distinct": dict(sorted(self._counts.items())),
        }


def _normalise(type_: str, value: str) -> str:
    if type_ == "email":
        return value.casefold()
    if type_ in ("phone", "card"):
        return re.sub(r"\D", "", value)
    if type_ == "national-id":
        return re.sub(r"[\s-]", "", value).upper()
    return value


def screen_text(text: str, **kwargs: Any) -> str:
    """Convenience: redact one string with a fresh :class:`Screener`."""
    return Screener(**kwargs).screen(text)[0]


def screen_config(manifest: Mapping[str, Any]) -> dict[str, Any]:
    """The manifest's ``screen`` block with defaults applied (redaction on unless opted out)."""
    raw = manifest.get("screen") or {}
    if not isinstance(raw, Mapping):
        raise ValueError("manifest 'screen' must be a mapping")
    cfg = {
        "redact": raw.get("redact", True),
        "redact_private_ips": raw.get("redact_private_ips", True),
        "reason": raw.get("reason"),
    }
    if not isinstance(cfg["redact"], bool) or not isinstance(cfg["redact_private_ips"], bool):
        raise ValueError("manifest 'screen.redact' and 'screen.redact_private_ips' are booleans")
    if cfg["redact"] is False and not (isinstance(cfg["reason"], str) and cfg["reason"].strip()):
        raise ValueError(
            "manifest 'screen.redact: false' needs a 'reason' (the opt-out is recorded)"
        )
    return cfg
