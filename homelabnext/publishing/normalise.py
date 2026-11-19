# SPDX-License-Identifier: Apache-2.0
"""Reading text the way a browser or a podcast app will, before any rule looks at it.

A rule that reads the bytes sees ``TLP&#58;RED`` or ``secret<ZWSP>host`` and misses what the reader
sees.  :func:`variants` returns the text as written and as rendered (HTML entities and percent
escapes decoded up to three layers, NFKC, zero-width and other format characters removed, look-alike
Cyrillic and Greek letters folded to Latin), plus the decoded payloads of ``data:`` URIs; for JSON,
:func:`json_text` is every key and string value after decoding.  Every rule runs over every variant.
The gate is a literal, normalised matcher: it does not run scripts or rebuild strings a page
assembles at run time.
"""

from __future__ import annotations

import base64
import html
import json
import re
import unicodedata
import urllib.parse
from html.parser import HTMLParser

from homelabnext.publishing.media import printable_text


def _table(*pairs: tuple[str, str]) -> dict[int, str]:
    out: dict[int, str] = {}
    for src, dst in pairs:
        out.update({ord(k): v for k, v in zip(src, dst, strict=True)})
    return out


# letters that read as Latin ones, as code points so this file holds no look-alike itself:
# Cyrillic, Greek, Coptic, Cherokee, small capitals and a few Latin-extended ones
_CONFUSABLES = _table(
    ("\u0410\u0412\u0415\u041a\u041c\u041d\u041e\u0420\u0421\u0422\u0425", "ABEKMHOPCTX"),
    ("\u0430\u0435\u043e\u0440\u0441\u0443\u0445\u0456\u0458\u0455\u04bb", "aeopcyxijsh"),
    ("\u0501\u050d\u051b\u051d", "dgqw"),
    (
        "\u0391\u0392\u0395\u0396\u0397\u0399\u039a\u039c\u039d\u039f\u03a1\u03a4\u03a5\u03a7",
        "ABEZHIKMNOPTYX",
    ),
    ("\u03bf\u03bd\u03c1", "ovp"),
    (
        "\u2c80\u2c82\u2c88\u2c8c\u2c8e\u2c92\u2c94\u2c98\u2c9a\u2c9e\u2ca2\u2ca4\u2ca6\u2ca8\u2cac",
        "ABEZHIKMNOPCTYX",
    ),
    (
        "\u13a0\u13a1\u13a2\u13aa\u13ac\u13b3\u13bb\u13b7\u13d3\u13da\u13de\u13e2\u13c0\u13d9",
        "DRTAEWHMZSLPGV",
    ),
    # small capitals
    (
        "\u1d00\u0299\u1d04\u1d05\u1d07\ua730\u0262\u029c\u026a\u1d0a\u1d0b\u029f\u1d0d\u0274",
        "ABCDEFGHIJKLMN",
    ),
    ("\u1d0f\u1d18\u0280\ua731\u1d1b\u1d1c\u1d20\u1d21\u028f\u1d22", "OPRSTUVWYZ"),
    ("\u0261", "g"),
    # Armenian letters drawn like Latin ones
    ("\u0570\u0578\u057d\u0585\u0581\u0555\u054d", "hnuogOS"),
)
_DATA_URI = re.compile(r"data:[A-Za-z0-9/+.;=_-]*;base64,([A-Za-z0-9+/_=-]{16,})")
_FORMAT = {"Cf", "Cc"}
_BIDI = set("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")
_MAX_LAYERS = 8
_CDATA = re.compile(r"<!\[CDATA\[|\]\]>")
_COMMENT = re.compile(r"<!--.*?-->", re.S)
_TAG = re.compile(r"<[^>]*>", re.S)
_ESC = re.compile(
    r"\\u\{([0-9a-fA-F]{1,6})\}|\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})|\\([0-9a-fA-F]{1,6})[ \t]?"
)


class NotConverged(ValueError):
    """Decoding still changed the text after the layer cap: refused, not guessed at."""


# characters that draw nothing: variation selectors, Mongolian free variation selectors, the Hangul
# fillers, the Khmer inherent vowels and the combining grapheme joiner
_INVISIBLE = {0x115F, 0x1160, 0x3164, 0xFFA0, 0x17B4, 0x17B5, 0x034F, 0x180B, 0x180C, 0x180D}


def _is_variation(c: str) -> bool:
    n = ord(c)
    return 0xFE00 <= n <= 0xFE0F or 0xE0100 <= n <= 0xE01EF or n in _INVISIBLE


def _step(text: str) -> str:
    new = urllib.parse.unquote(html.unescape(text))
    new = unicodedata.normalize("NFKC", new)
    return "".join(
        c
        for c in new
        if c in "\n\r\t" or (unicodedata.category(c) not in _FORMAT and not _is_variation(c))
    ).translate(_CONFUSABLES)


def canon(text: str) -> str:
    """The rendered form of ``text``, decoded to a fixed point (not case-folded: some secret
    shapes are case-sensitive).  Raises :class:`NotConverged` after the layer cap."""
    for _ in range(_MAX_LAYERS):
        new = _step(text)
        if new == text:
            return text
        text = new
    if _step(text) != text:
        raise NotConverged("text that is still encoded after the layer cap")
    return text


class _Text(HTMLParser):
    """The text of a document as a browser tokenises it: a ``>`` inside a quoted attribute does not
    end the tag, comments are dropped, CDATA sections and script and style bodies are kept."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)
        self.out: list[str] = []

    def handle_data(self, data: str) -> None:
        self.out.append(data)

    def handle_entityref(self, name: str) -> None:
        self.out.append(f"&{name};")

    def handle_charref(self, name: str) -> None:
        self.out.append(f"&#{name};")

    def unknown_decl(self, data: str) -> None:
        if data.startswith("CDATA["):
            self.out.append(data[6:])


def strip_markup(text: str) -> str:
    """The text a browser renders from ``text``, nothing put in the place of a tag (so a name split
    by ``<span>`` is whole again).  Read with an HTML tokeniser (a quoted ``>`` in an attribute is
    not the end of the tag); if that fails, with a pattern."""
    parser = _Text()
    try:
        parser.feed(text)
        parser.close()
    except (ValueError, AssertionError):
        return _TAG.sub("", _CDATA.sub("", _COMMENT.sub("", text)))
    return "".join(parser.out)


def decode_escapes(text: str) -> str:
    """JavaScript and CSS string escapes (``\\uXXXX``, ``\\u{X}``, ``\\xXX``, ``\\68 ``) resolved."""

    def one(m: re.Match[str]) -> str:
        code = m.group(1) or m.group(2) or m.group(3) or m.group(4)
        n = int(code, 16)
        return chr(n) if n <= 0x10FFFF else ""

    return _ESC.sub(one, text)


def _without_marks(text: str) -> str:
    return "".join(
        c for c in unicodedata.normalize("NFKD", text) if unicodedata.category(c) != "Mn"
    )


def _b64(blob: str) -> bytes | None:
    blob = blob.replace("-", "+").replace("_", "/")
    try:
        return base64.b64decode(blob + "=" * (-len(blob) % 4))
    except ValueError:
        return None


def variants(text: str, _depth: int = 0) -> list[str]:
    """``text`` as written and every way a reader or a browser renders it: decoded to a fixed
    point, with markup removed, with script and style escapes decoded, with combining marks
    stripped, reversed when it carries a bidi override, and the decoded payload of every base64
    data URI in it.  Raises :class:`NotConverged` for text that will not decode to a fixed point."""
    c = canon(text)
    out = [text, c]
    stripped = canon(strip_markup(c))
    out.append(stripped)
    out.append(canon(_TAG.sub("", _CDATA.sub("", _COMMENT.sub("", c)))))  # a second reading
    for base in (c, stripped):
        out.append(canon(decode_escapes(base)))
    out += [_without_marks(v) for v in list(out)]
    if any(ch in _BIDI for ch in text):
        out += [v[::-1] for v in list(out)]
    if _depth < 2:
        for m in _DATA_URI.finditer(c):
            raw = _b64(m.group(1))
            if raw:
                out += variants(printable_text(raw), _depth + 1)
    return list(dict.fromkeys(out))


def _leaves(node: object, out: list[str], depth: int = 0) -> None:
    if depth > 64:
        raise ValueError("nested too deeply")
    if isinstance(node, str):
        out.append(node)
    elif isinstance(node, dict):
        for k, v in node.items():
            out.append(str(k))
            _leaves(v, out, depth + 1)
    elif isinstance(node, list):
        for v in node:
            _leaves(v, out, depth + 1)


def json_text(raw: str) -> str:
    """Every key and string value of a JSON document, decoded (``\\u`` escapes resolved).  Raises
    ``ValueError`` for what is not JSON."""
    out: list[str] = []
    _leaves(json.loads(raw), out)
    return "\n".join(out)
