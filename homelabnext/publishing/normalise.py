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

from homelabnext.publishing.media import printable_text

# letters that read as Latin ones: Cyrillic and Greek capitals and the small ones drawn alike
# (code point -> the Latin letter); written as code points so the table holds no look-alike itself
_CONFUSABLES = {
    **{
        ord(k): v
        for k, v in zip(
            "\u0410\u0412\u0415\u041a\u041c\u041d\u041e\u0420\u0421\u0422\u0425"
            "\u0430\u0435\u043e\u0440\u0441\u0443\u0445\u0456\u0458\u0455",
            "ABEKMHOPCTXaeopcyxijs",
            strict=True,
        )
    },
    **{
        ord(k): v
        for k, v in zip(
            "\u0391\u0392\u0395\u0396\u0397\u0399\u039a\u039c\u039d\u039f\u03a1\u03a4\u03a5\u03a7"
            "\u03bf\u03bd\u03c1",
            "ABEZHIKMNOPTYXovp",
            strict=True,
        )
    },
}
_DATA_URI = re.compile(r"data:[A-Za-z0-9/+.;=_-]*;base64,([A-Za-z0-9+/_=-]{16,})")
_FORMAT = {"Cf", "Cc"}


def canon(text: str) -> str:
    """The rendered form of ``text`` (not case-folded: some secret shapes are case-sensitive)."""
    for _ in range(3):
        new = urllib.parse.unquote(html.unescape(text))
        new = unicodedata.normalize("NFKC", new)
        new = "".join(
            c for c in new if c in "\n\r\t" or unicodedata.category(c) not in _FORMAT
        ).translate(_CONFUSABLES)
        if new == text:
            break
        text = new
    return text


def _b64(blob: str) -> bytes | None:
    blob = blob.replace("-", "+").replace("_", "/")
    try:
        return base64.b64decode(blob + "=" * (-len(blob) % 4))
    except ValueError:
        return None


def variants(text: str, _depth: int = 0) -> list[str]:
    """``text`` as written, as rendered, and the decoded payload of every base64 data URI in it."""
    c = canon(text)
    out = [text] if c == text else [text, c]
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
