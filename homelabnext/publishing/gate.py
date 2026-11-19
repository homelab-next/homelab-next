# SPDX-License-Identifier: Apache-2.0
"""The publishing gate: nothing leaves unless it passes every rule here (fails closed).

An *item* is a directory ``<publishable>/<kind>/<id>/`` (kind ``site`` or ``podcast``) holding the
producer's files and one ``sidecar.json``::

    {"tlp": "clear", "producer": "<module>", "sha256s": {"<relative path>": "<64 hex>", ...}}

The gate never trusts the claim (ADR-0033 decision 13): the label an item leaves under is the
strictest of the sidecar's claim and every TLP marker in its text, and it must be at or below the
policy's ceiling (``clear``, or ``green`` for a community audience with an access control).  Then,
for every file: the sha256 must match the sidecar, the file's type must be one the gate knows, and
text is scanned for the site's deny-list (hostnames, addresses, names, patterns), the built-in
secret shapes and the disclosure-posture phrases of the old pipeline's guard.

A verdict names the rule and the file, never the text that matched (a log of a blocked secret
must not hold the secret).  Standard library only (plus ``homelabnext.tlp`` and ``tlp_egress``).
"""

from __future__ import annotations

import hashlib
import html
import json
import re
import stat
from dataclasses import dataclass
from pathlib import Path

from homelabnext import tlp, tlp_egress

SIDECAR = "sidecar.json"
KINDS = ("site", "podcast")
TEXT_SUFFIXES = frozenset(
    {
        ".html",
        ".htm",
        ".css",
        ".js",
        ".json",
        ".xml",
        ".txt",
        ".md",
        ".svg",
        ".webmanifest",
        ".map",
        ".csv",
    }
)
BINARY_SUFFIXES = frozenset(
    {".mp3", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".woff", ".woff2"}
)
MAX_TEXT_BYTES = 32 * 1024 * 1024
_HEX64 = re.compile(r"^[0-9a-f]{64}\Z")
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


class GateError(Exception):
    """A configuration or input problem (an unreadable deny-list, a bad item): never a pass."""


@dataclass(frozen=True)
class Reason:
    rule: str  # e.g. tlp-above-ceiling, deny-list, secret-shape, posture, sha256-mismatch
    path: str  # the file inside the item ("" for the item itself)
    detail: str = ""

    def as_dict(self) -> dict[str, str]:
        return {"rule": self.rule, "path": self.path, "detail": self.detail}


@dataclass(frozen=True)
class Verdict:
    item: str
    kind: str
    ok: bool
    label: str
    reasons: tuple[Reason, ...] = ()


@dataclass(frozen=True)
class Item:
    id: str
    kind: str
    root: Path
    sidecar: dict
    files: tuple[str, ...]  # relative paths, sorted, regular files only

    def path(self, rel: str) -> Path:
        return self.root / rel


# ----------------------------------------------------------------------------- deny-list
@dataclass(frozen=True)
class DenyList:
    """Lines of the site's deny-list.  ``#`` starts a comment; ``re:<pattern>`` is a regular
    expression; any other line is a literal (case-insensitive).  A line starting with ``!`` is an
    exception: a match of a deny line that lies wholly inside a match of an exception is excused
    (a public name under an otherwise internal domain).  Empty (no deny line) is refused: a gate
    with nothing to deny is a misconfiguration, not a pass."""

    deny: tuple[re.Pattern[str], ...]
    allow: tuple[re.Pattern[str], ...] = ()

    @classmethod
    def parse(cls, text: str) -> DenyList:
        deny: list[re.Pattern[str]] = []
        allow: list[re.Pattern[str]] = []
        for n, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            target = deny
            if line.startswith("!"):
                target, line = allow, line[1:].strip()
            if not line:
                raise GateError(f"deny-list line {n}: an empty exception")
            if len(line) > 500:
                raise GateError(f"deny-list line {n}: longer than 500 characters")
            src = line[3:] if line.startswith("re:") else re.escape(line)
            try:
                target.append(re.compile(src, re.IGNORECASE))
            except re.error as exc:
                raise GateError(f"deny-list line {n}: not a valid pattern ({exc})") from exc
        if not deny:
            raise GateError(
                "the deny-list holds no deny line: refusing to gate with nothing to deny"
            )
        return cls(tuple(deny), tuple(allow))

    def hits(self, text: str) -> list[int]:
        """Indexes of the deny lines that match ``text`` outside every exception."""
        excused = [m.span() for a in self.allow for m in a.finditer(text)]
        found = []
        for i, pat in enumerate(self.deny):
            for m in pat.finditer(text):
                s, e = m.span()
                if not any(es <= s and e <= ee for es, ee in excused):
                    found.append(i)
                    break
        return found


# built-in shapes: always on; a site's own names belong in the deny-list
_SECRET_SHAPES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private-key-block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("cloud-access-key-id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("forge-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("chat-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("bearer-token", re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{20,}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    (
        "credential-assignment",
        re.compile(
            r"\b(?:api[_-]?key|secret|token|passw(?:or)?d)\b\s*[:=]\s*[\"']?[A-Za-z0-9/+_.=-]{16,}",
            re.I,
        ),
    ),
)

# the old pipeline's disclosure guard, the language of "our own posture" (its first four rules; the
# count-adjacent rule needs a context window and stays with the producer's own check)
_POSTURE: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "possessive-posture",
        re.compile(
            r"\bour\s+(?:(?:own|internal|current|entire|whole|existing)\s+)?"
            r"(estate|assets?|systems?|hosts?|environment|infrastructure|network|fleet|exposure|"
            r"scan\s+results?|deployment|posture)\b",
            re.I,
        ),
    ),
    (
        "present-in-the-environment",
        re.compile(
            r"\b(present|found|detected|observed|identified|exploitable)\s+(in|on|across|within)\s+"
            r"(the|our)\s+(environment|estate|network|fleet|infrastructure|systems?)\b",
            re.I,
        ),
    ),
    (
        "we-run",
        re.compile(
            r"\bwe\s+(run|use|deploy|operate|host|are\s+running|are\s+affected|are\s+exposed|are\s+vulnerable)\b",
            re.I,
        ),
    ),
    (
        "affected-assets",
        re.compile(r"\baffected\s+(assets?|systems?|hosts?|machines?|devices?)\b", re.I),
    ),
)


@dataclass(frozen=True)
class Policy:
    deny_list: DenyList
    ceiling: tlp.Label = tlp.Label.CLEAR
    audience: str = "public"
    access_control: str = ""
    posture_rules: bool = True

    def __post_init__(self) -> None:
        if self.ceiling not in (tlp.Label.CLEAR, tlp.Label.GREEN):
            raise GateError("tlp_allowed is clear or green: amber and red never pass")
        if self.audience not in ("public", "community"):
            raise GateError("audience is public or community")
        if self.ceiling is tlp.Label.GREEN and not (
            self.audience == "community" and self.access_control
        ):
            raise GateError("green needs a community audience and an access control (ADR-0033)")


# ----------------------------------------------------------------------------- items
def _sha256_file(path: Path) -> str:
    with path.open("rb") as fh:
        return hashlib.file_digest(fh, "sha256").hexdigest()


def tree_digest(item: Item) -> str:
    """One digest for the item's payload (path and sha256 of each file, sorted)."""
    h = hashlib.sha256()
    for rel in item.files:
        h.update(f"{rel}\0{item.sidecar['sha256s'][rel]}\n".encode())
    return h.hexdigest()


def load_item(root: Path, kind: str) -> Item:
    """Read an item directory.  Refuses what cannot be judged: a missing or malformed sidecar, a
    symlink, a special file, an unsafe name, a payload that differs from the sidecar's list."""
    if kind not in KINDS:
        raise GateError(f"unknown item kind {kind!r}")
    if not _NAME.match(root.name):
        raise GateError(f"unsafe item name {root.name!r}")
    try:
        sc_path = root / SIDECAR
        if sc_path.is_symlink():
            raise GateError(f"{root.name}: the sidecar is a symlink")
        sidecar = json.loads(sc_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise GateError(f"{root.name}: no readable {SIDECAR} ({type(exc).__name__})") from exc
    if not isinstance(sidecar, dict) or set(sidecar) - {"tlp", "producer", "sha256s", "title"}:
        raise GateError(f"{root.name}: the sidecar holds keys beyond tlp, producer, sha256s, title")
    if not isinstance(sidecar.get("producer"), str) or not sidecar["producer"]:
        raise GateError(f"{root.name}: the sidecar has no producer")
    sums = sidecar.get("sha256s")
    if not isinstance(sums, dict) or not sums:
        raise GateError(f"{root.name}: the sidecar lists no files")
    files: list[str] = []
    base = root.resolve()
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root).as_posix()
        st = p.lstat()
        if stat.S_ISDIR(st.st_mode):
            continue
        if not stat.S_ISREG(st.st_mode):
            raise GateError(
                f"{root.name}: {rel} is not a regular file (links and special files are refused)"
            )
        if rel == SIDECAR:
            continue
        if any(part.startswith(".") or not _NAME.match(part) for part in rel.split("/")):
            raise GateError(f"{root.name}: unsafe file name {rel!r}")
        if base not in p.resolve().parents:
            raise GateError(f"{root.name}: {rel} resolves outside the item")
        files.append(rel)
    if set(files) != set(sums):
        raise GateError(f"{root.name}: the files differ from the sidecar's list (extra or missing)")
    if any(not isinstance(v, str) or not _HEX64.match(v) for v in sums.values()):
        raise GateError(f"{root.name}: a sidecar sha256 is not 64 lowercase hex")
    return Item(root.name, kind, root, sidecar, tuple(files))


# ----------------------------------------------------------------------------- the gate
def evaluate(item: Item, policy: Policy) -> Verdict:
    """Judge one item.  Reads every file; never raises for a content problem (it blocks)."""
    reasons: list[Reason] = []
    texts: dict[str, str] = {}
    for rel in item.files:
        suffix = Path(rel).suffix.lower()
        path = item.path(rel)
        if _sha256_file(path) != item.sidecar["sha256s"][rel]:
            reasons.append(Reason("sha256-mismatch", rel))
            continue
        if suffix in BINARY_SUFFIXES:
            continue
        if suffix not in TEXT_SUFFIXES:
            reasons.append(Reason("unknown-file-type", rel, suffix or "no suffix"))
            continue
        if path.stat().st_size > MAX_TEXT_BYTES:
            reasons.append(Reason("text-too-large", rel))
            continue
        try:
            texts[rel] = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            reasons.append(Reason("text-not-utf8", rel))

    decision = tlp_egress.egress_check(
        policy.ceiling,
        item.sidecar.get("tlp"),
        recorded=tlp_egress.NO_RECORD,
        body=list(texts.values()),
    )
    if not decision.allowed:
        reasons.append(Reason("tlp-above-ceiling", "", f"{decision.label} over {policy.ceiling}"))

    for rel, text in texts.items():
        for variant in {text, html.unescape(text)}:
            for i in policy.deny_list.hits(variant):
                reasons.append(Reason("deny-list", rel, f"line #{i + 1} of the deny-list"))
            for name, pat in _SECRET_SHAPES:
                if pat.search(variant):
                    reasons.append(Reason("secret-shape", rel, name))
            if policy.posture_rules:
                for name, pat in _POSTURE:
                    if pat.search(variant):
                        reasons.append(Reason("posture", rel, name))
    uniq = tuple(dict.fromkeys(reasons))
    return Verdict(item.id, item.kind, not uniq, str(decision.label), uniq)
