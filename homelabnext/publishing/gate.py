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
import json
import os
import re
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path

from homelabnext import tlp, tlp_egress
from homelabnext.publishing import media, normalise

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
#: names a Pages deploy would treat as configuration or code: never part of a publishable item
_RESERVED = re.compile(r"^(wrangler\.[A-Za-z]+|_worker\.js|functions)$")
_MAX_FILE = 512 * 1024 * 1024


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tree_digest(item: Item) -> str:
    """One digest for the item's payload (path and sha256 of each file, sorted)."""
    h = hashlib.sha256()
    for rel in item.files:
        h.update(f"{rel}\0{item.sidecar['sha256s'][rel]}\n".encode())
    return h.hexdigest()


def _read_sidecar(root: Path) -> dict:
    sc = root / SIDECAR
    try:
        if sc.is_symlink():
            raise GateError(f"{root.name}: the sidecar is a symlink")
        doc = json.loads(sc.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise GateError(f"{root.name}: no readable {SIDECAR} ({type(exc).__name__})") from exc
    if not isinstance(doc, dict) or set(doc) - {"tlp", "producer", "sha256s", "title"}:
        raise GateError(f"{root.name}: the sidecar holds keys beyond tlp, producer, sha256s, title")
    if not isinstance(doc.get("producer"), str) or not doc["producer"]:
        raise GateError(f"{root.name}: the sidecar has no producer")
    if "title" in doc and not isinstance(doc["title"], str):
        raise GateError(f"{root.name}: the sidecar title is not text")
    sums = doc.get("sha256s")
    if not isinstance(sums, dict) or not sums:
        raise GateError(f"{root.name}: the sidecar lists no files")
    if any(not isinstance(v, str) or not _HEX64.match(v) for v in sums.values()):
        raise GateError(f"{root.name}: a sidecar sha256 is not 64 lowercase hex")
    return doc


def _list_files(root: Path) -> list[str]:
    """The payload files of ``root``: regular, single-link, safely named; never the sidecar."""
    files: list[str] = []
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
        if st.st_nlink > 1:
            raise GateError(f"{root.name}: {rel} has more than one hard link")
        parts = rel.split("/")
        if any(part.startswith(".") or not _NAME.match(part) for part in parts):
            raise GateError(f"{root.name}: unsafe file name {rel!r}")
        if any(_RESERVED.match(part) for part in parts):
            raise GateError(f"{root.name}: {rel} is a deploy configuration name, never content")
        files.append(rel)
    return files


def load_item(root: Path, kind: str) -> Item:
    """Read an item directory in place.  Refuses what cannot be judged: a symlinked root, a missing
    or malformed sidecar, a link, a special file, an unsafe name, a payload that differs from the
    sidecar's list.  Publishing never reads this form: :func:`snapshot_item` copies it first."""
    if kind not in KINDS:
        raise GateError(f"unknown item kind {kind!r}")
    if root.is_symlink() or root.parent.is_symlink():
        raise GateError(f"{root.name}: the item (or its kind directory) is a symlink")
    if not _NAME.match(root.name):
        raise GateError(f"unsafe item name {root.name!r}")
    sidecar = _read_sidecar(root)
    files = _list_files(root)
    if set(files) != set(sidecar["sha256s"]):
        raise GateError(f"{root.name}: the files differ from the sidecar's list (extra or missing)")
    return Item(root.name, kind, root, sidecar, tuple(files))


def snapshot_item(root: Path, kind: str, snapshots: Path) -> Item:
    """Copy an item into a private snapshot under ``snapshots`` and return the copy.

    Every byte is read once with ``O_NOFOLLOW``, hashed as read and written from the same bytes, so
    what is later gated and published is what was hashed, whatever a producer does to the original
    afterwards.  The sidecar is not copied (it is never published).  The directory is named by the
    content, built beside and renamed in; an existing one must hold the same bytes.  Nothing is
    deleted."""
    src = load_item(root, kind)
    held: dict[str, bytes] = {}
    for rel in src.files:
        fd = os.open(root / rel, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_nlink > 1 or st.st_size > _MAX_FILE:
                raise GateError(f"{root.name}: {rel} changed or is too large")
            with os.fdopen(fd, "rb", closefd=False) as fh:
                held[rel] = fh.read()
        finally:
            os.close(fd)
    digest = hashlib.sha256(
        "".join(f"{r}\0{_sha256_bytes(held[r])}\n" for r in sorted(held)).encode()
    ).hexdigest()[:16]
    base = snapshots / kind
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    final = base / f"{root.name}-{digest}"
    if (
        final.exists()
    ):  # the same content was copied before: reused only if every byte still matches
        for rel, data in held.items():
            if (final / rel).read_bytes() != data:
                raise GateError(f"{root.name}: the existing snapshot differs from the source")
        return Item(root.name, kind, final, src.sidecar, src.files)
    tmp = base / f".tmp-{secrets.token_hex(6)}"
    tmp.mkdir(mode=0o700)
    for rel, data in held.items():
        dest = tmp / rel
        dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        dfd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(dfd, "wb") as out:
            out.write(data)
    os.rename(tmp, final)
    return Item(root.name, kind, final, src.sidecar, src.files)


# ----------------------------------------------------------------------------- the gate
def _scan(unit: str, variants: list[str], policy: Policy, reasons: list[Reason]) -> None:
    for variant in variants:
        for i in policy.deny_list.hits(variant):
            reasons.append(Reason("deny-list", unit, f"line #{i + 1} of the deny-list"))
        for name, pat in _SECRET_SHAPES:
            if pat.search(variant):
                reasons.append(Reason("secret-shape", unit, name))
        if policy.posture_rules:
            for name, pat in _POSTURE:
                if pat.search(variant):
                    reasons.append(Reason("posture", unit, name))


def _unit_variants(suffix: str, text: str, reasons: list[Reason], unit: str) -> list[str]:
    out = normalise.variants(text)
    if suffix in (".json", ".webmanifest"):
        try:
            out += normalise.variants(normalise.json_text(text))
        except ValueError:
            reasons.append(Reason("json-invalid", unit))
    return out


def judge(
    claimed: object, units: dict[str, list[str]], policy: Policy, reasons: list[Reason]
) -> str:
    """The label ``claimed`` and every marker in every variant leave under, and the rule hits."""
    body = [v for vs in units.values() for v in vs]
    decision = tlp_egress.egress_check(
        policy.ceiling, claimed, recorded=tlp_egress.NO_RECORD, body=body
    )
    if not decision.allowed:
        reasons.append(Reason("tlp-above-ceiling", "", f"{decision.label} over {policy.ceiling}"))
    for unit, vs in units.items():
        _scan(unit, vs, policy, reasons)
    return str(decision.label)


def gate_artifact(name: str, text: str, policy: Policy) -> Verdict:
    """Gate a generated artefact (the feed) before it is uploaded: the same rules, claim clear."""
    reasons: list[Reason] = []
    suffix = Path(name).suffix.lower()
    label = judge("clear", {name: _unit_variants(suffix, text, reasons, name)}, policy, reasons)
    uniq = tuple(dict.fromkeys(reasons))
    return Verdict(name, "artefact", not uniq, label, uniq)


def evaluate(item: Item, policy: Policy) -> Verdict:
    """Judge one item.  Reads every file once; never raises for a content problem (it blocks)."""
    reasons: list[Reason] = []
    units: dict[str, list[str]] = {}
    # what becomes a public URL or a visible field is content too: names, the id, the sidecar's text
    for n, rel in enumerate(item.files):
        units[f"name-of-file-{n + 1}"] = normalise.variants(rel)
    units["item-id"] = normalise.variants(item.id)
    for key in ("producer", "title"):
        if isinstance(item.sidecar.get(key), str):
            units[f"sidecar-{key}"] = normalise.variants(item.sidecar[key])
    for rel in item.files:
        suffix = Path(rel).suffix.lower()
        path = item.path(rel)
        try:
            data = path.read_bytes()
        except OSError:
            reasons.append(Reason("unreadable", rel))
            continue
        if _sha256_bytes(data) != item.sidecar["sha256s"][rel]:
            reasons.append(Reason("sha256-mismatch", rel))
            continue
        if suffix in BINARY_SUFFIXES:
            try:
                extracted = media.metadata_texts_of(suffix, data)
            except media.MediaError as exc:
                reasons.append(Reason("media-invalid", rel, str(exc)))
                continue
            units[rel] = [v for t in extracted for v in normalise.variants(t)]
            continue
        if suffix not in TEXT_SUFFIXES:
            reasons.append(Reason("unknown-file-type", rel, suffix or "no suffix"))
            continue
        if len(data) > MAX_TEXT_BYTES:
            reasons.append(Reason("text-too-large", rel))
            continue
        if media.looks_binary(data):
            reasons.append(Reason("media-invalid", rel, "binary content in a text file"))
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            reasons.append(Reason("text-not-utf8", rel))
            continue
        units[rel] = _unit_variants(suffix, text, reasons, rel)
    label = judge(item.sidecar.get("tlp"), units, policy, reasons)
    uniq = tuple(dict.fromkeys(reasons))
    return Verdict(item.id, item.kind, not uniq, label, uniq)
