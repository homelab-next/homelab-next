#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: private-leak-check
#   kind: check
#   purpose: Fail when a private overlay holds a plaintext secret or an unencrypted sealed file, or when this public tree holds any part of a private overlay.
#   owner: maintainers
#   trigger: [ci:ci/schemas, make:private-overlay-check]
#   invariant: [F-21]
#   inputs: "mode: private (the private overlay's CI) or public (this repository); a checkout root"
#   outputs: one line per finding
#   exit:
#     "0": clean
#     "1": at least one finding
#     "2": misconfiguration (not an overlay, unreadable .sops.yaml or marker)
"""Leak checks for the two halves of the public/private split (docs/private-overlay.md, ADR-0021).

``private ROOT`` runs in the PRIVATE overlay repository's CI.  Real addresses and host names are
allowed there (that is what the repository is for); secret VALUES are not.  ROOT must carry the
overlay marker ``.hnx-private-overlay.yml`` (``hnx_private_overlay: 1``), so the relaxed rules
can never run on the public tree by accident.  Findings:

  secret         a credential shape from ``tools/leak_scan.py``'s ``secret`` group (the same
                 patterns, imported, not copied) in plain text.  Two of that group are about
                 names, not values, and do not apply here: ``secret-name`` (an Ansible variable
                 called ``vault_*`` is the normal way to point at a vaulted value) and
                 ``vault-blob`` (vault ciphertext is expected; see ``vault-unencrypted``).
                 Well-formed SOPS ``ENC[...]`` tokens, the ``sops`` metadata and ansible-vault
                 header and hex lines are masked first: ciphertext is not a leak.  A token that
                 only looks like ciphertext (``ENC[AES256_GCM,data:<a token>]``) is not masked,
                 and a well-formed one is masked only in a SOPS file and only where sops writes
                 one: as a whole value (or a whole comment).  Anywhere else its ``data:`` is just
                 text, and a credential that happens to be valid base64 would hide in it.
  sops-unencrypted
                 a SEALED file that carries no SOPS metadata, i.e. what should be sealed was
                 committed in the clear.  Sealed means: every file under :data:`SEALED_PATHS`
                 (pinned here, so a commit to the overlay cannot drop it), under the marker's
                 ``sealed_paths``, or covered by a ``creation_rules[].path_regex`` of the root
                 ``.sops.yaml``; a ``README.md`` is the one name exempt.
  sops-malformed
                 a sealed file whose metadata is not real (no well-formed ``mac``, no recipient,
                 an unknown key) or a value or comment that is not a well-formed ``ENC[...]``
                 token, or a mapping that sets one key twice (a parser keeps the last value, so the
                 first would never be checked).  Only a key ending in the file's
                 ``unencrypted_suffix`` may stay plain.
  sops-partial   a sealed file encrypted only in part (``encrypted_regex``,
                 ``unencrypted_regex``, ``encrypted_suffix``, the comment regexes,
                 ``mac_only_encrypted``), or one that picks its own ``unencrypted_suffix``: only
                 the SOPS default ``_unencrypted``, or the one the marker pins
                 (``unencrypted_suffix``), may leave keys plain; the file cannot choose.
  sops-policy    a ``.sops.yaml`` that narrows the pinned sealed paths: no root ``.sops.yaml``
                 while sealed files exist, a sealed path no creation rule covers, a rule over a
                 sealed path that encrypts only in part, or a nested ``.sops.yaml`` (sops uses
                 the nearest one, so it would shadow the root rules).
  vault-unencrypted
                 a file the marker's ``ansible_vault_files`` globs (or the usual names: ``vault.yml``,
                 ``*.vault``, ``*.vault.yml``) name that is not an ansible-vault envelope: the
                 header line, then hex lines only, whose payload is the salt, HMAC and ciphertext.
  key-file       a decryption key committed next to the ciphertext it opens: an age identity
                 file, a vault password file (see :data:`KEY_FILE_GLOBS`).
  unscanned      a file the scanner could not read as text (binary, larger than 5 MB,
                 unreadable).  UTF-16 without a byte-order mark is decoded and scanned.  A file
                 the marker's ``allow_unscanned`` globs name is let through; a sealed or vault
                 file never is (``unscannable``).

``public ROOT`` is the reverse guard for THIS repository: nothing of a private overlay may be
committed here.  The fictional skeleton under ``examples/private-overlay/`` is the one exception,
and only while its marker says ``fictional: true``.  Findings:

  overlay-marker   a ``.hnx-private-overlay.yml`` outside the skeleton (or not fictional);
  overlay-path     a file under one of the skeleton marker's ``private_paths`` (the private
                   layout, e.g. ``lab/``), at the root of this tree;
  sops-config      a ``.sops.yaml`` outside the skeleton;
  ciphertext       a SOPS-encrypted file (sealed real data does not belong in public git
                   either: it is one leaked key away from plain text);
  scope-address    a site's network scope in public git.  The union of two rules over EVERY
                   file the scanner reads (any suffix; line ends CRLF or CR normalised first):
                   (1) the parse pass: a file that parses as JSON, TOML or YAML (by content;
                   YAML only within the size and depth bounds) has every scalar, keys
                   included, judged under any key whose resolved value casefolds to
                   ``scope``, at any depth (an alias-spelled key, ``? scope`` with comments,
                   a dedented flow, a CRLF header are just mappings here); (2) the raw rule:
                   the raw text under every ``scope`` key (any case, quoted or not, ``scope:``,
                   ``scope =`` at a line's start, ``[scope]``/``[[scope]]`` headers, dotted
                   ``scope.x`` keys, a comment before the colon, Markdown `` `scope`: ``,
                   ``**scope**:``, ``_scope_:`` and table rows, and the same after decoding
                   YAML, JSON and TOML escapes, an escaped line break and HTML character
                   references; never a call's ``scope=`` keyword argument or an HTML
                   attribute), which also reads what does not parse (Markdown prose and fences
                   of any kind, and each joined cell and textual output of a notebook).  Either
                   fails on an address-like token that is not a documentation address
                   (RFC 5737, ``2001:db8::/32``, ``3fff::/20``).  Address-like: an IPv6
                   address, a dotted form of four parts in any numeric spelling, an integer
                   (decimal, hex, octal, binary, underscored, float, sexagesimal) of 2**24 or
                   more, a short form that cannot be a version or a decimal (a hex part or a
                   part over 255) or sits in an address context (a prefix length, a port, a
                   URL); other short forms (``1.0``, ``24.04``, ``0.05``) are ignored; an alias is
                   followed to its anchor's last real definition (more than
                   :data:`SCOPE_MAX_ALIASES` is a finding), and a ``!!binary`` value is
                   refused.  What a key "holds" (raw rule) is over-read: the rest of its line,
                   every deeper-indented line, a value on the first later line with content,
                   a quoted scalar or flow collection opened there to its close, and for a TOML
                   header everything up to the next header.  Also, at an allowlisted path, an
                   entry of the site block that is not a string naming a documentation network
                   (the one malformed shape let through is a documentation address with a
                   prefix length of at most three digits out of range, which the generated
                   negative plants).
                   Threat model: the gate defends against an ACCIDENTAL commit of a real
                   address in any ordinary format (YAML, JSON, TOML, Markdown; CRLF; escapes;
                   integer, hex, zero-padded and short spellings) and fails closed on what it
                   cannot read.  A deliberately obfuscating author is out of scope for a text
                   gate and is review's to catch; known non-goals: hostnames that resolve to
                   the address they spell (``81-2-69-142.sslip.io``, ``*.nip.io``),
                   percent-encoded or ideographic dots, named HTML entities, Markdown
                   backslash escapes or emphasis inside a number, numbers spelt in words, an
                   address not under a scope key (``tools/leak_scan.py``'s), and carriers no
                   loader here reads as a scope (``.env``, CSV columns, INI ``[scope:x]``, XML,
                   HCL, YAML in comments or blockquotes; docs/modules.md lists them);
  scope-shape      at an allowlisted path (:data:`SCOPE_BLOCK_PATHS`: the example site
                   profiles and the generated selection examples and negatives), a scope block
                   not in the selection's shape: a part outside ``SCOPE_PARTS`` (what it holds
                   is still read), a part or ``scope`` key twice, an anchor or alias, a part
                   that is not a list, a group that is not a mapping, or a scope key anywhere
                   but the top level.  :data:`SCOPE_EXEMPT` lets through one exact location of
                   the generated misspelt-part negative; or a case variant of an
                   allowlisted path (a case-insensitive file system would load it);
  scope-unparsed   an allowlisted file the strict parse refuses: one that does not parse, or
                   is larger than :data:`SCOPE_MAX_BYTES` or nested deeper than
                   :data:`SCOPE_MAX_DEPTH` (checked before any parser sees it), or any file
                   the check itself failed on.  Refused, never skipped.
                   The real scope lives in the overlay's ``lab/modules.yml``.
  key-file         as above.

Files are what ``tools/leak_scan.py`` scans: in a git work tree the tracked and untracked,
not-ignored files.  Usage::

    python3 tools/private_leak_check.py private /path/to/private-overlay
    python3 tools/private_leak_check.py public .
"""

from __future__ import annotations

import argparse
import binascii
import bisect
import contextlib
import fnmatch
import functools
import ipaddress
import json
import re
import sys
import unicodedata
from base64 import b64decode
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import leak_scan  # noqa: E402  (also puts the checkout on sys.path for homelabnext)

from homelabnext import sops  # noqa: E402
from homelabnext.modules.scope import (  # noqa: E402
    EMBEDDED_V4,
    WAN_NOT_PUBLIC,
    ipv4_readings,
    is_documentation,
    scope_tree,
)

EXIT_CLEAN, EXIT_HIT, EXIT_CONFIG = 0, 1, 2

MARKER = ".hnx-private-overlay.yml"
SOPS_CONFIG = ".sops.yaml"
SKELETON = "examples/private-overlay/"
#: what is always sealed, whatever the overlay's own .sops.yaml says (directory prefixes)
SEALED_PATHS = ("lab/sealed/",)
#: the one file name under a sealed path that stays plain (it says what the directory is for)
SEALED_EXEMPT = frozenset({"README.md"})
#: a probe file name per sealed directory: the root .sops.yaml must cover it
SEALED_PROBE = "probe.sops.yaml"
#: sops options that leave part of a file in the clear (unencrypted_suffix is the one allowed)
PARTIAL_KEYS = (
    "encrypted_regex",
    "unencrypted_regex",
    "encrypted_suffix",
    "encrypted_comment_regex",
    "unencrypted_comment_regex",
    "mac_only_encrypted",
)
RECIPIENT_KEYS = ("age", "pgp", "kms", "gcp_kms", "azure_kv", "hc_vault", "key_groups")
META_KEYS = frozenset(
    {*PARTIAL_KEYS, *RECIPIENT_KEYS}
    | {"lastmodified", "mac", "version", "unencrypted_suffix", "shamir_threshold"}
)
DEFAULT_UNENCRYPTED_SUFFIX = "_unencrypted"
#: leak_scan secret patterns that name a secret instead of carrying one (see the docstring)
NAME_ONLY_PATTERNS = frozenset({"secret-name", "vault-blob"})
VAULT_HEADER = "$" + "ANSIBLE_VAULT;"
DEFAULT_VAULT_GLOBS = ("vault.yml", "vault.yaml", "*.vault", "*.vault.yml", "*.vault.yaml")
#: decryption keys: never in git, next to the ciphertext or anywhere else
KEY_FILE_GLOBS = (
    "*.agekey",
    "age-key.txt",
    "age.key",
    "sops/age/keys.txt",
    ".vault[-_]pass",
    ".vault[-_]pass.txt",
    ".vault[-_]password",
    "vault[-_]password.txt",
)
_B64 = r"[A-Za-z0-9+/]*={0,2}"
#: a SOPS value as sops writes it: AES-GCM, base64 data, a 32-byte IV, a 16-byte tag, a type
_ENC_TOKEN = re.compile(
    rf"ENC\[AES256_GCM,data:(?P<data>{_B64}),iv:(?P<iv>{_B64}),tag:(?P<tag>{_B64}),"
    r"type:(?:str|int|float|bool|bytes|time|comment)\]"
)
_ENC_ANY = re.compile(r"ENC\[[^\]\n]*\]")
_HEX_LINE = re.compile(r"^\s*[0-9a-f]{16,}\s*$")
_VAULT_HEADER_LINE = re.compile(
    "^" + re.escape(VAULT_HEADER) + r"1\.[12];AES256(?:;[A-Za-z0-9_.@-]+)?$"
)
_HEX_ONLY = re.compile(r"^[0-9a-f]+$")
_TOP_LEVEL = re.compile(r"^[^\s#]")


class ConfigError(Exception):
    """Misconfiguration (exit 2)."""


@dataclass(frozen=True)
class Finding:
    path: str
    rule: str
    detail: str

    def __str__(self) -> str:
        return f"{self.path}: [{self.rule}] {self.detail}"


# ---- reading -----------------------------------------------------------------------------------


def _files(root: Path) -> list[tuple[str, Path]]:
    """``(posix path relative to root, path)`` for every file leak_scan would scan."""
    out = []
    for f in leak_scan.iter_files([str(root)]):
        try:
            rel = f.relative_to(root).as_posix()
        except ValueError:
            rel = f.as_posix()
        out.append((rel, f))
    return out


def _utf16(data: bytes) -> str | None:
    """Text of UTF-16 without a byte-order mark (mostly-ASCII text, every other byte NUL)."""
    if len(data) < 4 or len(data) % 2:
        return None
    high, low = data[slice(1, None, 2)], data[slice(0, None, 2)]
    for zeros, codec in ((high, "utf-16-le"), (low, "utf-16-be")):
        if zeros.count(0) >= 0.9 * len(zeros):
            try:
                return data.decode(codec)
            except UnicodeDecodeError:
                return None
    return None


def _read(path: Path) -> str | leak_scan.Skipped:
    """Text to scan, or why it could not be scanned (UTF-16 without a BOM is decoded)."""
    got = leak_scan.read_text_file(path)
    if isinstance(got, leak_scan.Skipped) and got.reason.startswith("binary"):
        try:
            text = _utf16(path.read_bytes())
        except OSError:
            text = None
        if text is not None:
            return text
    return got


def _text(path: Path) -> str | None:
    got = _read(path)
    return None if isinstance(got, leak_scan.Skipped) else got


def _yaml(path: Path, what: str) -> object:
    import yaml

    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"cannot read {what} {path}: {exc.__class__.__name__}") from exc


def read_marker(path: Path) -> dict:
    doc = _yaml(path, "overlay marker")
    if not isinstance(doc, dict) or doc.get("hnx_private_overlay") != 1:
        raise ConfigError(f"{path}: not an overlay marker (needs hnx_private_overlay: 1)")
    for key in ("ansible_vault_files", "private_paths", "sealed_paths", "allow_unscanned"):
        v = doc.get(key, [])
        if not isinstance(v, list) or not all(isinstance(x, str) and x for x in v):
            raise ConfigError(f"{path}: {key} must be a list of non-empty strings")
    suffix = doc.get("unencrypted_suffix", DEFAULT_UNENCRYPTED_SUFFIX)
    if not isinstance(suffix, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", suffix):
        raise ConfigError(f"{path}: unencrypted_suffix must be a short plain suffix")
    return doc


@dataclass(frozen=True)
class SopsRule:
    path_regex: re.Pattern[str]
    partial: tuple[str, ...]  # the PARTIAL_KEYS the rule sets


def sops_rules(root: Path) -> list[SopsRule] | None:
    """The creation rules of ROOT/.sops.yaml in order (``None`` when there is no such file)."""
    p = root / SOPS_CONFIG
    if not p.is_file():
        return None
    doc = _yaml(p, "SOPS config")
    rules = doc.get("creation_rules") if isinstance(doc, dict) else None
    if not isinstance(rules, list):
        raise ConfigError(f"{p}: expected a creation_rules list")
    out = []
    for i, rule in enumerate(rules):
        rx = rule.get("path_regex") if isinstance(rule, dict) else None
        if not isinstance(rx, str) or not rx:
            raise ConfigError(
                f"{p}: creation_rules[{i}] has no path_regex (it would cover every file)"
            )
        try:
            compiled = re.compile(rx)
        except re.error as exc:
            raise ConfigError(f"{p}: creation_rules[{i}].path_regex: {exc}") from exc
        out.append(SopsRule(compiled, tuple(k for k in PARTIAL_KEYS if rule.get(k))))
    return out


def _first_rule(rules: list[SopsRule], rel: str) -> SopsRule | None:
    """The rule sops would use for ``rel``: the first whose path_regex matches."""
    return next((r for r in rules if r.path_regex.search(rel)), None)


def _under(rel: str, prefixes: Iterable[str]) -> bool:
    return any(rel.startswith(p.rstrip("/") + "/") or fnmatch.fnmatchcase(rel, p) for p in prefixes)


def is_sealed(rel: str, sealed_paths: Iterable[str], rules: list[SopsRule] | None) -> bool:
    """A file that must be SOPS-encrypted: under a pinned or declared sealed path, or covered by
    a root .sops.yaml creation rule.  A ``README.md`` is never sealed (it is still scanned)."""
    if rel.rsplit("/", 1)[-1] in SEALED_EXEMPT:
        return False
    return _under(rel, sealed_paths) or any(r.path_regex.search(rel) for r in rules or [])


# ---- what is sealed ----------------------------------------------------------------------------


def sops_format(text: str) -> str | None:
    """``yaml``/``json``/``dotenv``/``ini`` for a SOPS-encrypted file, else ``None``."""
    fmt = sops.format_of(text)
    if fmt:
        return fmt
    if re.search(r"^sops_mac=", text, re.MULTILINE):
        return "dotenv"
    if re.search(r"^\[sops\]\s*$", text, re.MULTILINE) and re.search(r"^mac\s*=", text, re.M):
        return "ini"
    return None


def well_formed_enc(value: str) -> bool:
    """True for a value exactly as sops writes one (``ENC[AES256_GCM,data:..,iv:..,tag:..,type:..]``
    with base64 that decodes, a 32-byte IV and a 16-byte tag)."""
    m = _ENC_TOKEN.fullmatch(value)
    if not m:
        return False
    try:
        b64decode(m["data"], validate=True)
        iv, tag = b64decode(m["iv"], validate=True), b64decode(m["tag"], validate=True)
    except (binascii.Error, ValueError):
        return False
    return len(iv) == 32 and len(tag) == 16


class DuplicateKey(ValueError):
    """A mapping sets one key twice."""


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict:
    out: dict = {}
    for k, v in pairs:
        if k in out:
            raise DuplicateKey(f"duplicate key {k!r}")
        out[k] = v
    return out


def load_unique(text: str, fmt: str) -> object:
    """A JSON or YAML document, refusing a mapping that sets a key twice (:class:`DuplicateKey`)."""
    if fmt == "json":
        return json.loads(text, object_pairs_hook=_unique_pairs)
    import yaml

    from homelabnext._yaml import UniqueKeyLoader

    try:
        return yaml.load(text, Loader=UniqueKeyLoader)
    except yaml.constructor.ConstructorError as exc:
        if "duplicate key" in str(exc.problem):
            raise DuplicateKey(str(exc.problem)) from None
        raise


#: where sops writes a token: a whole value (``key: ENC[..]``, ``- ENC[..]``, ``key=ENC[..]``,
#: ``"key": "ENC[..]"``) or a whole comment (``#ENC[..]``), alone on its line but for a JSON comma
_ENC_VALUE = {
    "yaml": re.compile(
        r"^(?P<pre>\s*(?:-\s+)*(?:[^\s#][^#\n]*?:\s+)?|\s*#\s*)(?P<tok>ENC\[[^\]\n]*\])\s*$"
    ),
    "json": re.compile(
        r'^(?P<pre>\s*(?:"(?:[^"\\]|\\.)*"\s*:\s*)?")(?P<tok>ENC\[[^\]\n]*\])"\s*,?\s*$'
    ),
    "dotenv": re.compile(r"^(?P<pre>[^=#\n]+=|#\s*)(?P<tok>ENC\[[^\]\n]*\])\s*$"),
    "ini": re.compile(r"^(?P<pre>\s*[^=#;\[\n]+=\s*|\s*[#;]\s*)(?P<tok>ENC\[[^\]\n]*\])\s*$"),
}


def _mask_enc(text: str, fmt: str | None) -> str:
    """Blank well-formed tokens where sops writes them, in a SOPS file only (else unchanged)."""
    rx = _ENC_VALUE.get(fmt or "")
    if rx is None:
        return text

    def one(line: str) -> str:
        m = rx.match(line)
        if not m or not well_formed_enc(m["tok"]):
            return line
        return line[: m.start("tok")] + "ENC[]" + line[m.end("tok") :]

    return "\n".join(one(ln) for ln in text.split("\n"))


def masked(text: str) -> str:
    """``text`` with ciphertext blanked: SOPS values and metadata, ansible-vault payloads.

    Only a well-formed ``ENC[...]`` token is ciphertext; only the vault header line itself and
    hex lines are a vault payload, so plain text after a header is still scanned.  Line numbers
    are kept for YAML, dotenv, ini and vault; a SOPS JSON file is re-serialised."""
    fmt = sops_format(text)
    if fmt == "json":
        try:
            doc = load_unique(text, "json")
        except DuplicateKey:
            doc = None  # re-serialising would drop the first value: scan the text as it is
        if isinstance(doc, dict):
            doc.pop("sops", None)
            text = json.dumps(doc, indent=2)
    elif fmt in ("yaml", "ini"):
        start = re.compile(r"^sops:[ \t]*$") if fmt == "yaml" else re.compile(r"^\[sops\]\s*$")
        lines, inside = [], False
        for line in text.splitlines():
            if start.match(line):
                inside = True
            elif inside and (_TOP_LEVEL.match(line) if fmt == "yaml" else line.startswith("[")):
                inside = False
            lines.append("" if inside else line)
        text = "\n".join(lines)
    elif fmt == "dotenv":
        text = "\n".join("" if ln.startswith("sops_") else ln for ln in text.splitlines())
    text = _mask_enc(text, fmt)
    if VAULT_HEADER in text:
        text = "\n".join(
            "" if _VAULT_HEADER_LINE.match(ln.strip()) or _HEX_LINE.match(ln) else ln
            for ln in text.splitlines()
        )
    return text


# ---- sealed and vaulted files ------------------------------------------------------------------


def envelope_problem(text: str) -> str | None:
    """Why ``text`` is not an ansible-vault envelope, or ``None`` when it is one."""
    lines = [ln.strip() for ln in text.strip().splitlines()]
    if not lines or not _VAULT_HEADER_LINE.match(lines[0]):
        return "a vault file without the ansible-vault header"
    body = "".join(lines[1:])
    if not body or not all(_HEX_ONLY.match(ln) for ln in lines[1:] if ln):
        return "a vault file whose body is not only hex lines (plain text after the header)"
    try:
        inner = bytes.fromhex(body).decode("ascii").split("\n")
    except ValueError:
        return "a vault file whose payload is not salt, HMAC and ciphertext"
    if len(inner) != 3 or not all(part and _HEX_ONLY.match(part) for part in inner):
        return "a vault file whose payload is not salt, HMAC and ciphertext"
    return None


def _flat_meta(text: str, fmt: str) -> tuple[dict, list[tuple[str, object]]]:
    """``(metadata, [(key path, value), ...])`` of a dotenv or ini SOPS file, flattened the way
    sops writes those formats (``sops_age__list_0__map_enc``, a ``[sops]`` section)."""
    meta: dict = {}
    leaves: list[tuple[str, object]] = []
    section = ""
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        if line.startswith(("#", ";")):
            leaves.append((f"line {n} (comment)", line[1:].strip()))
            continue
        if fmt == "ini" and line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            continue
        key, sep, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if not sep:
            leaves.append((f"line {n}", line))
            continue
        if fmt == "dotenv" and key.startswith("sops_"):
            meta[key.removeprefix("sops_")] = value
        elif fmt == "ini" and section == "sops":
            meta[key] = value
        else:
            leaves.append((f"{section}/{key}" if section else key, value))
    return meta, leaves


def _tree_leaves(node: object, suffix: str, path: str = "") -> Iterable[tuple[str, object]]:
    if isinstance(node, dict):
        for k, v in node.items():
            if isinstance(k, str) and suffix and k.endswith(suffix):
                continue
            yield from _tree_leaves(v, suffix, f"{path}/{k}" if path else str(k))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _tree_leaves(v, suffix, f"{path}/{i}")
    else:
        yield path or "<root>", node


def sealed_problems(
    text: str, rel: str, suffixes: Iterable[str] = (DEFAULT_UNENCRYPTED_SUFFIX,)
) -> list[Finding]:
    """Findings for a file that must be SOPS-encrypted throughout (empty when it is).
    ``suffixes``: the ``unencrypted_suffix`` values a sealed file may carry (the SOPS default and
    the one the overlay marker pins)."""
    fmt = sops_format(text)
    if fmt is None:
        return [
            Finding(
                rel, "sops-unencrypted", "a sealed path holds a file that is not SOPS-encrypted"
            )
        ]
    if fmt in ("dotenv", "ini"):
        meta, leaves = _flat_meta(text, fmt)
        has_recipient = any(k.startswith(f"{r}__list_") for k in meta for r in RECIPIENT_KEYS)
        unknown = sorted({k.split("__", 1)[0] for k in meta} - META_KEYS)
    else:
        try:
            doc = load_unique(text, fmt)
        except DuplicateKey as exc:
            return [Finding(rel, "sops-malformed", f"{exc}: the first value would go unchecked")]
        meta = doc.pop("sops")
        has_recipient = any(meta.get(r) for r in RECIPIENT_KEYS)
        unknown = sorted(str(k) for k in meta if k not in META_KEYS)
        leaves = []
    out: list[Finding] = []
    mac = meta.get("mac")
    if not (isinstance(mac, str) and well_formed_enc(mac)):
        out.append(Finding(rel, "sops-malformed", "SOPS metadata without a well-formed mac"))
    if not has_recipient:
        out.append(Finding(rel, "sops-malformed", "SOPS metadata names no recipient"))
    if unknown:
        out.append(
            Finding(rel, "sops-malformed", f"unknown SOPS metadata key(s): {', '.join(unknown)}")
        )
    partial = [k for k in PARTIAL_KEYS if meta.get(k) not in (None, "", False, "false")]
    if partial:
        out.append(Finding(rel, "sops-partial", f"encrypted only in part ({', '.join(partial)})"))
    suffix = meta.get("unencrypted_suffix", DEFAULT_UNENCRYPTED_SUFFIX)
    allowed = (*suffixes, "")  # an empty suffix leaves nothing plain
    if not isinstance(suffix, str) or suffix not in allowed:
        out.append(
            Finding(
                rel,
                "sops-partial",
                "the file picks its own unencrypted_suffix (only the SOPS default or the one "
                "the overlay marker pins may stay plain)",
            )
        )
        suffix = ""  # check every key, as if nothing were plain
    if fmt in ("dotenv", "ini"):
        plain = [
            k
            for k, v in leaves
            if not (suffix and k.rsplit("/", 1)[-1].endswith(suffix))
            and not (isinstance(v, str) and well_formed_enc(v))
        ]
    else:
        plain = [
            k
            for k, v in _tree_leaves(doc, suffix)
            if v is not None and not (isinstance(v, str) and well_formed_enc(v))
        ]
        if fmt == "yaml":
            plain += [
                f"line {n} (comment)"
                for n, ln in enumerate(text.splitlines(), 1)
                if ln.strip().startswith("#") and not well_formed_enc(ln.strip()[1:].strip())
            ]
    for where in plain[:20]:
        out.append(Finding(rel, "sops-malformed", f"{where}: not a well-formed ENC[...] value"))
    if len(plain) > 20:
        out.append(Finding(rel, "sops-malformed", f"... and {len(plain) - 20} more plain value(s)"))
    return out


def _matches(rel: str, globs: Iterable[str]) -> bool:
    name = rel.rsplit("/", 1)[-1]
    return any(fnmatch.fnmatchcase(rel, g) or fnmatch.fnmatchcase(name, g) for g in globs)


def _is_key_file(rel: str) -> bool:
    return any(
        fnmatch.fnmatchcase(rel, g) or fnmatch.fnmatchcase(rel, "*/" + g)
        if "/" in g
        else fnmatch.fnmatchcase(rel.rsplit("/", 1)[-1], g)
        for g in KEY_FILE_GLOBS
    )


# ---- the two modes -----------------------------------------------------------------------------


def _policy_findings(root: Path, files: list[str], sealed_paths: list[str]) -> list[Finding]:
    """``sops-policy``: the overlay's .sops.yaml may add sealed paths, never narrow them."""
    out: list[Finding] = []
    for rel in files:
        if rel.rsplit("/", 1)[-1] == SOPS_CONFIG and rel != SOPS_CONFIG:
            out.append(
                Finding(rel, "sops-policy", "a nested .sops.yaml shadows the root creation rules")
            )
    sealed = [
        r for r in files if _under(r, sealed_paths) and r.rsplit("/", 1)[-1] not in SEALED_EXEMPT
    ]
    rules = sops_rules(root)
    if rules is None:
        if sealed:
            out.append(
                Finding(SOPS_CONFIG, "sops-policy", "missing, while files under sealed paths exist")
            )
        return out
    probes = [
        p.rstrip("/") + "/" + SEALED_PROBE for p in sealed_paths if not any(c in p for c in "*?[")
    ]
    for rel in [*probes, *sealed]:
        rule = _first_rule(rules, rel)
        if rule is None:
            out.append(Finding(SOPS_CONFIG, "sops-policy", f"no creation rule covers {rel}"))
        elif rule.partial:
            out.append(
                Finding(
                    SOPS_CONFIG,
                    "sops-policy",
                    f"the rule for {rel} encrypts only in part ({', '.join(rule.partial)})",
                )
            )
    return out


def check_private(root: Path) -> list[Finding]:
    marker = root / MARKER
    if not marker.is_file():
        raise ConfigError(
            f"{root} has no {MARKER}: the private rules (real addresses allowed) only run on a "
            "repository that declares itself a private overlay"
        )
    doc = read_marker(marker)
    vaulted = [*DEFAULT_VAULT_GLOBS, *doc.get("ansible_vault_files", [])]
    sealed_paths = [*SEALED_PATHS, *doc.get("sealed_paths", [])]
    allow_unscanned = doc.get("allow_unscanned", [])
    suffixes = tuple({DEFAULT_UNENCRYPTED_SUFFIX, doc.get("unencrypted_suffix") or ""} - {""})
    rules = sops_rules(root)
    patterns = [
        p for p in leak_scan.PATTERNS if p.group == "secret" and p.name not in NAME_ONLY_PATTERNS
    ]
    files = _files(root)
    out: list[Finding] = _policy_findings(root, [rel for rel, _ in files], sealed_paths)
    for rel, f in files:
        if _is_key_file(rel):
            out.append(Finding(rel, "key-file", "a decryption key must never be committed"))
            continue
        sealed, vault = is_sealed(rel, sealed_paths, rules), _matches(rel, vaulted)
        text = _read(f)
        if isinstance(text, leak_scan.Skipped):
            if sealed or vault:
                out.append(Finding(rel, "unscannable", f"sealed file not readable: {text.reason}"))
            elif not _matches(rel, allow_unscanned):
                out.append(
                    Finding(
                        rel,
                        "unscanned",
                        f"{text.reason}: not scanned (name it in the marker's allow_unscanned "
                        "if that is intended)",
                    )
                )
            continue
        if sealed:
            problems = sealed_problems(text, rel, suffixes)
            if problems:
                out += problems
                continue  # its content is the leak; do not echo it line by line
        if vault:
            why = envelope_problem(text)
            if why:
                out.append(Finding(rel, "vault-unencrypted", why))
                continue
        for h in leak_scan.scan_text(masked(text), rel, patterns):
            out.append(Finding(rel, "secret", f"line {h.line}: {h.pattern} {h.shown}"))
    return out


# ---- public: a site's network scope ------------------------------------------------------------
#
# Fail closed by LOCATION, not by format.  A site scope block may sit in public git only at the
# paths of SCOPE_BLOCK_PATHS (the example site profiles and the generated selection examples and
# negatives), where the file is parsed strictly and every leaf is judged.  Everywhere else, in
# every file the scanner reads (any suffix, Markdown prose and fences of any kind included), the
# raw text under every scope key is tokenised and any address-like token that is not a
# documentation address is a finding.  Nothing outside the allowlist is parsed, so no format, no
# parser and no "whose scope is this" heuristic decides what is read.

#: the only public paths a site scope block may sit in (fnmatch globs, ``*`` stays inside one
#: directory): each is parsed strictly, in the selection's shape, every leaf judged
SCOPE_BLOCK_PATHS = (
    "examples/modules/sites/*.yml",
    "schemas/platform/examples/module_selection.*.yml",
    "schemas/platform/negative/module_selection.*.yml",
)
#: what the strict parse takes: larger or deeper is a finding (``scope-unparsed``) and is never
#: handed to a parser (libyaml's C composer recurses per level and segfaults on deep nesting)
SCOPE_MAX_BYTES = 256 * 1024
SCOPE_MAX_DEPTH = 32
_STR = "tag:yaml.org,2002:str"
_NULL = "tag:yaml.org,2002:null"

#: (file, finding, location) the public check lets through, each with its reason.  Narrow on
#: purpose: one exact location in one generated file, and what it holds is still read.
SCOPE_EXEMPT = {
    (
        "schemas/platform/negative/module_selection.scope-unknown-part.yml",
        "scope-shape",
        "scope.trusted.lan",  # scrub-allow: the generated negative misspelt part
    ): "the generated negative for a misspelt part (homelabnext.schemas): it must be misspelt",
}

#: a ``scope`` key in any format the text can show: ``scope:`` (YAML, JSON, a flow mapping, an
#: explicit ``? scope`` key, prose), ``scope =`` (TOML, INI), a dotted ``scope.trusted.wan``
#: key, and a TOML table header naming it (``[scope]``, ``[[scope]]``, ``[site.scope]``).
#: Quoted or not, any case (``re.I`` also folds the long s, U+017F); not part of a longer word.
#: Markdown spellings count (`` `scope`: ``, ``**scope**:``, ``_scope_:``, a table row whose first
#: cell is ``scope``).  Never a key: a call's keyword argument (``fixture(scope="module")``,
#: ``f(a, scope=x)``) or an HTML or XML attribute (``<th scope="row">``): ``scope =`` counts only
#: at a line's start or, spaced, inside a TOML inline table.
_SCOPE_KEY = re.compile(
    r"""(?<![\w$-])[`*_"']*scope[`*_"'\]}]*"""  # Markdown `scope`, **scope**, _scope_, quotes
    r"""(?:[ \t]*(?:\#[^\n]*)?\n)*[ \t]*"""  # comment lines and line breaks before the colon
    r"""(?::(?!:)|\.[ \t]*["']?[A-Za-z_])"""  # scope: or a dotted scope.x key
    r"""|^[ \t]*["']?scope["']?[ \t]*=(?!=)"""  # scope = at a line's start (TOML, INI)
    r"""|(?<=[{,])[ \t]*["']?scope["']?[ \t]+=[ \t]"""  # in a TOML inline table, spaced
    r"""|^[ \t]*\|[ \t]*[`*_]*scope(?:\.[\w.]+)?[`*_]*[ \t]*\|""",  # a Markdown table row
    re.I | re.M,
)
#: a TOML table header line (``[a.b]``, ``[[a."b"]]``): the whole line, nothing after but a comment
_TOML_HEADER = re.compile(
    r"""^[ \t]*\[\[?[ \t]*(?P<path>[\w"' .-]+?)[ \t]*\]\]?[ \t]*(?:#[^\n]*)?$""", re.M
)
#: escapes that could spell the key (or a value) without its plain text: YAML/JSON/TOML ``\x``,
#: ``\u``, ``\U``, a YAML escaped line break, and HTML character references (Markdown)
_ESCAPES = re.compile(
    r"\\x([0-9A-Fa-f]{2})|\\u([0-9A-Fa-f]{4})|\\U([0-9A-Fa-f]{8})|\\\r?\n[ \t]*|\\/"
    r"|&#([0-9]{1,7});|&#[xX]([0-9A-Fa-f]{1,6});"
)
#: an IPv6 candidate (two or more colons; brackets, a zone and a prefix length around it)
_V6_TOKEN = re.compile(
    r"(?<![\w:.])\[?((?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f.:]*)(?:%[\w.~-]*)?\]?(?:/([0-9]+))?"
)
#: a numeric token: an integer in any YAML/TOML/C spelling, a dotted form of one to four parts
#: (``inet_aton``), a float, and an optional prefix length.  Never part of a word.
_NUM_TOKEN = re.compile(
    r"(?<![\w.])"
    r"(0[xX][0-9A-Fa-f_]+|0[bB][01_]+|0[oO][0-7_]+|[0-9][0-9_]*)"
    r"((?:\.(?:0[xX][0-9A-Fa-f]+|[0-9]+))*)"
    r"(\.?[eE][+-]?[0-9]+)?"
    r"(?![\w])(?:/([0-9]+))?"
)
#: a YAML 1.1 sexagesimal integer (``190:20:30``)
_SEXAGESIMAL = re.compile(r"(?<![\w:.])[0-9][0-9_]*(?::[0-5]?[0-9])+(?![\w:.])")
_ALIAS = re.compile(r"(?:^|(?<=[\s\[{,:]))\*([^\s,\[\]{}]+)")
_BINARY = re.compile(r"!!binary|tag:yaml\.org,2002:binary", re.I)


class _Unreadable(Exception):
    """An allowlisted file the strict parse cannot read: a finding, never a skip."""


def scope_block_path(rel: str) -> bool:
    """True for a public path a site scope block may sit in (:data:`SCOPE_BLOCK_PATHS`)."""
    return any(
        fnmatch.fnmatchcase(rel, g) and rel.count("/") == g.count("/") for g in SCOPE_BLOCK_PATHS
    )


def _decoded(text: str) -> str:
    """``text`` with every escape of :data:`_ESCAPES` replaced by what it spells."""

    def one(m: re.Match[str]) -> str:
        code = next((g for g in m.groups() if g), None)
        if code is None:
            return "/" if m.group(0) == "\\/" else ""
        base = 10 if m.group(4) else 16
        try:
            return chr(int(code, base))
        except (ValueError, OverflowError):
            return m.group(0)

    return _ESCAPES.sub(one, text)


def _ascii_digits(text: str) -> str:
    """NFKC (fullwidth digits, dots, colons) and every other Unicode decimal digit as ASCII: a
    YAML int, ``int()`` and some resolvers read them."""
    text = unicodedata.normalize("NFKC", text)
    if text.isascii():
        return text
    return "".join(str(unicodedata.decimal(c)) if c.isdecimal() else c for c in text)


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" \t"))


def _newlines_normalised(text: str) -> str:
    """CRLF and lone CR as LF: a Windows or old-Mac editor's line ends are not an obfuscation."""
    return text.replace("\r\n", "\n").replace("\r", "\n")


_FLOW_CHARS = re.compile(r"""[\[\]{}"\n#\\&']""")
#: a YAML anchor definition (``&name``) where the text can hold one
_ANCHOR = re.compile(r"(?:^|(?<=[\s\[{,:]))&([^\s,\[\]{}]+)(?=[\s,\]}]|$)", re.M)
#: how many distinct aliases under scope keys one file may make the raw rule follow; more is a
#: finding (the cap fails closed), never a silent stop
SCOPE_MAX_ALIASES = 256


class _Index:
    """One linear pass over a text, so that no scope key re-reads what another already read.

    - ``close_of``: each flow opener's position mapped to just past its closer (the end of the
      text when it never closes).  Double-quoted strings and ``#`` comments are skipped; a
      single quote is not (an apostrophe in prose would hide every bracket after it), so a
      bracket inside a single-quoted string can pair wrongly: the parse pass reads such files.
    - ``headers``: the start of every TOML table header line, sorted.
    - ``anchors``: each anchor name mapped to the sorted positions of its real definitions
      (not in a comment, not inside a quoted string), found in the same pass.
    - ``newlines``: positions of every line break, for line starts, ends and numbers.

    Nothing here re-reads a line per key or per anchor, so the index is linear in the text."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.newlines = [m.start() for m in re.finditer("\n", text)]
        self.close_of: dict[int, int] = {}
        self.anchors: dict[str, list[int]] = {}
        stack: list[int] = []
        in_dq = in_comment = False
        sq_open = False  # an odd number of single quotes so far on this line
        prev_end = 0
        for m in _FLOW_CHARS.finditer(text):
            c, i = m.group(0), m.start()
            if c == "\n":
                in_comment = sq_open = False
                prev_end = i + 1
                continue
            if in_comment:
                continue
            if in_dq:
                if c == '"' and _even_backslashes(text, i):
                    in_dq = False
                continue
            if c == '"':
                in_dq = True
            elif c == "'":
                sq_open = not sq_open
            elif c == "&":
                a = None if sq_open else _ANCHOR.match(text, i)
                if a is not None:  # a real definition: not in a comment or a quoted string
                    self.anchors.setdefault(a.group(1), []).append(i)
            elif c == "#" and (i == prev_end or text[i - 1] in " \t"):
                in_comment = True
            elif c in "[{":
                stack.append(i)
            elif c in "]}" and stack:
                self.close_of[stack.pop()] = i + 1
        for opener in stack:
            self.close_of[opener] = len(text)
        self.headers = [m.start() for m in _TOML_HEADER.finditer(text)]

    def line_start(self, pos: int) -> int:
        i = bisect.bisect_left(self.newlines, pos)
        return self.newlines[i - 1] + 1 if i else 0

    def line_end(self, pos: int) -> int:
        """The position of the line break ending the line that holds ``pos`` (or the text's end)."""
        i = bisect.bisect_left(self.newlines, pos)
        return self.newlines[i] if i < len(self.newlines) else len(self.text)

    def line_of(self, pos: int) -> int:
        return bisect.bisect_left(self.newlines, pos) + 1

    def next_header(self, pos: int) -> int:
        i = bisect.bisect_right(self.headers, pos)
        return self.headers[i] if i < len(self.headers) else len(self.text)

    def anchor_before(self, name: str, pos: int) -> int | None:
        """The last real definition of ``&name`` before ``pos`` (YAML 1.2: a redefined anchor
        names its latest definition), or the last one anywhere when none precedes it."""
        found = self.anchors.get(name)
        if not found:
            return None
        i = bisect.bisect_left(found, pos)
        return found[i - 1] if i else found[-1]


def _even_backslashes(text: str, i: int) -> bool:
    """True when the backslashes right before ``text[i]`` escape one another (an even run)."""
    n = 0
    while i - n - 1 >= 0 and text[i - n - 1] == "\\":
        n += 1
    return n % 2 == 0


def _quoted_end(text: str, start: int) -> int:
    """Just past the quoted scalar opening at ``text[start]`` (``"`` with backslash escapes,
    ``'`` with ``''``), however many lines it spans; the end of the text when it never closes."""
    q, i = text[start], start + 1
    while i < len(text):
        c = text[i]
        if q == '"' and c == "\\":
            i += 2
            continue
        if c == q:
            if q == "'" and text[i + 1 : i + 2] == "'":
                i += 2
                continue
            return i + 1
        i += 1
    return len(text)


_LINE_INDENT = re.compile(r"[ \t]*")
#: the rest of a line holding nothing (or a comment): the value starts on a later line
_BLANK_REST = re.compile(r"[ \t]*(?:#[^\n]*)?(?=\n|\Z)")
#: what precedes a value's first character: the separator, and any tags or anchors
_VALUE_HEAD = re.compile(r"[ \t]*[:=]?[ \t]*(?:[!&]\S*[ \t]+)*")


def _walk(idx: _Index, pos: int, indent: int, end: int) -> int:
    """From the line starting at ``pos``, the end of every following line indented deeper than
    ``indent`` (blank and comment lines included, and a ``- `` item at exactly ``indent``, which
    YAML allows under a key); ``end`` if no line is taken.  Reads each line's indent only."""
    text = idx.text
    while pos < len(text):
        j = _LINE_INDENT.match(text, pos).end()
        nl = idx.line_end(pos)
        c = text[j] if j < len(text) else "\n"
        col = j - pos
        item = col == indent and c == "-" and text[j + 1 : j + 2] in (" ", "\t", "\n", "")
        if c not in "\n#" and col <= indent and not item:
            break
        end, pos = nl, nl + 1
    return end


def _span(
    idx: _Index,
    key_start: int,
    key_end: int,
    header: bool,
    blocks: list[tuple[int, int, int]] | None = None,
) -> tuple[int, int]:
    """``(start, end)`` of the raw text a scope key holds, over-read rather than under-read.

    - A TOML table header holds everything up to the next header.
    - Any other key holds the rest of its line and every following line indented deeper than
      the key's own column (blank and comment lines included, and a ``- `` item at that column,
      which YAML allows).  The key's column, not its line's indent: for ``- scope:`` a sibling
      ``- `` item ends the span.
    - A value that is not on the key's line (``"scope":`` then ``{...}`` on the next line, at
      any indent) holds the first non-blank, non-comment line after it, and the lines indented
      deeper than that one.
    - A flow collection or a quoted scalar that the value starts with holds through its close,
      however its lines are indented; when it is on the key's line and nothing deeper follows,
      it is the whole value (the rest of a minified line after it is another key's).

    ``blocks`` (keys in order) holds the enclosing indented blocks: a key indented deeper inside
    one ends inside it, so its lines are not walked again.  Line starts and ends are bisected
    from ``idx``; no line is sliced per key, so a long line with many keys stays linear."""
    text = idx.text
    if header:
        return key_end, idx.next_header(key_end)
    key_col = key_start - idx.line_start(key_start)
    eol = idx.line_end(key_end)
    while blocks and key_start >= blocks[-1][1]:
        blocks.pop()
    # inside an enclosing block a deeper key ends where that block does: its lines are not
    # walked again
    inside = bool(blocks) and key_col > blocks[-1][2]  # type: ignore[index]
    end = blocks[-1][1] if inside else _walk(idx, eol + 1, key_col, eol)  # type: ignore[index]
    if blocks is not None:
        blocks.append((key_start, end, key_col))
    # where the value starts: on the key's line, or on the first later line with content
    value_at = key_end
    if _BLANK_REST.match(text, key_end):
        pos = eol + 1
        while pos < len(text):
            m = _BLANK_REST.match(text, pos)
            nl = idx.line_end(pos)
            if m is None:
                value_at = pos
                end = max(end, _walk(idx, nl + 1, _LINE_INDENT.match(text, pos).end() - pos, nl))
                break
            pos = nl + 1
    head = _VALUE_HEAD.match(text, value_at)
    first = head.end() if head else value_at
    close = None
    if first < len(text) and text[first] in "\"'":
        close = _quoted_end(text, first)
    elif first < len(text) and text[first] in "[{":
        close = idx.close_of.get(first)
    if close is None:
        return key_end, end
    if value_at == key_end and end == eol and not inside:
        # a quoted or flow value on the key's line, nothing deeper: the value is exactly that,
        # not the rest of a minified line ({"scope": "read", "iat": 1700000000})
        return key_end, close
    return key_end, max(end, close)


def _merged(spans: list[tuple[int, int, int]]) -> list[tuple[int, int, int]]:
    """Overlapping ``(start, end, line)`` spans merged (the first key's line kept): each
    character is judged once, however many scope keys hold it."""
    out: list[tuple[int, int, int]] = []
    for start, end, line in sorted(spans):
        if out and start <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], end), out[-1][2])
        else:
            out.append((start, end, line))
    return out


def _int_values(head: str) -> set[int]:
    """Every value one numeric part can be read as: decimal (underscores allowed, as in YAML 1.1
    and TOML), hex, binary, ``0o`` octal, and a leading-zero octal (YAML 1.1, ``inet_aton``)."""
    clean, low = head.replace("_", ""), head.lower()
    values: set[int] = set()
    for base, prefix in ((16, "0x"), (2, "0b"), (8, "0o")):
        if low.startswith(prefix):
            with contextlib.suppress(ValueError):
                values.add(int(clean[2:], base))
    if clean.isdigit():
        values.add(int(clean))
        if len(clean) > 1 and clean[0] == "0" and set(clean) <= set("01234567"):
            values.add(int(clean, 8))
    return values


def _is_internal(net: ipaddress.IPv4Network) -> bool:
    """Private (RFC 1918) or shared (RFC 6598) space: a lab's internal network."""
    return any(net.overlaps(n) for n in WAN_NOT_PUBLIC if n.version == 4)


def _version_like(parts: list[str]) -> bool:
    """Two or three plain decimal parts, each 0 to 255 (leading zeros allowed): ``1.0``,
    ``16.4``, ``24.04``, ``0.05``, ``1.0.3``.  A hex part or a part over 255 is no version."""
    return all(p.isdigit() and int(p) <= 255 for p in parts)


@functools.lru_cache(maxsize=65536)
def _numeric_offends(groups: tuple[str | None, ...], context: bool) -> bool:
    """A numeric token of :data:`_NUM_TOKEN` that names a non-documentation IPv4 address.

    - four dotted parts, any spelling: every ``inet_aton`` reading is judged (strict);
    - one part (an integer in any spelling, a float): judged when 2**24 or more (below that it
      is in 0/8, which names no host: ``maxItems: 6`` is not an address);
    - two or three parts (an ``inet_aton`` short form: ``10.20`` is the octets 10, 0, 0, 20):
      judged only when it cannot be a version or a decimal, that is when a part is hex or over
      255 (``81.2.17806``, ``0x51.0x2458e``, ``1.300``), or when it sits in an address context
      (a prefix length such as ``10.20/16``, a port, after ``//`` or ``@``).  Every other short
      form (``1.0``, ``24.04``, ``0.05``, ``1.0.3``, and a bare ``10.20``) is ignored.  A
      reading in 0/8 never counts.
    """
    head, dotted, exp, plen = groups
    if head is None:
        return False
    parts = [head, *dotted[1:].split(".")] if dotted else [head]
    nets: list[ipaddress.IPv4Network] = []
    if exp or len(parts) == 2:  # a float (1359103374.0, 1.36e9) read as the integer it holds
        try:
            f = float((head + (dotted or "") + (exp or "")).replace("_", ""))
        except ValueError:
            f = -1.0
        if f.is_integer() and 1 << 24 <= f < 1 << 32:
            nets.append(ipaddress.IPv4Network(int(f)))
    if exp:
        pass
    elif len(parts) == 1:
        nets += [ipaddress.IPv4Network(v) for v in _int_values(head) if 1 << 24 <= v < 1 << 32]
    elif "_" not in head and len(parts) <= 4:
        readings = [ipaddress.IPv4Network(a) for a in ipv4_readings(parts)]
        if len(parts) < 4:
            filled = parts + ["0"] * (4 - len(parts))
            readings += [ipaddress.IPv4Network(a) for a in ipv4_readings(filled)]
            if _version_like(parts) and not (context or plen is not None):
                readings = []  # a version or a decimal, never judged as an address
            # a short form in 0/8 names no host (0.300 reads as an address inside 0/8), as for an integer
            readings = [n for n in readings if int(n.network_address) >= 1 << 24]
        nets += readings
    if plen is not None and len(plen) > 2:  # "/1359103374" is no prefix length: an integer
        nets += [ipaddress.IPv4Network(v) for v in _int_values(plen) if 1 << 24 <= v < 1 << 32]
    for net in nets:
        if plen is not None and len(plen) <= 3 and int(plen) <= 32:
            net = ipaddress.IPv4Network((int(net.network_address), int(plen)), strict=False)
        if not _is_documentation(net):
            return True
    return False


def _offending_tokens(region: str) -> list[str]:
    """The address-like tokens of ``region`` that are not documentation addresses."""
    region = _ascii_digits(region)
    bad: list[str] = []
    masked = list(region)
    for m in _V6_TOKEN.finditer(region):
        # the numeric scan below must not read a hex group (``::1e8``) as a number; a dotted
        # IPv4 tail (``::ffff:`` and a dotted quad) stays visible to it
        tail = re.search(r"[0-9.]*$", m.group(1))
        stop = m.start(1) + (tail.start() if tail and "." in tail.group(0) else len(m.group(1)))
        masked[m.start() : stop] = " " * (stop - m.start())
        addr, plen = m.group(1).rstrip("."), m.group(2)
        try:
            ip6 = ipaddress.ip_address(addr)
        except ValueError:
            continue
        net6: ipaddress.IPv4Network | ipaddress.IPv6Network = ipaddress.ip_network(ip6)
        if plen is not None:
            with contextlib.suppress(ValueError):
                net6 = ipaddress.ip_network(f"{ip6}/{int(plen)}", strict=False)
        if not _is_documentation(net6):
            bad.append(m.group(0))
    region = "".join(masked)
    for m in _NUM_TOKEN.finditer(region):
        before, after = region[max(0, m.start() - 2) : m.start()], region[m.end() : m.end() + 2]
        context = before.endswith(("//", "@")) or re.match(r":[0-9]", after) is not None
        if _numeric_offends(m.groups(), context):
            bad.append(m.group(0))
    for m in _SEXAGESIMAL.finditer(region):
        value = 0
        for p in m.group(0).replace("_", "").split(":"):
            value = value * 60 + int(p)
        if value >= 1 << 24 and (
            value >= 1 << 32 or not _is_documentation(ipaddress.IPv4Network(value))
        ):
            bad.append(m.group(0))
    return bad


def _raw_findings(rel: str, text: str) -> list[Finding]:
    """Every scope key in ``text`` (line ends normalised; escapes decoded too): what it holds,
    as raw text, carries no address-like token outside the documentation ranges, and no
    ``!!binary`` value.  An alias under a scope key is followed to its anchor's last real
    definition before it, whose value is judged too; more than :data:`SCOPE_MAX_ALIASES`
    distinct aliases is itself a finding."""
    text = _newlines_normalised(text)
    texts = [text]
    decoded = _decoded(text)
    if decoded != text:
        texts.append(decoded)
    out: list[Finding] = []
    seen: set[str] = set()

    def add(detail: str) -> None:
        if detail not in seen:
            seen.add(detail)
            out.append(Finding(rel, "scope-address", detail))

    for t in texts:
        if "scope" not in t.casefold():
            continue
        idx = _Index(t)
        keys = [(m.start(), m.end(), False) for m in _SCOPE_KEY.finditer(t)]
        keys += [
            (m.start(), m.end(), True)
            for m in _TOML_HEADER.finditer(t)
            if any(p.strip(" \t\"'").casefold() == "scope" for p in m["path"].split("."))
        ]
        blocks: list[tuple[int, int, int]] = []
        spans = []
        for start, key_end, header in sorted(keys):
            a, b = _span(idx, start, key_end, header, blocks)
            spans.append((a, b, idx.line_of(start)))
        spans = _merged(spans)
        names: set[str] = set()
        todo = [(a, b) for a, b, _ in spans]
        while todo:  # an alias's anchor holds the value: judge it too (each name once)
            a, b = todo.pop()
            for alias in _ALIAS.finditer(t, a, b):
                name = alias.group(1)
                if name in names:
                    continue
                if len(names) >= SCOPE_MAX_ALIASES:
                    add(
                        f"line {idx.line_of(alias.start())}: more than {SCOPE_MAX_ALIASES} "
                        "distinct aliases under scope keys: not followed, so refused"
                    )
                    todo = []
                    break
                names.add(name)
                at = idx.anchor_before(name, alias.start())
                if at is not None:
                    got = _span(idx, at, at + 1 + len(name), False)
                    spans.append((got[0], got[1], idx.line_of(got[0])))
                    todo.append(got)
        for a, b, line in _merged(spans):
            region = t[a:b]
            if _BINARY.search(region):
                add(f"line {line}: a !!binary value under a scope key cannot be judged")
                continue
            tokens = _offending_tokens(region)
            if tokens:
                add(
                    f"line {line}: {tokens[0]!r} under a scope key is not a documentation "
                    "address (RFC 5737, 2001:db8::/32, 3fff::/20); the real scope is the "
                    "private overlay's lab/modules.yml"
                )
    return out


class _Pairs(list):
    """A JSON object's key/value pairs, duplicates kept."""


def _judge_scalar(value: str) -> str | None:
    tokens = _offending_tokens(value)
    return tokens[0] if tokens else None


def _parsed_findings(rel: str, text: str) -> list[Finding]:
    """The parse pass, unioned with the raw rule: every file that parses as JSON, TOML or YAML
    (by content, whatever its suffix; line ends normalised first; YAML composed only within
    :func:`_too_deep`'s size and depth bounds) has every scalar judged, keys included,
    under any mapping key whose resolved value casefolds to ``scope``, at any depth.  A key
    spelled by an alias, an explicit ``? scope`` with comments, a CRLF TOML header and a flow
    dedented anywhere are all just mappings here.  A file that does not parse is left to the
    raw rule (outside the allowlist), never a finding by itself."""
    import tomllib

    import yaml

    text = _newlines_normalised(text).removeprefix("﻿")
    if "scope" not in text.casefold() and "scope" not in _decoded(text).casefold():
        return []
    bad: dict[str, str] = {}  # where -> token, first per location

    def judge_tree(root: object, fmt: str) -> None:
        stack: list[tuple[object, str, bool]] = [(root, "$", False)]
        while stack:
            node, path, under = stack.pop()
            if isinstance(node, _Pairs | dict):
                items = node if isinstance(node, _Pairs) else list(node.items())
                for k, v in items:
                    inside = under or (isinstance(k, str) and k.casefold() == "scope")
                    if inside and isinstance(k, str) and (tok := _judge_scalar(k)):
                        bad.setdefault(f"{fmt} {path}.{k}", tok)
                    stack.append((v, f"{path}.{k}", inside))
            elif isinstance(node, list):
                stack += [(v, f"{path}[{i}]", under) for i, v in enumerate(node)]
            elif under and not isinstance(node, bool) and node is not None:
                if tok := _judge_scalar(str(node)):
                    bad.setdefault(f"{fmt} {path}", tok)

    with contextlib.suppress(ValueError, RecursionError):
        judge_tree(json.loads(text, object_pairs_hook=_Pairs), "json")
    with contextlib.suppress(tomllib.TOMLDecodeError, RecursionError, ValueError):
        judge_tree(tomllib.loads(text), "toml")
    if _too_deep(text) is None:
        # within those bounds libyaml's composer is safe (its recursion is per nesting level)
        loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
        try:
            docs = list(yaml.compose_all(text, Loader=loader))
        except (yaml.YAMLError, RecursionError, ValueError):
            docs = []
        seen: set[tuple[int, bool]] = set()
        stack: list[tuple[object, str, bool]] = [(d, "$", False) for d in docs]
        while stack:  # each composed node once: an alias is a shared node, never an expansion
            node, path, under = stack.pop()
            if (id(node), under) in seen:
                continue
            seen.add((id(node), under))
            if isinstance(node, yaml.MappingNode):
                for k, v in node.value:
                    name = k.value if isinstance(k, yaml.ScalarNode) else None
                    inside = under or (isinstance(name, str) and name.casefold() == "scope")
                    stack += [(k, f"{path}.<key>", inside), (v, f"{path}.{name}", inside)]
            elif isinstance(node, yaml.SequenceNode):
                stack += [(v, f"{path}[{i}]", under) for i, v in enumerate(node.value)]
            elif under and isinstance(node, yaml.ScalarNode):
                if node.tag.endswith(":binary"):
                    bad.setdefault(f"yaml {path}", "!!binary")
                elif tok := _judge_scalar(node.value):
                    bad.setdefault(f"yaml {path}", tok)
    return [
        Finding(
            rel,
            "scope-address",
            f"{where.removesuffix('.<key>')}: {tok!r} under a scope key (parsed) is not a "
            "documentation address",
        )
        for where, tok in sorted(bad.items())
    ]


# ---- the strict parse, for the allowlisted paths only ------------------------------------------


def _too_deep(text: str) -> str | None:
    """Why ``text`` is not handed to a parser, or None: larger than :data:`SCOPE_MAX_BYTES`, or
    nested deeper than :data:`SCOPE_MAX_DEPTH` (flow brackets, indentation, or a run of block
    indicators such as ``- - - -`` on one line)."""
    if len(text.encode("utf-8", "replace")) > SCOPE_MAX_BYTES:
        return f"larger than {SCOPE_MAX_BYTES // 1024} KiB"
    depth = deepest = 0
    for c in text:
        if c in "[{":
            depth += 1
            deepest = max(deepest, depth)
        elif c in "]}":
            depth = max(0, depth - 1)
    if deepest > SCOPE_MAX_DEPTH:
        return f"flow collections nested deeper than {SCOPE_MAX_DEPTH}"
    for line in text.splitlines():
        if _indent(line) > 2 * SCOPE_MAX_DEPTH:
            return f"indented deeper than {2 * SCOPE_MAX_DEPTH} columns"
        if re.match(rf"[ \t]*(?:[-?:][ \t]+){{{SCOPE_MAX_DEPTH}}}", line):
            return f"more than {SCOPE_MAX_DEPTH} block indicators on one line"
    return None


def _compose(text: str) -> tuple[list[object], set[int]]:
    """``(documents as YAML nodes, ids of nodes an alias points at)``, with the pure-Python
    loader (bounded first by :func:`_too_deep`).  Composing builds no Python objects: an unknown
    tag is data, a merge key and a duplicate key stay visible, and an alias is a shared node,
    never an expansion."""
    import yaml

    text = text.removeprefix("﻿")
    why = _too_deep(text)
    if why:
        raise _Unreadable(why)
    try:
        docs = list(yaml.compose_all(text, Loader=yaml.SafeLoader))
    except (yaml.YAMLError, RecursionError, ValueError) as exc:
        raise _Unreadable(exc.__class__.__name__) from exc
    return docs, _aliased(docs)


def _aliased(docs: list[object]) -> set[int]:
    """Ids of the nodes an alias points at: a composed node referenced more than once (a
    document's root counts as referenced by the document).  One pass, each node once, so a
    self-alias or a billion-laughs shape costs what its text does."""
    import yaml

    refs: dict[int, int] = {}
    stack = list(docs)
    for d in docs:
        refs[id(d)] = refs.get(id(d), 0) + 1
    seen: set[int] = set()
    while stack:
        node = stack.pop()
        if id(node) in seen:
            continue
        seen.add(id(node))
        if isinstance(node, yaml.SequenceNode):
            children = node.value
        elif isinstance(node, yaml.MappingNode):
            children = [x for pair in node.value for x in pair]
        else:
            continue
        for c in children:
            refs[id(c)] = refs.get(id(c), 0) + 1
            stack.append(c)
    return {i for i, n in refs.items() if n > 1}


#: the IPv6 prefixes whose last 32 bits are the embedded IPv4 address (RFC 6052 /96 layout);
#: the NAT64 local-use /48 places it elsewhere, so it is never read as documentation
_EMBEDDED_96 = tuple(e for e in EMBEDDED_V4 if e.prefixlen == 96)


def _is_documentation(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    """A documentation network, or a /96-layout IPv6 form embedding one (IPv4-mapped): the
    reader refuses that form, but it leaks nothing."""
    if is_documentation(net):
        return True
    if net.version == 6 and net.prefixlen >= 96 and any(net.subnet_of(e) for e in _EMBEDDED_96):
        low = int(net.network_address) & 0xFFFFFFFF
        return is_documentation(ipaddress.ip_network((low, net.prefixlen - 96)))
    return False


def _documentation_leaf(node: object) -> bool:
    """A site scope entry public git may hold: a string naming a documentation network, nothing
    (null), or the one malformed shape the generated negatives plant (a documentation address
    with an out-of-range prefix length of at most three digits, such as /33)."""
    import yaml

    if not isinstance(node, yaml.ScalarNode):
        return False
    if node.tag == _NULL:
        return True
    if node.tag != _STR or node.value != node.value.strip() or "%" in node.value:
        return False
    try:
        return _is_documentation(ipaddress.ip_network(node.value, strict=False))
    except ValueError:
        pass
    left, slash, right = node.value.rpartition("/")
    if not (slash and right.isascii() and right.isdigit() and len(right) <= 3):
        return False
    try:
        return _is_documentation(ipaddress.ip_network(ipaddress.ip_address(left)))
    except ValueError:
        return False


def _site_block(rel: str, block: object, where: str, aliased: set[int]) -> list[Finding]:
    """A site's network scope block: its shape is the module selection's (parts from
    SCOPE_PARTS only), and every entry is a documentation network."""
    import yaml

    out: list[Finding] = []

    def shape(path: str, why: str) -> None:
        if (rel, "scope-shape", path) in SCOPE_EXEMPT:
            return
        out.append(
            Finding(
                rel,
                "scope-shape",
                f"{path}: {why} (a public scope block holds documentation networks only, in the selection's shape)",
            )
        )

    def keys(node: yaml.MappingNode, allowed: Iterable[str], path: str) -> list[tuple[str, object]]:
        got, seen = [], set()
        for k, v in node.value:
            name = k.value if isinstance(k, yaml.ScalarNode) and k.tag == _STR else None
            if name is None or name not in allowed:
                at = f"{path}.{getattr(k, 'value', '?')}"
                shape(at, "not a scope part")
                entries(v, at)  # what an unknown part holds is still read (its key: the raw rule)
            elif name in seen:
                shape(
                    f"{path}.{name}",
                    "listed twice (a loader keeps one, a reader may see the other)",
                )
            else:
                seen.add(name)
                got.append((name, v))
        return got

    def entries(node: object, path: str) -> None:
        """Every scalar under ``node`` is a documentation network (or nothing)."""
        stack, seen = [(node, path)], set()
        while stack:
            n, at = stack.pop()
            if id(n) in seen or id(n) in aliased:
                if id(n) in aliased:
                    shape(at, "an anchor or alias")
                continue
            seen.add(id(n))
            if isinstance(n, yaml.SequenceNode):
                stack += [(v, f"{at}[{i}]") for i, v in enumerate(n.value)]
            elif isinstance(n, yaml.MappingNode):
                stack += [
                    (x, f"{at}.{getattr(k, 'value', '?')}") for k, v in n.value for x in (k, v)
                ]
            elif not _documentation_leaf(n):
                out.append(Finding(rel, "scope-address", f"{at}: not a documentation network"))

    def part(node: object, path: str) -> None:
        if id(node) in aliased:
            shape(path, "an anchor or alias")
        elif isinstance(node, yaml.ScalarNode) and node.tag == _NULL:
            return
        elif not isinstance(node, yaml.SequenceNode):
            shape(path, "not a list")
            entries(node, path)
        else:
            for i, item in enumerate(node.value):
                at = f"{path}[{i}]"
                if id(item) in aliased:
                    shape(at, "an anchor or alias")
                elif path.endswith(".trusted.wan") and _source(item):
                    continue
                elif not _documentation_leaf(item):
                    out.append(
                        Finding(
                            rel,
                            "scope-address",
                            f"{at}: not a documentation network (the real scope is the private overlay's lab/modules.yml)",
                        )
                    )

    tree = scope_tree()
    if id(block) in aliased:
        shape(where, "an anchor or alias")
        return out
    if not isinstance(block, yaml.MappingNode):
        shape(where, "not a mapping")
        entries(block, where)
        return out
    for group, v in keys(block, tree, where):
        leaves = tree[group]
        at = f"{where}.{group}"
        if leaves is None:
            part(v, at)
        elif id(v) in aliased:
            shape(at, "an anchor or alias")
        elif isinstance(v, yaml.MappingNode):
            for leaf, pv in keys(v, leaves, at):
                part(pv, f"{at}.{leaf}")
        elif not (isinstance(v, yaml.ScalarNode) and v.tag == _NULL):
            shape(at, "not a mapping")
            entries(v, at)
    return out


def _source(node: object) -> bool:
    """A dynamic WAN source, ``{source: <name>}``: it names no address."""
    import yaml

    if not (isinstance(node, yaml.MappingNode) and len(node.value) == 1):
        return False
    k, v = node.value[0]
    return (
        isinstance(k, yaml.ScalarNode) and k.value == "source"
        and isinstance(v, yaml.ScalarNode) and v.tag == _STR
        and re.fullmatch(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*", v.value) is not None
    )  # fmt: skip


def _strict_findings(rel: str, text: str) -> list[Finding]:
    """An allowlisted file (:data:`SCOPE_BLOCK_PATHS`), parsed strictly: each document is a
    mapping, its one ``scope`` key (exactly that spelling, at the top level) holds a block in the
    selection's shape, and a scope key anywhere else, in any case, is refused."""
    import yaml

    try:
        docs, aliased = _compose(text)
    except _Unreadable as exc:
        return [
            Finding(
                rel,
                "scope-unparsed",
                f"a scope block's file that the strict parse refuses ({exc}): refused, never skipped",
            )
        ]
    out: list[Finding] = []
    for doc in docs:
        if not isinstance(doc, yaml.MappingNode):
            if not (isinstance(doc, yaml.ScalarNode) and doc.tag == _NULL):
                out.append(Finding(rel, "scope-shape", "$: a document that is not a mapping"))
            continue
        tops = [(k, v) for k, v in doc.value if isinstance(k, yaml.ScalarNode)]
        scopes = [(k, v) for k, v in tops if k.value == "scope" and k.tag == _STR]
        if len(scopes) > 1:
            out.append(Finding(rel, "scope-shape", "scope: the scope key twice"))
        for _, v in scopes:
            out += _site_block(rel, v, "scope", aliased)
        skip = {id(v) for _, v in scopes}
        stack: list[tuple[object, str, bool]] = [(doc, "$", True)]
        seen: set[int] = set()
        while stack:  # every other scope key, at any depth and in any case, is misplaced
            node, path, top = stack.pop()
            if id(node) in seen or id(node) in skip:
                continue
            seen.add(id(node))
            if isinstance(node, yaml.SequenceNode):
                stack += [(v, f"{path}[{i}]", False) for i, v in enumerate(node.value)]
            elif isinstance(node, yaml.MappingNode):
                for k, v in node.value:
                    name = k.value if isinstance(k, yaml.ScalarNode) else None
                    selection_scope = top and name == "scope" and k.tag == _STR
                    if isinstance(k, yaml.CollectionNode) or (
                        isinstance(name, str) and name.casefold() == "scope" and not selection_scope
                    ):
                        out.append(
                            Finding(
                                rel,
                                "scope-shape",
                                f"{path}.{name}: a scope key other than the selection's "
                                "top-level scope, or a key the strict parse cannot read",
                            )
                        )
                    stack += [(k, path, False), (v, f"{path}.{name}", False)]
    return out


def _joined(value: object) -> str | None:
    """A notebook string field as one text: a list of line strings joined, or the string."""
    if isinstance(value, str):
        return value
    if isinstance(value, list) and all(isinstance(x, str) for x in value):
        return "".join(value)
    return None


def _notebook_findings(rel: str, text: str) -> list[Finding]:
    """A Jupyter notebook stores each cell's lines as separate JSON strings, so neither rule sees
    a scope block inside one.  Each cell's ``source``, and each output's ``text`` and textual
    ``data`` (``text/plain``, ``text/markdown``, ...), is joined into its text and run through
    both rules as if it were a file of its own."""
    if '"cells"' not in text:
        return []
    try:
        nb = json.loads(text)
    except (ValueError, RecursionError):
        return []
    cells = nb.get("cells") if isinstance(nb, dict) else None
    if not isinstance(cells, list):
        return []
    out: list[Finding] = []
    for n, cell in enumerate(cells):
        if not isinstance(cell, dict):
            continue
        texts = [_joined(cell.get("source"))]
        for o in cell.get("outputs") or []:
            if isinstance(o, dict):
                texts.append(_joined(o.get("text")))
                data = o.get("data")
                if isinstance(data, dict):
                    texts += [_joined(v) for k, v in data.items() if str(k).startswith("text/")]
        for t in texts:
            if t and "scope" in t.casefold():
                for f in _raw_findings(rel, t) + _parsed_findings(rel, t):
                    out.append(Finding(rel, f.rule, f"notebook cell {n}: {f.detail}"))
    return out


def _allowlist_case_variant(rel: str) -> bool:
    """A path that matches :data:`SCOPE_BLOCK_PATHS` only when case is ignored: on a
    case-insensitive file system a loader globbing the allowlist would read it, so it is refused
    rather than left to the raw rule alone."""
    low = rel.casefold()
    return not scope_block_path(rel) and any(
        fnmatch.fnmatchcase(low, g.casefold()) and rel.count("/") == g.count("/")
        for g in SCOPE_BLOCK_PATHS
    )


def scope_findings(rel: str, text: str) -> list[Finding]:
    """A site's network scope in one public file, the union of three rules: at an allowlisted
    path (:data:`SCOPE_BLOCK_PATHS`) the strict parse; everywhere the raw-text rule
    (:func:`_raw_findings`) and the parse pass (:func:`_parsed_findings`).  It never raises: a
    check that crashed would read as clean to a caller that catches, so any failure is itself a
    finding."""
    try:
        out: list[Finding] = []
        if scope_block_path(rel):
            out += _strict_findings(rel, text)
        elif _allowlist_case_variant(rel):
            out.append(
                Finding(
                    rel,
                    "scope-shape",
                    "a case variant of an allowlisted scope path: a case-insensitive file "
                    "system would load it as a site profile; use the exact name",
                )
            )
        out += _raw_findings(rel, text) + _parsed_findings(rel, text)
        return out + _notebook_findings(rel, text)
    except Exception as exc:  # fail closed: the gate never crashes open
        return [
            Finding(
                rel,
                "scope-unparsed",
                f"the scope check could not read it ({exc.__class__.__name__}): refused",
            )
        ]


def check_public(root: Path) -> list[Finding]:
    skeleton_marker = root / SKELETON / MARKER
    private_paths: list[str] = []
    if skeleton_marker.is_file():
        private_paths = [
            p.rstrip("/") + "/" for p in read_marker(skeleton_marker).get("private_paths", [])
        ]
    out: list[Finding] = []
    for rel, f in _files(root):
        in_skeleton = rel.startswith(SKELETON)
        name = rel.rsplit("/", 1)[-1]
        if _is_key_file(rel):
            out.append(Finding(rel, "key-file", "a decryption key must never be committed"))
        if name == MARKER:
            fictional = in_skeleton and read_marker(f).get("fictional") is True
            if not fictional:
                out.append(
                    Finding(rel, "overlay-marker", "a private overlay is committed in public git")
                )
        if name == SOPS_CONFIG and not in_skeleton:
            out.append(Finding(rel, "sops-config", "SOPS config belongs to the private overlay"))
        hit = next((p for p in private_paths if rel.startswith(p)), None)
        if hit:
            out.append(Finding(rel, "overlay-path", f"under the private layout path {hit}"))
        text = _text(f)
        if text is None:
            continue
        if f.suffix in (".yml", ".yaml", ".json", ".env", ".ini") and sops_format(text):
            out.append(Finding(rel, "ciphertext", "a SOPS-encrypted file in public git"))
            continue
        out += scope_findings(rel, text)
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("mode", choices=("private", "public"))
    ap.add_argument("root", nargs="?", default=".", help="checkout root (default: .)")
    args = ap.parse_args(argv)
    root = Path(args.root)
    if not root.is_dir():
        print(f"private_leak_check: not a directory: {root}", file=sys.stderr)
        return EXIT_CONFIG
    try:
        found = check_private(root) if args.mode == "private" else check_public(root)
    except (ConfigError, leak_scan.ConfigError) as exc:
        print(f"private_leak_check: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    for f in found:
        print(f)
    if found:
        print(f"private_leak_check: {len(found)} finding(s) ({args.mode})", file=sys.stderr)
        return EXIT_HIT
    print(f"private_leak_check: clean ({args.mode})")
    return EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
