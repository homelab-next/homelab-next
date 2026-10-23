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
  scope-address    a site's network scope in public git: an entry of a site scope block that
                   is not a documentation network (RFC 5737, ``2001:db8::/32``, ``3fff::/20``).
                   Strict: every leaf counts, in any spelling (a zero-padded, integer or hex
                   address, a YAML or JSON number, a tagged value, ``0.0.0.0/0``, a widened
                   documentation prefix, free text); the one malformed shape let through is a
                   documentation address with an out-of-range prefix length, which the
                   generated negative plants (a /33).  Also an address under a
                   ``scope`` key that is not a site block (``scope: [<address>]``);
  scope-shape      a site scope block not in the selection's shape: a part outside
                   ``SCOPE_PARTS`` (what it holds is still read), a part or ``scope`` key twice,
                   an anchor or alias, a part that is not a list, a group that is not a mapping;
  scope-unparsed   a file that mentions a scope (or could spell the key with an escape) and does
                   not parse: a scope block nobody can read is refused, never skipped.
                   A site scope block is the value of a ``scope`` key at any depth, in any case,
                   in every document of a ``.yml``/``.yaml``/``.json``/``.toml`` file (template
                   suffixes such as ``.j2`` and ``.example`` read as the format under them) and
                   of a Markdown yaml, json or toml fence (an untagged fence when it parses),
                   unless it holds only another document's scope keys
                   (:data:`FOREIGN_SCOPE_KEYS`: a customization's selectors, an MCP parameter,
                   JSON Schema keywords).  The real scope lives in the overlay's
                   ``lab/modules.yml``.  :data:`SCOPE_EXEMPT` lets through one location of the
                   generated misspelt-part negative;
  key-file         as above.

Files are what ``tools/leak_scan.py`` scans: in a git work tree the tracked and untracked,
not-ignored files.  Usage::

    python3 tools/private_leak_check.py private /path/to/private-overlay
    python3 tools/private_leak_check.py public .
"""

from __future__ import annotations

import argparse
import binascii
import fnmatch
import ipaddress
import json
import re
import sys
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
    embedded_ipv4,
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

#: suffixes stripped before the format is read (``site.yml.j2``, ``lab.yaml.example``)
_TEMPLATE_SUFFIXES = (".j2", ".jinja", ".jinja2", ".example", ".sample", ".tmpl", ".template")
#: the formats a scope block is read in, by (lower-case) suffix
SCOPE_FORMATS = {
    ".yml": "yaml",
    ".yaml": "yaml",
    ".json": "json",
    ".toml": "toml",
    ".md": "md",
    ".markdown": "md",
}
#: keys a ``scope`` mapping has in other documents: a customization's selectors
#: (platform/customization), an MCP server's parameter (platform/mcp_server, a parameter named
#: ``scope``) and JSON Schema keywords (a schema's ``scope`` property).  A mapping
#: holding only these is not a site's network scope; one with any other key is, so a misspelt
#: part is read as a site scope block and refused, never skipped.
FOREIGN_SCOPE_KEYS = frozenset(
    {"capabilities", "services", "roles", "hosts"}
    | {"env"}
    | {
        "$comment", "$ref", "additionalProperties", "allOf", "anyOf", "const", "default",
        "deprecated", "description", "else", "enum", "examples", "format", "if", "items",
        "maxItems", "maxLength", "maxProperties", "minItems", "minLength", "minProperties",
        "not", "oneOf", "pattern", "patternProperties", "properties", "propertyNames",
        "required", "then", "title", "type", "uniqueItems",
    }
)  # fmt: skip
_STR = "tag:yaml.org,2002:str"
_NULL = "tag:yaml.org,2002:null"
#: a fenced block in Markdown: its info string, its body
_FENCE = re.compile(
    r"^(?P<fence>`{3,}|~{3,})[ \t]*(?P<lang>[\w+-]*)[^\n]*\n(?P<body>.*?)^(?P=fence)[ \t]*$",
    re.M | re.S,
)
_FENCE_FORMATS = {"yaml": "yaml", "yml": "yaml", "json": "json", "jsonc": "json", "toml": "toml"}
#: a YAML or JSON escape that could spell the scope key without the word in the text
_KEY_ESCAPE = re.compile(r"\\[xuU]")


_DOTTED_ANY = re.compile(r"(?:0[xX][0-9A-Fa-f]+|[0-9]+)(?:\.(?:0[xX][0-9A-Fa-f]+|[0-9]+)){3}")
_INT_ANY = re.compile(r"0[xX][0-9A-Fa-f]{1,8}|[0-9]{1,10}")


#: (file, finding) pairs the public check lets through, each with its reason.  Narrow on
#: purpose: one location in one generated file, and the entries under it are still read.
SCOPE_EXEMPT = {
    (
        "schemas/platform/negative/module_selection.scope-unknown-part.yml",
        "scope-shape",
        "scope.trusted.lan",  # scrub-allow: the generated negative misspelt part
    ): "the generated negative for a misspelt part (homelabnext.schemas): it must be misspelt",
}


class _Unreadable(Exception):
    """A document that may hold a scope block and does not parse: a finding, never a skip."""


def scope_format(rel: str) -> str | None:
    """The format a public file is read in for scope blocks, or None (not read)."""
    name = rel.rsplit("/", 1)[-1].lower()
    while name.endswith(_TEMPLATE_SUFFIXES):
        name = name[: name.rfind(".")]
    dot = name.rfind(".")
    return SCOPE_FORMATS.get(name[dot:]) if dot > 0 else None


def _node(obj: object) -> object:
    """A YAML node for a value parsed as JSON or TOML (so one walk reads every format); a JSON
    object keeps its duplicate keys (``object_pairs_hook``)."""
    import yaml

    if isinstance(obj, _Pairs | dict):
        items = obj if isinstance(obj, _Pairs) else list(obj.items())
        return yaml.MappingNode(
            "tag:yaml.org,2002:map", [(yaml.ScalarNode(_STR, k), _node(v)) for k, v in items]
        )
    if isinstance(obj, list):
        return yaml.SequenceNode("tag:yaml.org,2002:seq", [_node(v) for v in obj])
    if obj is None:
        return yaml.ScalarNode(_NULL, "")
    if isinstance(obj, str):
        return yaml.ScalarNode(_STR, obj)
    kind = {bool: "bool", int: "int", float: "float"}.get(type(obj), "timestamp")
    return yaml.ScalarNode(f"tag:yaml.org,2002:{kind}", str(obj))


class _Pairs(list):
    """A JSON object's key/value pairs, duplicates kept."""


def _compose(text: str, fmt: str) -> tuple[list[object], set[int]]:
    """``(documents as YAML nodes, ids of nodes an alias points at)``.  Composing builds no
    Python objects: an unknown tag (``!vault``, ``!Ref``) is data, a merge key and a duplicate
    key stay visible, and an alias is a shared node, never an expansion."""
    import yaml

    text = text.removeprefix("\ufeff")
    if fmt == "toml":
        import tomllib

        try:
            return [_node(tomllib.loads(text))], set()
        except (tomllib.TOMLDecodeError, RecursionError) as exc:
            raise _Unreadable(exc.__class__.__name__) from exc

    if fmt == "json":
        try:  # JSON's own parser first: fast, and it keeps duplicate keys (no aliases in JSON)
            return [_node(json.loads(text, object_pairs_hook=_Pairs))], set()
        except (ValueError, RecursionError):
            pass  # JSON with comments, or not JSON: YAML may still read it
    error: Exception | None = None
    for loader in (getattr(yaml, "CSafeLoader", None), yaml.SafeLoader):
        if loader is None:
            continue
        try:
            docs = list(yaml.compose_all(text, Loader=loader))
        except (yaml.YAMLError, RecursionError) as exc:
            error = exc
            continue
        return docs, _aliased(docs)
    raise _Unreadable(error.__class__.__name__)


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


def _networks(node: object) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Every network a scalar can be read as: strict text, a zone-id or zero-padded or hex
    dotted quad (decimal and ``inet_aton`` readings), a ``0x`` or decimal integer string, or a
    YAML or JSON integer.  Empty when it names no address."""
    import yaml

    if not isinstance(node, yaml.ScalarNode):
        return []
    value = node.value.strip()
    if node.tag == "tag:yaml.org,2002:int":
        try:
            n = int(value.replace("_", ""), 0)
        except ValueError:
            return []
        return [ipaddress.ip_network(n)] if 0 <= n < 1 << 128 else []
    try:
        return [ipaddress.ip_network(value.split("%", 1)[0], strict=False)]
    except ValueError:
        pass
    host, _, plen = value.partition("/")
    readings = []
    if _DOTTED_ANY.fullmatch(host):
        readings = ipv4_readings(host.split("."))
    elif _INT_ANY.fullmatch(host):
        n = int(host, 16) if host[:2].lower() == "0x" else int(host)
        readings = [ipaddress.IPv4Address(n)] if n < 1 << 32 else []
    out = []
    for a in readings:
        try:
            out.append(ipaddress.ip_network(f"{a}/{plen}" if plen else a, strict=False))
        except ValueError:
            out.append(ipaddress.ip_network(a))
    return out


def _is_documentation(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    """A documentation network, or an IPv6 form embedding one (IPv4-mapped): the
    reader refuses that form, but it leaks nothing."""
    if is_documentation(net):
        return True
    if embedded_ipv4(net) and net.prefixlen >= 96:
        low = int(net.network_address) & 0xFFFFFFFF
        return is_documentation(ipaddress.ip_network((low, net.prefixlen - 96)))
    return False


def _documentation_leaf(node: object) -> bool:
    """A site scope entry public git may hold: a string naming a documentation network, nothing
    (null), or the one malformed shape the generated negatives plant (a documentation address
    with an out-of-range prefix length, such as /33)."""
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
    if not (slash and right.isascii() and right.isdigit()):
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
                entries(v, at)  # what an unknown part holds is still read
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


def _document_findings(rel: str, root: object, aliased: set[int]) -> list[Finding]:
    """Every ``scope`` key at any depth, in any case: a mapping that is not a foreign scope
    (:data:`FOREIGN_SCOPE_KEYS`) is a site block; a scalar or list under it may not name a
    non-documentation address; a tagged value under it cannot be read and is refused."""
    import yaml

    out: list[Finding] = []
    seen: set[int] = set()
    stack: list[tuple[object, str]] = [(root, "$")]
    while stack:  # iterative, each node once: an alias is never expanded
        node, path = stack.pop()
        if id(node) in seen:
            continue
        seen.add(id(node))
        if isinstance(node, yaml.SequenceNode):
            stack += [(v, f"{path}[{i}]") for i, v in enumerate(node.value)]
            continue
        if not isinstance(node, yaml.MappingNode):
            continue
        scopes = []
        for k, v in node.value:
            name = k.value if isinstance(k, yaml.ScalarNode) else None
            if isinstance(name, str) and name.casefold() == "scope":
                scopes.append((name, v))
            else:
                stack += [(k, path), (v, f"{path}.{name}")]
        if len(scopes) > 1:
            out.append(
                Finding(
                    rel,
                    "scope-shape",
                    f"{path}: a scope key twice (a loader keeps one, a reader may see the other)",
                )
            )
        for name, v in scopes:
            at = f"{path}.{name}".removeprefix("$.")
            keys_ = (
                {k.value for k, _ in v.value if isinstance(k, yaml.ScalarNode)}
                if isinstance(v, yaml.MappingNode)
                else set()
            )
            if isinstance(v, yaml.MappingNode) and not (
                keys_ and keys_ <= FOREIGN_SCOPE_KEYS and len(keys_) == len(v.value)
            ):
                out += _site_block(rel, v, at, aliased)
                seen.add(id(v))
            elif isinstance(v, yaml.MappingNode):
                stack.append((v, at))  # a customization's scope or a schema property
            elif (
                isinstance(v, yaml.ScalarNode)
                and v.tag not in (_STR, _NULL)
                and not v.tag.startswith("tag:yaml.org,2002:")
            ):
                out.append(
                    Finding(
                        rel,
                        "scope-shape",
                        f"{at}: a tagged value ({v.tag}) under a scope key cannot be read",
                    )
                )
            else:
                items = v.value if isinstance(v, yaml.SequenceNode) else [v]
                for item in items:
                    if any(not _is_documentation(n) for n in _networks(item)):
                        out.append(
                            Finding(
                                rel,
                                "scope-address",
                                f"{at}: an address outside the documentation ranges",
                            )
                        )
                        break
                    if not isinstance(item, yaml.ScalarNode):
                        stack.append((item, at))
    return out


def scope_findings(rel: str, text: str, fmt: str | None = None) -> list[Finding]:
    """A site's network scope in a public file: every ``scope`` key, at any depth and in any
    case, in every document (YAML multi-document, JSON with or without duplicate keys, TOML,
    and the yaml, json and toml fenced blocks of Markdown; template suffixes such as ``.j2`` and
    ``.example`` are read as the format under them).  A document that may hold a scope key and
    does not parse is a finding (``scope-unparsed``), never a skip."""
    fmt = fmt or scope_format(rel)
    if fmt is None:
        return []
    if fmt == "md":
        out = []
        for m in _FENCE.finditer(text):
            lang = m.group("lang").lower()
            sub = _FENCE_FORMATS.get(lang)
            body = m.group("body")
            line = text.count("\n", 0, m.start()) + 1
            if sub is None and lang:
                continue  # another language's block
            if sub is None:  # an untagged block: read only when it parses (it may be shell)
                try:
                    _compose(body, "yaml")
                except _Unreadable:
                    continue
                sub = "yaml"
            out += scope_findings(f"{rel}:{line}", body, sub)
        return out
    mentions = "scope" in text.casefold()
    if not (mentions or _KEY_ESCAPE.search(text)):
        return []  # no document here can spell a scope key
    try:
        docs, aliased = _compose(text, fmt)
    except _Unreadable as exc:
        if mentions or _KEY_ESCAPE.search(text):
            return [
                Finding(
                    rel,
                    "scope-unparsed",
                    f"mentions a scope and does not parse as {fmt} ({exc}): a scope block nobody can read is refused, never skipped",
                )
            ]
        return []
    out = []
    for doc in docs:
        out += _document_findings(rel, doc, aliased)
    return out


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
        fmt = scope_format(rel)
        if f.suffix in (".yml", ".yaml", ".json", ".env", ".ini") or fmt:
            text = _text(f)
            if text is not None and sops_format(text):
                out.append(Finding(rel, "ciphertext", "a SOPS-encrypted file in public git"))
            elif text is not None and fmt:
                out += [
                    x
                    for x in scope_findings(rel, text, fmt)
                    if (x.path, x.rule, x.detail.split(":", 1)[0]) not in SCOPE_EXEMPT
                ]
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
