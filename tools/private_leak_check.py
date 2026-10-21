#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: private-leak-check
#   kind: check
#   purpose: Fail when a private overlay holds a plaintext secret or an unencrypted sealed file, or when this public tree holds any part of a private overlay.
#   owner: maintainers
#   trigger: [ci:ci/schemas, make:private-overlay-check]
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
                 SOPS ``ENC[...]`` values, the ``sops`` metadata and vault payloads are masked
                 first: ciphertext is not a leak.
  sops-unencrypted
                 a file a ``creation_rules[].path_regex`` of ``.sops.yaml`` covers that carries
                 no SOPS metadata, i.e. what should be sealed was committed in the clear.
  vault-unencrypted
                 a file the marker's ``ansible_vault_files`` globs (or the usual names: ``vault.yml``,
                 ``*.vault``, ``*.vault.yml``) name that does not start with the ansible-vault
                 envelope header.
  key-file       a decryption key committed next to the ciphertext it opens: an age identity
                 file, a vault password file (see :data:`KEY_FILE_GLOBS`).

``public ROOT`` is the reverse guard for THIS repository: nothing of a private overlay may be
committed here.  The fictional skeleton under ``examples/private-overlay/`` is the one exception,
and only while its marker says ``fictional: true``.  Findings:

  overlay-marker   a ``.hnx-private-overlay.yml`` outside the skeleton (or not fictional);
  overlay-path     a file under one of the skeleton marker's ``private_paths`` (the private
                   layout, e.g. ``lab/``), at the root of this tree;
  sops-config      a ``.sops.yaml`` outside the skeleton;
  ciphertext       a SOPS-encrypted file (sealed real data does not belong in public git
                   either: it is one leaked key away from plain text);
  key-file         as above.

Files are what ``tools/leak_scan.py`` scans: in a git work tree the tracked and untracked,
not-ignored files.  Usage::

    python3 tools/private_leak_check.py private /path/to/private-overlay
    python3 tools/private_leak_check.py public .
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import leak_scan  # noqa: E402  (also puts the checkout on sys.path for homelabnext)

from homelabnext import sops  # noqa: E402

EXIT_CLEAN, EXIT_HIT, EXIT_CONFIG = 0, 1, 2

MARKER = ".hnx-private-overlay.yml"
SOPS_CONFIG = ".sops.yaml"
SKELETON = "examples/private-overlay/"
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
_ENC = re.compile(r"ENC\[[A-Z0-9_]+,data:[^\]]*\]")
_HEX_LINE = re.compile(r"^\s*[0-9a-f]{16,}\s*$")
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


def _text(path: Path) -> str | None:
    got = leak_scan.read_text_file(path)
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
    for key in ("ansible_vault_files", "private_paths"):
        v = doc.get(key, [])
        if not isinstance(v, list) or not all(isinstance(x, str) and x for x in v):
            raise ConfigError(f"{path}: {key} must be a list of non-empty strings")
    return doc


def sops_rules(root: Path) -> list[re.Pattern[str]]:
    """The ``path_regex`` of every creation rule in ROOT/.sops.yaml (empty when there is none)."""
    p = root / SOPS_CONFIG
    if not p.is_file():
        return []
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
            out.append(re.compile(rx))
        except re.error as exc:
            raise ConfigError(f"{p}: creation_rules[{i}].path_regex: {exc}") from exc
    return out


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


def masked(text: str) -> str:
    """``text`` with ciphertext blanked: SOPS values and metadata, ansible-vault payloads.

    Line numbers are kept for YAML, dotenv, ini and vault; a SOPS JSON file is re-serialised."""
    fmt = sops_format(text)
    if fmt == "json":
        doc = json.loads(text)
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
    text = _ENC.sub("ENC[]", text)
    if VAULT_HEADER in text:
        if text.lstrip().startswith(VAULT_HEADER):
            return ""
        text = "\n".join(
            "" if VAULT_HEADER in ln or _HEX_LINE.match(ln) else ln for ln in text.splitlines()
        )
    return text


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


def check_private(root: Path) -> list[Finding]:
    marker = root / MARKER
    if not marker.is_file():
        raise ConfigError(
            f"{root} has no {MARKER}: the private rules (real addresses allowed) only run on a "
            "repository that declares itself a private overlay"
        )
    doc = read_marker(marker)
    vaulted = [*DEFAULT_VAULT_GLOBS, *doc.get("ansible_vault_files", [])]
    rules = sops_rules(root)
    patterns = [
        p for p in leak_scan.PATTERNS if p.group == "secret" and p.name not in NAME_ONLY_PATTERNS
    ]
    out: list[Finding] = []
    for rel, f in _files(root):
        if _is_key_file(rel):
            out.append(Finding(rel, "key-file", "a decryption key must never be committed"))
            continue
        text = _text(f)
        if text is None:
            if any(rx.search(rel) for rx in rules) or _matches(rel, vaulted):
                out.append(Finding(rel, "unscannable", "binary or unreadable sealed file"))
            continue
        if any(rx.search(rel) for rx in rules) and sops_format(text) is None:
            out.append(
                Finding(rel, "sops-unencrypted", f"{SOPS_CONFIG} says it is sealed; it is not")
            )
            continue  # its content is the leak; do not echo it line by line
        if _matches(rel, vaulted) and not text.lstrip().startswith(VAULT_HEADER):
            out.append(
                Finding(rel, "vault-unencrypted", "a vault file without the ansible-vault header")
            )
            continue
        for h in leak_scan.scan_text(masked(text), rel, patterns):
            out.append(Finding(rel, "secret", f"line {h.line}: {h.pattern} {h.shown}"))
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
        if f.suffix in (".yml", ".yaml", ".json", ".env", ".ini"):
            text = _text(f)
            if text is not None and sops_format(text):
                out.append(Finding(rel, "ciphertext", "a SOPS-encrypted file in public git"))
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
