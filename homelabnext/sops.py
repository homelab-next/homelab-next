# SPDX-License-Identifier: Apache-2.0
"""Read a data file that may be SOPS-encrypted (docs/private-overlay.md, ADR-0021).

A private overlay may keep some of its data files (a site, a registry, a guest) encrypted per file
with SOPS and age.  The document readers call :func:`read_text` instead of ``Path.read_text``: a
plain file comes back unchanged; a file that carries SOPS metadata (a top-level ``sops`` mapping
with a ``mac`` or ``version`` key, in YAML or JSON) is decrypted by the ``sops`` binary and the
plaintext comes back.  The plaintext stays in memory: nothing is written to disk.

SOPS is optional and never a Python dependency.  The binary is ``$HNX_SOPS`` when set, else
``sops`` on ``PATH``; it runs without a shell, with stdin closed and a timeout, and finds its own
keys the way it always does (``SOPS_AGE_KEY_FILE``, ``SOPS_AGE_KEY``, ...).  When the file is
encrypted and the binary is missing, fails or times out, :class:`SopsError` says so: ciphertext is
never handed to a reader as if it were data.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import Any

__all__ = [
    "MAX_TEXT_BYTES",
    "SOPS_ENV",
    "TIMEOUT",
    "SopsError",
    "decrypt",
    "format_of",
    "is_encrypted",
    "read_text",
]

SOPS_ENV = "HNX_SOPS"
TIMEOUT = 30.0  # seconds; a decrypt that needs longer is waiting on something it will not get
_MAX_DETAIL = 300

# cheap pre-filters: only a file that matches one is parsed a second time to confirm
_YAML_KEY = re.compile(r"^sops:[ \t]*$", re.MULTILINE)
_JSON_KEY = re.compile(r'"sops"\s*:\s*\{')
_UNPRINTABLE = re.compile(r"[^\x20-\x7e]+")


class SopsError(ValueError):
    """A SOPS-encrypted file could not be decrypted (or the binary is not available)."""


#: the largest text :func:`read_text` reads (and :func:`format_of` sniffs): far above any data
#: file of a lab, and a bound on what one file can cost every reader that walks it
MAX_TEXT_BYTES = 16 * 1024 * 1024


def _metadata(doc: Any) -> bool:
    meta = doc.get("sops") if isinstance(doc, Mapping) else None
    return isinstance(meta, Mapping) and ("mac" in meta or "version" in meta)


def _yaml_metadata(text: str) -> bool:
    """Whether YAML ``text``'s top level is a mapping with a ``sops`` mapping holding ``mac`` or
    ``version``, read from the composed node graph only: nothing is constructed, so no alias or
    merge is expanded, and any alias, a document past the shared expansion budget or nesting too
    deep reads as not encrypted (the caller's own reader then refuses it as it would any file)."""
    import yaml

    from homelabnext._yaml import BudgetedLoader

    class _Sniff(BudgetedLoader):
        allow_aliases = False

    try:
        node = yaml.compose(text, Loader=_Sniff)
    except (yaml.YAMLError, RecursionError):
        return False
    if not isinstance(node, yaml.MappingNode):
        return False
    for k, v in node.value:
        if isinstance(k, yaml.ScalarNode) and k.value == "sops" and isinstance(v, yaml.MappingNode):
            keys = {sk.value for sk, _ in v.value if isinstance(sk, yaml.ScalarNode)}
            if keys & {"mac", "version"}:
                return True
    return False


def format_of(text: str) -> str | None:
    """``"json"`` or ``"yaml"`` when ``text`` is a SOPS-encrypted document, else ``None``."""
    if len(text) > MAX_TEXT_BYTES:
        return None  # read_text refuses it before asking; nothing this size is sniffed
    if text.lstrip().startswith("{"):
        if not _JSON_KEY.search(text):
            return None
        try:
            return "json" if _metadata(json.loads(text)) else None
        except (ValueError, RecursionError):
            return None
    if not _YAML_KEY.search(text):
        return None
    # only a file that looks encrypted pays for the second read, which composes and never
    # constructs
    return "yaml" if _yaml_metadata(text) else None


def is_encrypted(text: str) -> bool:
    return format_of(text) is not None


def _binary(env: Mapping[str, str]) -> str | None:
    explicit = env.get(SOPS_ENV)
    if explicit:
        return explicit if Path(explicit).is_file() else None
    return shutil.which("sops", path=env.get("PATH"))


def _detail(raw: bytes) -> str:
    """The last non-empty line of sops's stderr, printable ASCII only and bounded."""
    lines = [ln for ln in raw.decode("utf-8", "replace").splitlines() if ln.strip()]
    text = _UNPRINTABLE.sub(" ", lines[-1]).strip() if lines else "no message"
    return text[:_MAX_DETAIL]


def decrypt(
    path: str | Path,
    fmt: str,
    *,
    env: Mapping[str, str] | None = None,
    timeout: float = TIMEOUT,
) -> str:
    """Plaintext of the SOPS file ``path`` (``fmt`` is ``yaml`` or ``json``)."""
    if fmt not in ("yaml", "json"):
        raise ValueError(f"unsupported SOPS format {fmt!r}")
    e = os.environ if env is None else env
    p = Path(path)
    sops = _binary(e)
    if sops is None:
        where = f"${SOPS_ENV} ({e[SOPS_ENV]})" if e.get(SOPS_ENV) else "sops on PATH"
        raise SopsError(
            f"{p} is SOPS-encrypted and {where} was not found: install sops and give it the age "
            f"key (SOPS_AGE_KEY_FILE), or set {SOPS_ENV} to the binary; hnx never reads ciphertext "
            "as data"
        )
    argv = [sops, "--decrypt", "--input-type", fmt, "--output-type", fmt, str(p)]
    try:
        done = subprocess.run(
            argv,
            capture_output=True,
            stdin=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
            env=dict(e),
        )
    except subprocess.TimeoutExpired as exc:
        raise SopsError(f"{p}: sops did not finish within {timeout:g} s") from exc
    except OSError as exc:
        raise SopsError(f"{p}: cannot run sops: {exc.__class__.__name__}") from exc
    if done.returncode != 0:
        raise SopsError(
            f"{p}: sops --decrypt failed (exit {done.returncode}): {_detail(done.stderr)}"
        )
    try:
        plain = done.stdout.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SopsError(f"{p}: sops returned output that is not UTF-8") from exc
    if format_of(plain) is not None:
        raise SopsError(f"{p}: sops returned a document that still carries SOPS metadata")
    return plain


def read_text(path: str | Path, *, env: Mapping[str, str] | None = None) -> str:
    """The text of ``path``, decrypted first when it is a SOPS-encrypted YAML or JSON document.

    Raises ``OSError`` when the file cannot be read and :class:`SopsError` when it is encrypted
    and cannot be decrypted, or is over :data:`MAX_TEXT_BYTES`."""
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if len(text) > MAX_TEXT_BYTES:
        raise SopsError(f"{p}: over {MAX_TEXT_BYTES} bytes: refused before it is read as data")
    fmt = format_of(text)
    return text if fmt is None else decrypt(p, fmt, env=env)
