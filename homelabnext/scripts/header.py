# SPDX-License-Identifier: Apache-2.0
"""The script header: a YAML block in comments near the top of every script.

    #!/usr/bin/env python3
    # SPDX-License-Identifier: Apache-2.0
    # hnx-script:
    #   id: leak-scan
    #   kind: check
    #   purpose: Fail when the tree carries a private identifier or a secret.
    #   ...

The marker line is exactly ``# hnx-script:`` and must sit within the first :data:`SCAN_LINES`
lines (after a shebang, the SPDX line and any usage comment).  The block is every following line
that starts with ``#`` plus at least two spaces; the first line that does not ends it.  The
block is parsed as YAML and validated against ``schemas/platform/script_header.schema.json``
plus the semantic rules JSON Schema cannot express (:func:`validate`).
"""

from __future__ import annotations

import json
import re
from typing import Any

from homelabnext import paths

__all__ = ["MARKER", "SCAN_LINES", "HeaderError", "find_header", "validate"]

MARKER = "# hnx-script:"
SCAN_LINES = 40
_MARKER_RE = re.compile(r"^# hnx-script:\s*$")
_BODY_RE = re.compile(r"^# {2,}\S")
_FAIL_CODE = re.compile(r"^([1-9]|[1-9][0-9])$")


class HeaderError(ValueError):
    """The header is present but cannot be read as YAML."""


def find_header(text: str) -> dict[str, Any] | None:
    """The parsed header of a script's text, None when there is no marker line.

    Raises :class:`HeaderError` when the marker is there but the block is empty or not YAML.
    """
    import yaml

    lines = text.splitlines()[:SCAN_LINES]
    start = next((i for i, line in enumerate(lines) if _MARKER_RE.match(line)), None)
    if start is None:
        return None
    body = []
    for line in text.splitlines()[start + 1 :]:
        if not _BODY_RE.match(line):
            break
        body.append(line[1:])
    if not body:
        raise HeaderError(f"line {start + 1}: '{MARKER}' is followed by no indented block")
    try:
        doc = yaml.safe_load("hnx-script:\n" + "\n".join(body))
    except yaml.YAMLError as exc:
        raise HeaderError(
            f"line {start + 1}: header is not YAML ({exc.__class__.__name__})"
        ) from exc
    head = doc["hnx-script"]
    if isinstance(head, dict) and isinstance(head.get("exit"), dict):
        # ``0: ok`` and ``"0": ok`` mean the same; the catalog keys exit codes as strings
        head["exit"] = {str(k): v for k, v in head["exit"].items()}
    return head


_VALIDATOR = None


def _validator():
    global _VALIDATOR
    if _VALIDATOR is None:
        from jsonschema import Draft202012Validator

        schema = json.loads(
            paths.schema_file("platform", "script_header.schema.json").read_text(encoding="utf-8")
        )
        _VALIDATOR = Draft202012Validator(schema)
    return _VALIDATOR


def validate(doc: Any) -> list[str]:
    """Problems with one parsed header (empty list = valid)."""
    if not isinstance(doc, dict):
        return ["$: the header must be a mapping"]
    out = []
    for err in sorted(_validator().iter_errors(doc), key=lambda e: [str(p) for p in e.path]):
        where = "/".join(str(p) for p in err.absolute_path) or "$"
        if err.validator == "not" and where == "$":
            out.append("invariant: only a header with kind: check may name invariants")
        else:
            out.append(f"{where}: {err.message}")
    exits = doc.get("exit")
    if (
        doc.get("kind") == "check"
        and isinstance(exits, dict)
        and not any(_FAIL_CODE.match(str(k)) for k in exits)
    ):
        out.append(
            "exit: a check documents a failing code in 1..99 (the invariants runner reads "
            "1..99 as fail and >= 100 as could-not-measure)"
        )
    return out
