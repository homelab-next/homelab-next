# SPDX-License-Identifier: Apache-2.0
"""Canonical JSON and the digest every agent artefact is identified by.

One definition, used by the profile compiler, the context-pack assembler and the broker, so a
digest computed anywhere can be recomputed anywhere.  Canonical form: UTF-8 JSON, keys sorted,
no insignificant whitespace, non-ASCII kept as is.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_text(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def digest_of(obj: Any) -> str:
    """``sha256:<hex>`` of the canonical JSON of ``obj``."""
    return sha256_text(canonical_json(obj))
