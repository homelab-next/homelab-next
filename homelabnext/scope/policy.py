# SPDX-License-Identifier: Apache-2.0
"""The out-of-scope policy as data.

Nothing about which targets are out of scope is written in code or prose.  It is this mapping
(typically a ``scope_policy:`` section of a registry file, or a small YAML file of its own):

.. code-block:: yaml

    scope_policy:
      unknown: deny            # deny (default, fail closed) | allow
      vmid_threshold: 9000     # a guest whose vmid is ABOVE this is out of scope (exclusive)
      out_tags: [lab, scratch] # a target carrying any of these tags is out of scope
      overrides:               # per canonical id, beats everything else
        guest:scratch-keep: in
        guest:prod-frozen: out

Per-target scope lives on the target itself (``scope: in|out`` in a guest or service file).
Precedence, first match wins: ``overrides`` > the target's own ``scope`` > ``vmid_threshold`` and
``out_tags`` (either one denies) > default allow.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

SCOPES = ("in", "out")
_TAG_RE = re.compile(r"^[a-z][a-z0-9_-]*$")
_ID_RE = re.compile(r"^[a-z]+:[a-z0-9][a-z0-9./-]*$")
_KEYS = {"unknown", "vmid_threshold", "out_tags", "overrides"}


class PolicyError(ValueError):
    def __init__(self, problems: list[str]):
        self.problems = problems
        super().__init__("invalid scope policy" + "".join(f"\n  - {p}" for p in problems))


@dataclass(frozen=True)
class ScopePolicy:
    unknown: str = "deny"
    vmid_threshold: int | None = None
    out_tags: frozenset[str] = frozenset()
    overrides: Mapping[str, str] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, doc: Mapping[str, Any] | None) -> ScopePolicy:
        doc = dict(doc or {})
        problems = [f"unknown key {k!r}" for k in sorted(set(doc) - _KEYS)]
        unknown = doc.get("unknown", "deny")
        if unknown not in ("deny", "allow"):
            problems.append("unknown must be 'deny' or 'allow'")
        thr = doc.get("vmid_threshold")
        if thr is not None and (isinstance(thr, bool) or not isinstance(thr, int) or thr < 1):
            problems.append("vmid_threshold must be a positive integer")
        tags = doc.get("out_tags", [])
        if not isinstance(tags, list) or not all(
            isinstance(t, str) and _TAG_RE.match(t) for t in tags
        ):
            problems.append("out_tags must be a list of lower-case tags")
            tags = []
        ov = doc.get("overrides", {})
        if not isinstance(ov, dict):
            problems.append("overrides must be a mapping of id -> in|out")
            ov = {}
        for k, v in ov.items():
            if not isinstance(k, str) or not _ID_RE.match(k):
                problems.append(f"overrides key {k!r} is not a logical id")
            if v not in SCOPES:
                problems.append(f"overrides[{k!r}] must be 'in' or 'out'")
        if problems:
            raise PolicyError(problems)
        return cls(
            unknown=unknown,
            vmid_threshold=thr,
            out_tags=frozenset(tags),
            overrides={str(k): v for k, v in ov.items()},
        )

    @classmethod
    def from_file(cls, path: str) -> ScopePolicy:
        import yaml

        with open(path, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh) or {}
        return cls.from_mapping(doc.get("scope_policy", doc) if isinstance(doc, dict) else None)
