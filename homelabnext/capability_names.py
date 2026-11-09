# SPDX-License-Identifier: Apache-2.0
"""The capability names the platform knows, in one small module with no dependency.

Two sources, read here and nowhere else: the conformance contracts (:data:`CAPABILITIES`, the
eighteen of ``docs/interfaces.md`` section 3, and :data:`EXTENDED`, the further suites the harness
ships) and the capability-class table (``homelabnext/agent/tool_classes.yml``).  Registry
validation (an ``eval`` or ``retiring`` row may not take one of these names, ADR-0039 decision 2),
the binding check (``hnx registry bindings``) and the MCP catalog read them from here, so
validating a registry imports neither the conformance harness nor the MCP catalog, both of which
import the registry.  ``homelabnext.conform.registry`` re-exports the two tuples.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

__all__ = [
    "CAPABILITIES",
    "CLASS_TABLE",
    "EXTENDED",
    "class_table_capabilities",
    "platform_capabilities",
]

CAPABILITIES: tuple[str, ...] = (
    "lake-query",
    "lake-catalog",
    "object-store",
    "inference",
    "fast-classifier",
    "notify",
    "cases",
    "events",
    "orchestration",
    "broker",
    "secrets",
    "idp",
    "records",
    "detections",
    "context",
    "projects",
    "codemode-executor",
    "codemode-runner",
)
#: additional suites that ship with the harness but are not among the eighteen
EXTENDED: tuple[str, ...] = (
    "backup",
    "dns",
    "edge",
    "broker-tokens",
    "orchestration-features",
    "migration",
    "log-pipeline",
)
#: the capability-class table (the same file as ``homelabnext.agent.readers.DEFAULT_CLASSES``)
CLASS_TABLE = Path(__file__).resolve().parent / "agent" / "tool_classes.yml"


def class_table_capabilities(path: str | Path | None = None) -> list[str]:
    """The ``cap:`` ids the capability-class table classifies, sorted."""
    import yaml

    doc = yaml.safe_load(Path(path or CLASS_TABLE).read_text(encoding="utf-8")) or {}
    caps = doc.get("capabilities") if isinstance(doc, Mapping) else None
    return sorted(caps or ())


def platform_capabilities() -> frozenset[str]:
    """Every capability name the platform knows, without the ``cap:`` prefix: the class table's
    and the conformance contracts'."""
    return frozenset(
        {c.removeprefix("cap:") for c in class_table_capabilities()} | {*CAPABILITIES, *EXTENDED}
    )
