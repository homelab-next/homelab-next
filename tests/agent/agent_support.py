# SPDX-License-Identifier: Apache-2.0
"""Shared fakes for the agent tests: an in-memory parts library and a canonical spec/manifest."""

import copy

from homelabnext.agent import PartsLibrary
from homelabnext.ids import MappingResolver

PARTS = {
    "persona:analyst": "You analyse findings and cite sources.",
    "skill:summarise": "Summarise in five bullets.",
    "skill:triage": "Rank findings by severity.",
    "cap:lake-query": "Read-only lake queries.",
    "cap:records-propose": "Write proposals.",
}


def library(parts=None) -> PartsLibrary:
    parts = PARTS if parts is None else parts
    resolver = MappingResolver("fake", {k: f"mem/{k}" for k in parts})
    return PartsLibrary(resolver, lambda loc: parts[loc[len("mem/") :]], source="fake-library")


def spec() -> dict:
    return copy.deepcopy(
        {
            "id": "profile:reader",
            "persona": "persona:analyst",
            "skills": ["skill:triage", "skill:summarise"],
            "capabilities": ["cap:lake-query"],
            "model_role": "mdl:fast-classifier",
            "mcp": ["lake"],
            "tier": "read",
            "ceiling": {
                "mcp": ["lake", "records"],
                "capabilities": ["cap:lake-query", "cap:records-propose"],
                "tier": "write",
                "budgets": {
                    "max_input_tokens": 64000,
                    "max_output_tokens": 4000,
                    "max_runtime_s": 900,
                    "max_tool_calls": 40,
                },
            },
            "memory_scopes": ["analyst"],
            "data_tier": "local-only",
            "budget_mode": "enforce",
            "budgets": {
                "max_input_tokens": 32000,
                "max_output_tokens": 2000,
                "max_runtime_s": 600,
                "max_tool_calls": 20,
            },
        }
    )


def manifest() -> dict:
    return {
        "id": "reader-pack",
        "persona": "persona:analyst",
        "skills": ["skill:summarise", "skill:triage"],
        "tools": ["lake"],
        "pregates": [{"id": "pipeline-health", "required": True, "max_age_s": 900}],
        "memory_scopes": ["analyst"],
        "delimiter": "=====",
        "must_cite": ["findings"],
        "budget_chars": 4000,
        "sections": [
            {
                "name": "charter",
                "tier": "stable",
                "source": "static",
                "required": True,
                "max_chars": 800,
                "text": "You are a read-only analyst. Cite every claim.",
            },
            {
                "name": "rules",
                "tier": "stable",
                "source": "static",
                "required": True,
                "max_chars": 800,
                "text": "Never act; only report.",
            },
            {
                "name": "memory",
                "tier": "session",
                "source": "input",
                "required": False,
                "max_chars": 600,
            },
            {
                "name": "findings",
                "tier": "volatile",
                "source": "input",
                "required": True,
                "max_chars": 2000,
            },
        ],
    }


GATE_OK = {
    "gate": "pipeline-health",
    "status": "ok",
    "observed_at": "2026-01-15T10:00:00Z",
    "sources": [{"name": "auth-events", "age_s": 42}],
}


def inputs() -> dict:
    return {
        "sections": {"findings": "f1: 3 failed logins", "memory": "no known scanners"},
        "pregates": {"pipeline-health": copy.deepcopy(GATE_OK)},
    }
