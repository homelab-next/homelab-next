# SPDX-License-Identifier: Apache-2.0
"""Workflows as code: the pack format, its offline validator and the deterministic runner.

A workflow pack (``schemas/workflows/pack.schema.json``) declares the event that triggers it,
ordered steps - deterministic ``enrich`` steps, model steps (``decide`` through a decision spec,
``prompt`` through a prompt template) and ``action`` steps naming broker actions - and fixtures
that pin which action calls a given event produces.  ``hnx workflows validate`` checks every
pack git tracks: schema, references, deterministic-before-model, fixture round-trips through
:func:`run_fixture`, and the approval binding of every risky action; then the deploy manifest's
digest pins.  Guide: ``docs/workflows.md``.
"""

from .pack import WorkflowError, discover, is_pack, load_doc, pack_digest, schema_errors
from .runner import (
    BrokerExecutor,
    Call,
    Executor,
    Outcome,
    RunResult,
    extract_iocs,
    is_risky,
    request_id,
    run_fixture,
    triggered,
)
from .validate import Problem, Report, Universe, check_pack, load_universe, validate_repo

__all__ = [
    "BrokerExecutor",
    "Call",
    "Executor",
    "Outcome",
    "Problem",
    "Report",
    "RunResult",
    "Universe",
    "WorkflowError",
    "check_pack",
    "discover",
    "extract_iocs",
    "is_pack",
    "is_risky",
    "load_doc",
    "load_universe",
    "pack_digest",
    "request_id",
    "run_fixture",
    "schema_errors",
    "triggered",
    "validate_repo",
]
