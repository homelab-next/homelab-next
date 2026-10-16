# SPDX-License-Identifier: Apache-2.0
"""Conformance harness core: suites of named checks that run against any implementation.

Entry points (see ``docs/interfaces.md`` and ``docs/conformance.md``):

    CheckResult, Capability      the result record and the suite protocol
    run(capability, target)      run a suite against a binding mapping
    Suite                        define a suite (``@suite.check(...)``)
    build_report()               the "capabilities without a passing test" export

The capability suites, protocols and fakes live outside this package, in ``conformance/`` of the
source tree, so a deployment can add its own without touching the library.
"""

from __future__ import annotations

from .core import Capability, CheckResult, Mutant, Skip, Suite, run_checks
from .registry import CAPABILITIES, EXTENDED, ConformError
from .report import build_report
from .runner import CapabilityRun, run, run_capability

__all__ = [
    "CAPABILITIES",
    "EXTENDED",
    "Capability",
    "CapabilityRun",
    "CheckResult",
    "ConformError",
    "Mutant",
    "Skip",
    "Suite",
    "build_report",
    "run",
    "run_capability",
    "run_checks",
]
