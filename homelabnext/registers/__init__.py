# SPDX-License-Identifier: Apache-2.0
"""Registers: the sources of truth for lessons, runbooks and invariants.

Lessons and runbooks are directories of record files, one Markdown file per entry with YAML
front-matter (``examples/registers/lessons/LL-001.md``); invariants stay one YAML file.
:func:`load_register` reads either form (a legacy single ``lessons.yml`` still loads) and is the
one reader the rest of the code uses; machine state (reviews, recurrences, verification runs,
applied transitions) is append-only sidecar events (:mod:`.events`) it derives fields from, and
:func:`write_record` / :func:`write_event` are the validating write path.  The transition decider
(:mod:`.transitions`) is the decision maker's tool and deliberately not re-exported here.  Each register has a fatal schema (an entry without a root
cause, a preventive control or a falsifiable verification aborts the render) and a generator
that emits one self-contained static HTML page plus a JSON document. See
``python -m homelabnext.registers --help``.
"""

from .records import join_register, load_register, split_register, stale_links
from .render import build_all, render_invariants, render_lessons, render_runbooks
from .schema import RegisterError, validate_invariants, validate_lessons, validate_runbooks
from .write import write_event, write_events, write_record, write_register

__all__ = [
    "RegisterError",
    "build_all",
    "join_register",
    "load_register",
    "render_invariants",
    "render_lessons",
    "render_runbooks",
    "split_register",
    "stale_links",
    "validate_invariants",
    "validate_lessons",
    "validate_runbooks",
    "write_event",
    "write_events",
    "write_record",
    "write_register",
]
