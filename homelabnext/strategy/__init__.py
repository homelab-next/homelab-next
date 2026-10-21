# SPDX-License-Identifier: Apache-2.0
"""Strategy to task: a strategy, its objective cascade and the requirements it answers.

The model (``docs/strategy.md``; ADR-0015):

* **strategy** -- one record: mission, intent, end state, priorities of work, assumptions,
  constraints (each with an owner);
* **objectives** -- the cascade SO -> OO -> TO -> TT, each measured by **MOPs** (are we doing the
  work?) that roll up to **MOEs** (is it working?); a measure binds to where its value comes from
  (an invariant, a status hub source, a records lane, a person, or nothing: not measurable);
* **requirements** -- the parent category, of exactly three types: **CCIR** (what the owner
  needs to know), **FFIR** (what the rest of the lab needs to know about itself), **PIR** (what
  we need to know about the environment or adversary); each supports objectives, an FFIR may
  serve CCIRs, a PIR CCIRs or FFIRs;
* **RFIs** -- questions raised by gaps, triaged into collection or production, with an LTIOV.

Nothing here is specific to intelligence work: the same records describe any discipline that
sets objectives, measures them and asks questions when a measure goes red.

Every record is one Markdown file named for its uid (a UUIDv7, ADR-0019) with [[<uid>]]
wiki-links, read and written by the registers' machinery (:mod:`homelabnext.registers`):
front-matter and sections, sidecar events (reviews, readings, transitions), ``check-lost``,
review tiers (:mod:`homelabnext.reviews`), intents decided by a decider (ADR-0014).  The number
a record is shown with (``OO 1.2``, ``PIR 2.1``) is computed from its type, parent and sibling
order (:meth:`Tree.label`), never stored.  The modules:

* :mod:`.records` -- the tree on disk, digests, the validating write path;
* :mod:`.rules` -- schemas, link rules, lifecycle, reviews and the record-level doctrine;
* :mod:`.doctrine` -- the data-driven doctrine policy (``doctrine.yml``): rules, the record
  hierarchy and the link table;
* :mod:`.measure` -- bindings, readings (``value`` events), grades and the rollup;
* :mod:`.rfis` -- gaps to RFIs, the decider, the LTIOV sweep;
* :mod:`.pages` -- the status hub pages; :mod:`.index` -- the Markdown index.
"""

from .doctrine import DEFAULT_HIERARCHY, DEFAULT_LINKS, DEFAULT_RULES, Doctrine, load_doctrine
from .measure import Context, Grade, Reading, grade, grade_all, measure_all, read, rollup
from .records import Tree, load_tree, write_events, write_new_record
from .rfis import StrategyDecider, gaps, raise_intents, sweep
from .rules import LIFECYCLE, Report, find_cycle, validate

__all__ = [
    "DEFAULT_HIERARCHY",
    "DEFAULT_LINKS",
    "DEFAULT_RULES",
    "LIFECYCLE",
    "Context",
    "Doctrine",
    "Grade",
    "Reading",
    "Report",
    "StrategyDecider",
    "Tree",
    "find_cycle",
    "gaps",
    "grade",
    "grade_all",
    "load_doctrine",
    "load_tree",
    "measure_all",
    "raise_intents",
    "read",
    "rollup",
    "sweep",
    "validate",
    "write_events",
    "write_new_record",
]
