# SPDX-License-Identifier: Apache-2.0
"""The repository knowledge graph: every service, capability, adapter, check, schema, lesson,
runbook, invariant, script, agent profile and page as a node, linked by typed edges read only from
facts in the source files (``hnx graph``; guide: ``docs/graph.md``; local build:
``docs/graph/graph.json``, not committed).

Later layers call the pure query functions: :func:`neighbours`, :func:`related` (ranked,
budgeted) and :func:`seeds_for` (edited paths and task text to seed nodes).  Retired,
superseded and incorporated records are excluded from all three unless
``include_inactive=True``.  Lessons, runbooks and criteria carry ``author`` and a review summary
(``reviewed``: the tiers -- ``agent_check``, ``challenge``, ``human`` -- whose latest review
passed; ``review_count``) when the record has them.

Edge vocabulary (``from -> to: asserted by``; the table is :data:`.vocab.EDGE_TYPES`)::

    provides       svc, compose -> cap: registry capability; a compose service named after a cap
    runs           svc, compose -> product: registry impl; compose image
    runs_on        svc -> host: registry host
    in_zone        host -> zone: registry hosts.zone
    depends_on     svc -> svc: registry upstreams
    serves         svc -> zone: registry clients
    exposes        svc -> mcp: registry mcp
    implements     adapter -> cap: target binding, contract import, make_fake
    faked_by       cap -> adapter: suite make_fake
    for            adapter -> product: a compose stack's target file + that stack's image
    checked_by     cap -> check: suite specs
    loads_schema   cap -> schema: schema paths the contract's code loads
    refs           schema -> schema: $ref
    triggered_by   script -> make, ci, pre-commit, compose, script, pkg: catalog trigger
    enforces       script -> inv: catalog invariant
    reads          script -> any node owning the path: catalog inputs
    about          lesson, runbook -> system: systems tags
    resolves_to    system -> svc, cap, product: a tag exactly equal to the name
    operates       runbook -> svc: a systems tag resolving to a service
    controlled_by  lesson -> runbook, inv, lesson: an id in preventive_control
    mentions       lesson, runbook -> lesson, runbook, inv: an id in another text field
    verified_by    lesson -> script, pkg, make: verification.observable command
    invokes        runbook -> script, pkg, make: commands in step do/verify
    checks         inv -> script, pkg, make: observable command; plugin owner
    retired_by     lesson -> inv, test: retired_by
    superseded_by  lesson -> lesson: superseded_by
    incorporated_into  lesson -> runbook, doc: incorporated_into
    from_lesson    runbook -> lesson: from_lessons (runbook or step)
    uses           profile, manifest -> skill, persona, cap, mcp: parts, persona, skills, tools
    uses_model     profile -> mdl: model_role
    backed_by      mdl -> svc: model role bindings[].backend
    falls_back_to  mdl -> mdl: model role fallback
    defines        broker -> action: broker manifest actions
    grants         profile, human, zone -> cap, mcp, action, svc, broker: keyring grants (level)
    applies_to     custom -> cap, svc, host: customization scope
    governed_by    custom -> adr: customization contract
    links          custom, doc, adr -> any: customization links; Markdown and [[wiki]] links
    documents      doc -> svc, cap: docs/systems/<svc>.md, docs/capabilities/<cap>.md
    targets        playbook -> cap: a cap_<name> hosts group
    applies        playbook -> role: play roles

Node kinds and their id forms are :data:`.vocab.NODE_KINDS`.
"""

from __future__ import annotations

from .build import GRAPH_JSON, Integrity, build, check, generate
from .model import Edge, Graph, Node, dumps, load, loads
from .query import DEFAULT_WEIGHTS, Related, is_active, neighbours, related, seeds_for
from .vocab import EDGE_TYPES, NODE_KINDS

__all__ = [
    "DEFAULT_WEIGHTS",
    "EDGE_TYPES",
    "GRAPH_JSON",
    "NODE_KINDS",
    "Edge",
    "Graph",
    "Integrity",
    "Node",
    "Related",
    "build",
    "check",
    "dumps",
    "generate",
    "is_active",
    "load",
    "loads",
    "neighbours",
    "related",
    "seeds_for",
]
