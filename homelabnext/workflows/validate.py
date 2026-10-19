# SPDX-License-Identifier: Apache-2.0
"""``hnx workflows validate``: every workflow pack in git, offline.

Rules (each problem is reported as ``<path>: <rule>: <detail>``):

``schema``               valid against ``schemas/workflows/pack.schema.json`` (R-01).
``in-git``               the pack is tracked by git (R-01; discovery mode only).
``duplicate``            pack names and step ids are unique; fixture names unique per pack.
``event-type``           the trigger's event type has a schema under ``schemas/events/`` (R-01).
``ref``                  a reference names ``$event`` or an *earlier* step; a trigger reads only
                         ``$event`` (R-01).
``manifest``             ``broker_manifest`` exists and is a valid broker manifest (R-01).
``action``               an action step names an action the broker manifest lists (R-01).
``grant``                the pack's ``actor`` holds a grant for that action at its tier (R-01).
``spec``                 a decide step names a decision spec tracked in git (R-01).
``template``             a prompt step names a shipped prompt template (R-01).
``slot``                 a prompt step binds every required slot and only known ones; a
                         *trusted* slot is bound to a literal, never to event or step data (G-01).
``deterministic-first``  a pack with a model step runs an unconditional deterministic (enrich)
                         step before its first model step (R-03).
``model-input``          every model step reads the output of at least one earlier enrich step:
                         the model sees enriched data, not only the raw event (R-03).
``risky-params``         a risky action takes no parameter from a prompt step's free-text output;
                         what it acts on comes from the event or a deterministic step.
``fixture``              each fixture event is a valid event of its type; the fixture gives a
                         model output for every model step that runs and no stale ones, and no
                         approval for a request the run never makes (R-07).
``round-trip``           running the fixture event through the offline runner produces exactly
                         the expected action calls (action, target, params, result; reason and
                         step when given), in order, and the expected trigger verdict (R-07).
``risky-untested``       every risky action step executes, under approval, in some fixture (R-04).
``approval-binding``     for each such fixture, the same run without the approval holds the
                         action, and the same run with the action's payload altered after
                         approval does not execute it (R-04).
``deploy``               the deploy manifest is valid and tracked; every pin names a pack that
                         validates cleanly, once, with exactly that pack's digest (R-01).

Exit codes: 0 clean, 1 a rule failed, 2 bad input, 100 the packs could not be enumerated (no git).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from homelabnext.events.envelope import event_problems, schema_for_type

from .pack import (
    WorkflowError,
    discover,
    expand,
    git_files,
    load_doc,
    pack_digest,
    schema_errors,
)
from .runner import (
    MODEL_KINDS,
    BrokerExecutor,
    ExecutorFactory,
    RunResult,
    action_entry,
    is_risky,
    ref_root,
    refs_in,
    run_fixture,
    step_refs,
)

DEFAULT_DEPLOY = Path("workflows") / "deploy.yml"
_TIER_RANK = {"read": 0, "write": 1, "execute": 2, "privileged": 3}


@dataclass(frozen=True)
class Problem:
    path: str
    rule: str
    detail: str

    def __str__(self) -> str:
        return f"{self.path}: {self.rule}: {self.detail}"


@dataclass
class Universe:
    """What a pack's references resolve against."""

    root: Path
    spec_labels: dict[str, tuple[str, ...]] = field(default_factory=dict)
    templates: dict[str, Any] = field(default_factory=dict)  # id -> PromptTemplate
    _manifests: dict[str, tuple[Any, list[str]]] = field(default_factory=dict)

    def manifest(self, rel: str) -> tuple[Any, list[str]]:
        """``(manifest, problems)`` for a repository-relative broker manifest path."""
        if rel not in self._manifests:
            path = self.root / rel
            if not path.is_file():
                self._manifests[rel] = (None, [f"{rel}: no such file"])
            else:
                try:
                    doc = load_doc(path)
                except WorkflowError as exc:
                    self._manifests[rel] = (None, [str(exc)])
                else:
                    errs = schema_errors("broker", "manifest", doc)
                    self._manifests[rel] = (None if errs else doc, [f"{rel}: {e}" for e in errs])
        return self._manifests[rel]


def load_universe(root: Path) -> Universe:
    """Decision specs git tracks (or has untracked; ``hnx decide lint`` flags those) and the
    shipped prompt templates."""
    from homelabnext.agent.template import TemplateError, load_templates
    from homelabnext.decide.lint import LintError
    from homelabnext.decide.lint import discover as discover_specs
    from homelabnext.decide.lint import load as load_spec_doc
    from homelabnext.decide.spec import SpecError, parse_spec

    uni = Universe(root)
    try:
        tracked, untracked = discover_specs(root)
    except LintError as exc:
        raise WorkflowError(str(exc), exc.code) from exc
    for f in [*tracked, *untracked]:
        try:
            spec = parse_spec(load_spec_doc(f))
        except (SpecError, Exception):  # an invalid spec is decide lint's finding, not ours
            continue
        uni.spec_labels[spec.id] = tuple(dict.fromkeys(t for _, t in spec.decision_table))
    try:
        uni.templates = {t.id: t for t in load_templates()}
    except TemplateError as exc:
        raise WorkflowError(f"prompt templates do not load: {exc}") from exc
    return uni


# ---------------------------------------------------------------- one pack
def check_pack(
    doc: Any,
    uni: Universe,
    *,
    executor_factory: ExecutorFactory = BrokerExecutor,
) -> list[tuple[str, str]]:
    """``(rule, detail)`` for every problem of one pack document (empty = clean)."""
    errs = schema_errors("workflows", "pack", doc)
    if errs:
        return [("schema", e) for e in errs]
    out: list[tuple[str, str]] = []
    steps = doc["steps"]
    trig = doc["trigger"]
    if schema_for_type(trig["event"]) is None:
        out.append(("event-type", f"trigger event {trig['event']!r} has no schema"))
    for c in trig.get("where", []):
        if ref_root(c["ref"])[0] != "event":
            out.append(("ref", f"trigger: {c['ref']!r} - a trigger can only read $event"))
    manifest, mproblems = uni.manifest(doc["broker_manifest"])
    out += [("manifest", p) for p in mproblems]
    out += _steps(doc, steps, manifest, uni)
    out += _deterministic_first(steps)
    if out:
        return out  # the references must hold before fixtures can mean anything
    out += _fixtures(doc, manifest, uni, executor_factory)
    return out


def _steps(doc, steps, manifest, uni: Universe) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    seen: dict[str, str] = {}  # id -> kind of every earlier step
    for i, step in enumerate(steps):
        sid, kind = step["id"], step["kind"]
        where = f"steps[{i}] {sid}"
        if sid in seen:
            out.append(("duplicate", f"{where}: step id used twice"))
        for ref in step_refs(step):
            root, target = ref_root(ref)
            if root == "steps" and target not in seen:
                out.append(("ref", f"{where}: {ref!r} names no earlier step"))
        if kind == "decide" and step["spec"] not in uni.spec_labels:
            out.append(("spec", f"{where}: no decision spec {step['spec']!r} in git"))
        if kind == "prompt":
            out += _slots(where, step, uni)
        if kind == "action" and manifest is not None:
            out += _action(where, doc, step, manifest, seen, steps)
        seen[sid] = kind
    return out


def _slots(where, step, uni: Universe) -> list[tuple[str, str]]:
    tmpl = uni.templates.get(step["template"])
    if tmpl is None:
        return [("template", f"{where}: no prompt template {step['template']!r}")]
    out: list[tuple[str, str]] = []
    slots = {s.name: s for s in tmpl.slots}
    bound = step["slots"]
    for name in sorted(set(bound) - set(slots)):
        out.append(("slot", f"{where}: template {tmpl.id!r} has no slot {name!r}"))
    for name in sorted(n for n, s in slots.items() if s.required and n not in bound):
        out.append(("slot", f"{where}: required slot {name!r} is not bound"))
    for name, value in sorted(bound.items()):
        if name in slots and slots[name].trust == "trusted" and refs_in(value):
            out.append(
                (
                    "slot",
                    f"{where}: trusted slot {name!r} is bound to {refs_in(value)[0]!r}; "
                    "event and step data are untrusted and may only fill untrusted slots",
                )
            )
    return out


def _action(where, doc, step, manifest, seen, steps) -> list[tuple[str, str]]:
    entry = action_entry(manifest, step["action"])
    if entry is None:
        return [("action", f"{where}: {step['action']!r} is not in {doc['broker_manifest']}")]
    out: list[tuple[str, str]] = []
    grant = next(
        (
            g
            for g in manifest.get("grants", [])
            if g["profile"] == doc["actor"] and step["action"] in g["actions"]
        ),
        None,
    )
    if grant is None:
        out.append(("grant", f"{where}: {doc['actor']} holds no grant for {step['action']!r}"))
    elif _TIER_RANK[entry["tier"]] > _TIER_RANK[grant["max_tier"]]:
        out.append(
            (
                "grant",
                f"{where}: {step['action']!r} is {entry['tier']}, above the grant's "
                f"max_tier {grant['max_tier']}",
            )
        )
    if is_risky(manifest, step["action"]):
        for ref in refs_in(step["params"]):
            root, target = ref_root(ref)
            if root == "steps" and seen.get(target) == "prompt":
                out.append(
                    (
                        "risky-params",
                        f"{where}: risky action {step['action']!r} takes {ref!r} from a "
                        "prompt step's free text; take it from the event or an enrich step",
                    )
                )
    return out


def _deterministic_first(steps) -> list[tuple[str, str]]:
    first_model = next((i for i, s in enumerate(steps) if s["kind"] in MODEL_KINDS), None)
    if first_model is None:
        return []
    out: list[tuple[str, str]] = []
    if not any(s["kind"] == "enrich" and not s.get("when") for s in steps[:first_model]):
        m = steps[first_model]
        out.append(
            (
                "deterministic-first",
                f"model step {m['id']!r} runs before any unconditional enrich step",
            )
        )
    enrich_ids: set[str] = set()
    for s in steps:
        if s["kind"] == "enrich":
            enrich_ids.add(s["id"])
        elif s["kind"] in MODEL_KINDS:
            reads = {ref_root(r)[1] for r in step_refs(s) if ref_root(r)[0] == "steps"}
            if not reads & enrich_ids:
                out.append(
                    (
                        "model-input",
                        f"model step {s['id']!r} reads no earlier enrich step's output",
                    )
                )
    return out


# ---------------------------------------------------------------- fixtures (R-07, R-04)
def _project(call, expected: Mapping[str, Any]) -> dict[str, Any]:
    keys = ["action", "target", "params", "result"]
    keys += [k for k in ("reason", "step") if k in expected]
    full = call.to_dict()
    return {k: full.get(k) for k in keys}


def _expected(e: Mapping[str, Any]) -> dict[str, Any]:
    keys = ["action", "target", "params", "result", *[k for k in ("reason", "step") if k in e]]
    return {k: e.get(k) for k in keys}


def _fixtures(doc, manifest, uni: Universe, executor_factory) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    names: set[str] = set()
    executed_under_approval: dict[str, list[Mapping[str, Any]]] = {}
    for fx in doc["fixtures"]:
        where = f"fixture {fx['name']}"
        if fx["name"] in names:
            out.append(("duplicate", f"{where}: fixture name used twice"))
        names.add(fx["name"])
        evp = event_problems(fx["event"])
        if evp:
            out += [("fixture", f"{where}: event {p}") for p in evp]
            continue
        res = _run(doc, fx, manifest, uni, executor_factory)
        out += [("fixture", f"{where}: {p}") for p in res.problems]
        out += _compare(where, fx, res)
        for call in res.calls:
            if call.result == "executed" and is_risky(manifest, call.action):
                executed_under_approval.setdefault(call.step, []).append(fx)
    for step in doc["steps"]:
        if step["kind"] != "action" or not is_risky(manifest, step["action"]):
            continue
        fxs = executed_under_approval.get(step["id"], [])
        if not fxs:
            out.append(
                (
                    "risky-untested",
                    f"risky action step {step['id']!r} ({step['action']}) executes, under "
                    "approval, in no fixture; add one so its approval binding is proven",
                )
            )
        for fx in fxs:
            out += _binding(doc, fx, step["id"], manifest, uni, executor_factory)
    return out


def _run(doc, fx, manifest, uni, executor_factory, **kw) -> RunResult:
    return run_fixture(
        doc,
        fx,
        manifest=manifest,
        spec_labels=uni.spec_labels,
        executor_factory=executor_factory,
        **kw,
    )


def _compare(where, fx, res: RunResult) -> list[tuple[str, str]]:
    exp = fx["expect"]
    want_trig = exp.get("triggered", True)
    if res.triggered != want_trig:
        return [("round-trip", f"{where}: triggered {res.triggered}, expected {want_trig}")]
    want = [_expected(e) for e in exp["calls"]]
    got = [_project(c, e) for c, e in zip(res.calls, exp["calls"], strict=False)]
    got += [_project(c, {}) for c in res.calls[len(want) :]]
    if got == want and len(res.calls) == len(want):
        return []
    out: list[tuple[str, str]] = []
    for i in range(max(len(got), len(want))):
        g = got[i] if i < len(got) else None
        w = want[i] if i < len(want) else None
        if g != w:
            out.append(("round-trip", f"{where}: call {i}: got {g}, expected {w}"))
    return out


def _binding(doc, fx, sid, manifest, uni, executor_factory) -> list[tuple[str, str]]:
    where = f"fixture {fx['name']}, step {sid}"
    out: list[tuple[str, str]] = []
    bare = _run(doc, fx, manifest, uni, executor_factory, approvals=[])
    got = {c.step: c.result for c in bare.calls}.get(sid)
    if got != "held":
        out.append(("approval-binding", f"{where}: without its approval the action is {got}"))

    def tamper(step, req):
        if step["id"] == sid:
            req = {**req, "params": {**req["params"], "x-altered-after-approval": True}}
        return req

    altered = _run(doc, fx, manifest, uni, executor_factory, tamper=tamper)
    got = {c.step: c.result for c in altered.calls}.get(sid)
    if got == "executed":
        out.append(
            ("approval-binding", f"{where}: executed with its payload altered after approval")
        )
    return out


# ---------------------------------------------------------------- the repository
def _rel(path: Path, base: Path) -> str:
    try:
        return path.resolve().relative_to(base.resolve()).as_posix()
    except ValueError:
        return str(path)


@dataclass
class Report:
    packs: dict[str, tuple[str, str]] = field(default_factory=dict)  # name -> (path, digest)
    clean: set[str] = field(default_factory=set)
    problems: list[Problem] = field(default_factory=list)


def validate_repo(
    paths_: Sequence[Path] = (),
    *,
    root: Path | None = None,
    deploy: Path | None = None,
    executor_factory: ExecutorFactory = BrokerExecutor,
) -> Report:
    """Validate ``paths_`` (files or directories), or every pack in the git tree at ``root``,
    then the deploy manifest (``deploy``; without paths, ``workflows/deploy.yml`` when present)."""
    base = (root or Path.cwd()).resolve()
    rep = Report()
    if paths_:
        files = expand(paths_)
    else:
        tracked, untracked = discover(base)
        rep.problems += [
            Problem(_rel(p, base), "in-git", "workflow pack is not tracked by git")
            for p in untracked
        ]
        files = [*tracked, *untracked]
    uni = load_universe(base)
    untracked_names = {p.path for p in rep.problems}
    for f in files:
        rel = _rel(f, base)
        doc = load_doc(f)
        probs = [
            Problem(rel, r, d) for r, d in check_pack(doc, uni, executor_factory=executor_factory)
        ]
        name = doc.get("pack") if isinstance(doc, dict) else None
        if isinstance(name, str):
            if name in rep.packs:
                probs.append(
                    Problem(rel, "duplicate", f"pack {name!r} also in {rep.packs[name][0]}")
                )
            else:
                rep.packs[name] = (rel, pack_digest(doc))
                if not probs and rel not in untracked_names:
                    rep.clean.add(name)
        rep.problems += probs
    dpath = deploy if deploy is not None else base / DEFAULT_DEPLOY
    # explicit paths validate a subset: the default deploy manifest pins the whole tree
    if deploy is not None or (not paths_ and dpath.is_file()):
        rep.problems += _deploy(dpath, base, rep)
    return rep


def _deploy(path: Path, base: Path, rep: Report) -> list[Problem]:
    rel = _rel(path, base)
    if not path.is_file():
        return [Problem(rel, "deploy", "no such deploy manifest")]
    doc = load_doc(path)
    errs = schema_errors("workflows", "deploy", doc)
    if errs:
        return [Problem(rel, "deploy", e) for e in errs]
    out: list[Problem] = []
    inside = not Path(rel).is_absolute()
    if not inside or rel not in git_files(base, "--cached", "--", rel):
        out.append(Problem(rel, "deploy", "the deploy manifest is not tracked by git"))
    seen: set[str] = set()
    for pin in doc["pins"]:
        name = pin["pack"]
        if name in seen:
            out.append(Problem(rel, "deploy", f"{name}: pinned twice"))
        seen.add(name)
        if name not in rep.packs:
            out.append(Problem(rel, "deploy", f"{name}: no such pack"))
            continue
        where, digest = rep.packs[name]
        if pin["digest"] != digest:
            out.append(
                Problem(
                    rel,
                    "deploy",
                    f"{name}: pinned {pin['digest']} but {where} is {digest} "
                    "(re-pin only a version that validates)",
                )
            )
        elif name not in rep.clean:
            out.append(Problem(rel, "deploy", f"{name}: pinned, but {where} does not validate"))
    return out
