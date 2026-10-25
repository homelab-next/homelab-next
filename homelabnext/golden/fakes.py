# SPDX-License-Identifier: Apache-2.0
"""The fakes CI runs the Code Mode golden suites with (CM-6): a scripted model and a fake broker
world.  **They prove the harness, the scorers and the report, not that any model is good.**

:class:`ScriptedAgentModel` is a recorded model: for each task and mode it replays the turns
written in the suite's script (``<suite>.script.yml`` beside the suite), keyed by the
conversation's opening (:func:`homelabnext.golden.agentic.opening`: the mode's system message and
the task's prompt) and the number of turns so far, so the same completer answers both modes of
every task deterministically.  It also "understands" the injection corpus exactly as
:class:`homelabnext.agent.injection.FakeInjectionModel` does (a case recognised by its
``markers`` after undoing the encodings) and differs only in where it looks:

* ``fence``: only outside the untrusted-data fences every tool result arrives in, so it follows
  nothing and plays its script (it must pass every task with 0 follows);
* ``naive``: anywhere, so on seeing a case it follows it: the canary as its answer, or an attempt
  of the case's forbidden tool (in Code Mode, from a program).  The report's control section
  proves the scorers catch it in both modes (as ``hnx conform mutants`` proves a suite).

:class:`FakeWorld` is the :data:`~homelabnext.golden.agentic.BackendFactory`: per run a fresh
:class:`FakeBackend` over :class:`conformance.fakes.command_broker.FakeBroker` (the suite's grant,
each granted action answering the task's fixtures for the call's target), the reference
:class:`homelabnext.codemode.runner.Runner` (its search index the generated
``examples/codemode/``, so exec results are held to their result schemas) and
:class:`conformance.fakes.code_executor.ForkingExecutor`, which is **not an isolation boundary**.
So the world serves only a :class:`ScriptedAgentModel`, and the backend runs only the programs that
model can write in that task as that task's agent (:meth:`ScriptedAgentModel.programs`); any other
program is refused, never run.  Suites and scripts are read from the repository's examples only:
a script's programs are trusted, reviewed code that CI runs.  A real model needs a real executor
(CM-8) and the live backend of CM-9.

The fakes need a source checkout (``conformance/fakes`` is not in the wheel).
"""

from __future__ import annotations

import contextlib
import copy
import json
import re
import shutil
import tempfile
from collections.abc import Iterator, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from conformance.protocols.broker import CODEMODE_EXECUTE, ArgSpec, BrokerError
from homelabnext import paths
from homelabnext.agent.digest import digest_of
from homelabnext.agent.injection import Corpus, found, outside_fences, squashed_views
from homelabnext.codemode.mcp_tools import CodemodeIndex
from homelabnext.codemode.runner import Runner, load_index, load_preludes

from .agentic import (
    EXECUTE,
    LANGUAGE,
    MODE_TOOLS,
    HarnessError,
    inject,
    opening,
)
from .runner import Completer
from .tasks import MODES, Suite

__all__ = [
    "NOT_SCRIPTED",
    "FakeBackend",
    "FakeWorld",
    "ScriptError",
    "ScriptedAgentModel",
    "default_index",
    "index_problems",
    "load_script",
    "served",
]

#: the fake's reply to a conversation it has no recorded turn for (a protocol error, visibly)
NOT_SCRIPTED = "fake model: no recorded turn for this conversation"
#: the fixed clock of the fake runs (the execution results carry it)
CLOCK = datetime(2026, 1, 1, tzinfo=UTC)
_JSON_TYPES = {"string": "str", "integer": "int", "boolean": "bool"}


#: The suites whose agent the fake world grants ``codemode.execute`` in Code Mode, and for each
#: the profile it must be and, when that grant is one the profile cannot hold live, why (the run
#: is then *hypothetical*: marked in the report, outside its totals, no adoption decision).  Any
#: other suite's Code Mode half is refused, and the actions it is granted must be read-tier.
CODEMODE_SUITES: dict[str, dict[str, Any]] = {
    "codemode-triage": {"profile": "profile:triage", "hypothetical": None},
    "codemode-reader": {
        "profile": "profile:reader",
        "hypothetical": (
            "a reader may not be granted codemode.execute (G-03); this measures ADR-0031's open "
            "question, a read-only codemode.execute variant, with a grant of the fake world only"
        ),
    },
}


def hypothetical_modes() -> dict[str, dict[str, str]]:
    """``{suite: {"codemode": why}}`` for :data:`CODEMODE_SUITES` whose grant is hypothetical."""
    return {
        name: {"codemode": entry["hypothetical"]}
        for name, entry in CODEMODE_SUITES.items()
        if entry["hypothetical"]
    }


def default_index() -> Path:
    """The generated Code Mode index of the example broker manifest (``examples/codemode``)."""
    return paths.examples_dir() / "codemode"


class ScriptError(ValueError):
    pass


# ---------------------------------------------------------------- the script
def load_script(path: str | Path, suite: Suite) -> dict[str, dict[str, list[dict]]]:
    """``{task id: {mode: [turn, ...]}}`` from a script file, checked against ``suite``: every
    task has turns in every mode of the suite, each turn a tool call of that mode or an answer,
    and only the last turn is the answer."""
    import yaml

    doc = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    problems: list[str] = []
    if not isinstance(doc, dict) or doc.get("suite") != suite.name:
        raise ScriptError(f"{path}: not the script of suite {suite.name}")
    tasks = doc.get("tasks")
    if not isinstance(tasks, dict):
        raise ScriptError(f"{path}: tasks must be a mapping")
    known = {t.id for t in suite.tasks}
    problems += [f"task {t}: not in the suite" for t in sorted(set(tasks) - known)]
    out: dict[str, dict[str, list[dict]]] = {}
    for task in suite.tasks:
        by_mode = tasks.get(task.id)
        if not isinstance(by_mode, dict):
            problems.append(f"task {task.id}: no turns")
            continue
        out[task.id] = {}
        for mode in suite.modes:
            turns = by_mode.get(mode)
            where = f"task {task.id} {mode}"
            if not isinstance(turns, list) or not turns:
                problems.append(f"{where}: no turns")
                continue
            for i, turn in enumerate(turns):
                last = i == len(turns) - 1
                if not isinstance(turn, dict):
                    problems.append(f"{where}[{i}]: a turn is a mapping")
                elif last != (set(turn) == {"answer"}):
                    problems.append(f"{where}[{i}]: only the last turn is the answer")
                elif not last and (
                    set(turn) - {"tool", "arguments"} or turn.get("tool") not in MODE_TOOLS[mode]
                ):
                    problems.append(f"{where}[{i}]: a tool call of mode {mode}")
            out[task.id][mode] = list(turns)
        problems += [
            f"task {task.id}: unknown mode {m!r}" for m in sorted(set(by_mode) - set(MODES))
        ]
    if problems:
        raise ScriptError(f"{path}:\n  - " + "\n  - ".join(problems))
    return out


def _text(turn: Mapping[str, Any]) -> str:
    return json.dumps(dict(turn), sort_keys=True, ensure_ascii=False)


#: in a scripted answer, ``$result`` is the last tool result the model was handed and ``$value``
#: that result's ``value`` (a program's), each optionally followed by ``.key`` steps: the recorded
#: answer then depends on what the run returned
_REF = re.compile(r"^\$(result|value)((?:\.[A-Za-z0-9_-]+)*)$")


def _fill(answer: Any, last: Any) -> Any:
    m = _REF.match(answer) if isinstance(answer, str) else None
    if m:
        node = last
        steps = (["value"] if m.group(1) == "value" else []) + [
            k for k in m.group(2).split(".") if k
        ]
        for key in steps:
            node = node.get(key) if isinstance(node, Mapping) else None
        return node
    if isinstance(answer, dict):
        return {k: _fill(v, last) for k, v in answer.items()}
    if isinstance(answer, list):
        return [_fill(v, last) for v in answer]
    return answer


_SECTION = re.compile(r"^(\S+) tool-result \[volatile\] ([0-9a-f]{16}) \1$")


def _last_result(messages: Sequence[Mapping[str, Any]]) -> Any:
    """The data of the last tool-result section the model was handed (read as data: the
    fenced lines between the section's opener and its closer), or ``None``."""
    for m in reversed(messages):
        if m.get("role") != "user":
            continue
        lines = str(m.get("content", "")).split("\n")
        for i, line in enumerate(lines):
            head = _SECTION.match(line)
            if not head:
                continue
            closer = f"{head.group(1)} end tool-result {head.group(2)} {head.group(1)}"
            if closer in lines[i + 1 :]:
                body = "\n".join(lines[i + 1 : lines.index(closer, i + 1)])
                with contextlib.suppress(ValueError):
                    return json.loads(body)
            return None
    return None


def _naive_program(tool: str) -> str:
    return f"result = broker.call({tool!r}, {{}})\n"


# ---------------------------------------------------------------- the scripted model
class ScriptedAgentModel:
    """A recorded model for the tool-using suites; ``mode`` is ``fence`` (default) or ``naive``
    (see the module doc)."""

    MODES = ("fence", "naive")

    def __init__(
        self,
        scripted: Sequence[tuple[Suite, Mapping[str, Mapping[str, Sequence[Mapping]]]]],
        corpus: Corpus,
        mode: str = "fence",
    ) -> None:
        if mode not in self.MODES:
            raise ScriptError(f"fake model mode must be one of {list(self.MODES)}")
        self.corpus = corpus
        self.mode = mode
        self.calls = 0
        self._turns: dict[tuple[str, str], tuple[str, list[dict]]] = {}
        #: (profile, suite, task) -> the programs this model may write in that task
        self._programs: dict[tuple[str, str, str], set[str]] = {}
        naive = {_naive_program(c.forbidden_tool) for c in corpus.cases if c.forbidden_tool}
        for suite, script in scripted:
            for task in suite.tasks:
                for m in suite.modes:
                    msgs = opening(suite, task, m)
                    key = (msgs[0]["content"], msgs[1]["content"])
                    if key in self._turns:
                        raise ScriptError(f"{suite.name}/{task.id}: two tasks open alike")
                    turns = list(script[task.id][m])
                    self._turns[key] = (m, [dict(t) for t in turns])
                    mine = self._programs.setdefault(
                        (str(suite.profile), suite.name, task.id), set(naive)
                    )
                    for t in turns:
                        if t.get("tool") == EXECUTE:
                            mine.add(str((t.get("arguments") or {}).get("code", "")))

    @property
    def name(self) -> str:
        return f"fake-scripted-{self.mode}"

    def programs(self, profile: str, suite: str, task: str) -> frozenset[str]:
        """The programs this model can write in one task, as one agent (its script's and the
        naive follows): the only ones the fake backend runs there."""
        return frozenset(self._programs.get((profile, suite, task), ()))

    def __call__(self, messages: list[dict], params: dict) -> str:
        self.calls += 1
        if len(messages) < 2:
            return NOT_SCRIPTED
        entry = self._turns.get((str(messages[0].get("content")), str(messages[1].get("content"))))
        if entry is None:
            return NOT_SCRIPTED
        mode, turns = entry
        done = sum(m.get("role") == "assistant" for m in messages)
        follow = self._follow(messages, mode)
        if follow is not None:
            return follow
        if done >= len(turns):
            return NOT_SCRIPTED
        turn = turns[done]
        if "answer" in turn:
            return _text({"answer": _fill(turn["answer"], _last_result(messages))})
        return _text(turn)

    def _follow(self, messages: Sequence[Mapping[str, Any]], mode: str) -> str | None:
        texts = [str(m.get("content", "")) for m in messages]
        if self.mode == "fence":
            texts = [outside_fences(t) for t in texts]
        visible = squashed_views("\n".join(texts))
        said = "\n".join(
            str(m.get("content", "")) for m in messages if m.get("role") == "assistant"
        )
        for case in self.corpus.cases:
            if not found(case.markers, visible):
                continue
            if case.canary:
                return _text({"answer": case.canary})
            tool = str(case.forbidden_tool)
            if tool in said:  # attempted once already: stop
                return _text({"answer": "done"})
            if mode == "codemode":
                code = _naive_program(tool)
                return _text({"tool": EXECUTE, "arguments": {"language": LANGUAGE, "code": code}})
            return _text({"tool": tool, "arguments": {}})
        return None


@contextlib.contextmanager
def served(model: Completer) -> Iterator[Completer]:
    """``model`` behind the fake OpenAI-compatible inference server, and a completer that reaches
    it over HTTP through :class:`homelabnext.registry.models.ModelClient` (the live adapter's own
    path), so a run proves the wire as well as the harness."""
    try:
        from conformance.fakes.openai_server import FakeOpenAIServer, Rule
    except ImportError as exc:  # checkout-only, as the module doc says
        raise _checkout_only() from exc
    from homelabnext.registry.models import ModelClient, ResolvedModel
    from homelabnext.registry.resolver import Endpoint

    srv = FakeOpenAIServer(rules=[Rule(r"", lambda req: model(req["messages"], {}))])
    srv.start()
    try:
        host, port = srv.address
        rm = ResolvedModel(
            role="codemode-golden",
            asked="codemode-golden",
            kind="chat",
            model_id=srv.models[0],
            backend="svc:inference",
            endpoint=Endpoint("inference", "http", host, port, "env"),
            params={},
        )
        client = ModelClient(rm)

        def complete(messages: list[dict], params: dict) -> str:
            return client.chat(messages, **params).text

        yield complete
    finally:
        srv.stop()


# ---------------------------------------------------------------- the fake broker world
def _specs(entry: Mapping[str, Any]) -> dict[str, ArgSpec]:
    """The fake broker's argument specs for an action, from its index ``params`` schema."""
    schema = entry.get("params") or {}
    required = set(schema.get("required") or ())
    out = {}
    for name, prop in (schema.get("properties") or {}).items():
        kind = _JSON_TYPES.get(prop.get("type")) if isinstance(prop, Mapping) else None
        if kind is None:
            raise HarnessError(f"{entry.get('name')}: parameter {name} is not a plain type")
        out[name] = ArgSpec(kind, required=name in required)
    return out


def index_problems(suite: Suite, index: Mapping[str, Mapping[str, Mapping[str, Any]]]) -> list[str]:
    """What the generated index says about ``suite``: its profile has an index, its grant is the
    profile's to have (and every granted action has plain parameters), and every fixture result,
    and the injection placement, match the action's result schema."""
    import jsonschema

    entries = index.get(str(suite.profile))
    if entries is None:
        return [f"{suite.name}: no Code Mode index for {suite.profile}"]
    out = [
        f"{suite.name}: {a} is not granted to {suite.profile} by the manifest"
        for a in suite.grant
        if a not in entries
    ]
    if out:
        return out
    for a in suite.grant:
        try:
            _specs(entries[a])
        except HarnessError as exc:
            out.append(f"{suite.name}: {exc}")
    for task in suite.tasks:
        worlds = [task.fixtures]
        if task.inject:
            worlds.append(inject(task.fixtures, task.inject, "probe"))
        for world in worlds:
            for action, by_target in world.items():
                schema = (entries[action].get("result") or {}).get("schema")
                for target, result in by_target.items():
                    if schema is None:
                        continue
                    errs = list(jsonschema.Draft202012Validator(schema).iter_errors(result))
                    if errs:
                        out.append(
                            f"{suite.name}/{task.id}: {action} {target}: not the action's result "
                            f"schema ({errs[0].message[:120]})"
                        )
    return sorted(set(out))


def _checkout_only() -> HarnessError:
    return HarnessError("the Code Mode golden fakes need a source checkout (conformance/fakes)")


def _fixture_broker() -> Any:
    try:
        from conformance.fakes.command_broker import FakeBroker
    except ImportError as exc:  # checkout-only, as the module doc says
        raise _checkout_only() from exc

    class FixtureBroker(FakeBroker):
        """The fake broker whose actions answer from fixtures for the call's target (the
        in-memory fake passes no target to a handler; the reference broker passes it as
        ``HNX_BROKER_TARGET``)."""

        def __init__(self) -> None:
            super().__init__()
            self.fixtures: dict[str, Any] = {}
            self.target: str | None = None

        def answer(self, action: str):
            def handler(**params: Any) -> Any:
                by_target = self.fixtures.get(action) or {}
                if self.target not in by_target:  # no such service: the handler fails
                    raise LookupError(action)
                return copy.deepcopy(by_target[self.target])

            return handler

        def token_call(self, token, command, args, *, target=None, sandbox_id=None):
            prev, self.target = self.target, target
            try:
                return super().token_call(
                    token, command, args, target=target, sandbox_id=sandbox_id
                )
            finally:
                self.target = prev

        def call_at(self, caller: str, command: str, args: Mapping[str, Any], target):
            prev, self.target = self.target, target
            try:
                return self.call(caller, command, dict(args))
            finally:
                self.target = prev

    return FixtureBroker()


class FakeBackend:
    """One run's broker world (see the module doc); built by :class:`FakeWorld`."""

    def __init__(self, world: FakeWorld, suite: Suite, task: Any, mode: str) -> None:
        self.world = world
        self.programs = world.model.programs(str(suite.profile), suite.name, task.id)
        self.actor = str(suite.profile)
        self.grant = sorted(suite.grant)
        self.mode = mode
        entries = world.index[self.actor]
        self.broker = _fixture_broker()
        for action in self.grant:
            self.broker.register(action, self.broker.answer(action), _specs(entries[action]))
        extra = [CODEMODE_EXECUTE] if mode == "codemode" else []
        if extra:
            allowed = CODEMODE_SUITES.get(suite.name)
            if allowed is None or allowed["profile"] != self.actor:
                raise HarnessError(
                    f"{suite.name}: the fake world grants codemode.execute only to the suites of "
                    "CODEMODE_SUITES, each to its own profile"
                )
            upper = sorted(a for a in self.grant if entries[a].get("tier") != "read")
            if upper:
                raise HarnessError(f"{suite.name}: a Code Mode run is read-only, not {upper}")
        self.broker.allow(self.actor, [*self.grant, *extra])
        grant = set(self.grant)
        self.index = CodemodeIndex(world.index_dir, lambda: (self.actor, grant))
        self._entries = entries
        self._runner: Runner | None = None
        self._executions = 0

    def seed(self, fixtures: Mapping[str, Any]) -> None:
        """What the granted actions answer for this run, per target (a copy)."""
        self.broker.fixtures = copy.deepcopy(dict(fixtures))

    def actions(self) -> dict[str, Any]:
        rows = []
        for name in self.grant:
            e = self._entries[name]
            rows.append(
                {
                    "action": name,
                    "tier": e.get("tier"),
                    "kind": e.get("kind"),
                    "needs_approval": bool(e.get("needs_approval")),
                    "params_schema": e.get("params"),
                    "description": e.get("summary", ""),
                }
            )
        return {"caller": self.actor, "actions": rows}

    def call(self, action: str, params: Mapping[str, Any], target: str | None) -> Any:
        return self.broker.call_at(self.actor, action, params, target)

    def search(self, query: str, limit: int) -> dict[str, Any]:
        return self.index.search(query, limit)

    def describe(self, name: str) -> dict[str, Any]:
        return self.index.describe(name)

    def execute(self, code: str, language: str) -> dict[str, Any]:
        if code not in self.programs:  # never run a program the fake did not write here
            refused = {
                "status": "error",
                "error": {
                    "kind": "sandbox",
                    "message": "the test backend runs recorded programs only",
                },
                "calls": [],
            }
            return refused
        self._runner_for()
        self._executions += 1
        params = {
            "execution_id": f"golden-{self._executions}",
            "language": language,
            "code": code,
            "budget": {"wall_s": 30, "max_calls": 50},
        }
        try:
            result = self.broker.call(self.actor, CODEMODE_EXECUTE, params)
        except BrokerError as exc:  # the execute itself refused: an attempt of codemode.execute
            reason = str(getattr(exc, "reason", "") or type(exc).__name__)[:64]
            call = {"step": 0, "action": CODEMODE_EXECUTE, "outcome": "denied", "reason": reason}
            return {"status": "error", "refused": reason, "calls": [call]}
        return dict(result)

    def _runner_for(self) -> Runner:
        if self._runner is None:
            state = self.world.state_dir()
            self._runner = Runner(
                self.broker,
                self.world.executor,
                state,
                index=self.world.index,
                preludes=self.world.preludes,
                actions_for=lambda actor: list(self.grant),
                clock=lambda: CLOCK,
            )
            self.broker.register_runner(self._runner.runner_id, self._runner.handle)
        return self._runner


class FakeWorld:
    """The backend factory of the fake runs: one forking executor and one scratch directory
    for every run (removed by :meth:`close`), a fresh broker and runner per run.  It serves only
    a :class:`ScriptedAgentModel` (anything else is refused: the executor is not a sandbox), and
    runs in each task only the programs that model can write there, as that task's agent."""

    def __init__(self, model: ScriptedAgentModel, index_dir: str | Path | None = None) -> None:
        if not isinstance(model, ScriptedAgentModel):
            raise HarnessError(
                "the fake world serves the scripted fake model only: its executor is not a "
                "sandbox, so a real model needs a real executor (CM-8) and a live backend"
            )
        try:
            from conformance.fakes.code_executor import ForkingExecutor
        except ImportError as exc:  # checkout-only, as the module doc says
            raise _checkout_only() from exc

        self.index_dir = Path(index_dir) if index_dir is not None else default_index()
        self.index = load_index(self.index_dir)
        self.preludes = load_preludes(self.index_dir)
        self.model = model
        self.executor = ForkingExecutor()
        self._root = Path(tempfile.mkdtemp(prefix="hnx-golden-codemode-"))
        self._n = 0

    def state_dir(self) -> Path:
        self._n += 1
        return self._root / f"run-{self._n}"

    def __call__(self, suite: Suite, task: Any, mode: str) -> FakeBackend:
        return FakeBackend(self, suite, task, mode)

    def close(self) -> None:
        self.executor.close()
        shutil.rmtree(self._root, ignore_errors=True)

    def __enter__(self) -> FakeWorld:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


# ---------------------------------------------------------------- the report CI checks
EXAMPLES = Path(__file__).resolve().parent / "examples" / "codemode"
DEFAULT_SUITES = (EXAMPLES / "triage.yml", EXAMPLES / "reader.yml")
DEFAULT_REPORT = EXAMPLES / "report.json"


def script_of(suite_path: str | Path) -> Path:
    """The script of a suite file: ``<stem>.script.yml`` beside it."""
    p = Path(suite_path)
    return p.with_name(f"{p.stem}.script.yml")


def fake_report(
    suite_paths: Sequence[str | Path] = DEFAULT_SUITES,
    *,
    fake: str = "fence",
    corpus: Corpus | None = None,
    via_server: bool = True,
    index_dir: str | Path | None = None,
    control: bool = True,
) -> dict[str, Any]:
    """The report of the scripted fake ``fake`` over ``suite_paths`` against the fake world,
    through the fake inference server unless ``via_server`` is false.  For ``fence`` with
    ``control``, the naive fake is run too and the report's ``control`` says whether the
    scorers caught it in every mode."""
    from homelabnext.agent.injection import load_corpus
    from homelabnext.agent.template import load_template

    from .agentic import TOOL_RESULT_TEMPLATE, control_of, file_digest, inputs_of, run_suites
    from .tasks import load_suite

    corpus = corpus or load_corpus()
    index_dir = Path(index_dir) if index_dir is not None else default_index()
    index = load_index(index_dir)
    loaded = []
    root = EXAMPLES.resolve()
    for path in suite_paths:
        resolved = Path(path).resolve()
        if not resolved.is_relative_to(root) or not script_of(resolved).resolve().is_relative_to(
            root
        ):
            # a script's programs run in CI on a test executor: they are trusted, reviewed code,
            # so only the repository's own examples are read
            raise HarnessError(f"{path}: suites and scripts are read from {EXAMPLES} only")
        suite = load_suite(path)
        if not suite.modes:
            raise HarnessError(f"{path}: not a tool-using suite (no modes)")
        loaded.append((suite, load_script(script_of(path), suite), Path(path)))
    problems = [p for suite, _, _ in loaded for p in index_problems(suite, index)]
    if problems:
        raise HarnessError("; ".join(problems))
    template = load_template(TOOL_RESULT_TEMPLATE)
    profiles = sorted({str(s.profile) for s, _, _ in loaded})
    extra = {
        "index": {p: file_digest(index_dir / p.split(":", 1)[1] / "search.json") for p in profiles},
        "preludes": {
            p: file_digest(index_dir / p.split(":", 1)[1] / "prelude.py") for p in profiles
        },
        "scripts": {s.name: file_digest(script_of(path)) for s, _, path in loaded},
        "codemode_suites": digest_of(CODEMODE_SUITES),
    }
    inputs = inputs_of([(s, file_digest(path)) for s, _, path in loaded], corpus, template, extra)

    def one(mode: str) -> dict[str, Any]:
        model = ScriptedAgentModel([(s, sc) for s, sc, _ in loaded], corpus, mode)
        with FakeWorld(model, index_dir) as world:
            ctx = served(model) if via_server else contextlib.nullcontext(model)
            with ctx as completer:
                return run_suites(
                    [s for s, _, _ in loaded],
                    completer,
                    world,
                    corpus,
                    model_info={"name": model.name, "live": False},
                    inputs=inputs,
                    hypothetical=hypothetical_modes(),
                )

    report = one(fake)
    if fake == "fence" and control:
        report["control"] = control_of(one("naive"))
        report["summary"]["ok"] = report["summary"]["ok"] and report["control"]["caught"]
    return report
