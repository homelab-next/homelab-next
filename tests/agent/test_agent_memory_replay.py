# SPDX-License-Identifier: Apache-2.0
"""Memory is judged by replay (ADR-0037 PR 5, decision 16).

``replay/fixture.yml`` is a history of reports and packs (timestamps, sources, labels, a write
through memory, an unchecked platform write, a verifier's stamp and an operator's retraction
partway through) with golden questions placed in it; ``replay/golden.yml`` holds the exact
answer to each question and the outcome of each step.  The test replays the history into a
fresh store on both backends and compares every answer, printing a unified diff per answer that
differs.  A later change to the memory design is judged by re-running it: a golden answer
changes only with a change of behaviour that is meant.

The questions: the value of a key as of T (``as_of``), the history of a key, ``dependents(S)``
(cited and exposed, including one hop through memory), what ``retract(S)`` retires and that a
later report citing or rendering S is refused (by its input uid, by a knowledge item's name,
through a marked memory revision, and by the closure of an unchecked platform write), which
entries are unsourced, unchecked or stale (everything is stale, since no ``Verifier`` ships,
except the one a test verifier confirmed, and that one too once its budget has passed), and what
a reader at a lowered ceiling sees withheld.

The goldens are read with :class:`GoldenLoader`, which leaves a time of day such as ``10:12`` a
string: YAML 1.1 reads it as the base-60 integer 612, so a hand edit dropping its quotes would
otherwise show as a confusing ``612`` against ``'10:12'``."""

import difflib
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml
from agent_support import digest, item, labelled_pack, library, spec, uid, verified
from memory_admin_support import operator, operators_file

from homelabnext.agent import compile_profile
from homelabnext.agent.deny import DenySet
from homelabnext.agent.knowledge import Selection
from homelabnext.agent.memory import (
    FileBackend,
    InMemoryBackend,
    MemoryAccessError,
    MemoryStore,
    MemoryUpdateError,
    Verifier,
    deny_path_from,
    memory_block_input,
)
from homelabnext.memory_admin import MemoryAdmin

HERE = Path(__file__).resolve().parent / "replay"
FIXTURE = HERE / "fixture.yml"
GOLDEN = HERE / "golden.yml"

#: the fields of a change record a golden answer keeps: everything that says what the store
#: believed and why, nothing that is only an encoding (a value's digest, a pack's hash, which
#: the answer names by the fixture step that assembled the pack instead)
RECORD_FIELDS = (
    "at",
    "op",
    "rev",
    "value",
    "sources",
    "closure",
    "checked",
    "tlp",
    "reason",
    "by",
    "verified_at",
    "refuted",
    "purged",
)


class GoldenLoader(yaml.SafeLoader):
    """YAML's safe loader without base-60 integers, so ``10:12`` (a time of day, as the goldens
    write it) reads as the string it is, quoted or not.  Every other integer form is kept."""


GoldenLoader.yaml_implicit_resolvers = {
    first: [(tag, rx) for tag, rx in resolvers if tag != "tag:yaml.org,2002:int"]
    for first, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
GoldenLoader.add_implicit_resolver(
    "tag:yaml.org,2002:int",
    re.compile(r"^(?:[-+]?0b[0-1_]+|[-+]?0[0-7_]+|[-+]?(?:0|[1-9][0-9_]*)|[-+]?0x[0-9a-fA-F_]+)$"),
    list("-+0123456789"),
)


def load(path):
    return yaml.load(path.read_text(encoding="utf-8"), Loader=GoldenLoader)


class Clock:
    def __init__(self, t):
        self.t = t

    def __call__(self):
        return self.t


class ConfirmAll(Verifier):
    """A test :class:`Verifier` (none ships) that confirms every fact it is asked about."""

    def verify(self, request):
        return True


class Replay:
    """One replay of the fixture into a fresh ``backend``; :meth:`run` returns the answers."""

    def __init__(self, fixture, backend, op):
        self.fx = fixture
        self.backend = backend
        self.op = op
        self.start = datetime.fromisoformat(fixture["start"].replace("Z", "+00:00"))
        self.day = self.start.strftime("%Y-%m-%dT")
        self.clock = Clock(self.start)
        self.profiles = {}
        self.names = {}  # profile id -> the first fixture name that has it
        for name, extra in fixture["profiles"].items():
            s = spec()
            s.update(extra)
            self.profiles[name] = verified(compile_profile(s, library()))
            self.names.setdefault(extra["id"], name)
        self.packs = {}  # pack hash -> the name of the step that assembled it
        self.answers = {}

    # ------------------------------------------------------------ symbols
    def expand(self, value):
        """A fixture identifier as the store knows it."""
        if value.startswith("uid:"):
            return uid(int(value[4:]))
        if value.startswith("digest:"):
            return digest(int(value[7:]))
        if value.startswith("lesson:uid:"):
            return f"lesson:{uid(int(value[11:]))}"
        m = re.fullmatch(r"mem:([^/]+)/(.+)", value)
        if m:
            return f"mem:{self.profiles[m[1]]['id']}/{m[2]}"
        return value

    def symbol(self, value):
        """An answer as the goldens write it: identifiers and times back in fixture form."""
        if isinstance(value, dict):
            return {self.symbol(k): self.symbol(v) for k, v in value.items()}
        if isinstance(value, list | tuple):
            return [self.symbol(v) for v in value]
        if not isinstance(value, str):
            return value
        if value in self.packs:
            return f"pack:{self.packs[value]}"
        value = re.sub(
            r"01900000-0000-7000-8000-([0-9a-f]{12})", lambda m: f"uid:{int(m[1], 16)}", value
        )
        value = re.sub(r"sha256:(0{48}[0-9a-f]{16})", lambda m: f"digest:{int(m[1], 16)}", value)
        value = re.sub(r"mem:(profile:[^/]+)/", lambda m: f"mem:{self.names[m[1]]}/", value)
        if value.startswith(self.day):  # a stamp on the fixture's day: its time of day only
            value = re.sub(r"(:00)?(\.0+)?Z$", "", value[len(self.day) :])
        return value

    def at(self, hhmm):
        h, m = (int(x) for x in hhmm.split(":"))
        return self.start.replace(hour=h, minute=m)

    # ------------------------------------------------------------ the replay
    def store(self, verifier=False):
        return MemoryStore(
            self.backend, now=self.clock, verifier=ConfirmAll() if verifier else None
        )

    def state(self):
        return {o: self.backend.load(o) for o in self.backend.owners()} | {
            "deny": self.backend.load_deny()
        }

    def run(self):
        # a fresh store: no owner's memory and no deny state before the first step
        assert not list(self.backend.owners()), "the replay must start from an empty store"
        assert not any(self.backend.load_deny().values()), "the replay must start undenied"
        for step in self.fx["steps"]:
            self.clock.t = self.at(step["at"])
            if "ask" in step:
                self.answers[step["ask"]] = self.symbol(getattr(self, "ask_" + step["kind"])(step))
            elif "retract" in step:
                self.answers[step["name"]] = self.symbol(self.retract(step["retract"]))
            else:
                self.answers[step["name"]] = self.symbol(self.write(step))
        return self.answers

    def updates(self, step):
        out = []
        for u in step["updates"]:
            u = {"scope": "analyst", **u}
            if "sources" in u:
                u["sources"] = [self.expand(s) for s in u["sources"]]
            out.append(u)
        return out

    def write(self, step):
        profile = self.profiles[step["as"]]
        store = self.store(step.get("verifier", False))
        if step.get("platform"):
            return store.apply_updates(profile, self.updates(step), unchecked=True)
        spec_ = step["pack"]
        block = None
        if "memory_block" in spec_:
            scopes = profile["memory_scopes"]
            block = [
                e
                for e in memory_block_input(store, profile, scopes)
                if e["key"] in spec_["memory_block"]
            ]
        extra = {}
        if "knowledge" in spec_:
            extra["knowledge"] = self.lessons(profile, spec_["knowledge"])
        pack, h = labelled_pack(
            [item(n, label) for n, label in spec_["findings"]],
            [item(999, "clear")],
            profile=profile,
            memory_block=block,
            **extra,
        )
        self.packs.setdefault(h, step["name"])  # the step that first assembled it
        report = {
            "pack_id": h,
            "profile": profile["id"],
            "status": "ok",
            "summary": f"replay step {step['name']}",
            "cites": [{"source": "findings", "ref": "f1"}],
            "unknowns": [],
            "memory_updates": self.updates(step),
        }
        # the outcome either way is the step's answer, so a refusal that became an apply (or the
        # reverse) shows in the diff and the replay goes on to the questions after it
        before = self.state()
        try:
            return store.apply_report(profile, report, pack=pack, pack_hash=h)
        except (MemoryUpdateError, MemoryAccessError) as exc:
            return {
                "refused": type(exc).__name__,
                "problems": getattr(exc, "problems", [str(exc)]),
                "changed": self.state() != before,
            }

    @staticmethod
    def lessons(profile, numbers):
        """A knowledge selection of lessons ``numbers``: lesson N is ``lesson:<uid N>`` with
        content digest N, as the knowledge graph would select it for ``profile``."""
        included = tuple(
            {"id": f"lesson:{uid(n)}", "kind": "lesson", "title": f"lesson {n}", "path": None,
             "reviewed": [], "distance": 0, "score": 1.0, "via": "seed", "from": "replay",
             "rules": [0], "max_chars": 1000, "digest": digest(n), "text": f"lesson {n}",
             "rank": i, "section": f"knowledge-{i:03d}-lesson"}
            for i, n in enumerate(numbers, 1)
        )  # fmt: skip
        return Selection(
            profile=profile["id"], profile_digest="sha256:" + "a" * 64,
            graph_digest="sha256:" + "b" * 64, rules=(), seeds=(), excluded=(),
            included=included,
        )  # fmt: skip

    def retract(self, spec_):
        admin = MemoryAdmin(self.backend, now=self.clock)
        source = self.expand(spec_["source"])
        dry = admin.dependents(source, by=self.op)
        done = admin.retract(source, spec_["reason"], by=self.op, confirm=dry["confirm"])
        return {
            "dry_run": dry["affected"],
            "aliases": done["aliases"],
            "marks": done["marks"],
            "retired": done["retired"],
            "resumed": done["resumed"],
        }

    # ------------------------------------------------------------ the questions
    def project(self, rec):
        row = {k: rec[k] for k in RECORD_FIELDS if k in rec}
        if "by" in row:
            row["by"] = "<operator>"  # the invoking user, whoever runs the tests
        if rec.get("pack_id"):
            row["pack"] = rec["pack_id"]
        return row

    def ask_as_of(self, q):
        p = self.profiles[q["as"]]
        return self.store().as_of(p, q.get("scope", "analyst"), self.at(q["t"]))

    def ask_history(self, q):
        p = self.profiles[q["as"]]
        got = self.store().history(p, q.get("scope", "analyst"), q["key"])
        return {"records": [self.project(r) for r in got["records"]], "withheld": got["withheld"]}

    def ask_read(self, q):
        return self.store().read(self.profiles[q["as"]], q.get("scope", "analyst"))

    def ask_audit(self, q):
        """Which shown entries are stale, unsourced and unchecked.  ``unsourced`` is the store's
        own meaning (the ``unsourced`` of the write that set the value, ADR-0037 decision 7): the
        entry's last value-setting record (``add`` or ``replace``) has no ``sources``, though its
        closure may still hold the sources since its ``add``.  ``unchecked``: its last record was
        an unchecked platform write."""
        p, scope = self.profiles[q["as"]], q.get("scope", "analyst")
        store = self.store()
        got = store.read(p, scope, stale_after=timedelta(minutes=q["stale_after_min"]))
        unsourced, unchecked = [], []
        for key in got["entries"]:
            recs = store.history(p, scope, key)["records"]
            setting = [r for r in recs if r["op"] in ("add", "replace")]
            if not setting[-1]["sources"]:
                unsourced.append(key)
            if not recs[-1]["checked"]:
                unchecked.append(key)
        return {
            "entries": got["entries"],
            "withheld": got["withheld"],
            "stale": got["stale"],
            "unsourced": unsourced,
            "unchecked": unchecked,
        }

    def ask_live(self, q):
        store, out = self.store(), {}
        for name, p in self.profiles.items():
            if self.names[p["id"]] != name:
                continue  # a ceiling variant of a profile already listed
            for scope in p["memory_scopes"]:
                out[f"{name}/{scope}"] = store.read(p, scope)["entries"]
        return out

    def ask_dependents(self, q):
        got = MemoryAdmin(self.backend, now=self.clock).dependents(
            self.expand(q["source"]), by=self.op
        )
        return {k: v for k, v in got.items() if k != "confirm"}  # a digest of the rest


def replay(backend, op):
    fixture = load(FIXTURE)
    return Replay(fixture, backend, op).run()


def mismatches(answers, golden):
    """A readable diff per answer that differs from its golden, or per one missing on a side."""
    out = []
    for name in sorted(set(answers) | set(golden), key=lambda n: (n not in golden, n)):
        want = yaml.safe_dump(golden.get(name, "<no golden answer>"), sort_keys=True).splitlines()
        got = yaml.safe_dump(answers.get(name, "<not asked>"), sort_keys=True).splitlines()
        if want != got:
            diff = difflib.unified_diff(want, got, "golden", "replay", lineterm="", n=2)
            out.append(f"--- {name}\n" + "\n".join(diff))
    return out


@pytest.fixture(params=["memory", "file"])
def backend(request, tmp_path):
    if request.param == "memory":
        return InMemoryBackend()
    # the deny file the operators file names, read from it as the runtime reads it (decision 14)
    deny = deny_path_from(operators_file(tmp_path))
    return FileBackend(tmp_path / "memory.json", deny_path=deny)


@pytest.fixture
def op(tmp_path):
    return operator(tmp_path)


@pytest.fixture(scope="module")
def golden():
    return load(GOLDEN)


def test_the_replay_matches_the_golden_answers(backend, op, golden):
    problems = mismatches(replay(backend, op), golden)
    if problems:
        pytest.fail(
            "the memory replay differs from tests/agent/replay/golden.yml (ADR-0037 decision "
            "16); change a golden answer only for a change of behaviour that is meant:\n\n"
            + "\n\n".join(problems),
            pytrace=False,
        )


def _no_mem_hops(monkeypatch):
    from homelabnext.memory_admin import admin

    monkeypatch.setattr(admin, "parse_mem_ref", lambda ref: None)


def _stale_ignores_budget(monkeypatch):
    from homelabnext.agent import memory

    def stale(entry, cutoff, when):
        return not entry.get("verified_at") or entry["verified_at"] > when

    monkeypatch.setattr(memory, "_stale", stale)


def _no_name_deny(monkeypatch):
    monkeypatch.setattr(DenySet, "denies", lambda self, names: False)


#: a memory behaviour changed on purpose -> (the patch, the answers that must move, and one
#: answer's diff line that shows how)
MUTATIONS = {
    # dependents stop following mem: hops: d (exposed through a@1) is gone
    "dependents-ignore-mem-hops": (
        _no_mem_hops,
        {"dependents-uid-1", "retract-uid-1"},
        ("dependents-uid-1", "-  key: d"),
    ),
    # staleness ignores the budget: g, verified at 09:40, reads fresh at 10:15 against 30 min
    "stale-ignores-budget": (
        _stale_ignores_budget,
        {"audit-reader-short"},
        ("audit-reader-short", "-  g:"),
    ),
    # the name-based deny check is off: a pack rendering a retracted knowledge item is applied
    "no-name-deny": (
        _no_name_deny,
        {"renders-retracted-lesson"},
        ("renders-retracted-lesson", "-refused: MemoryUpdateError"),
    ),
}


@pytest.mark.parametrize("mutation", sorted(MUTATIONS))
def test_a_changed_memory_behaviour_fails_the_replay(mutation, backend, op, golden, monkeypatch):
    """The replay is a test of the design, not a recording: change one memory behaviour and the
    replay names the answers that moved, with a diff that shows how, on both backends."""
    patch, must_move, (name, line) = MUTATIONS[mutation]
    patch(monkeypatch)
    problems = mismatches(replay(backend, op), golden)
    moved = {p.splitlines()[0][4:] for p in problems}
    assert must_move <= moved, moved
    (diff,) = [p for p in problems if p.startswith(f"--- {name}\n")]
    assert line in diff.splitlines(), diff


def test_a_golden_mismatch_prints_a_readable_diff():
    problems = mismatches({"q": {"entries": {"a": "A2"}}}, {"q": {"entries": {"a": "A1"}}})
    assert problems == [
        "--- q\n--- golden\n+++ replay\n@@ -1,2 +1,2 @@\n entries:\n-  a: A1\n+  a: A2"
    ]
    (missing,) = mismatches({"q": 1}, {})
    assert missing.startswith("--- q\n") and "-<no golden answer>" in missing
    assert mismatches({"q": [1]}, {"q": [1]}) == []


def test_every_question_has_a_golden_answer_and_every_golden_a_question(golden):
    fixture = load(FIXTURE)
    asked = [s.get("ask") or s["name"] for s in fixture["steps"]]
    assert len(asked) == len(set(asked)), "a question or step name is used twice"
    assert set(asked) == set(golden)
    # a step the fixture says is refused has a refusal as its golden answer, and no other has
    refused = {s["name"] for s in fixture["steps"] if s.get("refused")}
    assert refused == {n for n, a in golden.items() if isinstance(a, dict) and "refused" in a}
    assert all(golden[n]["changed"] is False for n in refused)


def test_fixture_times_are_in_order_and_utc():
    """(That each replay starts from a fresh store is asserted by :meth:`Replay.run`.)"""
    fixture = load(FIXTURE)
    times = [s["at"] for s in fixture["steps"]]
    assert times == sorted(times)
    assert datetime.fromisoformat(fixture["start"].replace("Z", "+00:00")).tzinfo == UTC


def test_the_golden_loader_keeps_a_time_of_day_a_string():
    assert yaml.safe_load("t: 10:12") == {"t": 612}  # what YAML 1.1 makes of it
    got = yaml.load("t: 10:12\nn: 42\nh: 0x1f\nf: 1.5\nq: '09:30'", Loader=GoldenLoader)
    assert got == {"t": "10:12", "n": 42, "h": 31, "f": 1.5, "q": "09:30"}
