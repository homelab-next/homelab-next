# SPDX-License-Identifier: Apache-2.0
"""The retrieval eval that gates a semantic ``context`` adapter (ADR-0032).

``python -m homelabnext.context.evalrun --docs docs --questions evals/context/questions.json``

A *corpus* is either a directory of Markdown (``--docs DIR``: one document per file, id
``doc:<path relative to DIR's parent>``, labelled ``clear``) or a JSON-lines file (``--corpus
FILE``: one object per line with ``id``, ``kind``, ``title``, ``content`` and optionally
``status``, ``tlp``).  *Questions* are a JSON list of ``{"id", "kind", "q", "answers"}`` where
``kind`` is ``symptom`` (an exact error or message), ``decision`` ("did we decide X"),
``howto`` ("how do we do Y") or ``none`` (nothing in the corpus answers it, ``answers`` empty).
The corpus and questions of a private lab stay outside this repository; this module reads
whatever paths it is given and prints aggregate numbers only.

Contenders: ``keyword`` (the reference store), ``semantic`` (the hybrid adapter, needs the
``context-semantic`` extra and ``--model-dir``) and ``judged`` (semantic plus a judge: replayed
with ``--judge-record FILE``, or live through ``--judge-url`` with the token read from the
environment variable named by ``--judge-token-env``; ``--judge-save FILE`` records the live
verdicts for replay).

Metrics: hit@1, hit@5 and MRR over the answerable questions (a hit is any listed answer);
abstain precision (of the questions where a contender returned nothing, the share that really
had no answer), abstain recall (of the no-answer questions, the share it abstained on) and
the answerable questions it wrongly abstained on; latency per query.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import statistics
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from homelabnext import tlp as _tlp

from .model import Document, Hit, Query
from .store import ContextStore

__all__ = ["Question", "Result", "evaluate", "load_corpus", "load_questions", "main", "render"]

KINDS = ("symptom", "decision", "howto", "none")


@dataclass(frozen=True)
class Question:
    id: str
    kind: str
    q: str
    answers: tuple[str, ...]


@dataclass
class Result:
    name: str
    hit1: float = 0.0
    hit5: float = 0.0
    mrr: float = 0.0
    abstain_precision: float | None = None
    abstain_recall: float = 0.0
    false_abstains: int = 0
    mean_ms: float = 0.0
    p95_ms: float = 0.0
    index_s: float = 0.0
    by_kind: dict[str, float] = field(default_factory=dict)  # hit@5 per question kind


def load_questions(path: str | Path) -> list[Question]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    out = []
    for n, item in enumerate(raw):
        kind, answers = item.get("kind"), tuple(item.get("answers", ()))
        if kind not in KINDS or not item.get("q") or not item.get("id"):
            raise ValueError(f"question {n}: needs id, q and kind in {KINDS}")
        if (kind == "none") != (not answers):
            raise ValueError(f"question {n}: kind 'none' means no answers, and only then")
        out.append(Question(item["id"], kind, item["q"], answers))
    if len({q.id for q in out}) != len(out):
        raise ValueError("duplicate question id")
    return out


_HEADING = re.compile(r"^#\s+(.+?)\s*$", re.MULTILINE)


def _docs_dir(root: Path) -> tuple[list[Document], dict[str, _tlp.Label]]:
    docs = []
    for p in sorted(root.rglob("*.md")):
        text = p.read_text(encoding="utf-8")
        m = _HEADING.search(text)
        rel = f"{root.name}/{p.relative_to(root).as_posix()}"
        docs.append(
            Document(f"doc:{rel}", "doc", text, title=m.group(1) if m else p.stem, path=rel)
        )
    return docs, {d.id: _tlp.Label.CLEAR for d in docs}  # the public repository is clear


def _jsonl(path: Path) -> tuple[list[Document], dict[str, _tlp.Label]]:
    docs, labels = [], {}
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        o = json.loads(line)
        try:
            d = Document(
                o["id"],
                o["kind"],
                o["content"],
                title=o.get("title", ""),
                path=o.get("path", ""),
                status=o.get("status", ""),
            )
        except KeyError as exc:
            raise ValueError(f"corpus line {n}: missing {exc}") from exc
        docs.append(d)
        labels[d.id] = _tlp.read(o.get("tlp"))  # absent is red
    return docs, labels


def load_corpus(
    docs: str | None = None, corpus: str | None = None
) -> tuple[list[Document], dict[str, _tlp.Label]]:
    if bool(docs) == bool(corpus):
        raise ValueError("give exactly one of --docs and --corpus")
    out = _docs_dir(Path(docs)) if docs else _jsonl(Path(corpus or ""))
    if not out[0]:
        raise ValueError("the corpus is empty")  # never pass vacuously
    return out


def _run(search: Callable[[str], Sequence[Hit]], questions: Sequence[Question]) -> Result:
    res = Result("")
    ranks: dict[str, int | None] = {}
    times, abstained = [], set()
    for q in questions:
        t = time.perf_counter()
        hits = search(q.q)
        times.append((time.perf_counter() - t) * 1000)
        ids = [h.id for h in hits]
        if not ids:
            abstained.add(q.id)
        ranks[q.id] = next((i + 1 for i, x in enumerate(ids) if x in q.answers), None)
    ans = [q for q in questions if q.kind != "none"]
    none = [q for q in questions if q.kind == "none"]
    if ans:
        res.hit1 = sum(ranks[q.id] == 1 for q in ans) / len(ans)
        res.hit5 = sum((ranks[q.id] or 99) <= 5 for q in ans) / len(ans)
        res.mrr = sum(1 / ranks[q.id] for q in ans if ranks[q.id]) / len(ans)
        res.false_abstains = sum(q.id in abstained for q in ans)
        for k in KINDS[:-1]:
            sub = [q for q in ans if q.kind == k]
            if sub:
                res.by_kind[k] = sum((ranks[q.id] or 99) <= 5 for q in sub) / len(sub)
    good = sum(q.id in abstained for q in none)
    res.abstain_precision = good / len(abstained) if abstained else None
    res.abstain_recall = good / len(none) if none else 0.0
    res.mean_ms = statistics.fmean(times)
    res.p95_ms = sorted(times)[max(0, int(len(times) * 0.95) - 1)]
    return res


def evaluate(
    contenders: dict[str, Callable[[list[Document]], Callable[[str], Sequence[Hit]]]],
    docs: list[Document],
    questions: Sequence[Question],
) -> list[Result]:
    """Build each contender over ``docs`` and run every question through it."""
    ids = {d.id for d in docs}
    missing = {a for q in questions for a in q.answers} - ids
    if missing:
        raise ValueError(f"{len(missing)} expected answer id(s) are not in the corpus")
    out = []
    for name, build in contenders.items():
        t = time.perf_counter()
        search = build(docs)
        built = time.perf_counter() - t
        r = _run(search, questions)
        r.name, r.index_s = name, built
        out.append(r)
    return out


def render(results: Sequence[Result], n_answerable: int, n_none: int) -> str:
    pct = lambda x: "n/a" if x is None else f"{100 * x:.0f}%"  # noqa: E731
    rows = [
        f"{n_answerable} answerable and {n_none} no-answer questions.",
        "",
        "| contender | hit@1 | hit@5 | MRR | abstain precision | abstain recall | wrong abstains "
        "| mean ms | p95 ms | index s |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in results:
        rows.append(
            f"| {r.name} | {pct(r.hit1)} | {pct(r.hit5)} | {r.mrr:.3f} | "
            f"{pct(r.abstain_precision)} | {pct(r.abstain_recall)} | {r.false_abstains} | "
            f"{r.mean_ms:.1f} | {r.p95_ms:.1f} | {r.index_s:.1f} |"
        )
    rows += [
        "",
        "hit@5 by question kind: "
        + "; ".join(
            f"{r.name}: " + ", ".join(f"{k} {pct(v)}" for k, v in r.by_kind.items())
            for r in results
        ),
    ]
    return "\n".join(rows)


def _keyword(docs: list[Document]):
    s = ContextStore()
    s.index(docs)
    allowed = frozenset({d.id.split(":", 1)[0] + ":" for d in docs})
    return lambda q: s.query(Query(allowed=allowed, text=q, budget=10))


def _semantic(model_dir: str, labels, **kw):
    from .semantic import SemanticContextStore

    def build(docs):
        s = SemanticContextStore(model_dir, tlp_of=lambda d: labels[d.id], **kw)
        s.index(docs)
        allowed = frozenset({d.id.split(":", 1)[0] + ":" for d in docs})
        build.store = s
        return lambda q: s.query(Query(allowed=allowed, text=q, budget=10))

    return build


def _judged(base, judge, **kw):
    from .judge import JudgedStore

    def build(docs):
        base(docs)
        s = JudgedStore(base.store, judge, **kw)
        allowed = frozenset({d.id.split(":", 1)[0] + ":" for d in docs})
        return lambda q: s.query(Query(allowed=allowed, text=q, budget=10))

    return build


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--docs")
    ap.add_argument("--corpus")
    ap.add_argument("--questions", required=True)
    ap.add_argument("--model-dir", default=os.environ.get("HNX_CONTEXT_MODEL_DIR"))
    ap.add_argument("--min-similarity", type=float, default=0.36)
    ap.add_argument(
        "--min-score",
        type=float,
        default=0.0,
        help="also run semantic with this abstention cut-off",
    )
    ap.add_argument("--dense-weight", type=float, default=0.5)
    ap.add_argument("--judge-record", help="replay recorded verdicts from this JSON file")
    ap.add_argument("--judge-url", help="live gateway base URL (OpenAI-compatible)")
    ap.add_argument("--judge-token-env", default="HNX_EVAL_GATEWAY_TOKEN")
    ap.add_argument("--judge-model", default="fast-classifier")
    ap.add_argument("--judge-save", help="write the live verdicts here for replay")
    ap.add_argument("--judge-threshold", type=float, default=0.5)
    ap.add_argument("--judge-top-k", type=int, default=5)
    ap.add_argument("--only", help="comma-separated contenders to run")
    ap.add_argument("--json", action="store_true", help="print the numbers as JSON")
    a = ap.parse_args(argv)

    docs, labels = load_corpus(a.docs, a.corpus)
    questions = load_questions(a.questions)
    contenders: dict = {"keyword": _keyword}
    if a.model_dir:
        sem = _semantic(
            a.model_dir, labels, min_similarity=a.min_similarity, dense_weight=a.dense_weight
        )
        contenders["semantic"] = sem
        if a.min_score:
            contenders["semantic+cutoff"] = _semantic(
                a.model_dir,
                labels,
                min_similarity=a.min_similarity,
                dense_weight=a.dense_weight,
                min_score=a.min_score,
            )
        judge = _make_judge(a)
        if judge is not None:
            contenders["semantic+judge"] = _judged(
                sem, judge, top_k=a.judge_top_k, threshold=a.judge_threshold
            )
    if a.only:
        keep = set(a.only.split(","))
        contenders = {k: v for k, v in contenders.items() if k in keep}
    results = evaluate(contenders, docs, questions)
    if a.judge_save and isinstance(getattr(a, "_judge", None), _Recording):
        a._judge.save(a.judge_save)
    n_none = sum(q.kind == "none" for q in questions)
    if a.json:
        print(json.dumps([r.__dict__ for r in results], indent=1))
    else:
        print(render(results, len(questions) - n_none, n_none))
    return 0


class _Recording:
    """Wraps a live judge and remembers each verdict, keyed for :class:`RecordedJudge`."""

    def __init__(self, inner):
        self._inner, self.seen = inner, {}

    def judge(self, question, hit, tlp):
        from .judge import PASSAGE_CHARS, pair_key

        v = self._inner.judge(question, hit, tlp)
        self.seen[pair_key(question, hit.content[:PASSAGE_CHARS])] = [v.answers, v.confidence]
        return v

    def save(self, path):
        Path(path).write_text(json.dumps(self.seen), encoding="utf-8")


def _make_judge(a):
    from .judge import GatewayJudge, RecordedJudge

    if a.judge_record:
        return RecordedJudge.load(a.judge_record)
    if a.judge_url:
        from homelabnext.conform.adapters.openai_compat import OpenAICompat

        token = os.environ.get(a.judge_token_env)
        client = OpenAICompat(
            a.judge_url,
            auth=(lambda: f"Bearer {token}") if token else None,
            timeout=60.0,
            allow_plaintext=True,
        )
        live = GatewayJudge(client, model=a.judge_model, tag="hnx-context-eval")
        a._judge = _Recording(live) if a.judge_save else live
        return a._judge
    return None


if __name__ == "__main__":
    raise SystemExit(main())
