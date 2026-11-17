# Context retrieval eval

The gate ADR-0032 puts in front of a semantic `context` adapter: it is adopted only if it beats
the keyword store on hit@5 without losing abstain precision.

```
pip install '.[context-semantic]'
python -m homelabnext.context.semantic_model /path/to/model      # provision the pinned model once
export HNX_CONTEXT_MODEL_DIR=/path/to/model
python -m homelabnext.context.evalrun --docs docs --questions evals/context/questions.json
```

`questions.json` is the **public fixture**: questions about this repository's own `docs/` (the corpus
is the docs directory, labelled `clear` as every file of a public repository is). A lab runs the same
harness over its **private** corpus and questions, kept outside this repository:

```
python -m homelabnext.context.evalrun --corpus corpus.jsonl --questions questions.json \
    [--min-score 0.57] [--judge-record verdicts.json | --judge-url URL --judge-save verdicts.json]
```

`corpus.jsonl` is one JSON object per line (`id`, `kind`, `title`, `content`, optional `status`,
`tlp`; a missing `tlp` is `red`). A question is `{id, kind, q, answers}` with `kind` one of
`symptom` (an exact error text), `decision`, `howto` or `none` (no answer exists; `answers` is empty
and the contender must return nothing). The harness prints aggregate numbers only.

`--min-score` adds a contender with an abstention cut-off. It depends on the corpus: calibrate it on
the public fixture, then apply it unchanged to the private set, as the pull request that added this
did. The judge (`--judge-*`) asks a gateway decision role (`kind: decision`, `POST /v1/systemone`) one noul
question per top passage (state "Question: ...\nPassage: ...", question "Does this passage answer the question?")
and reads the returned probability. It is an abstention **gate** by default (`--judge-mode gate`): the store's
ranking is kept and the query abstains when no top passage reaches `--judge-threshold` (default 0.10); the calls run
`--judge-workers` at a time (default 2, the decision server's slots) and stop at the first passage that clears.
`--judge-mode rerank` is opt-in. Live result, 2026-11-16 (fast-classifier, T = 0.10 chosen on the public fixture and
applied unchanged to a private set of 32 answerable and 6 no-answer questions): as a gate, abstain recall 0% to 100%
at 100% precision with hit@1 94% and hit@5 100% unchanged (private), and recall 17% to 100% at no hit@5 cost with one
wrong abstain on a question the store already missed (public: 23 and 6); as a reranker hit@1 fell 94% to 91% (private)
and 74% to 65% (public). Passages are cut to 1400 characters (the server's batch limit, LL-492) and shrunk once on an
HTTP 500 or 502. Latency was 15 to 20 s a query with five sequential calls (about 3 s each): that is why the calls are
concurrent and stop early. Only six no-answer questions per set: re-check on a larger set before relying on it.
a live judge needs a reachable endpoint and sends every passage with its `X-HNX-TLP` label.
