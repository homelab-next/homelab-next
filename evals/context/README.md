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
did. The judge (`--judge-*`) asks a gateway model role whether each top passage answers the question;
a live judge needs a reachable endpoint and sends every passage with its `X-HNX-TLP` label.
