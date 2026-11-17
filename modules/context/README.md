<!-- SPDX-License-Identifier: Apache-2.0 -->
# Module `context`: retrieval of the lab's own knowledge, by meaning, at each reader's TLP ceiling

The provider of the `context` slot (the contract `conformance/protocols/context.py`, ADR-0032): the
semantic adapter (`homelabnext/context_semantic.py`, the `semantic` feature) run as an HTTP service,
`homelabnext/context_service`, in one `compose_app` container built from this repository. It answers
"do we already have an answer to this?" over the lab's own registers, runbooks, ADRs and documents:

* the **index** is built from configured **git sources** (each a repository, a ref and path globs),
  fetched read-only by the service at every reindex;
* **every item carries a TLP label** (ADR-0033): its source's declared label, raised to the
  strictest marker or `tlp` field the item carries; and **every read is made at the caller's ceiling**
  (a caller is a token with a ceiling): an item above it is exactly as absent as one that does not exist;
* an optional **judge** (the gateway's `decision` role) is an **abstention gate**: the index's order is
  kept, and a query returns nothing when no top passage answers it.

No public route, no data of its own: the index, the checkouts and the last reindex's record are all
derived from the sources and rebuilt by a reindex (at every start, and on the timer).

## Why this design (the eval)

ADR-0032 allows a semantic adapter behind `context` only after an eval shows it beats the keyword store.
The eval (2026-11-16; the harness is `homelabnext/context/evalrun.py`, the public fixture
`evals/context/`) ran about 30 real questions with known answers (exact error strings, paraphrased
"did we decide X", "how do we do Y") plus questions with **no** answer, which must abstain:

| set | contender | hit@1 | hit@5 | MRR | abstain precision | abstain recall | latency |
|---|---|---|---|---|---|---|---|
| private (32 + 6) | A: keyword/relation store (today's) | 41% | 78% | 0.53 | n/a | 0% | - |
| private | B: hybrid BM25 + dense (this module, judge off) | 94% | 100% | 0.969 | n/a (never abstains) | 0% | ~80 ms |
| private | **B + judge as abstention gate, T = 0.10** (this module, judge on) | **94%** | **100%** | **0.969** | **100% (6/6)** | **100%** | ~15-20 s |
| private | B + judge as reranker | 91% | 100% | 0.945 | 100% | 100% | ~15-20 s |
| public (23 + 6) | B | 74% | 87% | 0.793 | 100% (1/1) | 17% | ~40 ms |
| public | B + judge as abstention gate | 74% | 87% | 0.793 | 86% (6/7) | 100% | ~15-20 s |

Hence: the hybrid index (B), and the judge as a **gate**, never as a reranker (reranking lowered hit@1,
94% to 91% private and 74% to 65% public). The threshold 0.10 was chosen on the public fixture and applied
unchanged to the private set, where the no-answer maximum was 0.083 and the weakest answerable maximum
0.638. The evidence is thin on the abstain side (six no-answer questions per set); re-check on a larger
set before tightening anything. The judge costs about 3 s a call; the service asks at most
`context_judge_workers` (2) at a time and stops at the first passage that clears.

## How it is built

```text
caller --Bearer--> POST /v1/query  --> caller's ceiling (a request may only lower it)
                                       --> semantic store (one store, every label; filtered per read)
                                       --> judge gate (optional, outside the store's lock)
timer / automation --> POST /v1/reindex --> git fetch each source (sibling dir, then rename)
                                        --> collect + label --> index what changed, drop what went
```

* **Image** (`image/Dockerfile`): Python 3.11 slim pinned by digest; git from the Debian archive at a
  snapshot date and an exact version; every wheel hash-checked (`image/requirements.txt`, from
  `requirements.in`); the embedding model (`sentence-transformers/all-MiniLM-L6-v2`, Apache-2.0) fetched
  at build by `homelabnext.context.semantic_model`, pinned by revision and **a sha256 and size per file**,
  and checked again at every start. The model is not taken from the model store: #459 pins it file by
  file in `semantic_model.FILES` and refuses a directory with any extra or symlinked file, which the
  store's hub layout (snapshots linking into blobs) would be. At run time nothing is downloaded but the
  sources.
* **Service** (`homelabnext/context_service`): `serve` (and an initial index in the background; when the
  fetch fails at start it indexes the checkouts already on disk), `reindex` and `check` (clients of the
  running server, run inside the container). Standard library HTTP.
* **Role** `context`: validates the settings, resolves every credential, renders `config.json`
  (read-only in the container; callers as the sha256 of their tokens), the owner-only env file (the
  admin token, the gateway key, the sources' credentials), the container (its own uid, no capability,
  the data root its only writable path) and the reindex timer, whose service writes its last-run record
  (role `last_run`, `timer:context/reindex`).

## The API

| Route | Auth | What |
|---|---|---|
| `GET /health` | none | the process answers (no content) |
| `GET /ready` | none | 200 once an index succeeded and holds documents; counts and the last reindex's outcome only |
| `POST /v1/query` | scope `query` | `{text, allowed, seeds?, kinds?, budget?, include_inactive?, ceiling?}` -> `{hits: [{id, kind, title, path, score, snippet, content, digest, tlp}], ceiling, judged}` |
| `POST /v1/get` | scope `query` | `{id, allowed, ceiling?}` -> `{hit}`; 404 exactly as for an id that does not exist |
| `POST /v1/reindex` | scope `reindex` | fetch and index now: 200 with the run's report, 500 when it failed (the index unchanged), 409 while one runs |
| `POST /v1/check` | admin | the canned query finds its item; the judge, when on, clears it |

`allowed` is the contract's scope (exact ids, or namespaces ending in `:` or `/`), stated by the caller.
The **ceiling** is the caller's: a request's `ceiling` may only lower it. 401 for a missing or unknown
token, 403 for a missing scope, 400 for a malformed query (the message never echoes the text), 413 for a
body over 64 KiB. The automation hook is `POST /v1/reindex` with a caller that has the `reindex` scope
(the rules that call it live with the automation pack, not here).

Document ids: `<kind>:<source>/<path>` for a file, `<kind>:<source>/<record id>` for a register record.

## Sources

`context_sources` (no default: every value is the site's):

| Key | Meaning |
|---|---|
| `name` | the source's name: the middle of its documents' ids (`a-z`, `0-9`, `-`) |
| `url` | `https://` only (http with `context_allow_plain_http`), never a credential in the URL |
| `ref` | a branch or tag (tracked: every reindex takes its head) or a 40-hex commit (pinned; refused if the fetch gives anything else) |
| `kind` | the documents' kind (`lesson`, `runbook`, `doc`, ...): the namespace callers scope on |
| `tlp` | the declared label of everything the source holds |
| `paths` | globs, relative to the repository root |
| `format` | `files` (one document per file; title the first `# ` heading) or `yaml-records` (one per record of a YAML list: `records_key`, `id_field` (`id`), `title_field` (`title`); a record's `status` is the contract's lifecycle status, so a `retired` one is inactive) |
| `honour_item_labels` | keep an item's own *looser* label (ADR-0033 decision 3: a human-approve choice); a stricter one is always kept |
| `credential`, `credential_scheme` | a secret reference such as `secret:context/sources/registers` holding a token (`bearer`) or `user:password` (`basic`); sent as git's `http.extraHeader` through its environment, never in an argument |

A source whose globs match nothing, a register that is not a list, or two items with one id fail the
reindex (never a silently empty index); a file whose name holds a space, an empty file or a symlink is
skipped and counted. A fetch goes to a sibling directory and is renamed into place only when it
succeeded; removal refuses anything not strictly inside the sources directory.

## What the overlay sets

* **Selection** (`lab/modules.yml`): `slots: {context: [{provider: context, instance: context, placement:
  {server: <host>}}]}` with the host on the agents guest; **grant** `grants.egress.context.server:
  [internet]` when any source is on a public forge.
* **Registry row** (`lab/services.yml`): this module's row as bound (`host` the guest, `version`
  0.1.0, the service's own; the index library is txtai 9.14.0, pinned in the image).
* **Group variables**: `context_image` (the lab's build, `localhost/hnx-context:<version>-<commit12>@sha256:...`),
  `context_sources`, `context_callers` (for example `{name: agents, secret: secret:context/agents-token,
  ceiling: amber, scopes: [query]}` and `{name: automation, secret: secret:context/automation-token,
  ceiling: clear, scopes: [reindex]}`), `context_health_query` (`{text, expect, ceiling}`: a question one
  known item answers), and, for the judge, `context_gateway_id` (the gateway's registry id).
* **Secrets**: `secret:context/admin-token`; one token per caller; `secret:context/gateway-key` (a
  gateway key whose role list includes the decision role) when the judge is on; one credential per
  private source.
* **Footprint**: 2 vCPU, 3 GiB (the container's `context_mem_limit` is 3g; the model and torch take about
  1 GiB), 20 GB disk (the image is about 2.1 GB; the checkouts are shallow).

The image is built by the lab from a checkout of this repository:

```sh
docker build -f modules/context/image/Dockerfile -t localhost/hnx-context:0.1.0-<commit12> .
```

## Conformance

`conformance/target.yml` runs the `context` suite against the module's own code through the shared
adapter `homelabnext.conform.adapters.context_service`: the suite's documents go to the service's store
and every read is a JSON request through the service's routes (the deployed instance indexes only its
sources, so the suite cannot index into it). With the pinned model: 16 of 16 checks pass, the `semantic`
SHOULD included. CI runs the same routes with the adapter's test seams
(`tests/context_service/test_context_conformance.py`).
