<!-- SPDX-License-Identifier: Apache-2.0 -->
# Module `context`: retrieval of the lab's own knowledge, by meaning, at each reader's TLP ceiling

The provider of the `context` slot (the contract `conformance/protocols/context.py`, ADR-0032): the
semantic adapter (`homelabnext/context_semantic.py`, the `semantic` feature) run as an HTTP service,
`homelabnext/context_service`, in one `compose_app` container built from this repository. It answers
"do we already have an answer to this?" over the lab's own registers, runbooks, ADRs and documents:

* the **index** is built from configured **sources**: **git sources** (each a repository, a ref and
  path globs), fetched read-only by the service at every reindex, and **documents sources** (the
  document store's REST API, by tag: the documents stay in the store);
* **every item carries a TLP label** (ADR-0033): the strictest of its base (the source's declared
  label, or the item's own `tlp` field read against it) and every TLP marker in its content; a
  marker only ever raises it. **Every read is made at the caller's ceiling** (a caller is a token
  with a ceiling): an item above it is exactly as absent as one that does not exist, and every hit is
  re-checked under the store's lock, so a concurrent reindex can never put one above it;
* an optional **judge** (the gateway's `decision` role) is an **abstention gate**: the index's order is
  kept, and a query returns nothing when no top passage answers it. The gateway receives the
  caller's question with the passage, so the request is labelled (`X-HNX-TLP`) at the request's
  **effective ceiling**, not the passage's label. A request whose ceiling is above
  `context_judge_ceiling` is never sent: `context_judge_on_error` decides (`fallback`, the default:
  the index's own ranking, answered with `judged: false`; `abstain`: nothing). A caller that wants the
  gate lowers `ceiling` on its request, declaring its question to be at that tier.

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
  the data root its only writable path: the data root is the project owner's, 0750, readable by the
  container's group, and its writable directories `sources/`, `state/`, `home/` and `cache/` are the
  container user's, 0700) and the reindex timer, whose service writes its last-run record
  (role `last_run`, `timer:context/reindex`).

## The API

| Route | Auth | What |
|---|---|---|
| `GET /health` | none | the process answers (no content) |
| `GET /ready` | none | 200 once an index succeeded and holds documents, `{ready}` alone; with any caller's token also the document count, the judge flag and the last reindex's outcome (never content) |
| `POST /v1/query` | scope `query` | `{text, allowed, seeds?, kinds?, budget?, include_inactive?, ceiling?}` -> `{hits: [{id, kind, title, path, score, snippet, content, digest, tlp}], ceiling, judged}` |
| `POST /v1/get` | scope `query` | `{id, allowed, ceiling?}` -> `{hit}`; 404 exactly as for an id that does not exist |
| `POST /v1/reindex` | scope `reindex` | fetch and index now: 200 with the run's report; 500 when it failed (the index unchanged, except that documents whose label changed in that run stay dropped until the next good run: fail closed, counted as `relabel_dropped`); 409 while one runs; 429 within `reindex_min_interval_s` (60 s) of the last run's end (not for the admin, the timer's caller) |
| `POST /v1/check` | admin | the canned query finds its item; the judge, when on, clears it |

`allowed` is the contract's scope (exact ids, or namespaces ending in `:` or `/`), stated by the caller.
The **ceiling** is the caller's: a request's `ceiling` may only lower it. 401 for a missing or unknown
token, 403 for a missing scope, 400 for a malformed query (the message never echoes the text), 413 for a
body over 64 KiB; a connection idle for 30 s is closed. The automation hook is `POST /v1/reindex` with a caller that has the `reindex` scope
(the rules that call it live with the automation pack, not here).

Document ids: `<kind>:<source>/<path>` for a file, `<kind>:<source>/<record id>` for a register
record, `<kind>:<source>/<doc id>-<slug>` for a document of the store (the store's numeric id leads,
so the id is unique and stable; a retitled document gets a new id and the old one is removed).
A persona's `context_allowed` prefix is the kind plus a colon (`tax:`, `yardi:`).

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
| `honour_item_labels` | keep a record's own *looser* `tlp` field (ADR-0033 decision 3: a human-approve choice); a stricter one is always kept, and no field ever lowers a record below a TLP marker in its content |
| `credential`, `credential_scheme` | a secret reference such as `secret:context/sources/registers` holding a token (`bearer`) or `user:password` (`basic`); sent as git's `http.extraHeader` through its environment, never in an argument |

A source whose globs match nothing, a register that is not a list, or two items with one id fail the
reindex (never a silently empty index); a file whose name holds a space, an empty file, a symlink or a
file too large to be a document (checked by its size before it is read) is skipped and counted. With
a credential set, git follows no redirect (the header never travels to another host). A fetch goes to a sibling directory and is renamed into place only when it
succeeded; removal refuses anything not strictly inside the sources directory.

### Documents sources (`type: documents`): the document store, indexed in place

The lab's document store (the tax library, the property-management knowledge base) holds documents
that must not be copied into a git repository: a copy is a second place to protect, to keep current
and to forget. So a `documents` source reads the store through its REST API at every reindex and
indexes the text in place. Nothing is exported, mirrored or checked out; the index is derived and
rebuilt by a reindex like every other.

| Key | Meaning |
|---|---|
| `name`, `kind`, `tlp` | as for a git source (`kind` is the namespace prefix, e.g. `tax`, `yardi`) |
| `type` | `documents` |
| `service` | the document store's **registry id**: the endpoint is the registry's base URL (a host name, never an address; https unless `context_allow_plain_http`); no host is written in the source |
| `tags` | 1 to 16 tag names; every document carrying any of them is indexed (a document under two is one document) |
| `credential`, `credential_scheme` | a secret reference in the module's own `context/` namespace (required) holding the store's API token, read from the secret store at deploy time into the owner-only env file; `token` (default: `Authorization: Token ...`) or `bearer`. Never in the config, a URL, a log or an error message |
| `host_header` | an explicit `Host` header, for a store that answers only to a name it knows (a bare address gets a 400). With https the certificate is still checked against the URL's host, so prefer the registry name |
| `ca_file` | an absolute path of the lab CA bundle verifying https (empty: the system store) |
| `page_size` (100), `max_doc_bytes` (4000000), `timeout` (30 s), `max_documents` (20000) | the bounds: documents per request, a document with more text is skipped and counted, seconds per request, a total over this fails the reindex |

Behaviour: the service lists `GET <endpoint>/api/documents/?tags__name__iexact=<tag>&page=N` until
the last page and takes each document's `id`, `title`, `created` and `content`; the indexed text is
the title, the created date and the content. **Incremental**: the index compares content digests, so
an unchanged document is not embedded again (the report counts `added`, `replaced`, `unchanged`,
`removed`); a document that was deleted or lost its tag is no longer listed and is removed. **Fails
closed**: a store that does not answer, a refused token, a redirect (never followed, so the token
cannot travel to another host), a response that is not the expected shape, or a tag that matches no
document fails the reindex and leaves the index as it was (a mistyped tag must never empty it).
There is no copy on disk, so the start-up fallback (index the checkouts already on disk) does not
apply to a documents source: it is reindexed when the store answers. The label is the source's
`tlp`, raised by any TLP marker in the text.

## What the overlay sets

* **Selection** (`lab/modules.yml`): `slots: {context: [{provider: context, instance: context, placement:
  {server: <host>}}]}` with the host on the agents guest; **grant** `grants.egress.context.server:
  [internet]` when any source is on a public forge.
* **Registry row** (`lab/services.yml`): this module's row as bound (`host` the guest, `version`
  0.1.0, the service's own; the index library is txtai 9.14.0, pinned in the image).
* **Group variables**: `context_image` (the lab's build, `localhost/hnx-context:<version>-<commit12>@sha256:...`),
  `context_sources` (git and documents sources), `context_callers` (for example `{name: agents, secret: secret:context/agents-token,
  ceiling: amber, scopes: [query]}` and `{name: automation, secret: secret:context/automation-token,
  ceiling: clear, scopes: [reindex]}`), `context_health_query` (`{text, expect, ceiling}`: a question one
  known item answers), and, for the judge, `context_gateway_id` (the gateway's registry id).
* **Secrets**: `secret:context/admin-token`; one token per caller; `secret:context/gateway-key` (a
  gateway key whose role list includes the decision role) when the judge is on; one credential per
  private git source and one API token per documents source.
* **Firewall**: a documents source needs the context guest to reach the document store's port.
  The row is `tls: none`, so bearer tokens and labelled content cross the LAN in clear;
  the guest firewall must admit port 8094 from the readers' guests (the agents, the automation
  host) and the metrics scraper only.
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
