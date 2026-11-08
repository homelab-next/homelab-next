---
summary: Parsers are fuzzed, Go gets CodeQL, cross-language rules share vectors, allowlists grow only by label, security changes get a second model.
summary_of: outline:sha256:d352356126acf331
---
# ADR-0048: Verification does not rest on one reviewer

- **Status:** proposed
- **Date:** 2026-11-07
- **Related:** ADR-0005 (swap conformance), ADR-0011 decision 3 (the leak layers), ADR-0026 (the Go
  module `orchestrator/`), ADR-0027 (the product-name lint and its baseline), ADR-0028 (one source;
  copies are generated or checked), ADR-0033 and ADR-0038 decision 5 (the shared TLP admission
  vectors), ADR-0038 (the gateway and its config contract); this batch: ADR-0039 (one primary
  product per capability: the ledger's "alternative" column), ADR-0040 (modules are replaceable by
  construction), ADR-0041 (versioned capability contracts: the vectors carry the contract version),
  ADR-0042 (the cold-start graph builder and cycle detector are fuzzed here), ADR-0043 (the cutover
  ledger), ADR-0044 (the broker carries the vault's lifecycle), ADR-0045 (per-principal
  credentials), ADR-0046 (repository governance: the review tiers, `review-gate`, `agent-reviews`
  and the label reader this ADR extends), ADR-0047 (traced runs: the review's run id and model),
  ADR-0049 (the SOC data plane and the lab's checks as modules), and ADR-0026's amendment (placing
  what the split left unplaced); `tools/experimental.py`, `tools/product_name_lint.py`,
  `tools/dup_check.py`, `tools/fix_has_test.py`, `tests/gates/test_ci_trusted_gates.py`,
  `.github/workflows/ci.yml`, `.github/workflows/codeql.yml`, `tools/licences.yml`
- **Depends-on:** ADR-0046, ADR-0047

## Context

Almost every change in this repository is written by a model and then design-reviewed and
security-audited by subagents of the same model. That catches a lot, and it has a ceiling: a
reviewer that shares the author's training shares its blind spots, and two passes of one model
agree with each other more often than either agrees with the code. The deterministic gates the
repository already has (the leak scans, the product-name and duplication ratchets, the schema
checks, the TLP vectors, `fix_has_test --prove`) are the parts of verification that do not depend
on who reviews. The tech-debt audit of 2026-11-07 (sections 3 and 4) found five places where that
deterministic layer is missing or has stopped holding:

- **Hand-written parsers and validators have no fuzzing.** The Go module has no `Fuzz` function
  at all. The code that takes untrusted input is hand-written: `internal/safefs` (path walking
  under one root, given paths from a model), `internal/pathscope` (scope decisions on path
  strings), `internal/gateway/validate.go` (316 lines of regex and field checks over the rendered
  config), `internal/gateway/jsonscan.go` (a scanner that finds top-level keys without decoding),
  `internal/gateway/sse.go` (upstream event streams), `internal/events` (`DeriveID`, which
  re-implements Python's `json.dumps(ensure_ascii=True)` byte for byte) and the test-only JSON
  Schema subset validator (`internal/events/jsonschema_test.go`, 481 lines, which judges the event
  envelope's extension-attribute names among other rules). On the Python side the redirect
  handlers in `homelabnext/_http.py` decide by hand which `Location` is the same origin, and eight
  separate path-containment helpers each carry their own symlink and `..` handling.
- **Static analysis does not cover Go.** `.github/workflows/codeql.yml` analyses `python` and
  `actions` only. staticcheck and govulncheck run in the `go` job, but neither is a dataflow
  security analysis. CodeQL's results are uploaded as SARIF, and nothing fails a pull request on a
  new alert.
- **Cross-language rules are kept equal by hard-coded copies.** `DeriveID` is held to the Python
  derivation by five vectors written into `events_test.go`, "computed with" Python once: a change
  to the Python side is not seen by Go. The two already disagree: Python's `derive_event_id`
  refuses an empty dedupe key, and Go's derives an id for it. The gateway config contract
  (`schemas/platform/gateway_config.schema.json`, three examples and thirteen negatives) is
  enforced in Go by `validate.go` and `ParseConfig`, and no Go test reads the schema's examples or
  negatives. The TLP admission rule already does this properly: `tests/models/test_tlp_admit_vectors.py`
  generates `conformance/fixtures/tlp_admit_vectors.json` from `admit` itself, and the Go test reads
  the file in place (ADR-0038 decision 5, as amended by ADR-0026).
- **The allowlists grow unreviewed.** Only `tools/product_names.baseline.json`,
  `tools/dup_check.baseline.json` and `tools/experimental.yml` ratchet against the base commit in
  `trusted-gates`. The others only grow: between 2026-10-19 (or 2026-10-31) and the audit,
  `tools/product_names.yml` `allow:` went from 9 to 17 entries while the baseline it exempts from
  shrank 11%, `scrub-allow:` suppressions of the leak scan from 19 to 66,
  `tools/no_raw_endpoints.allow.yml` from 40 to 71, and `tools/scripts.allow.yml` from 11 to 21. Each
  entry carries a reason and was read by the same reviewer as the change that needed it, so each
  addition is locally plausible and the sum is unreviewed.
- **No one records what the lab built instead of buying.** The repository maintains its own
  gateway, safe filesystem layer, path scoping, event id derivation, schema subset validator,
  redirect policy, TLP rules and leak scanners. Each is a deliberate choice with an alternative
  (ADR-0038 names LiteLLM for the gateway), and none of those choices is written down in one place
  with who owns it and how it is tested, so "is this still worth owning?" has no place to be asked.

`tools/experimental.py ratchet` is the pattern this ADR generalises: a list held to the base
commit's copy, by the base commit's code, which may shrink freely and grows only on the run that the
operator's label triggered.

## Decision

1. **Every hand-written parser or validator in the security set has a fuzz target, and CI runs it.**
   - **Go.** Native fuzz functions (`func FuzzX(f *testing.F)`) beside the code, each seeded with
     its package's table-test inputs through `f.Add` and with `testdata/fuzz/FuzzX/`. The first set,
     each with the property it checks besides "does not panic":

     | Target | Property |
     |---|---|
     | `safefs.FuzzOps` | over a tree built in `t.TempDir()` with a symbolic link, a hard link and a directory pointing outside the root, every `ReadFile`, `ListFiles`, `WriteFile` and `CreateFile` of the fuzzed relative path either refuses or reaches an inode whose path lies under the root; nothing outside the root changes |
     | `safefs.FuzzClipPath` | the result is the input when `len ≤ maxEchoedPath`; otherwise it is `input[:cut]` + `...[len bytes]` with `cut ≤ maxEchoedPath` on a rune boundary, so valid UTF-8 input gives valid UTF-8 output and a rune is never split (`ClipPath` only bounds an error-message echo; it does not clean paths). `pathscope.clipPath` is a second copy of the same function: step 6 makes `pathscope` call the one copy, and until then the ledger row lists both |
     | `pathscope.FuzzCheck` | `CheckWrite`/`CheckRead` allow a path only if a reference built on `path.Clean` and component-wise prefix comparison allows it, and never a path with a hidden segment; a write allowed implies a read allowed |
     | `pathscope.FuzzZones` | `NewZones`, `NewScope` and the `Validate*Prefix` functions never accept a prefix that the reference above would let escape its zone |
     | `gateway.FuzzParseConfig` | a config `ParseConfig` accepts re-encodes and re-parses to an equal value, and passes the schema subset validator against `gateway_config.schema.json` (decision 3); an `unsupported` verdict on that schema fails the target |
     | `gateway.FuzzJSONScan` | on any input `json.Valid` accepts, each top-level value the scanner finds equals what `json.Unmarshal` into `map[string]json.RawMessage` finds, duplicate keys included (the scanner's choice of first or last is stated in its doc comment and asserted) |
     | `gateway.FuzzSSE` | the line reader never returns a line longer than `maxSSELine`, and splitting the same stream at any byte boundary yields the same events |
     | `events.FuzzDeriveID` | `asciiJSON` is pure ASCII and decodes to the input strings (valid UTF-8 input) or to their U+FFFD replacement (invalid input); `DeriveID` is deterministic and refuses what decision 3's vectors refuse |
     | `schematest.FuzzSchemaSubset` | the subset validator never panics, and for every schema example and negative mutated by the fuzzer it returns pass, fail or unsupported, never pass on a document it reported unsupported for |
     | the cold-start graph builder and cycle detector of ADR-0042 | the order is a topological order of `requires:`, and a cycle is always reported, never broken silently |
     | `trace.FuzzRunToken` (ADR-0047) | a token the parser accepts re-encodes to the same bytes, and no tampered byte verifies |
     | `trace.FuzzTraceparent` (ADR-0047) | accepted exactly when the shared vectors' reference grammar accepts |
     | `gateway.FuzzHoneytokenScan` (ADR-0047) | every candidate reported is a substring of the input in a declared format, and a declared-format substring is always reported |

     The last four land with the code of ADR-0042 and ADR-0047 that they test, not before it.
     ADR-0047's reply tool-call counter extends `jsonscan`, so `gateway.FuzzJSONScan` covers it,
     and its property gains "the count equals the number of `tool_calls` entries `json.Unmarshal`
     finds".
   - **The schema subset validator moves out of `events`.** It is test-only code in
     `internal/events/jsonschema_test.go`, which another package's tests cannot import, and its
     `schemaDirs` read only `schemas/ids` and `schemas/events`. It moves to an internal test-helper
     package, `orchestrator/internal/schematest` (imported only by `_test.go` files, which a test
     asserts), and its directories gain `schemas/platform`. Its own fuzz target moves with it.
   - **Every property can fail.** Each target's `_test.go` holds a deliberately wrong reference
     function (for example a `pathscope` reference that compares strings, not components), and the
     seed corpus includes an input on which the property, checked against that wrong reference,
     fails. A test in the blocking `go` job asserts that it does, so a property weakened until it
     cannot fail is a red test, deterministically.

   - **Python.** Property tests with Hypothesis, beside the module's tests, for:
     `SameOriginRedirectHandler` (a redirect it follows has, by `http.client`'s own host and port
     parsing, the request's scheme, host and port: the property is a differential against the
     connection `http.client` would actually open), `_NoRedirect` (never follows), `tlp.read`
     (every input reads as an accepted label or as `red`, and the canonical spelling round-trips),
     `derive_event_id` (against decision 3's vectors and for determinism), and the one Python
     path-containment helper of decision 3.
   - **When it runs.** The blocking `go` job already runs every `Fuzz` function's seed corpus
     (`go test` does), so seeds cost nothing new and a committed crash input is a regression test.
     A new required job, `fuzz-changed`, runs `go test -run '^$' -fuzz '^FuzzX$' -fuzztime 30s` for
     each target whose package the pull request changes (at most six minutes in all, the rest
     reported as skipped), and the Hypothesis tests run in the ordinary Python suites under a
     `ci` profile with a fixed example count and `derandomize=True`, so a red is reproducible. The
     nightly workflow gains a `fuzz` job that runs every Go target for five minutes and the
     Hypothesis tests under a `nightly` profile with ten times the examples; a failure fails the
     workflow and uploads the minimised input as an artifact.
   - **A crash is fixed with its input.** The fix commits the minimised input under
     `testdata/fuzz/FuzzX/` (Go) or as an `@example` (Python). `tools/fix_has_test.py` already
     counts a Go `testdata/` file as a test change, and `--prove` shows it fails on the parent.
   - **Coverage is checked, not remembered.** Each ledger row (decision 5) lists its
     `entrypoints:`: the functions that take a `string`, `[]byte` or `io.Reader` (Go), or a `str`,
     `bytes` or file object (Python), that comes from outside the process. `fuzz_coverage.py` under `tools/`
     fails unless every entrypoint is listed under some fuzz target's `covers:` or waived in its
     row with a reason, and fails when an entrypoint names a function that does not exist. A name
     heuristic (`Parse`, `Validate`, `Check`, `Decode`, `Read`, `Clip`, `Derive`, `New` in Go;
     public `read`, `parse`, `validate`, `derive` in Python) over the rows' paths is printed as an
     advisory report of functions that might be entrypoints, and never fails. It runs in the
     `schemas` job.
2. **Static analysis covers Go, and a new alert fails the pull request.**
   - `codeql.yml` adds `go` to its matrix with `build-mode: manual` and a build step that runs
     `go build ./...` in `orchestrator/` (and each other Go module `tools/go_modules.py` lists),
     with the same `security-extended` query suite.
   - Each analysis writes its SARIF to a directory (`output:`) as well as uploading it.
     `sarif_gate.py` under `tools/` reads that SARIF and fails on any result of level `error`, or with a
     `security-severity` of 4.0 or more (medium and up, so a `warning`-level result between 4.0 and
     6.9 does not land silently), that is not in `tools/codeql.baseline.json`. A result is
     identified by rule id, path and CodeQL's `primaryLocationLineHash` fingerprint, so a moved line
     is not new. The gate runs the **base commit's** copy of `sarif_gate.py` (checked out to
     `$RUNNER_TEMP/base`), as the ratchets of `trusted-gates` do, never the pull request's.
   - The baseline is one of decision 4's ratcheted lists: it may shrink, and grows only by the
     operator's label. Every entry of the first `codeql.baseline.json` carries a triage reason
     (why the result is a false positive or accepted), and the operator reviews that first file as
     a seed, in the pull request that adds it; it is not "whatever the first run finds".
   - `codeql` becomes a required check of `main`'s ruleset (a change to the ruleset that
     ADR-0046 decision 3 puts in the CI class).
   - Repository-specific patterns (an unverified TLS context, a credential header on a redirecting
     client, a private copy of a shared helper) stay where they are, in the repository's own lints
     (`tls_verify_lint.py`, the credential-header check of `tests/roles/test_credential_uri_tasks.py`, `shared_helpers_lint.py`); this decision adds no
     second rule engine for them.
3. **A rule implemented in two languages is held to one committed set of vectors, generated from
   the implementation that is its source.** The TLP admission vectors are the pattern: the file is
   regenerated from the source implementation by a test that fails when the committed file differs
   (`HNX_REGEN_*=1` rewrites it), and every other implementation reads it in place. It is ADR-0028's
   rule applied to tests: the hard-coded copy goes.
   - **Event ids.** `test_event_id_vectors.py` under `tests/events/` generates
     `conformance/fixtures/event_id_vectors.json` from `derive_event_id` over the five current inputs
     and new ones (non-BMP text, DEL and C0 controls, U+2028/U+2029, long fields), and **refusal**
     vectors (an empty dedupe key). The vectors fix the shared domain: they include `subject` null
     and `""`, which give the same id (Python reads `None` as `""`; Go has only `""`). Lone
     surrogates and invalid UTF-8 are outside the shared domain, because a JSON fixture cannot
     carry Go's invalid bytes and Go decodes `\ud800` to U+FFFD: both implementations refuse them,
     and the fixture records that refusal for Python's lone surrogates while Go's invalid-UTF-8
     refusal is a Go-only table case. `TestDeriveID_MatchesThePythonDerivation` reads the file
     instead of its five literals. Go's `DeriveID` becomes `(string, error)` and refuses what
     Python refuses, which fixes the disagreement above in the same pull request; `events.New`,
     which calls it, becomes `(Event, error)` too.
   - **Gateway config.** A Go test reads every `schemas/platform/examples/gateway_config.*.json`
     (must pass `ParseConfig`) and every `schemas/platform/negative/gateway_config.*.json` (must be
     refused), by glob, so a negative added to the schema is a Go test case with no edit. A rule
     `validate.go` holds that the schema cannot express is listed with its reason in
     `orchestrator/internal/gateway/testdata/stricter_than_schema.json`, each with a document that
     the schema accepts and Go refuses; the test fails on an unlisted disagreement in either
     direction. The vectors carry the contract version (ADR-0041), so a gateway that claims a
     version is tested on that version's vectors.
   - **Path containment.** The eight Python helpers of the audit (`_inside`, `_contained`, `_under`
     in the broker, status, MCP, generator, loader and supply modules) collapse into one
     `_paths.py` under `homelabnext/` function, which `tools/shared_helpers_lint.py` gains as a seam (a
     private copy fails CI, ADR-0003). `conformance/fixtures/path_containment_vectors.json` is
     generated from it (root, candidate, symlink layout, verdict), and `pathscope.Within` reads the
     purely lexical subset in place.
   - **The census.** `test_shared_vectors.py` under `tools/tests/` lists every Go test that compares with a
     value "computed with" Python (a comment or a literal next to a Python module path) and fails
     unless it reads a `conformance/fixtures/*_vectors.json` file instead; it starts with
     `DeriveID` and the gateway config as its two cases.
4. **Every allowlist is ratcheted: it may shrink, and it grows only by the operator's label.**
   - `tools/ratchets.yml` lists each suppression list once: its file, how its entries are
     identified, and the tool that reads it. The first version holds `tools/product_names.yml`
     (`allow:`, `moved:`, `retired:`), the `scrub-allow:` markers of `tools/leak_scan.py` (every
     file), `tools/no_raw_endpoints.allow.yml`, `tools/scripts.allow.yml` (all keys),
     `tools/shared_helpers.allow.yml`, `tools/caddy_lint.allow.yml`,
     `tools/credential_headers.allow.yml`, `tools/run_output_lint.allow.yml`,
     `tools/workstation_refs.allow.yml`, `orchestrator/skips.yml`, `tools/codeql.baseline.json`
     (decision 2) and `docs/in-house.yml` (decision 5), and names the three lists that already
     ratchet by their own tool, so the census is complete. Lists that other ADRs of this batch add
     join it in the pull request that adds them: ADR-0049's `detections/native.baseline.json`, and
     ADR-0040's identifier-lint baseline and its `allow:` list.
   - An entry's identity is its key (`path`, script id, test and package) with its reason. A
     `scrub-allow:` marker's identity is (file, reason, sha256 of its line with the marker
     removed), so a marker moved to suppress a different line is a new identity. The ratchet
     compares multisets (a count per identity), so a duplicate marker with a reason the file
     already uses is growth. A changed reason, an entry moved to another list key or a marker
     copied to another file is growth. A count that stays equal while one entry replaces another is
     growth too: the ratchet compares identities, not sizes.
   - **The ledger ratchets the other way.** In `docs/in-house.yml` what grows unchecked is the
     uncovered part, so growth is: a `covers:` waiver added or its reason changed, a row removed, a
     row's `paths:` shrinking, a `covers:` entry removed, or a `revisit:` date moved later.
   - `tools/allowlist_ratchet.py --base <sha>` holds every listed file to the base commit's, run
     by the base's code in `trusted-gates` like `experimental.py ratchet`, and joins `RATCHETS` in
     `tests/gates/test_ci_trusted_gates.py`. A test fails when a `tools/*.allow.yml`, a
     `*.baseline.json` or a suppression marker that a gate reads is not in `tools/ratchets.yml`.
   - Growth passes only on the run that the operator's `allowlist-growth` label triggered, read the
     way ADR-0046 decision 4 reads `experimental-growth` (the `labeled` event names the governance
     owner and comes after the head commit). The run prints each added entry with its reason, which
     is what the operator reads.
   - **Until ADR-0046's `review-gate` label reader is live, the label is checked by event alone**,
     as `experimental-growth` is today (`github.event.label.name`), and no agent applies it by
     convention. Agents still act with the operator's token until ADR-0046's App exists, so in that
     window the label proves nothing about who applied it. Step 2 switches to the actor-and-ordering
     check in the same pull request that ships that reader.
   - Each run writes every list's size to the job summary, so the trend the audit had to
     reconstruct by hand is visible on every pull request.
5. **A build-vs-buy ledger names every in-house security-relevant component.**
   - `docs/in-house.yml` is the authored ledger; `docs/in-house.md` is generated from it between
     `hnx:gen` markers and checked in CI like the docs index. Each row holds: `id`; `paths`; what it
     does; `owner` (a code owner, as of the base, of every path it lists; today always the single
     operator, and kept so that a second maintainer can own rows without a schema change); why it
     is built here;
     the `alternative` considered (a named product or library, or `none-known` with what was looked
     at) and what that alternative lacks; its `entrypoints:`, its fuzz targets and the functions
     each `covers:` (decision 1); its shared vectors (decision 3); the ADR that decided it; and
     `revisit:`, a date at most twelve months ahead.
   - `docs/in-house.yml` joins the leak-gates class of `.github/review-tiers.yml` (ADR-0046
     decision 3), so a waiver, a removed row or a renewed date is an operator-tier change; no class
     there covers `docs/` today.
   - `in_house_check.py` under `tools/` fails when a field is missing, a path, entrypoint or fuzz target
     does not exist, an owner does not own a path, or a path that should be covered is not: every package under `orchestrator/internal/` and `orchestrator/cmd/`, and every path of
     the egress, grants, TLP and leak-gate classes of `.github/review-tiers.yml` (ADR-0046 decision
     3), must sit in exactly one row.
   - The first rows: the gateway (alternative LiteLLM, ADR-0038), the gateway config validator,
     the gateway's stream and JSON scanners, `safefs` (alternative `os.Root` alone), `pathscope`,
     event ids and the outbox, the schema subset validator (alternative a JSON Schema library, not
     taken so that the Go module stays standard-library only), the redirect handlers, the TLP rules
     and admission, the egress generator, the broker's approval digest, the code-mode sandbox
     (ADR-0031), the SSH CA client, and the leak and product-name scanners.
   - **An expired `revisit:` is not a calendar time bomb.** It fails the nightly workflow, which
     opens (or updates) one GitHub issue on this repository labelled `in-house-revisit` naming the
     row. On a pull request it fails only when the pull request touches that row's paths, so an
     unrelated change is never red because a date passed. The row is re-decided in a pull request
     that either renews the date with a sentence of why, or files the replacement as a swap
     (ADR-0005, ADR-0039); renewing is operator-tier, because the ledger is in the leak-gates class.
     The ledger decides nothing by itself.
6. **Security-tier changes get a review by a second model family.**
   - A pull request that touches a path of the egress, grants, TLP, CODEOWNERS-and-tiers or
     leak-gate classes of `.github/review-tiers.yml`, or a path of a ledger row, is security-tier.
   - **It adds to the operator's approval and never replaces it.** Most security-tier paths are
     already operator-tier under ADR-0046 decision 3 (egress, grants, TLP, CODEOWNERS-and-tiers,
     leak gates, `/orchestrator/`); there the second-family review is evidence for the operator to
     read, and a passing one never stands in for the operator's approval. The paths where it
     changes the outcome are the ledger rows' paths that no ADR-0046 class covers (the redirect
     handlers in `homelabnext/_http.py`, the path-containment helper, the broker's approval
     digest): there it is required before an agent may merge.
   - Its `hnx-review: security-audit` comment (ADR-0046 decision 5) gains a `model:` field naming
     the backend model the reviewing run used, as the run's trace records it (ADR-0047). The
     `agent-reviews` job requires, for a security-tier pull request, that this model's family
     differs from the author's. Families are an authored table, `.github/review-models.yml` (model
     id pattern to family), in the CI class.
   - **The author's family is the family of every commit's `Co-Authored-By:` model.** A commit
     with no such trailer, commits naming more than one family, or a model id that matches no
     `review-models.yml` pattern each count as "family unknown", and an unknown family on either
     side fails the check (it never counts as a second family). Each agent commit also carries an
     `Hnx-Run:` trailer with the authoring run's id, so the author's claim has a run to check it
     against.
   - **A capability floor.** `review-models.yml` marks the families eligible for security-tier
     review. An ineligible family counts as unavailable, so a small local model of another family
     does not meet the rule on paper.
   - **The fallback.** If no eligible second family is available, the check fails unless
     `review-gate` records a governance-owner approval on the head commit (ADR-0046 decision 4); it
     never passes on one family. On operator-tier paths that approval is required anyway, so the
     fallback means the operator reviews without a second-family report.
   - **The reviewer's reach is narrow.** The second-family reviewer runs as a gateway model role
     with TLP ceiling `clear` (ADR-0033, ADR-0038), under its own principal and credential
     (ADR-0045), in a workspace that holds only the public checkout at the head SHA, with no lab
     MCP servers and no overlay. Its run is traced like any other (ADR-0047). Overlay reviews are
     outside this decision.
   - **A sample of the rest.** Every week, the agent pull requests merged to `main` that were not
     security-tier and whose merge SHA satisfies `int(merge SHA, 16) mod 10 == 0` (the modulus is
     a field of `review-models.yml`), so that no one chooses, are re-reviewed by the second family
     after the fact. The sample runs as a lab-scheduled agent run under the same constraints, not
     as a GitHub workflow, because the reviewer is a gateway role. A finding that is a
     vulnerability is filed as a draft security advisory on this repository (private to its
     maintainers, as `SECURITY.md` asks of reporters); any other finding is a GitHub issue labelled
     `cross-review`. The findings stay on this repository because the pull requests are its own.
   - **Both claims are audited.** The `model:` field and the `Co-Authored-By:` and `Hnx-Run:`
     trailers are all written by agent runs, so CI compares claims. A lab-side audit compares both,
     the authoring run's and the reviewing run's, with the gateway's usage records for their run
     ids (ADR-0038 decision 6, ADR-0047), and reports a mismatch on either; that audit, not CI, is
     what makes the claims checkable.

### Out of scope

- Mutation testing, coverage targets beyond `tools/coverage_floor.py`, and formal verification.
- Fuzzing code outside the security set (renderers, generators, the status hub's views); they gain
  a target when a ledger row names them.
- A second static analyser or rule engine (semgrep) beside CodeQL and the repository's own lints.
- Replacing any in-house component: the ledger records and dates the choice, and a replacement is a
  swap (ADR-0005) under ADR-0039 and ADR-0040.
- Who may merge, and the App identity that writes review comments (ADR-0046); run tracing and the
  usage records the model audit reads (ADR-0047, ADR-0038).
- The private overlay's CI, its reviews and its deny-list scan (ADR-0046 and the overlay's own
  rules). The ratchets and vectors here are this repository's.
- The `orch_accepts` mirror of the external orchestrator's grant rules in
  `homelabnext/mcp/clients.py`: it goes away with the controller's move (ADR-0026 and its
  amendment), not by vectors against code outside the tree.

## Consequences

- A same-model blind spot now has to get past properties a fuzzer searches, a dataflow analysis,
  vectors generated from the other language and, on the paths that matter most, a reviewer trained
  differently. None of these needs the reviewer to think of the case.
- The event id disagreement on an empty dedupe key is fixed by step 3's refusal half, still open
  (its note of 2026-11-08), and the next divergence between Go and Python on a shared rule is a
  red test in the pull request that causes it, in either repository half.
- Allowlists stop growing silently. An agent that needs a new suppression waits for the operator's
  label, which costs a round trip per growth. That is the point: the 66 `scrub-allow:` markers
  each cost one, and nobody saw the total. Existing entries are not re-reviewed by this ADR; the
  first ratchet run freezes today's lists. Until ADR-0046's label reader is live, the label is
  checked by event alone and agents act with the operator's token, so in that window the ratchet
  rests on the convention that no agent applies the label; the gap closes when step 2's switch
  lands with that reader.
- CI cost rises: `fuzz-changed` adds up to six minutes to a pull request that touches a fuzzed Go
  package, CodeQL gains a Go build, and the Hypothesis profiles add to the Python suites
  (`tools/tests` is at 85% of its budget, and the budget is raised in the same pull request rather
  than squeezed). The nightly `fuzz` job adds about an hour of runner time a night.
- Hypothesis becomes a test dependency (MPL-2.0, allowed unmodified by `tools/licences.yml`'s
  linked-code rule). It joins the `test` and `dev` extras and `constraints/`, a CI-class change.
- `DeriveID` and `events.New` change signature (to `(string, error)` and `(Event, error)`); their
  callers in `internal/events` and `internal/store` handle the error.
- The schema subset validator moves from `internal/events` to `internal/schematest`, a test-only
  package.
- Security-tier pull requests need an eligible second model family to be reachable. When it is
  not, they wait for the operator, which is slower but never weaker. A second family is a second
  provider, reached through the gateway with a `clear` ceiling and its own credential; that is a
  new egress the lab's TLP rules already cover, and the reviewer sees only the public checkout.
- Each agent commit carries an `Hnx-Run:` trailer, which the commit conventions gain.
- The ledger is a list to keep: twelve-month revisit dates come due, and an expired one fails the
  nightly workflow and opens an issue until the operator re-decides. That is the forcing function,
  and its cost is an operator-tier pull request per row per year.

### Implementation plan

Each step is one pull request; the gates of the context file and the tests of what it touches run
before every push.

1. **This ADR** (`docs:`), with its index row. Its test is the ADR log lint and the docs index
   check.
2. **The allowlist ratchet** (decision 4). `tools/ratchets.yml`, `allowlist_ratchet.py` under `tools/`, its
   `trusted-gates` step and its `RATCHETS` entry, the `allowlist-growth` label in
   `CONTRIBUTING.md`, and the size report. The label is read by event alone in this step, as
   `experimental-growth` is today; the actor-and-ordering check ships in the pull request that ships
   ADR-0046's `review-gate` label reader. Tests prove: shrinking passes; adding an entry, changing
   a reason, replacing one entry by another, copying a `scrub-allow:` marker to a new file, adding
   a marker whose reason the file already uses, and moving a marker to another line each fail
   without the label and pass with it; an unlisted `tools/*.allow.yml` fails the census; the step
   runs the base's copy of the tool. First, so the lists stop growing while the rest lands.
3. **Event id vectors** (`fix:`, decision 3). The generator test, the fixture, the Go test reading
   it, `DeriveID` refusing an empty dedupe key and `events.New` returning its error. Tests prove:
   the fixture equals what `derive_event_id` produces; Go agrees on every vector, refusals
   included; null and empty `subject` give the same id; invalid UTF-8 is refused in Go; the refusal
   test fails on the parent commit (`fix_has_test --prove`).

   *Note, 2026-11-08:* #315 landed the generator, the fixture and the Go test reading it in place,
   and left out the refusal half: there are no refusal vectors yet, `DeriveID` still derives an
   id for an empty dedupe key, and it and `events.New` keep their signatures. Making them
   `(string, error)` and `(Event, error)` would break the controller's queue, whose open pull
   requests (#322, #324) call `events.New`, so the change waits for them to land and then takes
   its own `fix:`. Until it does, `FuzzDeriveID` (step 5) checks everything but refusal.
4. **The schema subset validator moves, and gateway config vectors** (decision 3). First the move
   of the validator to `orchestrator/internal/schematest` with `schemas/platform` in its
   directories; then the Go test over the schema's examples and negatives by glob, and
   `stricter_than_schema.json`. Tests prove: `schematest` is imported only by `_test.go` files; the
   gateway schema gets no `unsupported` verdict; every example parses, every negative is refused,
   an unlisted disagreement in either direction fails, and adding a negative needs no Go edit.

   *Note, 2026-11-08:* #315 landed the second half another way: the Go test reads the schema's
   examples and negatives by glob, and `conformance/fixtures/gateway_config_vectors.json`
   (generated by the Python tests from the schema, each intentional difference named) stands where
   `stricter_than_schema.json` was planned. The validator's move to `internal/schematest` did not
   happen then; it happened with ADR-0026 stage 2's PR 2.6a (#322), which moved it to
   `orchestrator/internal/schematest` (test-only, asserted, reading `schemas/ids`,
   `schemas/events` and `schemas/platform`) and `FuzzSchemaSubset` (step 5) with its seed corpus
   beside it. `gateway.FuzzParseConfig` still checks the round trip without its "passes the
   schema subset validator" half, which can now be added.
5. **Go fuzz targets, first set** (decision 1): `pathscope`, `events` (`FuzzDeriveID`),
   `schematest` (`FuzzSchemaSubset`), `gateway` (`FuzzJSONScan`, `FuzzSSE`, `FuzzParseConfig`),
   with seed corpora. Tests prove, in the blocking `go` job: each property holds on the seeds, and
   each target's seed corpus holds an input on which the property, checked against the
   deliberately wrong reference function in its `_test.go`, fails. Any crash found while writing
   them lands as its own `fix:` with the input.
6. **`safefs` and graph fuzz targets** (decision 1): `FuzzOps` with its planted links,
   `FuzzClipPath`, and `pathscope` calling the one `ClipPath`; ADR-0042's graph targets and
   ADR-0047's trace and honeytoken targets land with their code. Tests prove the property on the
   seeds and against each wrong reference, and that `FuzzOps` runs under the `go` job's
   unprivileged and root runs alike.
7. **Fuzz CI** (decision 1): the `fuzz-changed` job and the nightly `fuzz` job. Tests prove: the
   job selects exactly the targets of changed packages and stays within its cap.
8. **Python properties and the containment helper** (decisions 1 and 3): Hypothesis in the extras,
   constraints and licence register; the `ci` and `nightly` profiles; property tests for the
   redirect handlers, `tlp.read` and `derive_event_id`; `_paths.py` under `homelabnext/` replacing the eight
   helpers, its `shared_helpers_lint` seam and `path_containment_vectors.json`, read by
   `pathscope.Within`'s test. Tests prove: the redirect property against `http.client`'s parsing,
   one verdict per vector in both languages, and a ninth private helper fails the lint.
9. **CodeQL for Go and the SARIF gate** (decision 2): the matrix entry, `sarif_gate.py` under `tools/`,
   `tools/codeql.baseline.json` (added to `ratchets.yml`), and the required check. Tests prove the
   gate on recorded SARIF: a new error-level result fails, a baselined one passes, a moved line with
   the same fingerprint passes, a shrunk baseline passes.
10. **The build-vs-buy ledger and fuzz coverage** (decisions 1 and 5): `docs/in-house.yml` (added
    to `tools/ratchets.yml` and to the leak-gates class of `review-tiers.yml`), the generated page,
    `in_house_check.py` under `tools/`, `fuzz_coverage.py` under `tools/` in the `schemas` job, and the nightly
    revisit check with its issue. After step 7, so fuzz targets exist to cite. Tests prove each
    failure the checker names: a missing field, an unowned path, an uncovered
    `orchestrator/internal/` package or review-tier path, a nonexistent entrypoint or fuzz target;
    an entrypoint with no `covers:` entry or waiver fails the coverage check, and the name
    heuristic only reports; an expired `revisit:` fails the nightly run and a pull request touching
    that row's paths, and passes a pull request that does not; adding a waiver, removing a row or
    moving a date later is ratchet growth.
11. **Cross-model review** (decision 6), after ADR-0046's `agent-reviews` job and ADR-0047's run
    traces exist: `.github/review-models.yml` with its eligible families, the `model:` field and
    the `Hnx-Run:` trailer and their check, the operator fallback, the reviewer role and its
    workspace, the weekly sample, and the lab-side claim audit. Tests prove: a security-tier pull
    request with a same-family audit fails, with an eligible second-family audit passes, with an
    ineligible one or none available fails unless `review-gate` records a governance-owner approval
    on the head commit; a missing trailer, two families among the commits, or an unmatched model id
    fails as "family unknown"; a non-security pull request needs no second family; the sample picks
    the same pull requests on every run for a given week; the audit reports a mismatch on the
    author's claim and on the reviewer's.

## Alternatives

- **Rely on more reviews by the same model.** More passes cost turns and find what the first pass
  would have found. The audit's numbers (allowlists that doubled, a Go/Python divergence nobody
  saw) are what that has produced so far.
- **Semgrep instead of, or beside, CodeQL.** CodeQL already runs here for Python and the
  workflows, its Go support is a matrix entry, and the repository's own lints already encode the
  patterns a custom semgrep rule would. A second engine is a second set of rules and results to
  triage for little new coverage. Revisit if a pattern cannot be expressed in either.
- **A hard cap on each allowlist instead of a label.** A cap is either too tight (it blocks honest
  growth with no one to ask) or too loose (it is the same silent growth, later). The label puts the
  decision with the operator at the moment of growth, as `experimental-growth` already does.
- **Go fuzzing only, no Python properties.** The redirect handlers and the containment helpers are
  Python and take attacker-influenced input (a server's `Location`, a path from a manifest). Leaving
  them to example tests leaves the half of the code most of the lab runs.
- **Atheris for Python fuzzing.** It is coverage-guided, but needs a native build and a separate
  harness per target, and does not run inside the ordinary pytest suites. Hypothesis does, with
  reproducible shrinking, which suits a blocking CI run.
- **A cross-model review of every pull request.** It doubles the review cost of every change for
  the many that touch no security path. The tier plus a deterministic one-in-ten sample of the rest
  keeps the second view where a miss costs most and still measures the rest.
