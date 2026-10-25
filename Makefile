# SPDX-License-Identifier: Apache-2.0
# `make check` is the one command contributors and CI run.  Gates whose tool does not exist
# yet (they arrive with later tasks) are skipped with a visible note, never silently.

PY ?= python3
RUFF ?= $(PY) -m ruff
SCHEMA_CHECK := tools/schema_check.py
ENDPOINT_GATE := tools/no_raw_endpoints.py
ROLE_LINT := tools/role_lint.py
ROLES := $(wildcard ansible/roles/*)
PLAYBOOKS := $(wildcard ansible/playbooks/*.yml)
REGISTERS_OUT := build/registers

.PHONY: help check lint fmt test coverage component-tests hermetic-lint schemas gates decide-lint decide-safety models-check models-report models-eval agent-lint prompts-lint injection-check injection-report injection-eval workflows detections registers ids-check conform conform-check spdx leak-scan secret-scan leak-scan-history changelog-check constraints clean lab-up lab-down lab-smoke lab-broker

help:
	@echo "targets: check lint fmt test coverage component-tests hermetic-lint schemas gates decide-lint decide-safety models-check models-report agent-lint prompts-lint injection-check injection-report workflows detections registers ids-check conform conform-check spdx leak-scan secret-scan leak-scan-history changelog-check clean"
	@echo "hygiene: helpers-lint dup-check tls-lint caddy-lint workstation-lint run-output-lint keyring-check keyring"
	@echo "knowledge graph (local docs/graph/, integrity checked in gates): graph"
	@echo "strategy to task (examples/strategy, docs/strategy.md; in check): strategy"
	@echo "script catalog (M-01, M-02, M-04): scripts-check"
	@echo "invariants register, fast criteria, never pages (not in check; CI runs it): invariants"
	@echo "lab-in-a-box (needs docker with compose): lab-up lab-down lab-smoke lab-broker"
	@echo "live (needs a real model endpoint): injection-eval MODEL=<role> REGISTRY=<file> ROLES=<file>; models-eval REGISTRY=<file>"
	@echo "override RUFF=/path/to/ruff if ruff is not importable as a module"

check: lint component-tests hermetic-lint test schemas gates decide-lint decide-safety models-check agent-lint prompts-lint injection-check workflows scripts-check detections registers ids-check conform-check spdx leak-scan changelog-check
	@echo "make check: OK"

lint:
	$(RUFF) check .
	$(RUFF) format --check .

fmt:
	$(RUFF) check --fix .
	$(RUFF) format .

# The same selection as CI's test job (tools/tests/test_make_matches_ci.py holds them equal):
# test_this_repo_meets_the_floor runs tools/coverage_floor.py, the whole suite again under
# coverage, which no suite time budget allows for; `coverage` below runs it on its own, as CI's
# coverage job does.
PYTEST_ARGS := -q -m "not live" --deselect tools/tests/test_coverage_floor.py::test_this_repo_meets_the_floor
test:
	$(PY) -m pytest $(PYTEST_ARGS)

# Q-07: each security-critical unit (broker, scope guard, records lifecycle, decide cascade, the
# agent grant ceiling and the others listed in tools/coverage_floor.py) keeps >= 80% line
# coverage from its own tests.  A prerequisite of `check`, as the coverage job is of CI.
check: coverage
coverage:
	$(PY) tools/coverage_floor.py

# every package, conformance capability, role, plugin, compose stack and tool has tests
component-tests:
	$(PY) tools/component_tests.py

# test code reads neither the wall clock nor unseeded randomness (the network is guarded at run
# time by tests/network_guard.py)
hermetic-lint:
	$(PY) tools/hermetic_lint.py

# the generated module-manifest schemas, examples and negatives match their generators
# BASE=<rev> also checks that schemas/_frozen/ is append-only against it (CI: the PR base)
schemas:
	$(PY) $(SCHEMA_CHECK) --strict $(if $(BASE),--base $(BASE))
	$(PY) -m homelabnext.schemas --check

# endpoints come from the registry; role and playbook rules come from the role interface;
# `custom check` fails on an unowned or expired customization; the system and capability pages
# (docs/systems/, docs/capabilities/) match the registry and the conformance code; the status
# source catalog (docs/status/sources.md) and views.yml match the registry; the knowledge graph
# has no dangling edge or duplicate id; docs/terms.md matches homelabnext/agent/terms.md; the Code
# Mode stubs and search index (examples/codemode/) match the example broker manifest (ADR-0031)
gates:
	$(PY) $(ENDPOINT_GATE) .
	$(PY) $(ROLE_LINT) $(ROLES)
	$(PY) $(ROLE_LINT) --playbook $(PLAYBOOKS) --inventory ansible/inventory/example/hosts.yml
	$(PY) -m homelabnext.cli custom check
	$(PY) -m homelabnext.cli docs systems check examples/services.yml docs/systems
	$(PY) -m homelabnext.cli docs capabilities check
	$(PY) -m homelabnext.cli status catalog check
	$(PY) -m homelabnext.cli status views check
	$(PY) -m homelabnext.cli graph check
	$(PY) -m homelabnext.cli agent terms --check docs/terms.md
	$(PY) -m homelabnext.cli codemode gen --check

# every decision spec git tracks is complete, asks well-formed questions, and inline specs stay fast
decide-lint:
	$(PY) -m homelabnext.cli decide lint

# K-15: the required safety specs (sensitive-content, hostile-content, purpose-consistency,
# disclosure-risk) exist, are safety-only and pass their case sets against deterministic fakes
decide-safety:
	$(PY) -m homelabnext.cli decide safety

# G-11: every model binding is pinned by version and digest, and the committed evaluation report
# (golden suites + the K-12 replay gate, against the deterministic fake) is the one for these pins
MODEL_ROLES := examples/model_roles.json
MODEL_EVAL := examples/model_roles.eval.json
# the model store and serving plan (docs/model-serving.md): the example store is valid, every
# binding resolves to an entry its engine may serve, and the generated vllm_server instances and
# gateway config match the plan
SERVING := examples/model-serving
models-check:
	$(PY) -m homelabnext.cli golden pins check --roles $(MODEL_ROLES) --report $(MODEL_EVAL)
	$(PY) -m homelabnext.cli models store validate $(SERVING)/model_store.json --roles $(SERVING)/model_roles.json
	$(PY) -m homelabnext.cli models serving check $(SERVING)/serving.yml $(SERVING)
	$(PY) -m homelabnext.cli gen gateway render $(SERVING)/gateway.yml $(SERVING)/gateway --check

# the LLM gateway config (LiteLLM + Bifrost) is generated from the role table and the agent
# profiles: no drift, and no local-only or agent role can reach a cloud model (docs/llm-gateway.md)
GATEWAY_SPEC := compose/lab-in-a-box/config/llm-gateway/gateway.yml
.PHONY: gateway-check gateway-render
check: gateway-check
gateway-check:
	$(PY) -m homelabnext.cli gen gateway render $(GATEWAY_SPEC) $(dir $(GATEWAY_SPEC)) --check

# the MCP catalog (docs/mcp-catalog.md, ADR-0024): every record valid and reviewed, the registry's
# MCP entries and every profile's grants resolve to it, and the rendered example client configs
# (every home of every render spec) have no drift
MCP_SPECS := $(wildcard examples/mcp/clients/*.yml)
.PHONY: mcp-check mcp-render
check: mcp-check
mcp-check:
	$(PY) -m homelabnext.cli mcp catalog check
	@for s in $(MCP_SPECS); do $(PY) -m homelabnext.cli mcp catalog render --spec $$s --check || exit 1; done

# after changing a catalog record, a render spec or a profile: regenerate and commit
mcp-render:
	@for s in $(MCP_SPECS); do $(PY) -m homelabnext.cli mcp catalog render --spec $$s || exit 1; done

# after changing the role table, a profile or the gateway spec: regenerate and commit
gateway-render:
	$(PY) -m homelabnext.cli gen gateway render $(GATEWAY_SPEC) $(dir $(GATEWAY_SPEC))

# after changing the example store, its role table or its serving spec: regenerate and commit
.PHONY: serving-render
serving-render:
	$(PY) -m homelabnext.cli models serving render $(SERVING)/serving.yml $(SERVING)
	$(PY) -m homelabnext.cli gen gateway render $(SERVING)/gateway.yml $(SERVING)/gateway

# after changing a pin, a golden suite or the replay inputs: regenerate the report and commit it
models-report:
	$(PY) -m homelabnext.cli golden pins report --roles $(MODEL_ROLES) --report $(MODEL_EVAL)

# LIVE, never in CI: the same evaluation against the real pinned models through the resolver.
# Keep build/models/eval.json with the model change.
models-eval:
	@test -n "$(REGISTRY)" || { echo "usage: make models-eval REGISTRY=<services.yml> [MODEL_ROLES=<roles.json>]"; exit 2; }
	$(PY) -m homelabnext.cli golden pins report --roles $(MODEL_ROLES) --registry $(REGISTRY) --report build/models/eval.json

# readers cannot act (G-03): no agent profile or context manifest in the repository that reads
# untrusted content holds a shell, file-write, egress or credential grant
agent-lint:
	$(PY) -m homelabnext.cli agent lint

# G-01: every prompt template declares a trust level per slot and never interpolates an untrusted
# slot outside the nonce-fenced, escaped untrusted-data delimiters
prompts-lint:
	$(PY) -m homelabnext.cli agent prompts lint

# G-02: the injection corpus through every template against the deterministic fence-respecting
# fake: 0 instruction-follows, and the committed report must be the one for the current templates
# and corpus (it proves the harness and the delimiting, not a real model -- see injection-eval)
INJECTION_REPORT := homelabnext/agent/prompts/injection/report.json
injection-check:
	$(PY) -m homelabnext.cli agent injection run --fake fence --check $(INJECTION_REPORT)

# after changing a template, the corpus or the runner: regenerate the golden report and commit it
injection-report:
	$(PY) -m homelabnext.cli agent injection run --fake fence --out $(INJECTION_REPORT)

# LIVE, never in CI: the same eval against a real OpenAI-compatible model, through the model-role
# resolver.  Run before any model or prompt change; keep build/injection/<role>.json with the change.
injection-eval:
	@test -n "$(MODEL)" -a -n "$(REGISTRY)" -a -n "$(ROLES)" || { echo "usage: make injection-eval MODEL=<role> REGISTRY=<services.yml> ROLES=<roles.json>"; exit 2; }
	$(PY) -m homelabnext.cli agent injection run --role $(MODEL) --registry $(REGISTRY) --roles $(ROLES) --out build/injection/$(MODEL).json
	$(PY) -m homelabnext.cli agent injection check-report build/injection/$(MODEL).json

# R-01/R-03/R-04/R-07: every workflow pack in git validates offline (references resolve,
# deterministic steps before any model, fixtures round-trip to the exact action calls, risky
# actions bound to an approval of their payload digest) and the deploy pins match; the StackStorm
# pack rendered from the bound packs (workflows/stackstorm/) is current (docs/stackstorm.md)
workflows:
	$(PY) -m homelabnext.cli workflows validate
	$(PY) -m homelabnext.cli workflows st2 check

# M-01 every script has a valid header and docs/scripts/catalog.* is current (`hnx scripts catalog`
# regenerates it); M-02 the headers' triggers are exactly what runs each script, nothing called is
# uncatalogued, nothing active is uncalled; M-04 every check runs through the invariants runner
.PHONY: scripts-check
scripts-check:
	$(PY) -m homelabnext.cli scripts catalog --check
	$(PY) -m homelabnext.cli scripts reality
	$(PY) -m homelabnext.cli scripts runner-lint

# X-06: `lint-ids` fails on an engine rule number in an agent-facing file (charters, profiles,
# decision specs, schedules); rule numbers live in detections/det_map.yml only
detections:
	$(PY) -m homelabnext.detections lint
	$(PY) -m homelabnext.detections lint-ids
	$(PY) -m homelabnext.detections run
	$(PY) -m homelabnext.detections map --check
	$(PY) -m homelabnext.detections coverage --check detections/attack_coverage.json

# T-07, Q-05: every event type and shared lake table has a passing publisher and consumer
# contract test (generated from schemas/events and schemas/ocsf)
.PHONY: contracts
check: contracts
contracts:
	$(PY) tools/contract_coverage.py

# lessons/ and runbooks/ are record directories (one Markdown file per entry); every record's
# generated `## Links` block is current (`hnx registers links <dir>` rewrites them); the lesson
# review's due list is printed as a warning, never a failure (`... review --strict` fails on it);
# every front-matter `summary:` of a record or docs page is one line of <= 160 characters
# (ADR-0032: a broken one fails, a missing one is counted as a warning)
RECORD_DIRS := examples/registers/lessons examples/registers/runbooks
registers:
	$(PY) -m homelabnext.registers build examples/registers $(REGISTERS_OUT)
	$(PY) -m homelabnext.registers links --check $(RECORD_DIRS)
	$(PY) -m homelabnext.registers review examples/registers
	$(PY) -m homelabnext.registers summaries examples/registers docs

# the strategy-to-task records (docs/strategy.md): the example tree validates (schemas, link
# rules, lifecycle, review tiers, the doctrine in examples/strategy/doctrine.yml), every record's
# Links block and the generated index (docs/strategy/README.md) are current
STRATEGY_DIR := examples/strategy
.PHONY: strategy
check: strategy
strategy:
	$(PY) -m homelabnext.strategy check $(STRATEGY_DIR)
	$(PY) -m homelabnext.strategy links --check $(STRATEGY_DIR)
	$(PY) -m homelabnext.strategy index --check $(STRATEGY_DIR)

# the example projects (docs/projects.md) keep the board rules and link to existing strategy records
PROJECTS_DIR := examples/projects
.PHONY: projects
check: projects
projects:
	$(PY) -m homelabnext.cli projects check --dir $(PROJECTS_DIR) --strategy $(STRATEGY_DIR)

# Every fast criterion of the example register through the invariants runner, never paging; the
# plugin-only rows (X-04, X-06, X-09, X-10) run nowhere else.  Slow criteria (leak scans, schema
# check, coverage floor, pytest selections) are gates of their own.  Not a prerequisite of `check`:
# its CLI gates are gates of `check` already and the rest would repeat ~60 s of what `check` has
# just run; CI runs it as its own job (INVARIANTS_ARGS="--skip X-NN" skips one).
INVARIANTS_OUT := build/invariants/results.json
.PHONY: invariants
invariants:
	$(PY) -m homelabnext.invariants run examples/registers/invariants.yml --fast --no-notify --out $(INVARIANTS_OUT) $(INVARIANTS_ARGS)

# M-16, M-17: every record carries its uid and is named <uid>.md, no key occurs twice; with
# BASE=<rev> also no record that BASE had may vanish (CI: PR base).  Without paths the tool checks
# every register git tracks or HEAD/BASE has (record directories and invariants.yml), so a deleted
# record file is seen too.  Records are identified by uids (ADR-0019): nothing is allocated, so
# there is no merge-time step.
ids-check:
	$(PY) tools/register_ids.py check-dupes
	$(PY) tools/register_ids.py check-uids
	$(if $(BASE),$(PY) tools/register_ids.py check-lost --base $(BASE))

# run every capability suite against the built-in fakes (TARGET=my-target aims it elsewhere)
conform:
	$(PY) -m homelabnext.cli conform run all --target $(or $(TARGET),fake)

# `hnx conform list` and `hnx conform report --json`; fails if any of the 17 capabilities lacks a passing test
conform-check:
	$(PY) tools/conform_coverage.py

spdx:
	$(PY) tools/check_spdx.py

# Generic shapes (addresses, MACs, e-mails, private TLDs, keys, tokens).  Set HNX_DENYLIST=<file>
# to also check run-time terms that must never be published (the file itself is never committed;
# see CONTRIBUTING.md "The leak scan").
leak-scan:
	$(PY) tools/leak_scan.py .

secret-scan:
	$(PY) tools/leak_scan.py --groups secret .

# the reverse guard of the public/private split (ADR-0021): nothing of a private overlay (its
# marker, its layout paths, a .sops.yaml, SOPS ciphertext, a decryption key) is committed here.
# The private overlay's own CI runs the same tool as `private_leak_check.py private .`.
.PHONY: private-overlay-check
check: private-overlay-check
private-overlay-check:
	$(PY) tools/private_leak_check.py public .

# lines added by the commits in RANGE (default: everything not yet on origin/main)
leak-scan-history:
	$(PY) tools/leak_scan.py --history $(or $(RANGE),origin/main..HEAD)

changelog-check:
	$(PY) tools/check_changelog.py

# batch-3 hygiene gates, prerequisites of `check` (make merges this with the rule above):
#   M-03 no private notify/state/lake helpers outside the shared libraries, and no copy-paste
#        beyond tools/dup_check.baseline.json (which only shrinks)
#   F-07 no client with TLS certificate verification off (Python and YAML/JSON; RL013 does roles)
#   F-23 no Caddy config lets a client set its own identity headers; Caddy pinned >= 2.11.2
#   F-17 no runtime config points at the admin workstation (runs beside X-01's endpoint gate)
#   M-12 the generated keyring has 0 drift from its sources
#   scripts write scratch output under their run directory (homelabnext.runs) or build/ only
.PHONY: helpers-lint dup-check dup-baseline tls-lint caddy-lint workstation-lint keyring-check keyring run-output-lint
check: helpers-lint dup-check tls-lint caddy-lint workstation-lint keyring-check run-output-lint

helpers-lint:
	$(PY) tools/shared_helpers_lint.py .

dup-check:
	$(PY) tools/dup_check.py .

# after removing duplication (a stale entry): shrink the baseline and commit it.  Raising it needs
# `$(PY) tools/dup_check.py --update-baseline --allow-increase "<reason>"` by hand.
dup-baseline:
	$(PY) tools/dup_check.py --update-baseline .

caddy-lint:
	$(PY) tools/caddy_lint.py .

tls-lint:
	$(PY) tools/tls_verify_lint.py .

workstation-lint:
	$(PY) tools/workstation_refs.py .

run-output-lint:
	$(PY) tools/run_output_lint.py .

KEYRING_SOURCES := examples/keyring/sources.yml
keyring-check:
	$(PY) -m homelabnext.cli agent keyring check $(KEYRING_SOURCES)

# a local build of the knowledge graph for Obsidian and scripts (docs/graph/, gitignored)
.PHONY: graph
graph:
	$(PY) -m homelabnext.cli graph build

# after changing a registry, profile or broker source of the keyring: regenerate and commit it
keyring:
	$(PY) -m homelabnext.cli agent keyring build $(KEYRING_SOURCES)

# Q-08: every `fix:` commit (or `Fixes:` trailer) in RANGE touches a test file; PROVE=1 also runs
# each fix's tests on its parent, where they must fail.  Skipped with a note when RANGE's base
# does not exist (a fresh clone without origin/main).
.PHONY: fix-check
check: fix-check
fix-check:
	$(PY) tools/fix_has_test.py --range $(or $(RANGE),origin/main..HEAD) --allow-missing-base $(if $(PROVE),--prove)

# Regenerate the hashed CI constraints (needs uv).  Versions published in the last 14 days are
# skipped unless a direct pin needs one (CONSTRAINTS_FRESH: packages exempt from that cooldown;
# filelock and setuptools since 2026-10-24, for the pip-audit fixes CVE-2026-112907/112913/112940
# and GHSA-xmj3-9gf7-h52w).
CONSTRAINTS_CUTOFF ?= $(shell date -u -d '14 days ago' +%Y-%m-%d 2>/dev/null)
CONSTRAINTS_FRESH ?= ruff pyarrow certifi filelock setuptools
constraints:
	uv pip compile pyproject.toml constraints/ci-tools.in --extra dev --extra test --extra lake \
	  --extra core --extra nats --extra mcp --extra ansible --universal --python-version 3.11 --generate-hashes --no-header \
	  --exclude-newer $(CONSTRAINTS_CUTOFF) \
	  $(foreach p,$(CONSTRAINTS_FRESH),--exclude-newer-package $(p)=$(shell date -u +%Y-%m-%d)) \
	  -o constraints/ci.txt
	awk '/^pip==/{p=1} p{print} p&&!/\\$$/{exit}' constraints/ci.txt > constraints/bootstrap.txt

clean:
	rm -rf build dist .pytest_cache .ruff_cache *.egg-info .coverage .coverage.*
	find . -name __pycache__ -type d -prune -exec rm -rf {} +

# --- lab-in-a-box: the laptop/CI-sized reference environment (needs docker with compose) -----------
LAB_DIR := compose/lab-in-a-box
LAB_ENV := --env-file $(LAB_DIR)/.env.example $(addprefix --env-file ,$(wildcard $(LAB_DIR)/.env))
LAB_COMPOSE := docker compose $(LAB_ENV) -f $(LAB_DIR)/docker-compose.yml

# bind_guard.sh refuses a non-loopback LAB_BIND (as written, and as `docker compose config` resolves
# it) unless LAB_I_UNDERSTAND_UNAUTHENTICATED=1 and every credential differs from its .env.example
# placeholder (lab-smoke runs it through smoke.sh)
lab-up:
	bash $(LAB_DIR)/bind_guard.sh
	$(LAB_COMPOSE) up -d --build --wait --wait-timeout 420

lab-down:
	$(LAB_COMPOSE) down --volumes --remove-orphans

lab-smoke:
	$(LAB_DIR)/smoke.sh

# the broker end to end alone: its three containers, the scenario, down again (lab-smoke runs the
# same scenario as its broker check, with the whole stack up)
lab-broker:
	bash $(LAB_DIR)/bind_guard.sh
	$(LAB_COMPOSE) up -d --build --wait --wait-timeout 180 broker status-hub broker-edge
	$(LAB_COMPOSE) exec -T broker-edge python /src/compose/lab-in-a-box/broker_e2e.py run; \
	  rc=$$?; $(LAB_COMPOSE) down --volumes --remove-orphans; exit $$rc
