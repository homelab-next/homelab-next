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
REGISTER_FILES := $(shell git ls-files -- $(foreach k,lessons runbooks invariants queue,'*$(k).yml' '*$(k).yaml') 2>/dev/null)

.PHONY: help check lint fmt test coverage component-tests hermetic-lint schemas gates decide-lint decide-safety models-check models-report models-eval agent-lint prompts-lint injection-check injection-report injection-eval workflows detections registers ids-check ids-resolve conform conform-check spdx leak-scan secret-scan leak-scan-history changelog-check constraints clean lab-up lab-down lab-smoke

help:
	@echo "targets: check lint fmt test coverage component-tests hermetic-lint schemas gates decide-lint decide-safety models-check models-report agent-lint prompts-lint injection-check injection-report workflows detections registers ids-check ids-resolve conform conform-check spdx leak-scan secret-scan leak-scan-history changelog-check clean"
	@echo "hygiene: helpers-lint dup-check tls-lint workstation-lint keyring-check keyring ids-placeholders"
	@echo "script catalog (M-01, M-02, M-04): scripts-check"
	@echo "invariants register, fast criteria, never pages (not in check; CI runs it): invariants"
	@echo "lab-in-a-box (needs docker with compose): lab-up lab-down lab-smoke"
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

test:
	$(PY) -m pytest -q

# broker, scope guard, records lifecycle, decide cascade and the agent grant ceiling each keep
# >= 80% line coverage from their own tests.  Not a prerequisite of `check`: `test` already runs
# tools/tests/test_coverage_floor.py, which enforces the same floor; this target prints the table.
coverage:
	$(PY) tools/coverage_floor.py

# every package, conformance capability, role, plugin, compose stack and tool has tests
component-tests:
	$(PY) tools/component_tests.py

# test code reads neither the wall clock nor unseeded randomness (the network is guarded at run
# time by tests/network_guard.py)
hermetic-lint:
	$(PY) tools/hermetic_lint.py

schemas:
	$(PY) $(SCHEMA_CHECK) --strict

# endpoints come from the registry; role and playbook rules come from the role interface;
# `custom check` fails on an unowned or expired customization
gates:
	$(PY) $(ENDPOINT_GATE) .
	$(PY) $(ROLE_LINT) $(ROLES)
	$(PY) $(ROLE_LINT) --playbook $(PLAYBOOKS) --inventory ansible/inventory/example/hosts.yml
	$(PY) -m homelabnext.cli custom check
	$(PY) -m homelabnext.cli docs systems check examples/services.yml docs/systems

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
models-check:
	$(PY) -m homelabnext.cli golden pins check --roles $(MODEL_ROLES) --report $(MODEL_EVAL)

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
# actions bound to an approval of their payload digest) and the deploy pins match
workflows:
	$(PY) -m homelabnext.cli workflows validate

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

registers:
	$(PY) -m homelabnext.registers build examples/registers $(REGISTERS_OUT)

# Every fast criterion of the example register through the invariants runner, never paging; the
# plugin-only rows (X-04, X-06, X-09, X-10) run nowhere else.  Slow criteria (leak scans, schema
# check, coverage floor, pytest selections) are gates of their own.  Not a prerequisite of `check`:
# `test` already runs the fast CLI gates through the register and the rest would repeat ~30 s of
# gates `check` has just run; CI runs it as its own job (INVARIANTS_ARGS="--skip M-16" on a pull
# request, which may carry XX-NEW placeholders until merge).
INVARIANTS_OUT := build/invariants/results.json
.PHONY: invariants
invariants:
	$(PY) -m homelabnext.invariants run examples/registers/invariants.yml --fast --no-notify --out $(INVARIANTS_OUT) $(INVARIANTS_ARGS)

# no allocated register id twice; with BASE=<rev> also no id that BASE had may vanish (CI: PR base)
ids-check:
	$(PY) tools/register_ids.py check-dupes $(REGISTER_FILES)
	$(if $(BASE),$(PY) tools/register_ids.py check-lost --base $(BASE) $(REGISTER_FILES))

# maintainers, at merge time on the target branch: allocate every XX-NEW placeholder (exit 3 =
# rewrote something, which is success here; review and commit the result)
ids-resolve:
	@rc=0; $(PY) tools/register_ids.py resolve $(REGISTER_FILES) || rc=$$?; [ $$rc -eq 0 ] || [ $$rc -eq 3 ]

# run every capability suite against the built-in fakes (TARGET=my-target aims it elsewhere)
conform:
	$(PY) -m homelabnext.cli conform run all --target $(or $(TARGET),fake)

# `hnx conform list` and `hnx conform report --json`; fails if any of the 14 capabilities lacks a passing test
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

# lines added by the commits in RANGE (default: everything not yet on origin/main)
leak-scan-history:
	$(PY) tools/leak_scan.py --history $(or $(RANGE),origin/main..HEAD)

changelog-check:
	$(PY) tools/check_changelog.py

# batch-3 hygiene gates, prerequisites of `check` (make merges this with the rule above):
#   M-03 no private notify/state/lake helpers outside the shared libraries, and no copy-paste
#        beyond tools/dup_check.baseline.json (which only shrinks)
#   F-07 no client with TLS certificate verification off (Python and YAML/JSON; RL013 does roles)
#   F-17 no runtime config points at the admin workstation (runs beside X-01's endpoint gate)
#   M-12 the generated keyring has 0 drift from its sources
.PHONY: helpers-lint dup-check dup-baseline tls-lint workstation-lint keyring-check keyring ids-placeholders
check: helpers-lint dup-check tls-lint workstation-lint keyring-check

helpers-lint:
	$(PY) tools/shared_helpers_lint.py .

dup-check:
	$(PY) tools/dup_check.py .

# after removing duplication (a stale entry): shrink the baseline and commit it.  Raising it needs
# `$(PY) tools/dup_check.py --update-baseline --allow-increase "<reason>"` by hand.
dup-baseline:
	$(PY) tools/dup_check.py --update-baseline .

tls-lint:
	$(PY) tools/tls_verify_lint.py .

workstation-lint:
	$(PY) tools/workstation_refs.py .

KEYRING_SOURCES := examples/keyring/sources.yml
keyring-check:
	$(PY) -m homelabnext.cli agent keyring check $(KEYRING_SOURCES)

# after changing a registry, profile or broker source of the keyring: regenerate and commit it
keyring:
	$(PY) -m homelabnext.cli agent keyring build $(KEYRING_SOURCES)

# M-16: XX-NEW is allowed on a pull request, never on main; CI runs this on every push to main
# (not part of `check`, which pull requests run).  Maintainer fix: `make ids-resolve` on main.
ids-placeholders:
	$(PY) tools/register_ids.py check-placeholders $(REGISTER_FILES)

# Q-08: every `fix:` commit (or `Fixes:` trailer) in RANGE touches a test file; PROVE=1 also runs
# each fix's tests on its parent, where they must fail.  Skipped with a note when RANGE's base
# does not exist (a fresh clone without origin/main).
.PHONY: fix-check
check: fix-check
fix-check:
	$(PY) tools/fix_has_test.py --range $(or $(RANGE),origin/main..HEAD) --allow-missing-base $(if $(PROVE),--prove)

# Regenerate the hashed CI constraints (needs uv).  Versions published in the last 14 days are
# skipped unless a direct pin needs one (CONSTRAINTS_FRESH: packages exempt from that cooldown).
CONSTRAINTS_CUTOFF ?= $(shell date -u -d '14 days ago' +%Y-%m-%d 2>/dev/null)
CONSTRAINTS_FRESH ?= ruff pyarrow
constraints:
	uv pip compile pyproject.toml constraints/ci-tools.in --extra dev --extra test --extra lake \
	  --extra core --extra nats --universal --python-version 3.11 --generate-hashes --no-header \
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

# bind_guard.sh refuses a non-loopback LAB_BIND unless LAB_I_UNDERSTAND_UNAUTHENTICATED=1 and every
# credential differs from its .env.example placeholder (lab-smoke runs it through smoke.sh)
lab-up:
	bash $(LAB_DIR)/bind_guard.sh
	$(LAB_COMPOSE) up -d --build --wait --wait-timeout 420

lab-down:
	$(LAB_COMPOSE) down --volumes --remove-orphans

lab-smoke:
	$(LAB_DIR)/smoke.sh
