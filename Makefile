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

.PHONY: help check lint fmt test schemas gates detections registers ids-check ids-resolve conform conform-check spdx leak-scan secret-scan leak-scan-history changelog-check constraints clean lab-up lab-down lab-smoke

help:
	@echo "targets: check lint fmt test schemas gates detections registers ids-check ids-resolve conform conform-check spdx leak-scan secret-scan leak-scan-history changelog-check clean"
	@echo "lab-in-a-box (needs docker with compose): lab-up lab-down lab-smoke"
	@echo "override RUFF=/path/to/ruff if ruff is not importable as a module"

check: lint test schemas gates detections registers ids-check conform-check spdx leak-scan changelog-check
	@echo "make check: OK"

lint:
	$(RUFF) check .
	$(RUFF) format --check .

fmt:
	$(RUFF) check --fix .
	$(RUFF) format .

test:
	$(PY) -m pytest -q

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

detections:
	$(PY) -m homelabnext.detections lint
	$(PY) -m homelabnext.detections run
	$(PY) -m homelabnext.detections map --check

registers:
	$(PY) -m homelabnext.registers build examples/registers $(REGISTERS_OUT)

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

# Regenerate the hashed CI constraints (needs uv).  Versions published in the last 14 days are
# skipped unless a direct pin needs one (CONSTRAINTS_FRESH: packages exempt from that cooldown).
CONSTRAINTS_CUTOFF ?= $(shell date -u -d '14 days ago' +%Y-%m-%d 2>/dev/null)
CONSTRAINTS_FRESH ?= ruff pyarrow
constraints:
	uv pip compile pyproject.toml constraints/ci-tools.in --extra dev --extra test --extra lake \
	  --extra core --universal --python-version 3.11 --generate-hashes --no-header \
	  --exclude-newer $(CONSTRAINTS_CUTOFF) \
	  $(foreach p,$(CONSTRAINTS_FRESH),--exclude-newer-package $(p)=$(shell date -u +%Y-%m-%d)) \
	  -o constraints/ci.txt
	awk '/^pip==/{p=1} p{print} p&&!/\\$$/{exit}' constraints/ci.txt > constraints/bootstrap.txt

clean:
	rm -rf build dist .pytest_cache .ruff_cache *.egg-info
	find . -name __pycache__ -type d -prune -exec rm -rf {} +

# --- lab-in-a-box: the laptop/CI-sized reference environment (needs docker with compose) -----------
LAB_DIR := compose/lab-in-a-box
LAB_ENV := --env-file $(LAB_DIR)/.env.example $(addprefix --env-file ,$(wildcard $(LAB_DIR)/.env))
LAB_COMPOSE := docker compose $(LAB_ENV) -f $(LAB_DIR)/docker-compose.yml

lab-up:
	$(LAB_COMPOSE) up -d --build --wait --wait-timeout 420

lab-down:
	$(LAB_COMPOSE) down --volumes --remove-orphans

lab-smoke:
	$(LAB_DIR)/smoke.sh
