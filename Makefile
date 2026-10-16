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

.PHONY: help check lint fmt test schemas gates detections registers spdx leak-scan secret-scan changelog-check clean

help:
	@echo "targets: check lint fmt test schemas gates detections registers spdx leak-scan secret-scan changelog-check clean"
	@echo "override RUFF=/path/to/ruff if ruff is not importable as a module"

check: lint test schemas gates detections registers spdx leak-scan changelog-check
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

# endpoints come from the registry; role and playbook rules come from the role interface
gates:
	$(PY) $(ENDPOINT_GATE) .
	$(PY) $(ROLE_LINT) $(ROLES)
	$(PY) $(ROLE_LINT) --playbook $(PLAYBOOKS) --inventory ansible/inventory/example/hosts.yml

detections:
	$(PY) -m homelabnext.detections lint
	$(PY) -m homelabnext.detections run
	$(PY) -m homelabnext.detections map --check

registers:
	$(PY) -m homelabnext.registers build examples/registers $(REGISTERS_OUT)

spdx:
	$(PY) tools/check_spdx.py

# Generic shapes (addresses, MACs, e-mails, private TLDs, keys, tokens).  Set HNX_DENYLIST=<file>
# to also check run-time terms that must never be published (the file itself is never committed).
leak-scan:
	$(PY) tools/leak_scan.py .

secret-scan:
	$(PY) tools/leak_scan.py --groups secret .

changelog-check:
	$(PY) tools/check_changelog.py

clean:
	rm -rf build dist .pytest_cache .ruff_cache *.egg-info
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
