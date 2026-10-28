# Developer commands. Python tools run inside backend/.venv via uv, and Node
# tools inside frontend/node_modules via npm; nothing is installed globally.
UV := uv --directory backend
NPM := npm --prefix frontend

.PHONY: help install format lint typecheck test check verify-fixtures fixtures check-linux measure \
	web-install web-build web-check e2e serve worker schemas \
	compose-check compose-build compose-up compose-down demo audit

help:
	@echo "make install          create backend/.venv from uv.lock and frontend/node_modules from package-lock.json"
	@echo "make serve            build the UI and run Bytasm + its worker natively on http://127.0.0.1:8000 (fixtures-only)"
	@echo "make worker           run only the analysis worker (for a separately started bytasm serve)"
	@echo "make compose-up       build the image and run Bytasm in the hardened container on 127.0.0.1:8000"
	@echo "make compose-down     stop the container (keeps the bytasm-data volume)"
	@echo "make compose-check    assert the security settings of the resolved compose.yaml"
	@echo "make demo             scripted demo: import a fixture, check metadata, export the report, run YARA-X"
	@echo "make audit            audit locked Python (pip-audit) and npm dependencies for known vulnerabilities"
	@echo "make format           format Python code with ruff"
	@echo "make lint             check formatting and lint rules (ruff)"
	@echo "make typecheck        run mypy in strict mode"
	@echo "make test             run the test suite (pytest)"
	@echo "make check            backend lint + typecheck + test, then frontend lint + typecheck + unit tests"
	@echo "make e2e              Playwright end-to-end tests against real local servers"
	@echo "make schemas          regenerate schemas/report.schema.json from the report models"
	@echo "make verify-fixtures  check committed fixtures against MANIFEST.sha256"
	@echo "make fixtures         rebuild fixtures (needs Docker + clang; see fixtures/BUILD_INFO.txt)"
	@echo "make check-linux      lint + typecheck + test in a Linux container (PLATFORM=arm64 by default, or amd64)"
	@echo "make measure          parse time and peak memory for fixtures and 64 MiB synthetic inputs"

install: web-install
	$(UV) sync --locked

web-install:
	$(NPM) ci

format:
	$(UV) run ruff format .

lint:
	$(UV) run ruff format --check .
	$(UV) run ruff check .

typecheck:
	$(UV) run mypy

test:
	$(UV) run pytest

check: lint typecheck test web-check

web-check:
	$(NPM) run lint
	$(NPM) run typecheck
	$(NPM) run test

web-build:
	$(NPM) run build

# Uses the Chromium build pinned by @playwright/test; install it once with
# `npx --prefix frontend playwright install chromium` if it is missing.
e2e:
	$(NPM) run e2e

# The server and the v0.2 analysis worker share one data directory; stopping
# the server (Ctrl-C) also stops the worker.
serve: web-build
	@$(UV) run --no-sync bytasm worker & worker=$$!; \
	trap 'kill $$worker 2>/dev/null; wait $$worker 2>/dev/null' EXIT INT TERM; \
	$(UV) run --no-sync bytasm serve

worker:
	$(UV) run --no-sync bytasm worker

schemas:
	$(UV) run --no-sync python -m bytasm.reports.model > schemas/report.schema.json

# Revision baked into the image (the image has no .git); shown in reports.
SOURCE_REVISION := $(shell git describe --always --dirty --abbrev=40 2>/dev/null)

compose-check:
	$(UV) run --no-sync python ../scripts/check_compose.py

compose-build: web-build compose-check
	BYTASM_SOURCE_REVISION=$(SOURCE_REVISION) docker compose build

compose-up: compose-build
	BYTASM_SOURCE_REVISION=$(SOURCE_REVISION) docker compose up --detach --wait
	./scripts/check-container.sh
	@echo "Bytasm is running on http://127.0.0.1:8000/ (fixtures-only). Stop it with: make compose-down"

compose-down:
	docker compose down

# Throwaway native server by default; DEMO_ARGS="--url http://127.0.0.1:8000"
# runs it against `make compose-up` instead. See docs/demo.md.
demo: web-build
	$(UV) run --no-sync python ../scripts/demo.py $(DEMO_ARGS)

# Every locked Python package (runtime, dev and the audit tool itself), with
# hashes, checked by the locked pip-audit; then the npm lockfile. Both query
# public advisory databases (PyPI/OSV, npm registry) with package names and
# versions only.
audit:
	@req=$$(mktemp) && trap 'rm -f "$$req"' EXIT && \
	$(UV) export --locked --all-groups --no-emit-project --format requirements-txt --quiet -o "$$req" && \
	$(UV) run --locked --isolated --only-group audit \
		pip-audit --strict --require-hashes --disable-pip --progress-spinner off -r "$$req"
	$(NPM) audit --audit-level=high

verify-fixtures:
	cd fixtures && shasum -a 256 -c MANIFEST.sha256

fixtures:
	./fixtures/build/build.sh

PLATFORM ?= arm64
check-linux:
	./scripts/check-linux.sh linux/$(PLATFORM) 3.12

measure:
	$(UV) run --no-sync python ../scripts/measure_parse.py
