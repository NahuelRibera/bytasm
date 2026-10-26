# Developer commands. Python tools run inside backend/.venv via uv; nothing is
# installed globally.
UV := uv --directory backend

.PHONY: help install format lint typecheck test check verify-fixtures fixtures check-linux measure

help:
	@echo "make install          create backend/.venv from uv.lock"
	@echo "make format           format Python code with ruff"
	@echo "make lint             check formatting and lint rules (ruff)"
	@echo "make typecheck        run mypy in strict mode"
	@echo "make test             run the test suite (pytest)"
	@echo "make check            lint + typecheck + test (what CI runs)"
	@echo "make verify-fixtures  check committed fixtures against MANIFEST.sha256"
	@echo "make fixtures         rebuild fixtures (needs Docker + clang; see fixtures/BUILD_INFO.txt)"
	@echo "make check-linux      lint + typecheck + test in a Linux container (PLATFORM=arm64 by default, or amd64)"
	@echo "make measure          parse time and peak memory for fixtures and 64 MiB synthetic inputs"

install:
	$(UV) sync --locked

format:
	$(UV) run ruff format .

lint:
	$(UV) run ruff format --check .
	$(UV) run ruff check .

typecheck:
	$(UV) run mypy

test:
	$(UV) run pytest

check: lint typecheck test

verify-fixtures:
	cd fixtures && shasum -a 256 -c MANIFEST.sha256

fixtures:
	./fixtures/build/build.sh

PLATFORM ?= arm64
check-linux:
	./scripts/check-linux.sh linux/$(PLATFORM) 3.12

measure:
	$(UV) run --no-sync python ../scripts/measure_parse.py
