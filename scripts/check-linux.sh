#!/bin/sh
# Run the backend check suite (ruff, mypy, pytest) inside a Linux container,
# to confirm the locked LIEF wheel installs and behaves the same on Linux.
#
# Usage: scripts/check-linux.sh <linux/arm64|linux/amd64> [3.12|3.14] [measure]
#
# With `measure`, it runs scripts/measure_parse.py instead (with RLIMIT_AS set
# to the provisional 1 GiB limit) after the same locked install.
#
# The repository is mounted read-only and copied into the container, so the
# host's backend/.venv and caches are never touched. Dependencies come only
# from backend/uv.lock (`uv sync --locked`); that is the only network use.
# Fixtures are read as data; nothing is executed.
set -eu

PLATFORM="${1:?usage: scripts/check-linux.sh <linux/arm64|linux/amd64> [3.12|3.14]}"
PYTHON="${2:-3.12}"
MODE="${3:-check}"
ROOT=$(cd "$(dirname "$0")/.." && pwd)

# ghcr.io/astral-sh/uv:0.12.23-python<X>-trixie-slim, pinned by index digest.
case "$PYTHON" in
  3.12) IMAGE="ghcr.io/astral-sh/uv@sha256:28d570c06d150303b39adfa731ada20956c63fc86b1277d7ff2ad63185974092" ;;
  3.14) IMAGE="ghcr.io/astral-sh/uv@sha256:8e88a074b0969bdc461f681727238e109438d70771828909f9ef19cfcc96c43a" ;;
  *) echo "unsupported Python version: $PYTHON" >&2; exit 2 ;;
esac

docker run --rm --platform "$PLATFORM" \
  -v "$ROOT:/repo:ro" \
  -e UV_PROJECT_ENVIRONMENT=/tmp/venv \
  -e UV_PYTHON_DOWNLOADS=never \
  -e MODE="$MODE" \
  "$IMAGE" sh -eu -c '
    mkdir /work
    tar -C /repo -cf - --exclude=.venv --exclude="*_cache" --exclude=__pycache__ \
      backend fixtures scripts | tar -C /work -xf -
    cd /work/backend
    echo "platform: $(uname -sm), $(python3 --version)"
    uv sync --locked --quiet
    uv run --no-sync python -c "import lief, platform; print(\"lief\", lief.__version__, platform.machine())"
    if [ "$MODE" = measure ]; then
      uv run --no-sync python ../scripts/measure_parse.py --rlimit-as 1024
      exit 0
    fi
    uv run --no-sync ruff format --check .
    uv run --no-sync ruff check .
    uv run --no-sync mypy
    uv run --no-sync pytest -q
  '
