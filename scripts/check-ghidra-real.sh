#!/bin/sh
# Explicit local verification only. No download, installation or sample execution.
# Supply a locked-dependency Bytasm test image (pytest required), plus verified
# Linux Ghidra12.2/JDK25 installations. Nothing is bundled by this helper.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
: "${BYTASM_GHIDRA_HOME:?Set the verified Ghidra installation root}"
: "${BYTASM_GHIDRA_JAVA_HOME:?Set the verified Linux JDK25 root}"
: "${BYTASM_GHIDRA_TEST_IMAGE:?Set the local Bytasm test image containing locked pytest dependencies}"
docker run --rm --network none --read-only --user 10001:10001 --cap-drop ALL \
  --security-opt no-new-privileges --memory 2g --memory-swap 2g \
  --cpus 2 --pids-limit 128 \
  --tmpfs /data:rw,nosuid,nodev,noexec,size=256m,uid=10001,gid=10001 \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=256m,mode=1777 \
  -v "$ROOT/backend/src/bytasm:/app/backend/src/bytasm:ro" \
  -v "$ROOT/backend/tests:/app/backend/tests:ro" \
  -v "$ROOT/fixtures:/app/fixtures:ro" \
  -v "$BYTASM_GHIDRA_HOME:/tools/ghidra:ro" \
  -v "$BYTASM_GHIDRA_JAVA_HOME:/tools/jdk:ro" \
  -e BYTASM_GHIDRA_HOME=/tools/ghidra \
  -e BYTASM_GHIDRA_JAVA_HOME=/tools/jdk \
  -e BYTASM_TEST_REAL_GHIDRA=1 \
  "$BYTASM_GHIDRA_TEST_IMAGE" python -m pytest \
  /app/backend/tests/integration/test_ghidra_real.py \
  --basetemp=/data/pytest-real -p no:cacheprovider -q
