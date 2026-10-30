#!/bin/sh
# Rebuild Bytasm's committed test fixtures and regenerate MANIFEST.sha256.
#
# This script only COMPILES. It never runs any of the binaries it produces.
# CI never runs it: CI reads the committed bytes in fixtures/bin/.
#
# Toolchains (see fixtures/BUILD_INFO.txt for exact versions):
#   - AArch64 ELF executables: GCC + GNU ld inside a locally available arm64
#     Debian image, run with no network and without pulling anything.
#   - x86-64 ELF relocatable object: the host's clang (compile only, no link).
#   - Linked x86-64 ELF and PE (MinGW-w64) files: cross-compilers in the
#     project's own pinned image, fixtures/build/Dockerfile. Building that
#     image is the only step that uses the network (pinned Debian snapshot);
#     compiling then runs with no network and without pulling anything.
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
SRC="$ROOT/fixtures/src"
OUT="$ROOT/fixtures/build/out"
BIN="$ROOT/fixtures/bin"
IMAGE="${BYTASM_FIXTURE_IMAGE:-ruby:3.1.2-bullseye}"
CLANG="${BYTASM_FIXTURE_CLANG:-/usr/bin/clang}"
CROSS_IMAGE="${BYTASM_FIXTURE_CROSS_IMAGE:-bytasm-fixture-toolchain:trixie-20261020}"

# A fixed timestamp keeps compiler output from embedding the build time.
SOURCE_DATE_EPOCH=1761436800 # 2025-10-26T00:00:00Z
export SOURCE_DATE_EPOCH

# Build (or reuse from cache) the pinned x86-64 cross-toolchain image. It is
# linux/arm64 on purpose: cross-compiling needs no x86-64 emulation.
docker build --platform linux/arm64 -t "$CROSS_IMAGE" \
  -f "$ROOT/fixtures/build/Dockerfile" "$ROOT/fixtures/build"

# Empty out/ in place instead of deleting it: Docker Desktop's file sharing can
# keep bind-mounting a just-deleted directory, so the compilers fail to write.
mkdir -p "$OUT" "$BIN"
find "$OUT" -mindepth 1 -delete

python3 "$ROOT/fixtures/build/gen_blob.py"

# AArch64 ELF executables (native arm64 GCC inside the container).
docker run --rm --network none --pull never \
  -u "$(id -u):$(id -g)" \
  -e SOURCE_DATE_EPOCH \
  -v "$SRC:/src:ro" -v "$OUT:/out" -w /src \
  "$IMAGE" sh -eu -c '
    gcc -O0 -ffile-prefix-map=/src=. -o /out/hello_v1-aarch64.elf hello_v1.c
    strip -o /out/hello_v1-aarch64-stripped.elf /out/hello_v1-aarch64.elf
    gcc -O0 -ffile-prefix-map=/src=. -o /out/entropy_blob-aarch64.elf entropy_blob.c
    { gcc --version | head -n 1; ld --version | head -n 1; } > /out/toolchain-aarch64.txt
  '

# x86-64 ELF relocatable object (compile only; there is no x86-64 ELF linker).
(cd "$SRC" && "$CLANG" --target=x86_64-linux-gnu -O0 -c \
  -ffile-prefix-map="$SRC"=. -o "$OUT/hello_v1-x86_64.o" hello_v1.c)
"$CLANG" --version | head -n 1 > "$OUT/toolchain-x86_64.txt"

# Linked x86-64 ELF and PE files (cross-compilers, pinned image).
# PE: --no-insert-timestamp keeps the COFF timestamp at 0 so rebuilds are
# byte-identical; -s drops the MinGW CRT's DWARF so fixtures stay < 100 KB.
docker run --rm --network none --pull never \
  -u "$(id -u):$(id -g)" \
  -e SOURCE_DATE_EPOCH \
  -v "$SRC:/src:ro" -v "$OUT:/out" -w /src \
  "$CROSS_IMAGE" sh -eu -c '
    x86_64-linux-gnu-gcc -O0 -ffile-prefix-map=/src=. -o /out/hello_v1-x86_64.elf hello_v1.c
    x86_64-linux-gnu-gcc -O0 -ffile-prefix-map=/src=. -o /out/hello_v2-x86_64.elf hello_v2.c
    x86_64-linux-gnu-strip -o /out/hello_v1-x86_64-stripped.elf /out/hello_v1-x86_64.elf
    x86_64-w64-mingw32-gcc -O0 -s -ffile-prefix-map=/src=. -Wl,--no-insert-timestamp \
      -o /out/hello_v1-x86_64.exe hello_v1.c
    x86_64-w64-mingw32-gcc -O0 -s -shared -ffile-prefix-map=/src=. -Wl,--no-insert-timestamp \
      -o /out/exports_v1-x86_64.dll exports_v1.c
    {
      x86_64-linux-gnu-gcc --version | head -n 1
      x86_64-linux-gnu-ld --version | head -n 1
      x86_64-w64-mingw32-gcc --version | head -n 1
      x86_64-w64-mingw32-ld --version | head -n 1
      cat /toolchain-packages.txt
    } > /out/toolchain-x86_64-cross.txt
  '

cp "$OUT"/*.elf "$OUT"/*.o "$OUT"/*.exe "$OUT"/*.dll "$BIN"/
# Fixtures are data, not programs: drop the executable bit.
chmod 0644 "$BIN"/*

# The manifest is the fixtures-mode allowlist: regenerate it in the same change.
(cd "$ROOT/fixtures" && shasum -a 256 bin/* > MANIFEST.sha256)

echo "Fixtures written to $BIN"
cat "$OUT"/toolchain-*.txt
cat "$ROOT/fixtures/MANIFEST.sha256"
