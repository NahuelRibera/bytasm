# Bytasm fixture toolchain: x86-64 ELF and PE (MinGW-w64) cross-compilers.
#
# Used only by fixtures/build/build.sh to COMPILE self-authored fixture sources.
# Nothing built with it is ever executed.
#
# Pinned three ways so a rebuild installs the same compilers:
#   - the base image by digest (multi-arch index of debian:trixie-slim),
#   - apt sources fixed to one snapshot.debian.org timestamp,
#   - the top-level toolchain packages by exact version.
#
# Built and run as linux/arm64. The compilers are *cross* compilers whose
# target is x86-64, so no x86-64 emulation is needed on Apple Silicon hosts.
# (The fixture's target architecture is unrelated to the container's.)
FROM debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad

ARG DEBIAN_SNAPSHOT=20261020T000000Z

# Signatures are still checked against the image's Debian archive keyring.
# Check-Valid-Until is disabled because snapshot Release files are, by design, old.
RUN printf '%s\n' \
      'Types: deb' \
      "URIs: http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}" \
      'Suites: trixie trixie-updates' \
      'Components: main' \
      'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg' \
      '' \
      'Types: deb' \
      "URIs: http://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT}" \
      'Suites: trixie-security' \
      'Components: main' \
      'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg' \
      > /etc/apt/sources.list.d/debian.sources \
 && apt-get -o Acquire::Check-Valid-Until=false update \
 && apt-get install -y --no-install-recommends \
      gcc-x86-64-linux-gnu=4:14.2.0-1 \
      gcc-14-x86-64-linux-gnu=14.2.0-19cross1 \
      binutils-x86-64-linux-gnu=2.44-3 \
      libc6-dev-amd64-cross=2.41-11cross1 \
      gcc-mingw-w64-x86-64-win32=14.2.0-19+27+b1 \
      binutils-mingw-w64-x86-64=2.44-3+12+b1 \
      mingw-w64-x86-64-dev=12.0.0-5 \
 && rm -rf /var/lib/apt/lists/* \
 && dpkg-query -W -f '${Package}=${Version}\n' > /toolchain-packages.txt

USER 65534:65534
