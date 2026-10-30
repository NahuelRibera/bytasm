# Bytasm local image: the API, the LIEF adapter it starts as a child process,
# the built UI, and the analysis worker with strings, YARA-X and capa adapters and
# Bytasm's bundled rule set. compose.yaml runs the API and the worker as two
# services from this one image. Run it only through compose.yaml, which applies
# the container settings (non-root, read-only root, no capabilities, limits).
#
# Build with `make compose-build`: it builds frontend/dist on the host first,
# so no Node image is needed here. Python dependencies come only from
# backend/uv.lock; downloading them is the build's only network use. Fixture
# binaries are not copied: the image only needs the manifest of their hashes.

# ghcr.io/astral-sh/uv:0.12.23-python3.12-trixie-slim, pinned by index digest
# (the same image scripts/check-linux.sh uses).
FROM ghcr.io/astral-sh/uv@sha256:28d570c06d150303b39adfa731ada20956c63fc86b1277d7ff2ad63185974092

ENV UV_PYTHON_DOWNLOADS=never \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/app/.venv \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --system --gid 10001 bytasm \
    && useradd --system --uid 10001 --gid 10001 --no-create-home \
       --home-dir /nonexistent --shell /usr/sbin/nologin bytasm

WORKDIR /app/backend
COPY backend/pyproject.toml backend/uv.lock ./
# Runtime dependencies only, exactly as locked. The project itself is put on
# the path with a .pth file instead of an editable build, so no unpinned build
# backend is fetched; `python -I` (the adapter child) still reads .pth files.
RUN uv sync --locked --no-dev --no-install-project \
    && echo /app/backend/src > /app/.venv/lib/python3.12/site-packages/bytasm.pth

COPY backend/src ./src
COPY fixtures/MANIFEST.sha256 /app/fixtures/MANIFEST.sha256
# The rule set is part of the image: there is no way to load other rules at run time.
COPY rules/yara /app/rules/yara
COPY rules/capa /app/rules/capa
COPY frontend/dist /app/frontend/dist
RUN /app/.venv/bin/python -m compileall -q /app/backend/src \
    && install -d -m 0700 -o 10001 -g 10001 /data

ARG BYTASM_SOURCE_REVISION=""
ENV BYTASM_SOURCE_REVISION=${BYTASM_SOURCE_REVISION} \
    BYTASM_CONTAINER=1 \
    BYTASM_DATA_DIR=/data \
    BYTASM_INPUT_POLICY=fixtures \
    PATH=/app/.venv/bin:/usr/local/bin:/usr/bin:/bin

USER 10001:10001
WORKDIR /app
EXPOSE 8000
CMD ["python", "-m", "bytasm", "serve"]
