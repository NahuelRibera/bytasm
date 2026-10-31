# Pre-existing trusted local image supplies locked Python/LIEF dependencies.
# The broker and API are deliberately removed from the disposable image.
ARG BASE_IMAGE=bytasm-local:v0.4
FROM ${BASE_IMAGE}
USER root
RUN rm -rf /app/backend /app/frontend /app/rules /app/fixtures
COPY backend/src/bytasm/__init__.py backend/src/bytasm/errors.py /app/backend/src/bytasm/
COPY backend/src/bytasm/adapters/__init__.py backend/src/bytasm/adapters/entropy.py backend/src/bytasm/adapters/metadata_lief.py /app/backend/src/bytasm/adapters/
COPY backend/src/bytasm/intake/__init__.py backend/src/bytasm/intake/identify.py /app/backend/src/bytasm/intake/
COPY backend/src/bytasm/runner/__init__.py backend/src/bytasm/runner/limits.py backend/src/bytasm/runner/child.py backend/src/bytasm/runner/isolated_metadata_child.py /app/backend/src/bytasm/runner/
COPY isolation/probe.py /opt/bytasm-boundary-probe.py
RUN /app/.venv/bin/python -m compileall -q /app/backend/src/bytasm
USER 65532:65532
WORKDIR /work
ENTRYPOINT ["/app/.venv/bin/python", "-I", "-m", "bytasm.runner.isolated_metadata_child"]
