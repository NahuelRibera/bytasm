"""`bytasm worker`: the background process that runs queued analysis runs (blueprint 5.4.2).

A hand-rolled claim loop over the same SQLite database the API uses (ADR-0003):

- One worker per data directory, enforced with an exclusive lock on
  `<data>/worker.lock`. A second worker exits at start-up.
- It waits until the API has migrated the schema; it never migrates itself.
- At start-up, runs left `running` by a worker that stopped are finished:
  `partial` if a step had committed its results, otherwise `failed`
  (`worker_interrupted`). A run never stays `running`.
- It touches `<data>/worker.heartbeat` every loop, so `/api/v1/health` and
  the UI can say when no worker is processing the queue.
- It claims one run at a time and executes its steps in order (strings, then
  YARA-X; bytasm.jobs.pipeline), each in a resource-limited child process.
- On SIGTERM/SIGINT it stops claiming, kills a running child's process group,
  records the interrupted step as `cancelled` (`worker_interrupted`), finishes
  the run as `partial` or `failed`, and exits.

The worker holds no secrets and never parses a sample itself. Like the API,
it is not a sandbox: it runs as the same user with the same data volume.
"""

import asyncio
import contextlib
import fcntl
import json
import logging
import os
import signal
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import Engine

from bytasm.config import Settings
from bytasm.db.session import alembic_config, create_sqlite_engine, session_factory
from bytasm.intake.manifest import Manifest, default_manifest_path
from bytasm.intake.policy import InputPolicy
from bytasm.jobs import runs
from bytasm.jobs.pipeline import execute_run, finish_after_error
from bytasm.jobs.steps import ScanDeps
from bytasm.runner.supervisor import yara_adapter_command
from bytasm.storage import ContentStore

log = logging.getLogger("bytasm.worker")

POLL_SECONDS: Final = 0.5
SCHEMA_WAIT_SECONDS: Final = 60.0
HEARTBEAT_NAME: Final = "worker.heartbeat"
LOCK_NAME: Final = "worker.lock"


class WorkerError(Exception):
    """The worker cannot start (another worker runs, or the schema is not ready)."""


def heartbeat_path(data_dir: Path) -> Path:
    return data_dir / HEARTBEAT_NAME


def touch_heartbeat(data_dir: Path) -> None:
    path = heartbeat_path(data_dir)
    path.touch(mode=0o600, exist_ok=True)
    os.utime(path)


@contextlib.contextmanager
def single_instance(data_dir: Path) -> Iterator[None]:
    data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(data_dir / LOCK_NAME, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise WorkerError("another bytasm worker is already using this data directory") from exc
        yield
    finally:
        os.close(fd)  # releases the lock


def schema_is_current(engine: Engine) -> bool:
    head = ScriptDirectory.from_config(alembic_config()).get_current_head()
    with engine.connect() as connection:
        return MigrationContext.configure(connection).get_current_revision() == head


@dataclass
class Worker:
    deps: ScanDeps
    data_dir: Path
    stop: asyncio.Event

    async def process_next(self) -> str | None:
        """Claim and execute one queued run. Returns its final status, or None."""
        with self.deps.sessions() as session:
            run_id = runs.claim_next(session)
        if run_id is None:
            return None
        try:
            return await execute_run(self.deps, run_id, stopping=self.stop.is_set)
        except Exception as exc:
            log.error(
                json.dumps({"event": "run_error", "run_id": run_id, "error": type(exc).__name__})
            )
            return finish_after_error(self.deps, run_id) or "failed"

    async def run_forever(self) -> None:
        while not self.stop.is_set():
            touch_heartbeat(self.data_dir)
            if await self.process_next() is None:
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(self.stop.wait(), POLL_SECONDS)


def build_deps(
    settings: Settings, adapter_command: list[str] | None = None
) -> tuple[ScanDeps, Engine]:
    engine = create_sqlite_engine(settings.database_path)
    deps = ScanDeps(
        sessions=session_factory(engine),
        blobs=ContentStore(settings.blobs_dir),
        outputs=ContentStore(settings.outputs_dir),
        policy=InputPolicy(settings.input_policy, Manifest.load(default_manifest_path())),
        limits=settings.limits,
        tmp_dir=settings.tmp_dir,
        adapter_command=adapter_command or yara_adapter_command(),
        ghidra=settings.ghidra,
    )
    return deps, engine


async def main_async(settings: Settings) -> None:
    deps, engine = build_deps(settings)
    try:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + SCHEMA_WAIT_SECONDS
        while not settings.database_path.exists() or not schema_is_current(engine):
            if loop.time() > deadline:
                raise WorkerError(
                    "the database schema is not up to date; start `bytasm serve` first"
                )
            await asyncio.sleep(1.0)
        # A fixed bounded status document lets the API report the worker's actual
        # provider boundary without making the network-connected API analyze a sample.
        from bytasm.ghidra_provider import provider_health

        status_path = settings.data_dir / "ghidra-health.json"
        # A restarted or reconfigured worker cannot advertise its predecessor's
        # successful self-check while the new check is pending.
        status_path.unlink(missing_ok=True)
        diagnostic = await provider_health(settings.ghidra, settings.tmp_dir)
        staging = settings.data_dir / ".ghidra-health.json.part"
        fd = os.open(staging, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(diagnostic, handle, sort_keys=True)
        os.replace(staging, status_path)
        with deps.sessions() as session:
            interrupted = runs.fail_interrupted_runs(session)
        log.info(
            json.dumps(
                {
                    "event": "worker_start",
                    "input_policy": settings.input_policy,
                    "interrupted": interrupted,
                },
                sort_keys=True,
            )
        )
        stop = asyncio.Event()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, stop.set)
        await Worker(deps, settings.data_dir, stop).run_forever()
        log.info(json.dumps({"event": "worker_stop"}))
    finally:
        engine.dispose()


def run_worker(settings: Settings) -> None:
    with single_instance(settings.data_dir):
        asyncio.run(main_async(settings))
