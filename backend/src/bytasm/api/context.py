"""Everything a request handler needs, created once per application."""

from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from bytasm.config import Settings
from bytasm.intake.policy import InputPolicy
from bytasm.provenance import Generator
from bytasm.storage import ContentStore


class ParserSlot:
    """The single parser slot (blueprint 5.4.1 step 3).

    Acquired without waiting. It lives in memory, so it only works because
    the API runs as one server process with one event loop.
    """

    def __init__(self) -> None:
        self._busy = False

    def try_acquire(self) -> bool:
        if self._busy:
            return False
        self._busy = True
        return True

    def release(self) -> None:
        self._busy = False

    @property
    def busy(self) -> bool:
        return self._busy


@dataclass
class AppContext:
    settings: Settings
    policy: InputPolicy
    engine: Engine
    sessions: sessionmaker[Session]
    blobs: ContentStore
    outputs: ContentStore
    reports: ContentStore
    adapter_command: list[str]
    generator: Generator
    parser_slot: ParserSlot = field(default_factory=ParserSlot)

    @property
    def tmp_dir(self) -> Path:
        return self.settings.tmp_dir
