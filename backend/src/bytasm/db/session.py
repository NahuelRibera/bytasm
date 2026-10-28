"""Create the SQLite engine and bring the schema up to date with Alembic."""

from pathlib import Path
from typing import Any

from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"


def create_sqlite_engine(path: Path) -> Engine:
    engine = create_engine(
        f"sqlite:///{path}",
        # FastAPI runs sync endpoints in a thread pool.
        connect_args={"check_same_thread": False, "timeout": 30},
    )

    @event.listens_for(engine, "connect")
    def _on_connect(dbapi_connection: Any, _record: Any) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys = ON")
        cursor.execute("PRAGMA journal_mode = WAL")
        cursor.close()

    return engine


def alembic_config() -> Config:
    config = Config()
    config.set_main_option("script_location", str(MIGRATIONS_DIR))
    return config


class MigrationError(Exception):
    """A migration left rows that violate a foreign key; it was rolled back."""


def migrate(engine: Engine, target: str = "head", *, downgrade: bool = False) -> None:
    """Run Alembic to `target` atomically, with foreign keys off.

    - Atomic: Python's sqlite3 module does not put DDL inside its implicit
      transactions, so a failed migration could leave half-created tables.
      Here the driver's own transaction handling is switched off and Bytasm
      issues BEGIN itself; SQLite then rolls back DDL like any other change.
    - Foreign keys: SQLite cannot ALTER most columns, so Alembic's batch mode
      copies a table and drops the old one, which fails while other rows
      reference it. Enforcement is switched off for the migration (SQLite
      only honours that outside a transaction), and every reference is
      checked with `PRAGMA foreign_key_check` before committing.
    """
    config = alembic_config()
    with engine.connect() as connection:
        driver = connection.connection.driver_connection
        previous = driver.isolation_level  # type: ignore[union-attr]
        driver.isolation_level = None  # type: ignore[union-attr]
        try:
            connection.exec_driver_sql("PRAGMA foreign_keys = OFF")
            connection.commit()
            with connection.begin():
                connection.exec_driver_sql("BEGIN")
                config.attributes["connection"] = connection
                if downgrade:
                    command.downgrade(config, target)
                else:
                    command.upgrade(config, target)
                if connection.exec_driver_sql("PRAGMA foreign_key_check").first() is not None:
                    raise MigrationError(f"foreign key violations after migrating to {target}")
        finally:
            connection.exec_driver_sql("PRAGMA foreign_keys = ON")
            connection.commit()
            driver.isolation_level = previous  # type: ignore[union-attr]


def upgrade_to_head(engine: Engine) -> None:
    migrate(engine, "head")


def session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(engine, expire_on_commit=False)
