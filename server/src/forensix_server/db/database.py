"""SQLite engine lifecycle with forensic-safe durability defaults."""

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import Engine, create_engine, event, text
from sqlalchemy.orm import Session, sessionmaker

from .base import Base


class Database:
    def __init__(self, database_url: str, data_dir: Path) -> None:
        data_dir.mkdir(parents=True, exist_ok=True)
        self.engine = create_engine(
            database_url,
            connect_args={"check_same_thread": False, "timeout": 5.0},
            pool_pre_ping=True,
        )
        event.listen(self.engine, "connect", _configure_sqlite_connection)
        self._session_factory = sessionmaker(
            bind=self.engine,
            autoflush=False,
            expire_on_commit=False,
        )

    def initialize(self) -> None:
        Base.metadata.create_all(self.engine)

    def ready(self) -> bool:
        try:
            with self.engine.connect() as connection:
                connection.execute(text("SELECT 1"))
        except Exception:  # readiness boundary intentionally converts driver failures
            return False
        return True

    @contextmanager
    def session(self) -> Iterator[Session]:
        session = self._session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def dispose(self) -> None:
        self.engine.dispose()


def _configure_sqlite_connection(dbapi_connection: object, _: object) -> None:
    cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
    try:
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=FULL")
        cursor.execute("PRAGMA busy_timeout=5000")
    finally:
        cursor.close()


def sqlite_pragmas(engine: Engine) -> dict[str, int | str]:
    with engine.connect() as connection:
        return {
            "foreign_keys": connection.execute(text("PRAGMA foreign_keys")).scalar_one(),
            "journal_mode": connection.execute(text("PRAGMA journal_mode")).scalar_one(),
            "synchronous": connection.execute(text("PRAGMA synchronous")).scalar_one(),
            "busy_timeout": connection.execute(text("PRAGMA busy_timeout")).scalar_one(),
        }
