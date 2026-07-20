"""SQLite database lifecycle and transaction helpers."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.engine import make_url
from sqlalchemy.engine.interfaces import DBAPIConnection
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import ConnectionPoolEntry, StaticPool

from evitriage.errors import StorageError
from evitriage.storage.models import Base


class Database:
    """Own a SQLAlchemy 2 engine and provide bounded transactions."""

    def __init__(self, url: str, *, echo: bool = False) -> None:
        parsed = make_url(url)
        if parsed.get_backend_name() != "sqlite":
            raise StorageError("Gate A supports SQLite database URLs only")
        database_name = parsed.database
        database_path: Path | None = None
        if database_name is not None and database_name not in {"", ":memory:"}:
            raw_database_path = Path(database_name).expanduser()
            if raw_database_path.is_symlink():
                raise StorageError("SQLite database must not be a symbolic link")
            database_path = raw_database_path.resolve(strict=False)
            try:
                database_path.parent.mkdir(parents=True, exist_ok=True)
                database_path.parent.chmod(0o700, follow_symlinks=False)
                if database_path.exists():
                    database_path.chmod(0o600, follow_symlinks=False)
            except OSError as exc:
                raise StorageError(
                    f"cannot secure SQLite database path {database_path}: {exc}"
                ) from exc

        options: dict[str, object] = {
            "echo": echo,
            "pool_pre_ping": True,
        }
        if parsed.database == ":memory:":
            options["poolclass"] = StaticPool
            options["connect_args"] = {"check_same_thread": False}
        else:
            options["connect_args"] = {"timeout": 30.0}
        self.engine: Engine = create_engine(url, **options)
        self._sessions = sessionmaker(
            bind=self.engine,
            class_=Session,
            expire_on_commit=False,
        )
        self._configure_sqlite(self.engine, database_path)

    @classmethod
    def from_path(cls, path: str | Path, *, echo: bool = False) -> Database:
        """Create a database backed by an absolute SQLite file path."""

        raw_path = Path(path).expanduser()
        if raw_path.is_symlink():
            raise StorageError("SQLite database must not be a symbolic link")
        database_path = raw_path.resolve(strict=False)
        database_path.parent.mkdir(parents=True, exist_ok=True)
        return cls(f"sqlite+pysqlite:///{database_path.as_posix()}", echo=echo)

    @staticmethod
    def _configure_sqlite(engine: Engine, database_path: Path | None) -> None:
        @event.listens_for(engine, "connect")
        def _set_pragmas(connection: DBAPIConnection, _: ConnectionPoolEntry) -> None:
            cursor = connection.cursor()
            try:
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.execute("PRAGMA busy_timeout=30000")
                cursor.execute("PRAGMA journal_mode=WAL")
            finally:
                cursor.close()
            if database_path is not None:
                database_path.chmod(0o600, follow_symlinks=False)

    @contextmanager
    def session(self) -> Iterator[Session]:
        """Yield a session that commits on success and rolls back on failure."""

        session = self._sessions()
        try:
            yield session
            session.commit()
        except SQLAlchemyError as exc:
            session.rollback()
            raise StorageError(f"database transaction failed: {exc}") from exc
        except BaseException:
            session.rollback()
            raise
        finally:
            session.close()

    def create_schema(self) -> None:
        """Create current tables for ephemeral tests.

        Persistent installations should use ``alembic upgrade head`` so schema
        history remains auditable.
        """

        try:
            Base.metadata.create_all(self.engine)
        except SQLAlchemyError as exc:
            raise StorageError(f"failed to create database schema: {exc}") from exc

    def dispose(self) -> None:
        """Close pooled database connections."""

        self.engine.dispose()


__all__ = ["Database"]
