"""Database engine and session management."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool


class Base(DeclarativeBase):
    pass


_engine: Engine | None = None
_session_factory: sessionmaker[Session] | None = None


def init_engine(url: str) -> Engine:
    global _engine, _session_factory
    if _engine is not None and str(_engine.url) == url:
        return _engine
    kwargs: dict = {"future": True}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
        if ":memory:" in url or url.endswith("sqlite://"):
            kwargs["poolclass"] = StaticPool
    else:
        kwargs.update(pool_pre_ping=True, pool_size=10, max_overflow=10)
    _engine = create_engine(url, **kwargs)
    _session_factory = sessionmaker(bind=_engine, expire_on_commit=False)
    return _engine


def create_schema() -> None:
    from kubeshield import models  # noqa: F401  (register tables)

    assert _engine is not None
    Base.metadata.create_all(_engine)


def get_engine() -> Engine:
    assert _engine is not None, "database not initialised"
    return _engine


@contextmanager
def session_scope() -> Iterator[Session]:
    assert _session_factory is not None, "database not initialised"
    session = _session_factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_db() -> Iterator[Session]:
    """FastAPI dependency."""
    assert _session_factory is not None, "database not initialised"
    session = _session_factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def after_commit(session: Session, callback: Callable[[], object]) -> None:
    """Run callback after the session's current transaction commits (dropped on rollback)."""
    session.info.setdefault("after_commit", []).append(callback)


@event.listens_for(Session, "after_commit")
def _run_after_commit(session: Session) -> None:
    for callback in session.info.pop("after_commit", []):
        callback()


@event.listens_for(Session, "after_rollback")
def _drop_after_commit(session: Session) -> None:
    session.info.pop("after_commit", None)
