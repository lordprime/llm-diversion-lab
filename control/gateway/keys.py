"""The per-run key registry: which key may use which model, until when.

The runner mints a fresh key for every run (``secrets.token_urlsafe(32)``), hands it
to the run's agent, and registers only its SHA-256 here through the admin API. The
key itself never reaches the gateway's memory, its database or its logs: a request's
key is hashed and looked up by that hash.

Grants live in memory, for the proxy's hot path, and are mirrored to the
``gateway_grants`` table so a gateway restart keeps the running runs' grants. The
mirror is written first: a grant the database did not take is not granted. A revoke
works the other way round: access is cut in memory at once, even when the database
cannot be reached (the stale row then lapses at its ``expires_at``).
"""

from __future__ import annotations

import hashlib
import re
import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Final, Protocol

from sqlalchemy import Engine, delete, select
from sqlalchemy.exc import IntegrityError

from control.core.ids import ID_PATTERN
from control.db import tables as t
from control.db.engine import session_scope
from control.runner.experiment import LABEL_PATTERN

__all__ = [
    "MAX_GRANT_LIFETIME",
    "MAX_GRANT_MODELS",
    "GrantConflict",
    "GrantInvalid",
    "GrantStore",
    "PostgresGrantStore",
    "RunGrant",
    "RunKeys",
    "key_sha256",
]

#: The longest a grant may live: a run's timeout plus its teardown, with room to spare.
MAX_GRANT_LIFETIME: Final = timedelta(days=2)
#: The most model ids one run may be granted.
MAX_GRANT_MODELS: Final = 8

_SHA256_HEX: Final = re.compile(r"[0-9a-f]{64}")
_RUN_ID: Final = re.compile(ID_PATTERN)
_MODEL: Final = re.compile(LABEL_PATTERN)


def key_sha256(key: str) -> str:
    """The hex SHA-256 of a run key, the only form the gateway ever stores."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


class GrantInvalid(ValueError):
    """A grant that is malformed: bad run id, hash, models or expiry."""


class GrantConflict(ValueError):
    """A grant that clashes with one already held (same run or same key)."""


@dataclass(frozen=True, slots=True)
class RunGrant:
    """One run's permission: its key's hash, its model ids, and when it lapses."""

    run_id: str
    key_sha256: str = field(repr=False)
    models: frozenset[str]
    expires_at: datetime
    embeddings: bool = False

    def expired(self, now: datetime) -> bool:
        return now >= self.expires_at


class GrantStore(Protocol):
    """Where grants are mirrored so they survive a restart."""

    def save(self, grant: RunGrant) -> None: ...
    def delete(self, run_id: str) -> None: ...
    def load(self) -> list[RunGrant]: ...


class PostgresGrantStore:
    """:class:`GrantStore` on the control-plane database (``gateway_grants``)."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def save(self, grant: RunGrant) -> None:
        row = t.GatewayGrant(
            run_id=grant.run_id,
            key_sha256=grant.key_sha256,
            models=sorted(grant.models),
            embeddings=grant.embeddings,
            expires_at=grant.expires_at,
        )
        try:
            with session_scope(self._engine) as session:
                existing = session.get(t.GatewayGrant, grant.run_id)
                if existing is not None:
                    if _from_row(existing) != grant:
                        raise GrantConflict(f"run {grant.run_id} already holds another grant")
                    return
                session.add(row)
        except IntegrityError as exc:
            raise GrantConflict("the key or the run already holds another grant") from exc

    def delete(self, run_id: str) -> None:
        with session_scope(self._engine) as session:
            session.execute(delete(t.GatewayGrant).where(t.GatewayGrant.run_id == run_id))

    def load(self) -> list[RunGrant]:
        with session_scope(self._engine) as session:
            return [_from_row(row) for row in session.scalars(select(t.GatewayGrant))]


def _from_row(row: t.GatewayGrant) -> RunGrant:
    return RunGrant(
        run_id=row.run_id,
        key_sha256=row.key_sha256,
        models=frozenset(row.models),
        expires_at=row.expires_at,
        embeddings=row.embeddings,
    )


class RunKeys:
    """The gateway's grants, looked up by the hash of the key a request carries."""

    def __init__(
        self,
        store: GrantStore | None = None,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._store = store
        self._clock = clock
        self._by_hash: dict[str, RunGrant] = {}
        self._by_run: dict[str, RunGrant] = {}
        # register and revoke change both maps together; lookups only read one
        self._lock = threading.Lock()

    def load(self) -> int:
        """Take the mirrored grants that are still live; drop the lapsed ones.

        Raises if the mirror cannot be read: a gateway that silently forgot its
        grants would fail every running run.
        """
        if self._store is None:
            return 0
        now = self._clock()
        live = 0
        for grant in self._store.load():
            if grant.expired(now):
                self._store.delete(grant.run_id)
                continue
            with self._lock:
                self._by_hash[grant.key_sha256] = grant
                self._by_run[grant.run_id] = grant
            live += 1
        return live

    def register(
        self,
        run_id: str,
        key_sha256: str,
        models: Iterable[str],
        expires_at: datetime,
        *,
        embeddings: bool = False,
    ) -> RunGrant:
        """Grant ``run_id``'s key ``models`` until ``expires_at``.

        Registering the same grant again is a no-op; another grant for the same run,
        or the same key for another run, is a :class:`GrantConflict`.
        """
        grant = self._validated(run_id, key_sha256, list(models), expires_at, embeddings)
        with self._lock:
            held = self._by_run.get(run_id)
            if held == grant:
                return held
            if held is not None:
                raise GrantConflict(f"run {run_id} already holds another grant")
            if key_sha256 in self._by_hash:
                raise GrantConflict("this key is already granted to another run")
        if self._store is not None:
            self._store.save(grant)  # first: a grant the mirror did not take is not granted
        with self._lock:
            self._by_hash[grant.key_sha256] = grant
            self._by_run[grant.run_id] = grant
        return grant

    def revoke(self, run_id: str) -> bool:
        """Withdraw ``run_id``'s grant at once; whether it was held here. Idempotent."""
        with self._lock:
            grant = self._by_run.pop(run_id, None)
            if grant is not None:
                self._by_hash.pop(grant.key_sha256, None)
        if self._store is not None:
            self._store.delete(run_id)  # also after a restart that had not loaded it
        return grant is not None

    def lookup(self, key: str) -> RunGrant | None:
        """The live grant of a run key, or ``None`` (unknown, revoked or lapsed)."""
        if not key:
            return None
        grant = self._by_hash.get(key_sha256(key))
        if grant is None:
            return None
        if grant.expired(self._clock()):
            with self._lock:
                self._by_hash.pop(grant.key_sha256, None)
                self._by_run.pop(grant.run_id, None)
            return None
        return grant

    def _validated(
        self,
        run_id: str,
        digest: str,
        models: list[str],
        expires_at: datetime,
        embeddings: bool,
    ) -> RunGrant:
        if not _RUN_ID.fullmatch(run_id):
            raise GrantInvalid("run_id is not a run id")
        if not _SHA256_HEX.fullmatch(digest):
            raise GrantInvalid("key_sha256 must be 64 lowercase hex digits")
        if not models or len(models) > MAX_GRANT_MODELS:
            raise GrantInvalid(f"a grant names 1 to {MAX_GRANT_MODELS} models")
        if not all(_MODEL.fullmatch(m) for m in models):
            raise GrantInvalid("a model id is malformed")
        if expires_at.tzinfo is None:
            raise GrantInvalid("expires_at must carry a time zone")
        now = self._clock()
        if expires_at <= now or expires_at > now + MAX_GRANT_LIFETIME:
            raise GrantInvalid(f"expires_at must lie in the next {MAX_GRANT_LIFETIME}")
        return RunGrant(run_id, digest, frozenset(models), expires_at, embeddings)
