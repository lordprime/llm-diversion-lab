"""The per-run key registry: in memory, mirrored to Postgres so a restart keeps grants."""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import Engine, select

from control.db import tables as t
from control.db.engine import session_scope
from control.gateway.keys import (
    GrantConflict,
    GrantInvalid,
    PostgresGrantStore,
    RunGrant,
    RunKeys,
    key_sha256,
)

NOW = datetime(2026, 11, 25, 12, 0, tzinfo=UTC)


class Clock:
    def __init__(self) -> None:
        self.now = NOW

    def __call__(self) -> datetime:
        return self.now


def _key() -> tuple[str, str]:
    key = secrets.token_urlsafe(32)
    return key, hashlib.sha256(key.encode()).hexdigest()


def test_key_sha256_is_the_hex_digest_of_the_utf8_key() -> None:
    key, digest = _key()
    assert key_sha256(key) == digest


def test_register_lookup_revoke() -> None:
    keys = RunKeys(clock=Clock())
    key, digest = _key()
    grant = keys.register("run_a", digest, ["qwen3:14b"], NOW + timedelta(hours=1))
    assert grant == RunGrant("run_a", digest, frozenset({"qwen3:14b"}), NOW + timedelta(hours=1))
    assert keys.lookup(key) == grant
    assert keys.lookup(digest) is None  # the hash is not the key
    assert keys.revoke("run_a") is True
    assert keys.lookup(key) is None
    assert keys.revoke("run_a") is False  # idempotent


def test_unknown_and_empty_keys_find_nothing() -> None:
    keys = RunKeys(clock=Clock())
    _, digest = _key()
    keys.register("run_a", digest, ["m"], NOW + timedelta(hours=1))
    for probe in ("", " ", "x" * 10_000, "\x00", digest.upper()):
        assert keys.lookup(probe) is None


def test_an_expired_grant_is_gone() -> None:
    clock = Clock()
    keys = RunKeys(clock=clock)
    key, digest = _key()
    keys.register("run_a", digest, ["m"], NOW + timedelta(minutes=5))
    clock.now = NOW + timedelta(minutes=5)
    assert keys.lookup(key) is None


def test_reregistering_the_same_grant_is_idempotent_and_another_is_a_conflict() -> None:
    keys = RunKeys(clock=Clock())
    key, digest = _key()
    expires = NOW + timedelta(hours=1)
    first = keys.register("run_a", digest, ["m"], expires)
    assert keys.register("run_a", digest, ["m"], expires) == first
    _, other = _key()
    with pytest.raises(GrantConflict):
        keys.register("run_a", other, ["m"], expires)  # same run, another key
    with pytest.raises(GrantConflict):
        keys.register("run_a", digest, ["other"], expires)  # same run, another model
    with pytest.raises(GrantConflict):
        keys.register("run_b", digest, ["m"], expires)  # one key, two runs
    assert keys.lookup(key) == first


@pytest.mark.parametrize(
    ("run_id", "digest", "models", "expires"),
    [
        ("", "a" * 64, ["m"], NOW + timedelta(hours=1)),
        ("run/../x", "a" * 64, ["m"], NOW + timedelta(hours=1)),
        ("run_a", "A" * 64, ["m"], NOW + timedelta(hours=1)),
        ("run_a", "a" * 63, ["m"], NOW + timedelta(hours=1)),
        ("run_a", "g" * 64, ["m"], NOW + timedelta(hours=1)),
        ("run_a", "a" * 64, [], NOW + timedelta(hours=1)),
        ("run_a", "a" * 64, ["bad model id"], NOW + timedelta(hours=1)),
        ("run_a", "a" * 64, ["m"] * 20, NOW + timedelta(hours=1)),
        ("run_a", "a" * 64, ["m"], NOW),
        ("run_a", "a" * 64, ["m"], NOW - timedelta(seconds=1)),
        ("run_a", "a" * 64, ["m"], NOW + timedelta(days=30)),
        ("run_a", "a" * 64, ["m"], datetime(2026, 11, 25, 13, 0)),  # naive
    ],
)
def test_invalid_grants_are_refused(
    run_id: str, digest: str, models: list[str], expires: datetime
) -> None:
    keys = RunKeys(clock=Clock())
    with pytest.raises(GrantInvalid):
        keys.register(run_id, digest, models, expires)


def test_the_grant_repr_never_shows_its_hash() -> None:
    _, digest = _key()
    grant = RunGrant("run_a", digest, frozenset({"m"}), NOW)
    assert digest not in repr(grant)


# --------------------------------------------------------------------------- Postgres


def test_grants_survive_a_restart_through_postgres(engine: Engine) -> None:
    clock = Clock()
    first = RunKeys(PostgresGrantStore(engine), clock=clock)
    key, digest = _key()
    grant = first.register(
        "run_a", digest, ["qwen3:14b"], NOW + timedelta(hours=1), embeddings=True
    )
    gone_key, gone_digest = _key()
    first.register("run_b", gone_digest, ["m"], NOW + timedelta(hours=1))
    first.revoke("run_b")

    restarted = RunKeys(PostgresGrantStore(engine), clock=clock)
    assert restarted.load() == 1
    assert restarted.lookup(key) == grant
    assert restarted.lookup(gone_key) is None
    with session_scope(engine) as s:
        rows = s.scalars(select(t.GatewayGrant)).all()
    assert [(r.run_id, r.key_sha256) for r in rows] == [("run_a", digest)]
    # only the hash is stored: the key itself is nowhere in the row
    assert key not in repr([(r.run_id, r.key_sha256, r.models) for r in rows])


def test_load_drops_expired_grants(engine: Engine) -> None:
    clock = Clock()
    RunKeys(PostgresGrantStore(engine), clock=clock).register(
        "run_a", _key()[1], ["m"], NOW + timedelta(minutes=1)
    )
    clock.now = NOW + timedelta(minutes=2)
    restarted = RunKeys(PostgresGrantStore(engine), clock=clock)
    assert restarted.load() == 0
    with session_scope(engine) as s:
        assert s.scalars(select(t.GatewayGrant)).all() == []


def test_a_conflict_in_the_database_is_a_grant_conflict(engine: Engine) -> None:
    # two gateways (or a restart race) must not both hold run_a under different keys
    clock = Clock()
    RunKeys(PostgresGrantStore(engine), clock=clock).register(
        "run_a", _key()[1], ["m"], NOW + timedelta(hours=1)
    )
    other = RunKeys(PostgresGrantStore(engine), clock=clock)
    with pytest.raises(GrantConflict):
        other.register("run_a", _key()[1], ["m"], NOW + timedelta(hours=1))


class FlakyStore:
    """A mirror whose database can go away."""

    def __init__(self, *, broken: bool) -> None:
        self.broken = broken
        self.saved: list[RunGrant] = []

    def _check(self) -> None:
        if self.broken:
            raise RuntimeError("database down")

    def save(self, grant: RunGrant) -> None:
        self._check()
        self.saved.append(grant)

    def delete(self, run_id: str) -> None:
        self._check()

    def load(self) -> list[RunGrant]:
        self._check()
        return list(self.saved)


def test_a_grant_the_mirror_cannot_store_is_not_granted() -> None:
    keys = RunKeys(FlakyStore(broken=True), clock=Clock())
    key, digest = _key()
    with pytest.raises(RuntimeError):
        keys.register("run_a", digest, ["m"], NOW + timedelta(hours=1))
    assert keys.lookup(key) is None


def test_revoke_cuts_access_even_when_the_mirror_fails() -> None:
    store = FlakyStore(broken=False)
    keys = RunKeys(store, clock=Clock())
    key, digest = _key()
    keys.register("run_a", digest, ["m"], NOW + timedelta(hours=1))
    store.broken = True  # the database goes away after the grant
    with pytest.raises(RuntimeError):
        keys.revoke("run_a")
    assert keys.lookup(key) is None


def test_load_refuses_to_start_without_its_mirror() -> None:
    with pytest.raises(RuntimeError):
        RunKeys(FlakyStore(broken=True), clock=Clock()).load()
