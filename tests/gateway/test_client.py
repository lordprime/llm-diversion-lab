"""The runner's admin client against the real admin API, and against a broken one."""

from __future__ import annotations

import json
import secrets
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from control.gateway.admin import AdminApi
from control.gateway.client import GatewayAdminError, GrantClient
from control.gateway.config import GatewayConfig, Listener
from control.gateway.keys import RunKeys, key_sha256
from tests.gateway.conftest import LiveServer

SECRET = secrets.token_urlsafe(32)
CONFIG = GatewayConfig(
    upstream="http://ollama:11434",
    listen=Listener("172.31.232.10", 4000),
    admin_listen=Listener("172.31.231.20", 4001),
    admin_secret=SECRET,
)


def test_grant_and_revoke_through_the_admin_api() -> None:
    keys = RunKeys()
    key = secrets.token_urlsafe(32)
    expires = datetime.now(UTC) + timedelta(hours=1)
    with LiveServer(AdminApi(CONFIG, keys)) as admin, httpx.Client(base_url=admin.url) as http:
        client = GrantClient(http, SECRET)
        client.grant("run_a", key, ["qwen3:14b"], expires)
        client.grant("run_a", key, ["qwen3:14b"], expires)  # idempotent
        grant = keys.lookup(key)
        assert grant is not None and grant.models == frozenset({"qwen3:14b"})
        with pytest.raises(GatewayAdminError, match="409"):
            client.grant("run_a", secrets.token_urlsafe(32), ["qwen3:14b"], expires)
        client.revoke("run_a")
        client.revoke("run_a")  # idempotent
        assert keys.lookup(key) is None
        with pytest.raises(GatewayAdminError, match="401") as info:
            GrantClient(http, "x" * 40).grant("run_b", key, ["m"], expires)
        assert SECRET not in str(info.value)


def test_only_the_hash_and_the_secret_go_over_the_wire() -> None:
    sent: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(201 if request.method == "POST" else 204)

    key = secrets.token_urlsafe(32)
    http = httpx.Client(base_url="http://admin", transport=httpx.MockTransport(handler))
    client = GrantClient(http, SECRET)
    client.grant("run_a", key, ["m"], datetime(2026, 11, 25, 13, tzinfo=UTC))
    client.revoke("run_a")
    post, delete = sent
    body = json.loads(post.content)
    assert body == {
        "run_id": "run_a",
        "key_sha256": key_sha256(key),
        "models": ["m"],
        "expires_at": "2026-11-25T13:00:00+00:00",
    }
    assert key.encode() not in post.content
    assert post.headers["authorization"] == f"Bearer {SECRET}"
    assert (delete.method, delete.url.path) == ("DELETE", "/admin/grants/run_a")
    assert SECRET not in repr(client)


def test_an_unreachable_gateway_is_an_admin_error_without_detail() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    http = httpx.Client(base_url="http://admin", transport=httpx.MockTransport(handler))
    with pytest.raises(GatewayAdminError, match="unreachable") as info:
        GrantClient(http, SECRET).revoke("run_a")
    assert SECRET not in str(info.value)
    assert info.value.__cause__ is None


def test_from_env() -> None:
    assert GrantClient.from_env({}) is None
    client = GrantClient.from_env(
        {"LAB_GATEWAY_ADMIN_URL": "http://172.31.231.20:4001", "LAB_GATEWAY_ADMIN_SECRET": SECRET}
    )
    assert client is not None and SECRET not in repr(client)
    with pytest.raises(ValueError, match="LAB_GATEWAY_ADMIN_SECRET"):
        GrantClient.from_env({"LAB_GATEWAY_ADMIN_URL": "http://172.31.231.20:4001"})
