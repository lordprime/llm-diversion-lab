"""Stub LLM gateway: deterministic, Anthropic-Messages-shaped, offline."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from cell.stub_llm.app import OK_TEXT, create_app

MODEL = "claude-test-model"
REQUEST = {
    "model": MODEL,
    "max_tokens": 64,
    "messages": [{"role": "user", "content": "hello"}],
}


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app())


def test_ok_script_returns_fixed_assistant_message(client: TestClient) -> None:
    r = client.post("/v1/messages", json=REQUEST, headers={"x-lab-script": "ok"})
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/json"
    doc = r.json()
    assert doc["type"] == "message"
    assert doc["role"] == "assistant"
    assert doc["model"] == MODEL  # echoes the requested model
    assert doc["content"] == [{"type": "text", "text": OK_TEXT}]
    assert doc["stop_reason"] == "end_turn"
    assert doc["stop_sequence"] is None
    assert doc["id"].startswith("msg_stub_")
    assert set(doc["usage"]) == {"input_tokens", "output_tokens"}


def test_same_input_gives_byte_identical_output(client: TestClient) -> None:
    body = json.dumps(REQUEST).encode()
    headers = {"x-lab-script": "ok", "content-type": "application/json"}
    a = client.post("/v1/messages", content=body, headers=headers)
    b = client.post("/v1/messages", content=body, headers=headers)
    other = TestClient(create_app()).post("/v1/messages", content=body, headers=headers)
    assert a.status_code == b.status_code == other.status_code == 200
    assert a.content == b.content == other.content


def test_model_is_echoed_per_request(client: TestClient) -> None:
    r = client.post(
        "/v1/messages", json={**REQUEST, "model": "other-model"}, headers={"x-lab-script": "ok"}
    )
    assert r.json()["model"] == "other-model"


def test_missing_script_header_defaults_to_ok(client: TestClient) -> None:
    r = client.post("/v1/messages", json=REQUEST)
    assert r.status_code == 200
    assert r.json()["content"][0]["text"] == OK_TEXT


def test_auth_headers_are_ignored(client: TestClient) -> None:
    plain = client.post("/v1/messages", json=REQUEST, headers={"x-lab-script": "ok"})
    authed = client.post(
        "/v1/messages",
        json=REQUEST,
        headers={"x-lab-script": "ok", "x-api-key": "not-a-key", "authorization": "Bearer x"},
    )
    assert authed.content == plain.content


def test_unknown_script_is_a_400(client: TestClient) -> None:
    r = client.post("/v1/messages", json=REQUEST, headers={"x-lab-script": "nope"})
    assert r.status_code == 400
    assert r.json()["type"] == "error"
    assert r.json()["error"]["type"] == "invalid_request_error"


@pytest.mark.parametrize(
    "body",
    [b"not json", b"[]", json.dumps({"messages": []}).encode(), json.dumps({"model": ""}).encode()],
)
def test_request_without_model_is_a_400(client: TestClient, body: bytes) -> None:
    r = client.post("/v1/messages", content=body, headers={"content-type": "application/json"})
    assert r.status_code == 400
    assert r.json()["error"]["type"] == "invalid_request_error"


def test_streaming_request_is_refused(client: TestClient) -> None:
    r = client.post("/v1/messages", json={**REQUEST, "stream": True})
    assert r.status_code == 400


def test_healthz(client: TestClient) -> None:
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}
