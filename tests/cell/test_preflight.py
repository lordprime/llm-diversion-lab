"""The in-injector pre-flight probe against a local HTTP server."""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from cell.injector.placement import PROBE_HEADER
from cell.injector.preflight import main, probe

SECRET = "preflight-secret-0123"  # noqa: S105 -- per-test probe secret


class _Handler(BaseHTTPRequestHandler):
    seen: list[str | None] = []  # noqa: RUF012 - shared across requests on purpose

    def do_GET(self) -> None:
        type(self).seen.append(self.headers.get(PROBE_HEADER))
        status = 200 if self.path == "/robots.txt" else 404
        body = b"User-agent: *\n" if status == 200 else b"not found"
        self.send_response(status)
        self.send_header("content-type", "text/plain")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:  # quiet
        pass


@pytest.fixture
def server() -> Iterator[int]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield srv.server_address[1]
    finally:
        srv.shutdown()
        srv.server_close()


def test_probe_reports_status_and_sends_the_secret(server: int) -> None:
    _Handler.seen.clear()
    assert probe("/robots.txt", port=server, secret=SECRET)["status"] == 200
    result = probe("/.env", port=server, secret=SECRET)
    assert (result["status"], result["bytes"]) == (404, 9)
    assert _Handler.seen == [SECRET, SECRET]


def test_main_prints_json_and_fails_without_a_listener(
    server: int, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("LAB_PROBE_SECRET", SECRET)
    assert main(["--port", str(server), "/robots.txt", "/.env"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert [r["status"] for r in doc["results"]] == [200, 404]
    assert main(["--port", "1", "/robots.txt"]) == 1
    assert json.loads(capsys.readouterr().out)["results"][0]["status"] is None


def test_main_needs_the_probe_secret(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("LAB_PROBE_SECRET", raising=False)
    assert main(["/robots.txt"]) == 1
    assert "LAB_PROBE_SECRET" in capsys.readouterr().out
