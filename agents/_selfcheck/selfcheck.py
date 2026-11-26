"""The agent lane's self-check: a stand-in agent that proves the smoke harness works.

This is not a tool under test. It is a tiny one-shot client, built and smoke-tested by
build-images.yml like a real agent image (but never pushed), so the lane shows end to end
that the stub model answers every API shape and that the egress canary, the timeout and
the cell-guard socket behave. ``ci/check.sh`` runs it once per mode:

* ``apis``: one call to the tap on each API shape (Ollama chat streamed and not, embed,
  embeddings, tags; OpenAI chat streamed and not, models, embeddings; Anthropic messages
  streamed and not); each reply must be well formed and end the way its API ends;
* ``egress-name HOST``: resolve ``HOST`` and connect to it on 443 (the canary must see both);
* ``egress-ip ADDRESS``: connect to a literal address on 443 (the canary must see it);
* ``hang``: never finish (smoke.sh must time it out);
* ``fail``: exit 7 (smoke.sh must report the agent failed);
* ``docker IMAGE...``: through ``DOCKER_HOST`` (cell-guard), check that the real socket is
  not there, that cell-guard refuses a container mounting it, then start each ``IMAGE``
  as a worker that fetches ``http://tap:8000/api/tags`` (it must succeed);
* ``docker-egress IMAGE``: start one worker that tries to reach ``example.com`` (the
  canary must see it).

Only the standard library is used: the image is a bare pinned Python.
"""

from __future__ import annotations

import http.client
import json
import os
import socket
import sys
import time
import urllib.request
from collections.abc import Callable, Sequence
from typing import Any, ClassVar

TAP = os.environ.get("SELFCHECK_TAP", "http://tap:8000")
REAL_SOCKETS = ("/var/run/docker.sock", "/run/docker.sock")


class Fail(Exception):
    """The self-check found the harness misbehaving."""


class TapClient:
    """Calls the stub model and checks that each reply ends the way its API ends."""

    MESSAGES: ClassVar[list[dict[str, str]]] = [
        {"role": "user", "content": "self-check: say something"}
    ]

    def call(self, path: str, body: dict[str, Any] | None = None) -> tuple[str, bytes]:
        data = None if body is None else json.dumps(body).encode()
        method = "GET" if body is None else "POST"
        request = urllib.request.Request(TAP + path, data=data, method=method)  # noqa: S310
        request.add_header("Content-Type", "application/json")
        request.add_header("Authorization", "Bearer selfcheck-not-a-key")
        with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
            return response.headers.get("Content-Type", ""), response.read()

    @staticmethod
    def json_body(raw: bytes, path: str) -> dict[str, Any]:
        doc = json.loads(raw)
        if not isinstance(doc, dict):
            raise Fail(f"{path}: reply is not a JSON object")
        return doc

    def check_all(self) -> None:
        checks: list[tuple[str, Callable[[], None]]] = [
            ("ollama chat", lambda: self.ollama_chat(stream=False)),
            ("ollama chat stream", lambda: self.ollama_chat(stream=True)),
            ("ollama embed", self.ollama_embed),
            ("ollama embeddings", self.ollama_embeddings),
            ("ollama tags", self.ollama_tags),
            ("openai chat", lambda: self.openai_chat(stream=False)),
            ("openai chat stream", lambda: self.openai_chat(stream=True)),
            ("openai models", self.openai_models),
            ("openai embeddings", self.openai_embeddings),
            ("anthropic messages", lambda: self.anthropic(stream=False)),
            ("anthropic messages stream", lambda: self.anthropic(stream=True)),
        ]
        for label, check in checks:
            check()
            print(f"selfcheck: {label}: ok", flush=True)

    def ollama_chat(self, *, stream: bool) -> None:
        _, raw = self.call(
            "/api/chat", {"model": "stub-model", "messages": self.MESSAGES, "stream": stream}
        )
        lines = [json.loads(line) for line in raw.splitlines() if line.strip()]
        if not lines or lines[-1].get("done") is not True or (len(lines) > 1) != stream:
            raise Fail(f"/api/chat (stream={stream}): reply does not end with done")

    def ollama_embed(self) -> None:
        _, raw = self.call("/api/embed", {"model": "stub-model", "input": ["a", "b"]})
        if len(self.json_body(raw, "/api/embed").get("embeddings", [])) != 2:
            raise Fail("/api/embed: expected two embeddings")

    def ollama_embeddings(self) -> None:
        _, raw = self.call("/api/embeddings", {"model": "stub-model", "prompt": "a"})
        if not self.json_body(raw, "/api/embeddings").get("embedding"):
            raise Fail("/api/embeddings: no embedding")

    def ollama_tags(self) -> None:
        _, raw = self.call("/api/tags")
        if not self.json_body(raw, "/api/tags").get("models"):
            raise Fail("/api/tags: no models")

    def openai_chat(self, *, stream: bool) -> None:
        _, raw = self.call(
            "/v1/chat/completions",
            {"model": "stub-model", "messages": self.MESSAGES, "stream": stream},
        )
        if stream:
            if not raw.rstrip().endswith(b"data: [DONE]"):
                raise Fail("/v1/chat/completions stream: no [DONE]")
        elif not self.json_body(raw, "/v1/chat/completions").get("choices"):
            raise Fail("/v1/chat/completions: no choices")

    def openai_models(self) -> None:
        _, raw = self.call("/v1/models")
        if not self.json_body(raw, "/v1/models").get("data"):
            raise Fail("/v1/models: no models")

    def openai_embeddings(self) -> None:
        _, raw = self.call("/v1/embeddings", {"model": "stub-model", "input": "a"})
        if len(self.json_body(raw, "/v1/embeddings").get("data", [])) != 1:
            raise Fail("/v1/embeddings: expected one embedding")

    def anthropic(self, *, stream: bool) -> None:
        body = {
            "model": "stub-model",
            "max_tokens": 64,
            "messages": self.MESSAGES,
            "stream": stream,
        }
        _, raw = self.call("/v1/messages", body)
        if stream:
            if b"event: message_stop" not in raw:
                raise Fail("/v1/messages stream: no message_stop")
        elif self.json_body(raw, "/v1/messages").get("type") != "message":
            raise Fail("/v1/messages: not a message")


class GuardClient:
    """Talks to the Docker API through cell-guard's socket (DOCKER_HOST)."""

    def __init__(self) -> None:
        host = os.environ.get("DOCKER_HOST", "")
        if not host.startswith("unix://"):
            raise Fail(f"DOCKER_HOST is not a unix socket: {host!r}")
        self.path = host.removeprefix("unix://")
        self.version = ""

    def request(self, method: str, path: str, body: object = None) -> tuple[int, bytes]:
        connection = http.client.HTTPConnection("docker", timeout=120)
        connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.sock.settimeout(120)
        connection.sock.connect(self.path)
        data = None if body is None else json.dumps(body).encode()
        headers = {"Content-Type": "application/json"} if data is not None else {}
        connection.request(method, f"{self.version}{path}", body=data, headers=headers)
        response = connection.getresponse()
        return response.status, response.read()

    def handshake(self) -> None:
        status, raw = self.request("GET", "/version")
        if status != 200:
            raise Fail(f"cell-guard /version answered {status}")
        self.version = "/v" + json.loads(raw)["ApiVersion"]

    def run(self, image: str, command: Sequence[str]) -> tuple[int, str]:
        """Create, start and wait for one worker; return its exit status and logs."""
        status, raw = self.request(
            "POST", "/containers/create", {"Image": image, "Cmd": list(command)}
        )
        if status != 201:
            raise Fail(f"creating a worker from {image} answered {status}: {raw[:300]!r}")
        cid = json.loads(raw)["Id"]
        try:
            self.expect(self.request("POST", f"/containers/{cid}/start"), 204, "start")
            status, raw = self.request("POST", f"/containers/{cid}/wait")
            self.expect((status, raw), 200, "wait")
            code = int(json.loads(raw)["StatusCode"])
            _, logs = self.request("GET", f"/containers/{cid}/logs?stdout=1&stderr=1")
            return code, logs.decode("utf-8", errors="replace")
        finally:
            self.request("DELETE", f"/containers/{cid}?force=1")

    @staticmethod
    def expect(result: tuple[int, bytes], status: int, what: str) -> None:
        if result[0] != status:
            raise Fail(f"{what} answered {result[0]}: {result[1][:300]!r}")


def check_docker(images: Sequence[str]) -> None:
    for path in REAL_SOCKETS:
        if os.path.exists(path):
            raise Fail(f"the real Docker socket is visible at {path}")
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            probe.connect(path)
        except OSError:
            pass
        else:
            raise Fail(f"connected to {path}")
        finally:
            probe.close()
    print("selfcheck: the real Docker socket is not reachable", flush=True)
    guard = GuardClient()
    guard.handshake()
    status, raw = guard.request(
        "POST",
        "/containers/create",
        {
            "Image": images[0],
            "Cmd": ["true"],
            "HostConfig": {"Binds": ["/var/run/docker.sock:/var/run/docker.sock"]},
        },
    )
    if status != 403:
        raise Fail(f"cell-guard let a worker mount the Docker socket ({status}: {raw[:300]!r})")
    print("selfcheck: cell-guard refused a worker mounting the Docker socket", flush=True)
    for image in images:
        code, logs = guard.run(image, ["wget", "-q", "-T", "10", "-O", "-", f"{TAP}/api/tags"])
        if code != 0 or "models" not in logs:
            raise Fail(f"worker {image} could not reach the tap (exit {code}): {logs[-300:]}")
        print(f"selfcheck: worker {image} reached the tap", flush=True)


def check_docker_egress(image: str) -> None:
    guard = GuardClient()
    guard.handshake()
    code, logs = guard.run(image, ["wget", "-q", "-T", "5", "-O", "-", "http://example.com/"])
    print(f"selfcheck: worker egress attempt exited {code}: {logs[-200:]}", flush=True)


def connect(host: str) -> None:
    try:
        socket.create_connection((host, 443), timeout=5).close()
    except OSError as exc:
        print(f"selfcheck: connecting to {host}:443 failed as expected: {exc}", flush=True)


def main(argv: Sequence[str]) -> int:
    mode, args = (argv[0], list(argv[1:])) if argv else ("apis", [])
    try:
        if mode == "apis":
            TapClient().check_all()
        elif mode in ("egress-name", "egress-ip") and len(args) == 1:
            connect(args[0])
        elif mode == "hang":
            while True:
                time.sleep(3600)
        elif mode == "fail":
            return 7
        elif mode == "docker" and args:
            check_docker(args)
        elif mode == "docker-egress" and len(args) == 1:
            check_docker_egress(args[0])
        else:
            print(f"selfcheck: unknown mode {' '.join(argv)!r}", file=sys.stderr)
            return 2
    except (Fail, OSError, ValueError, KeyError) as exc:
        print(f"selfcheck: FAILED: {exc}", file=sys.stderr, flush=True)
        return 1
    print(f"selfcheck: {mode}: passed", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
