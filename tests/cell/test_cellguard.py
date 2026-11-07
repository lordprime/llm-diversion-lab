"""cell-guard: the deny-by-default Docker socket proxy of a run cell (DEPLOYMENT §0.3).

Three layers:

* :func:`cell.cellguard.policy.evaluate` is driven directly with hand-built requests;
* the proxy plumbing runs against a fake upstream daemon on a temporary Unix socket
  (forwarding, rewriting, denial, connection upgrades, ownership lookups);
* one integration test puts the proxy in front of the rootless Podman socket and drives
  it with the Docker SDK. It is skipped if that socket is unreachable.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import tempfile
import threading
import uuid
from collections.abc import AsyncIterator, Callable, Iterator
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, urlsplit

import pytest

from cell.cellguard.policy import (
    RUN_LABEL,
    AllowedImage,
    CellContext,
    Decision,
    DockerRequest,
    Target,
    evaluate,
    load_images_lock,
    route,
)
from cell.cellguard.proxy import (
    CELLGUARD_STREAM,
    DECISIONS_FILE,
    CellGuard,
    CellGuardConfig,
    DecisionLog,
)
from control.core.ids import new_id

DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
NETWORK = "lab-cell-net"
RUN = new_id("run")
OTHER_RUN = new_id("run")
CID = "c" * 64
OTHER_CID = "d" * 64


def make_ctx(**overrides: Any) -> CellContext:
    values: dict[str, Any] = {
        "run_id": RUN,
        "network": NETWORK,
        "images": (
            AllowedImage(name="ghcr.io/usestrix/strix-sandbox:0.1", digest=DIGEST_A),
            AllowedImage(name="alpine", digest=DIGEST_B),
        ),
        "scratch_volume": "lab-scratch",
        "scratch_dir": "/srv/lab/scratch/cell1",
        "memory_bytes": 1 << 30,
        "nano_cpus": 1_000_000_000,
        "pids_limit": 256,
    }
    values.update(overrides)
    return CellContext(**values)


CTX = make_ctx()


def create(body: dict[str, Any], path: str = "/v1.44/containers/create") -> Decision:
    return evaluate(DockerRequest("POST", path, json.dumps(body).encode()), CTX)


def allowed_create(body: dict[str, Any]) -> dict[str, Any]:
    decision = create(body)
    assert decision.allowed, decision.reason
    forwarded: dict[str, Any] = json.loads(decision.body)
    return forwarded


def own(kind: str = "container", ident: str = CID, name: str = "mine") -> Target:
    return Target(kind=kind, id=ident, name=name, labels={RUN_LABEL: RUN})


def foreign(kind: str = "container", ident: str = OTHER_CID, name: str = "theirs") -> Target:
    return Target(kind=kind, id=ident, name=name, labels={RUN_LABEL: OTHER_RUN})


IMG = f"ghcr.io/usestrix/strix-sandbox@{DIGEST_A}"


# --------------------------------------------------------------------------- brief minimum


def test_unlisted_image_is_denied() -> None:
    decision = create({"Image": "docker.io/library/ubuntu:24.04"})
    assert not decision.allowed
    assert decision.op == "container.create"
    assert decision.rule == "image.not_allowed"


def test_privileged_create_is_denied() -> None:
    decision = create({"Image": IMG, "HostConfig": {"Privileged": True}})
    assert not decision.allowed
    assert decision.rule == "create.privileged"


def test_allowed_image_gets_network_labels_and_limits_forced() -> None:
    body = allowed_create(
        {
            "Image": IMG,
            "Cmd": ["sleep", "60"],
            "Labels": {"purpose": "sandbox"},
            "HostConfig": {"Memory": 0, "CpuQuota": 500000, "CpuPeriod": 100000},
        }
    )
    assert body["Image"] == IMG
    assert body["Cmd"] == ["sleep", "60"]
    assert body["Labels"] == {"purpose": "sandbox", RUN_LABEL: RUN}
    host = body["HostConfig"]
    assert host["NetworkMode"] == NETWORK
    assert host["Memory"] == 1 << 30
    assert host["MemorySwap"] == 1 << 30
    assert host["NanoCpus"] == 1_000_000_000
    assert host["PidsLimit"] == 256
    assert "CpuQuota" not in host and "CpuPeriod" not in host
    assert body["NetworkingConfig"] == {"EndpointsConfig": {NETWORK: {}}}
    decision = create({"Image": IMG})
    assert decision.allowed
    assert {"Labels", "HostConfig.NetworkMode", "HostConfig.Memory"} <= set(decision.forced)


def test_inspect_of_another_runs_container_is_denied() -> None:
    path = f"/v1.44/containers/{OTHER_CID[:12]}/json"
    decision = evaluate(DockerRequest("GET", path, target=foreign()), CTX)
    assert not decision.allowed
    assert decision.op == "container.inspect"
    assert decision.rule == "target.not_owned"


def test_pull_is_denied() -> None:
    decision = evaluate(DockerRequest("POST", "/v1.44/images/create?fromImage=alpine&tag=3"), CTX)
    assert not decision.allowed
    assert decision.op == "image.pull"


def test_unknown_path_is_denied() -> None:
    for method, path in [
        ("GET", "/v1.44/swarm"),
        ("POST", "/v1.44/swarm/init"),
        ("GET", "/v1.44/plugins"),
        ("POST", "/v1.44/system/prune"),
        ("GET", "/v1.44/info"),
        ("GET", "/v1.44/events"),
        ("GET", "/totally/unknown"),
        ("POST", "/v1.44/containers/prune"),
        ("GET", "/v1.44/secrets"),
    ]:
        decision = evaluate(DockerRequest(method, path), CTX)
        assert not decision.allowed, path


# --------------------------------------------------------------------------- create: denials


@pytest.mark.parametrize(
    ("host_config", "rule"),
    [
        ({"Binds": ["/:/host"]}, "create.mount"),
        ({"Binds": ["/var/run/docker.sock:/var/run/docker.sock"]}, "create.mount"),
        ({"Binds": ["/srv/lab/scratch/cell1/../cell2:/x"]}, "create.mount"),
        ({"Binds": ["/srv/lab/scratch/cell10:/x"]}, "create.mount"),
        ({"Binds": ["other-volume:/x"]}, "create.mount"),
        ({"Mounts": [{"Type": "bind", "Source": "/etc", "Target": "/x"}]}, "create.mount"),
        (
            {"Mounts": [{"Type": "volume", "Source": "someone-elses", "Target": "/x"}]},
            "create.mount",
        ),
        (
            {
                "Mounts": [
                    {
                        "Type": "volume",
                        "Target": "/x",
                        "VolumeOptions": {
                            "DriverConfig": {
                                "Name": "local",
                                "Options": {"type": "none", "o": "bind", "device": "/"},
                            }
                        },
                    }
                ]
            },
            "create.mount",
        ),
        ({"CapAdd": ["SYS_ADMIN"]}, "create.capabilities"),
        ({"CapAdd": ["CAP_SYS_PTRACE"]}, "create.capabilities"),
        ({"CapAdd": ["ALL"]}, "create.capabilities"),
        ({"NetworkMode": "host"}, "create.network"),
        ({"NetworkMode": "container:" + OTHER_CID}, "create.network"),
        ({"NetworkMode": "other-cell-net"}, "create.network"),
        ({"PidMode": "host"}, "create.namespace"),
        ({"IpcMode": "host"}, "create.namespace"),
        ({"UsernsMode": "host"}, "create.namespace"),
        ({"UTSMode": "host"}, "create.namespace"),
        ({"CgroupnsMode": "host"}, "create.namespace"),
        (
            {"Devices": [{"PathOnHost": "/dev/kmsg", "PathInContainer": "/dev/kmsg"}]},
            "create.field",
        ),
        ({"DeviceRequests": [{"Count": -1, "Capabilities": [["gpu"]]}]}, "create.field"),
        ({"SecurityOpt": ["seccomp=unconfined"]}, "create.security_opt"),
        ({"SecurityOpt": ["seccomp:unconfined"]}, "create.security_opt"),
        ({"SecurityOpt": ["apparmor=unconfined"]}, "create.security_opt"),
        ({"SecurityOpt": ["label=disable"]}, "create.security_opt"),
        ({"SecurityOpt": ["systempaths=unconfined"]}, "create.security_opt"),
        ({"MaskedPaths": []}, "create.field"),
        ({"PortBindings": {"80/tcp": [{"HostPort": "8080"}]}}, "create.field"),
        ({"PublishAllPorts": True}, "create.field"),
        ({"VolumesFrom": [OTHER_CID]}, "create.field"),
        ({"CgroupParent": "/"}, "create.field"),
        ({"Runtime": "runc-unsafe"}, "create.field"),
        ({"Sysctls": {"kernel.core_pattern": "|/x"}}, "create.field"),
        ({"LogConfig": {"Type": "gelf", "Config": {"gelf-address": "udp://x:1"}}}, "create.field"),
        ({"SomeFutureField": {"Escape": True}}, "create.field"),
        ({"ContainerIDFile": "/etc/cron.d/x"}, "create.field"),
        ({"OomScoreAdj": -1000}, "create.field"),
        ({"Tmpfs": {"/x:/y": ""}}, "create.mount"),
    ],
)
def test_dangerous_host_config_is_denied(host_config: dict[str, Any], rule: str) -> None:
    decision = create({"Image": IMG, "HostConfig": host_config})
    assert not decision.allowed, host_config
    assert decision.rule == rule, decision.reason


def test_volumes_keys_must_be_container_paths() -> None:
    # Podman parses a Volumes key like a -v flag: "/host:/x" would bind the host path.
    for key in ["/:/host", "/etc:/x:rw", "relative", "/a/../b"]:
        decision = create({"Image": IMG, "Volumes": {key: {}}})
        assert not decision.allowed, key
        assert decision.rule == "create.mount"
    assert create({"Image": IMG, "Volumes": {"/data": {}}}).allowed


def test_networking_config_for_another_network_is_denied() -> None:
    decision = create(
        {"Image": IMG, "NetworkingConfig": {"EndpointsConfig": {"other-cell-net": {}}}}
    )
    assert not decision.allowed
    assert decision.rule == "create.network"


def test_spoofed_run_label_is_denied() -> None:
    decision = create({"Image": IMG, "Labels": {RUN_LABEL: OTHER_RUN}})
    assert not decision.allowed
    assert decision.rule == "create.labels"


def test_unknown_top_level_field_set_is_denied() -> None:
    assert not create({"Image": IMG, "Escape": "please"}).allowed
    # Zero values of any field are tolerated: the Docker CLI sends full structs.
    assert create({"Image": IMG, "Escape": None, "Other": [], "Third": ""}).allowed


def test_malformed_create_body_is_denied() -> None:
    for raw in [b"", b"not json", b"[]", b'{"Image": 1}', b'{"Image": "x", "HostConfig": []}']:
        decision = evaluate(DockerRequest("POST", "/containers/create", raw), CTX)
        assert not decision.allowed, raw


# --------------------------------------------------------------------------- create: allowed


def test_allowed_capabilities_and_safe_options_pass() -> None:
    body = allowed_create(
        {
            "Image": IMG,
            "HostConfig": {
                "CapAdd": ["NET_RAW", "CAP_NET_ADMIN"],
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges", "no-new-privileges:true"],
                "NetworkMode": "default",
                "IpcMode": "private",
                "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
                "LogConfig": {"Type": "", "Config": {}},
                "Binds": [
                    "lab-scratch:/scratch",
                    "/srv/lab/scratch/cell1/work:/work:ro",
                ],
                "Mounts": [
                    {"Type": "tmpfs", "Target": "/tmp"},  # noqa: S108
                    {"Type": "volume", "Target": "/anon"},
                    {"Type": "bind", "Source": "/srv/lab/scratch/cell1", "Target": "/s"},
                ],
            },
        }
    )
    assert body["HostConfig"]["CapAdd"] == ["NET_RAW", "CAP_NET_ADMIN"]
    assert body["HostConfig"]["NetworkMode"] == NETWORK


def test_lower_requested_limits_are_kept() -> None:
    body = allowed_create(
        {"Image": IMG, "HostConfig": {"Memory": 1 << 20, "NanoCpus": 5, "PidsLimit": 10}}
    )
    assert body["HostConfig"]["Memory"] == 1 << 20
    assert body["HostConfig"]["MemorySwap"] == 1 << 20
    assert body["HostConfig"]["NanoCpus"] == 5
    assert body["HostConfig"]["PidsLimit"] == 10
    body = allowed_create({"Image": IMG, "HostConfig": {"Memory": 1 << 40, "PidsLimit": -1}})
    assert body["HostConfig"]["Memory"] == 1 << 30
    assert body["HostConfig"]["PidsLimit"] == 256


def test_endpoint_config_for_cell_network_keeps_aliases_only() -> None:
    body = allowed_create(
        {
            "Image": IMG,
            "NetworkingConfig": {
                "EndpointsConfig": {
                    NETWORK: {"Aliases": ["sandbox"], "IPAMConfig": {"IPv4Address": "1.2.3.4"}}
                }
            },
        }
    )
    assert body["NetworkingConfig"] == {"EndpointsConfig": {NETWORK: {"Aliases": ["sandbox"]}}}


@pytest.mark.parametrize(
    ("image", "forwarded"),
    [
        (IMG, IMG),
        (
            f"ghcr.io/usestrix/strix-sandbox:0.1@{DIGEST_A}",
            f"ghcr.io/usestrix/strix-sandbox:0.1@{DIGEST_A}",
        ),
        ("ghcr.io/usestrix/strix-sandbox:0.1", IMG),
        ("alpine", f"docker.io/library/alpine@{DIGEST_B}"),
        ("docker.io/library/alpine:3.20", f"docker.io/library/alpine@{DIGEST_B}"),
        (f"alpine@{DIGEST_B}", f"alpine@{DIGEST_B}"),
    ],
)
def test_listed_images_are_pinned_to_their_digest(image: str, forwarded: str) -> None:
    body = allowed_create({"Image": image})
    assert body["Image"] == forwarded


@pytest.mark.parametrize(
    "image",
    [
        f"ghcr.io/usestrix/strix-sandbox@{DIGEST_B}",  # listed digest, wrong repo
        f"ghcr.io/evil/strix-sandbox@{DIGEST_A}",
        "ghcr.io/usestrix/strix-sandbox:latest",  # unlisted tag of a tag-pinned entry
        DIGEST_A,  # a bare id is not a reference to a listed image
        "a" * 12,
        "",
        "UPPER/case",
    ],
)
def test_other_image_references_are_denied(image: str) -> None:
    assert not create({"Image": image}).allowed


def test_create_query_and_version_prefix() -> None:
    for path in [
        "/containers/create?name=sbx",
        "/v1.44/containers/create",
        "/v1.24/containers/create",
    ]:
        decision = create({"Image": IMG}, path)
        assert decision.allowed, path
        assert decision.op == "container.create"
        assert decision.path == path


# --------------------------------------------------------------------------- routing


def test_route_strips_version_prefix() -> None:
    r = route("POST", "/v1.44/containers/abc/start")
    assert (r.op, r.version, r.base, r.target_kind, r.ref) == (
        "container.start",
        "1.44",
        "/containers/abc/start",
        "container",
        "abc",
    )
    assert route("GET", "/containers/abc/json").version is None


@pytest.mark.parametrize(
    "path",
    [
        "/v1.44/containers/../images/create",
        "/v1.44//containers/create",
        "/v1.44/containers/abc%2F..%2Fx/json",
        "/v1.44/containers/abc\\x/json",
        "v1.44/containers/create",
        "/v1.44/containers/a b/json",
    ],
)
def test_malformed_paths_are_denied(path: str) -> None:
    decision = evaluate(DockerRequest("GET", path, target=own()), CTX)
    assert not decision.allowed
    assert decision.rule == "path.malformed"


def test_handshake_endpoints_are_allowed() -> None:
    assert evaluate(DockerRequest("GET", "/_ping"), CTX).allowed
    assert evaluate(DockerRequest("HEAD", "/_ping"), CTX).allowed
    assert evaluate(DockerRequest("GET", "/v1.44/version"), CTX).allowed


# --------------------------------------------------------------------------- lifecycle


LIFECYCLE = [
    ("POST", "/v1.44/containers/{ref}/start", "container.start"),
    ("POST", "/v1.44/containers/{ref}/stop?t=1", "container.stop"),
    ("POST", "/v1.44/containers/{ref}/kill?signal=KILL", "container.kill"),
    ("POST", "/v1.44/containers/{ref}/wait", "container.wait"),
    ("DELETE", "/v1.44/containers/{ref}?force=1&v=1", "container.remove"),
    ("GET", "/v1.44/containers/{ref}/json", "container.inspect"),
    ("GET", "/v1.44/containers/{ref}/logs?stdout=1", "container.logs"),
    ("POST", "/v1.44/containers/{ref}/attach?stream=1&stdout=1", "container.attach"),
    ("GET", "/v1.44/containers/{ref}/attach/ws?stream=1", "container.attach"),
    ("POST", "/v1.44/containers/{ref}/resize?h=10&w=10", "container.resize"),
]


@pytest.mark.parametrize(("method", "template", "op"), LIFECYCLE)
def test_lifecycle_on_own_container_is_allowed_and_pinned_to_its_id(
    method: str, template: str, op: str
) -> None:
    decision = evaluate(DockerRequest(method, template.format(ref="mine"), target=own()), CTX)
    assert decision.allowed, decision.reason
    assert decision.op == op
    assert decision.path == template.format(ref=CID)


@pytest.mark.parametrize(("method", "template", "op"), LIFECYCLE)
def test_lifecycle_on_foreign_or_unknown_container_is_denied(
    method: str, template: str, op: str
) -> None:
    path = template.format(ref="theirs")
    assert not evaluate(DockerRequest(method, path, target=foreign()), CTX).allowed
    assert not evaluate(DockerRequest(method, path, target=None), CTX).allowed
    unlabelled = Target(kind="container", id=OTHER_CID, name="x", labels={})
    assert not evaluate(DockerRequest(method, path, target=unlabelled), CTX).allowed


def test_upgrade_routes_are_marked() -> None:
    attach = evaluate(DockerRequest("POST", f"/containers/{CID}/attach", target=own()), CTX)
    assert attach.upgrade
    start = evaluate(DockerRequest("POST", f"/containers/{CID}/start", target=own()), CTX)
    assert not start.upgrade


def test_remove_with_link_is_denied() -> None:
    path = f"/v1.44/containers/{CID}?link=1"
    assert not evaluate(DockerRequest("DELETE", path, target=own()), CTX).allowed


def test_other_container_operations_are_denied() -> None:
    for method, suffix in [
        ("POST", "pause"),
        ("POST", "restart"),
        ("POST", "update"),
        ("POST", "rename?name=x"),
        ("GET", "archive?path=/"),
        ("PUT", "archive?path=/"),
        ("GET", "export"),
        ("POST", "commit"),
        ("GET", "changes"),
        ("GET", "top"),
        ("GET", "stats"),
    ]:
        path = f"/v1.44/containers/{CID}/{suffix}"
        assert not evaluate(DockerRequest(method, path, target=own()), CTX).allowed, suffix


def test_exec_create_on_own_container() -> None:
    body = json.dumps({"Cmd": ["id"], "AttachStdout": True, "Tty": False}).encode()
    path = "/v1.44/containers/mine/exec"
    decision = evaluate(DockerRequest("POST", path, body, target=own()), CTX)
    assert decision.allowed
    assert decision.op == "exec.create"
    assert decision.path == f"/v1.44/containers/{CID}/exec"
    assert not evaluate(DockerRequest("POST", path, body, target=foreign()), CTX).allowed
    # docker-py repeats the container in the body: it must be the one in the path.
    same = json.dumps({"Cmd": ["id"], "Container": "mine"}).encode()
    assert evaluate(DockerRequest("POST", path, same, target=own()), CTX).allowed
    other = json.dumps({"Cmd": ["id"], "Container": OTHER_CID}).encode()
    assert not evaluate(DockerRequest("POST", path, other, target=own()), CTX).allowed


def test_privileged_exec_is_denied() -> None:
    body = json.dumps({"Cmd": ["sh"], "Privileged": True}).encode()
    decision = evaluate(DockerRequest("POST", f"/containers/{CID}/exec", body, target=own()), CTX)
    assert not decision.allowed
    assert decision.rule == "exec.privileged"


def test_exec_operations_follow_the_owning_container() -> None:
    exec_id = "e" * 64
    mine = Target(kind="exec", id=exec_id, name=None, labels={RUN_LABEL: RUN})
    theirs = Target(kind="exec", id=exec_id, name=None, labels={RUN_LABEL: OTHER_RUN})
    for method, path, op in [
        ("POST", f"/v1.44/exec/{exec_id}/start", "exec.start"),
        ("POST", f"/v1.44/exec/{exec_id}/resize?h=1&w=1", "exec.resize"),
        ("GET", f"/v1.44/exec/{exec_id}/json", "exec.inspect"),
    ]:
        body = b'{"Detach": false, "Tty": false}' if op == "exec.start" else b""
        decision = evaluate(DockerRequest(method, path, body, target=mine), CTX)
        assert decision.allowed and decision.op == op
        assert decision.upgrade == (op == "exec.start")
        assert not evaluate(DockerRequest(method, path, body, target=theirs), CTX).allowed


def test_container_list_is_forced_to_own_label() -> None:
    decision = evaluate(DockerRequest("GET", "/v1.44/containers/json?all=1"), CTX)
    assert decision.allowed
    query = parse_qs(urlsplit(decision.path).query)
    assert query["all"] == ["1"]
    assert json.loads(query["filters"][0]) == {"label": [f"{RUN_LABEL}={RUN}"]}

    filters = quote(json.dumps({"label": {"purpose=x": True}, "name": ["sbx"]}))
    decision = evaluate(DockerRequest("GET", f"/containers/json?filters={filters}"), CTX)
    assert decision.allowed
    forced = json.loads(parse_qs(urlsplit(decision.path).query)["filters"][0])
    assert forced == {"label": ["purpose=x", f"{RUN_LABEL}={RUN}"], "name": ["sbx"]}

    bad = evaluate(DockerRequest("GET", "/containers/json?filters=notjson"), CTX)
    assert not bad.allowed


# --------------------------------------------------------------------------- images


def test_image_read_only_operations() -> None:
    assert evaluate(DockerRequest("GET", "/v1.44/images/json"), CTX).allowed
    inspect = evaluate(DockerRequest("GET", "/v1.44/images/docker.io/library/alpine:3/json"), CTX)
    assert inspect.allowed and inspect.op == "image.inspect"
    for method, path, op in [
        ("POST", "/v1.44/images/create?fromSrc=-", "image.import"),
        ("POST", "/v1.44/images/load", "image.import"),
        ("POST", "/v1.44/build", "image.build"),
        ("POST", "/v1.44/images/alpine/push", "image.push"),
        ("POST", "/v1.44/images/alpine/tag?repo=x", "image.tag"),
        ("DELETE", "/v1.44/images/alpine", "image.remove"),
        ("GET", "/v1.44/images/alpine/get", "image.export"),
    ]:
        decision = evaluate(DockerRequest(method, path), CTX)
        assert not decision.allowed, path
        assert decision.op == op, path


# --------------------------------------------------------------------------- networks, volumes


def test_networks() -> None:
    listed = evaluate(DockerRequest("GET", "/v1.44/networks"), CTX)
    assert listed.allowed
    assert (
        f"{RUN_LABEL}={RUN}"
        in json.loads(parse_qs(urlsplit(listed.path).query)["filters"][0])["label"]
    )
    cell_net = Target(kind="network", id="n" * 64, name=NETWORK, labels={})
    inspect = evaluate(DockerRequest("GET", f"/networks/{NETWORK}", target=cell_net), CTX)
    assert inspect.allowed and inspect.path == "/networks/" + "n" * 64
    other = Target(kind="network", id="o" * 64, name="bridge", labels={})
    assert not evaluate(DockerRequest("GET", "/networks/bridge", target=other), CTX).allowed
    for method, path in [
        ("POST", "/v1.44/networks/create"),
        ("POST", f"/v1.44/networks/{NETWORK}/connect"),
        ("POST", f"/v1.44/networks/{NETWORK}/disconnect"),
        ("DELETE", f"/v1.44/networks/{NETWORK}"),
        ("POST", "/v1.44/networks/prune"),
    ]:
        assert not evaluate(DockerRequest(method, path, target=cell_net), CTX).allowed, path


def test_volumes() -> None:
    assert evaluate(DockerRequest("GET", "/v1.44/volumes"), CTX).allowed
    mine = Target(kind="volume", id="v1", name="v1", labels={RUN_LABEL: RUN})
    assert evaluate(DockerRequest("GET", "/volumes/v1", target=mine), CTX).allowed
    theirs = Target(kind="volume", id="v2", name="v2", labels={RUN_LABEL: OTHER_RUN})
    assert not evaluate(DockerRequest("GET", "/volumes/v2", target=theirs), CTX).allowed

    made = evaluate(
        DockerRequest("POST", "/v1.44/volumes/create", json.dumps({"Name": "work"}).encode()), CTX
    )
    assert made.allowed
    assert json.loads(made.body)["Labels"] == {RUN_LABEL: RUN}
    for body in [
        {"Name": "w", "Driver": "nfs"},
        {"Name": "w", "DriverOpts": {"type": "none", "o": "bind", "device": "/"}},
        {"Name": "w", "Labels": {RUN_LABEL: OTHER_RUN}},
    ]:
        decision = evaluate(
            DockerRequest("POST", "/volumes/create", json.dumps(body).encode()), CTX
        )
        assert not decision.allowed, body
    assert not evaluate(DockerRequest("DELETE", "/volumes/v1", target=mine), CTX).allowed
    assert not evaluate(DockerRequest("POST", "/volumes/prune"), CTX).allowed


# --------------------------------------------------------------------------- images.lock


def test_load_images_lock_yaml_json_and_list(tmp_path: Path) -> None:
    entries = [
        {
            "name": "ghcr.io/usestrix/strix-sandbox:0.1",
            "digest": DIGEST_A,
            "expect_tools": ["nmap"],
        },
        {"name": "alpine", "digest": DIGEST_B, "expect_tools": []},
    ]
    yml = tmp_path / "images.lock"
    yml.write_text(
        "- name: ghcr.io/usestrix/strix-sandbox:0.1\n"
        f"  digest: {DIGEST_A}\n"
        "  expect_tools: [nmap]\n"
        "- name: alpine\n"
        f"  digest: {DIGEST_B}\n"
        "  expect_tools: []\n"
    )
    js = tmp_path / "images.json"
    js.write_text(json.dumps({"images": entries}))
    expected = (
        AllowedImage("ghcr.io/usestrix/strix-sandbox:0.1", DIGEST_A, ("nmap",)),
        AllowedImage("alpine", DIGEST_B, ()),
    )
    assert load_images_lock(yml) == expected
    assert load_images_lock(str(js)) == expected
    assert load_images_lock(entries) == expected


@pytest.mark.parametrize(
    "entries",
    [
        [{"name": "x", "digest": "sha256:short"}],
        [{"name": "", "digest": DIGEST_A}],
        [{"digest": DIGEST_A}],
        [{"name": "x", "digest": DIGEST_A, "expect_tools": "nmap"}],
        ["x"],
        {"not": "a list"},
    ],
)
def test_load_images_lock_rejects_malformed(entries: Any) -> None:
    with pytest.raises(ValueError):
        load_images_lock(entries)


# --------------------------------------------------------------------------- decision log


def test_decision_log_appends_resumes_and_closes_torn_lines(tmp_path: Path) -> None:
    path = tmp_path / DECISIONS_FILE
    log = DecisionLog(RUN, path)
    request = DockerRequest("POST", "/v1.44/containers/create", b'{"Image":"x"}')
    denied = evaluate(request, CTX)
    first = log.record(request, denied)
    assert first["seq"] == 0
    assert first["stream"] == CELLGUARD_STREAM
    assert first["run_id"] == RUN
    assert first["allowed"] is False
    assert first["rule"] == "image.not_allowed"
    assert first["op"] == "container.create"
    assert "body_sha256" in first
    assert b'"Image":"x"' not in path.read_bytes()  # bodies are hashed, never stored
    ok = DockerRequest("GET", "/_ping")
    log.record(ok, evaluate(ok, CTX))
    with path.open("ab") as fh:
        fh.write(b'{"seq": 2, "torn')  # a crash mid-append: never parsed, never counted
    resumed = DecisionLog(RUN, path)
    third = resumed.record(ok, evaluate(ok, CTX))
    assert third["seq"] == 2
    lines = path.read_bytes().splitlines()
    assert len(lines) == 4  # the torn line was closed with a newline, not overwritten
    parsed = []
    for line in lines:
        with contextlib.suppress(ValueError):
            parsed.append(json.loads(line)["seq"])
    assert parsed == [0, 1, 2]


def test_decision_log_rejects_bad_run_id(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        DecisionLog("../escape", tmp_path / "x.jsonl")


def test_config_from_env(tmp_path: Path) -> None:
    lock = tmp_path / "images.lock"
    lock.write_text(f"- name: alpine\n  digest: {DIGEST_B}\n  expect_tools: []\n")
    env = {
        "LAB_RUN_ID": RUN,
        "LAB_EVIDENCE_DIR": str(tmp_path / "ev"),
        "LAB_CELLGUARD_LISTEN": str(tmp_path / "guard.sock"),
        "LAB_CELLGUARD_UPSTREAM": "/var/run/docker.sock",
        "LAB_CELLGUARD_NETWORK": NETWORK,
        "LAB_CELLGUARD_IMAGES_LOCK": str(lock),
        "LAB_CELLGUARD_SCRATCH_VOLUME": "lab-scratch",
        "LAB_CELLGUARD_MEMORY": "268435456",
        "LAB_CELLGUARD_NANO_CPUS": "500000000",
        "LAB_CELLGUARD_PIDS": "128",
    }
    config = CellGuardConfig.from_env(env)
    assert config.context.run_id == RUN
    assert config.context.network == NETWORK
    assert config.context.images == (AllowedImage("alpine", DIGEST_B, ()),)
    assert config.context.memory_bytes == 268435456
    assert config.context.pids_limit == 128
    assert config.context.scratch_dir is None
    assert config.listen == tmp_path / "guard.sock"
    for missing in ["LAB_RUN_ID", "LAB_CELLGUARD_NETWORK", "LAB_CELLGUARD_IMAGES_LOCK"]:
        with pytest.raises(ValueError):
            CellGuardConfig.from_env({k: v for k, v in env.items() if k != missing})
    with pytest.raises(ValueError):
        CellGuardConfig.from_env({**env, "LAB_CELLGUARD_PIDS": "lots"})


# --------------------------------------------------------------------------- proxy plumbing


Handler = Callable[[str, str, dict[str, str], bytes], tuple[int, dict[str, Any] | bytes]]


@contextlib.contextmanager
def short_tmp() -> Iterator[Path]:
    # AF_UNIX paths are limited to ~107 bytes; pytest's tmp_path can be longer.
    with tempfile.TemporaryDirectory(prefix="cg-", dir="/tmp") as d:
        yield Path(d)


class FakeDaemon:
    """A minimal upstream: canned JSON per route, plus a hijacking echo on exec start."""

    def __init__(self, sock: Path) -> None:
        self.sock = sock
        self.requests: list[tuple[str, str, dict[str, str], bytes]] = []
        self.containers: dict[str, dict[str, Any]] = {
            "mine": {"Id": CID, "Name": "/mine", "Config": {"Labels": {RUN_LABEL: RUN}}},
            CID: {"Id": CID, "Name": "/mine", "Config": {"Labels": {RUN_LABEL: RUN}}},
            "theirs": {
                "Id": OTHER_CID,
                "Name": "/theirs",
                "Config": {"Labels": {RUN_LABEL: OTHER_RUN}},
            },
        }
        self.execs = {"e1": {"ID": "e1", "ContainerID": CID}}
        self.server: asyncio.Server | None = None

    async def start(self) -> None:
        self.server = await asyncio.start_unix_server(self._handle, path=str(self.sock))

    async def close(self) -> None:
        assert self.server is not None
        self.server.close()
        await self.server.wait_closed()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            head = await reader.readuntil(b"\r\n\r\n")
            lines = head.decode().split("\r\n")
            method, target, _ = lines[0].split(" ")
            headers = {
                k.strip().lower(): v.strip()
                for k, _, v in (line.partition(":") for line in lines[1:] if line)
            }
            body = await reader.readexactly(int(headers.get("content-length", "0")))
            path = urlsplit(target).path
            self.requests.append((method, target, headers, body))
            base = path.removeprefix("/v1.44")
            if base.startswith("/exec/") and base.endswith("/start"):
                writer.write(
                    b"HTTP/1.1 101 UPGRADED\r\nContent-Type: application/vnd.docker.raw-stream"
                    b"\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n"
                )
                await writer.drain()
                while data := await reader.read(1024):
                    writer.write(b"echo:" + data)
                    await writer.drain()
                return
            status, payload = self._respond(method, base)
            raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
            writer.write(
                f"HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n"
                f"Content-Length: {len(raw)}\r\nConnection: close\r\n\r\n".encode()
                + raw
            )
            await writer.drain()
        finally:
            writer.close()

    def _respond(self, method: str, base: str) -> tuple[int, dict[str, Any] | bytes]:
        parts = base.strip("/").split("/")
        if parts[0] == "containers" and len(parts) == 3 and parts[2] == "json":
            found = self.containers.get(parts[1])
            return (200, found) if found else (404, {"message": "no such container"})
        if parts[0] == "exec" and len(parts) == 3 and parts[2] == "json":
            exec_found = self.execs.get(parts[1])
            return (200, exec_found) if exec_found else (404, {"message": "no such exec"})
        if base == "/containers/create":
            return 201, {"Id": CID, "Warnings": []}
        return 200, {"ok": True, "method": method, "base": base}


@contextlib.asynccontextmanager
async def running_guard(tmp_path: Path) -> AsyncIterator[tuple[CellGuard, FakeDaemon, Path]]:
    with short_tmp() as d:
        daemon = FakeDaemon(d / "up.sock")
        await daemon.start()
        log = DecisionLog(RUN, tmp_path / DECISIONS_FILE)
        guard = CellGuard(CTX, str(daemon.sock), log)
        listen = d / "guard.sock"
        server = await guard.serve(listen)
        try:
            yield guard, daemon, listen
        finally:
            server.close()
            await server.wait_closed()
            await daemon.close()


async def call(sock: Path, raw: bytes) -> bytes:
    reader, writer = await asyncio.open_unix_connection(str(sock))
    writer.write(raw)
    await writer.drain()
    data = await asyncio.wait_for(reader.read(), timeout=5)
    writer.close()
    return data


def req(method: str, path: str, body: bytes = b"", extra: str = "") -> bytes:
    return (
        f"{method} {path} HTTP/1.1\r\nHost: docker\r\nContent-Length: {len(body)}\r\n{extra}\r\n"
    ).encode() + body


async def test_proxy_forwards_rewritten_create_and_logs(tmp_path: Path) -> None:
    async with running_guard(tmp_path) as (_guard, daemon, sock):
        body = json.dumps({"Image": IMG, "HostConfig": {"Privileged": False}}).encode()
        resp = await call(sock, req("POST", "/v1.44/containers/create?name=sbx", body))
        assert resp.startswith(b"HTTP/1.1 201")
        method, target, headers, sent = daemon.requests[-1]
        assert (method, target) == ("POST", "/v1.44/containers/create?name=sbx")
        assert headers["connection"] == "close"
        forwarded = json.loads(sent)
        assert forwarded["HostConfig"]["NetworkMode"] == NETWORK
        assert forwarded["Labels"][RUN_LABEL] == RUN
    records = [json.loads(x) for x in (tmp_path / DECISIONS_FILE).read_text().splitlines()]
    assert [(r["op"], r["allowed"]) for r in records] == [("container.create", True)]


async def test_proxy_denies_with_403_without_forwarding(tmp_path: Path) -> None:
    async with running_guard(tmp_path) as (_guard, daemon, sock):
        body = json.dumps({"Image": IMG, "HostConfig": {"Privileged": True}}).encode()
        resp = await call(sock, req("POST", "/v1.44/containers/create", body))
        assert resp.startswith(b"HTTP/1.1 403")
        assert b"cell-guard" in resp and b"create.privileged" in resp
        resp = await call(sock, req("POST", "/v1.44/images/create?fromImage=alpine"))
        assert resp.startswith(b"HTTP/1.1 403")
        assert daemon.requests == []
    records = [json.loads(x) for x in (tmp_path / DECISIONS_FILE).read_text().splitlines()]
    assert [(r["seq"], r["allowed"], r["rule"]) for r in records] == [
        (0, False, "create.privileged"),
        (1, False, "image.pull"),
    ]


async def test_proxy_resolves_ownership_before_forwarding(tmp_path: Path) -> None:
    async with running_guard(tmp_path) as (_guard, daemon, sock):
        resp = await call(sock, req("POST", "/v1.44/containers/mine/start"))
        assert resp.startswith(b"HTTP/1.1 200")
        assert daemon.requests[-1][1] == f"/v1.44/containers/{CID}/start"
        resp = await call(sock, req("POST", "/v1.44/containers/theirs/stop"))
        assert resp.startswith(b"HTTP/1.1 403")
        resp = await call(sock, req("GET", "/v1.44/containers/ghost/json"))
        assert resp.startswith(b"HTTP/1.1 403")
        forwarded = [(m, t) for m, t, _, _ in daemon.requests if not t.endswith("/json")]
        assert forwarded == [("POST", f"/v1.44/containers/{CID}/start")]
    records = [json.loads(x) for x in (tmp_path / DECISIONS_FILE).read_text().splitlines()]
    assert [(r["op"], r["allowed"], r["target"]) for r in records] == [
        ("container.start", True, CID),
        ("container.stop", False, OTHER_CID),
        ("container.inspect", False, None),
    ]


async def test_proxy_passes_upgrades_through(tmp_path: Path) -> None:
    async with running_guard(tmp_path) as (_guard, daemon, sock):
        reader, writer = await asyncio.open_unix_connection(str(sock))
        body = b'{"Detach":false,"Tty":false}'
        writer.write(
            req("POST", "/v1.44/exec/e1/start", body, "Connection: Upgrade\r\nUpgrade: tcp\r\n")
        )
        await writer.drain()
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
        assert head.startswith(b"HTTP/1.1 101")
        writer.write(b"hello")
        await writer.drain()
        assert await asyncio.wait_for(reader.readexactly(10), timeout=5) == b"echo:hello"
        writer.write_eof()
        assert await asyncio.wait_for(reader.read(), timeout=5) == b""
        writer.close()
        headers = daemon.requests[-1][2]
        assert headers["connection"].lower() == "upgrade"
        assert headers["upgrade"] == "tcp"


async def test_proxy_rejects_malformed_http(tmp_path: Path) -> None:
    async with running_guard(tmp_path) as (_guard, daemon, sock):
        resp = await call(
            sock,
            b"POST /v1.44/containers/create HTTP/1.1\r\nContent-Length: 2\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n{}",
        )
        assert resp.startswith(b"HTTP/1.1 400")
        resp = await call(sock, b"garbage\r\n\r\n")
        assert resp.startswith(b"HTTP/1.1 400")
        assert daemon.requests == []


async def test_proxy_forwards_nothing_if_the_decision_cannot_be_recorded(tmp_path: Path) -> None:
    async with running_guard(tmp_path) as (_guard, daemon, sock):
        log_path = tmp_path / DECISIONS_FILE
        log_path.unlink(missing_ok=True)
        log_path.mkdir()  # appending to a directory fails
        resp = await call(sock, req("GET", "/v1.44/version"))
        assert resp.startswith(b"HTTP/1.1 500")
        assert daemon.requests == []


async def test_proxy_reports_an_unreachable_daemon(tmp_path: Path) -> None:
    with short_tmp() as d:
        guard = CellGuard(CTX, str(d / "absent.sock"), DecisionLog(RUN, tmp_path / "d.jsonl"))
        server = await guard.serve(d / "guard.sock")
        try:
            resp = await call(d / "guard.sock", req("GET", "/v1.44/version"))
            assert resp.startswith(b"HTTP/1.1 502")
            # An ownership lookup that cannot reach the daemon resolves nothing: denied.
            resp = await call(d / "guard.sock", req("POST", "/v1.44/containers/mine/start"))
            assert resp.startswith(b"HTTP/1.1 403")
        finally:
            server.close()
            await server.wait_closed()


async def test_proxy_accepts_chunked_request_bodies(tmp_path: Path) -> None:
    async with running_guard(tmp_path) as (_guard, daemon, sock):
        body = json.dumps({"Image": IMG}).encode()
        chunked = f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n"
        raw = (
            b"POST /v1.44/containers/create HTTP/1.1\r\nHost: d\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n" + chunked
        )
        resp = await call(sock, raw)
        assert resp.startswith(b"HTTP/1.1 201")
        assert json.loads(daemon.requests[-1][3])["Labels"][RUN_LABEL] == RUN


# --------------------------------------------------------------------------- podman integration


PODMAN_SOCK = Path(f"/run/user/{os.getuid()}/podman/podman.sock")
ALPINE = "docker.io/library/alpine:3.20"


def _podman_client() -> Any:
    docker = pytest.importorskip("docker")
    if not PODMAN_SOCK.exists():
        pytest.skip(f"no Podman socket at {PODMAN_SOCK}")
    try:
        client = docker.DockerClient(base_url=f"unix://{PODMAN_SOCK}", timeout=30)
        client.ping()
        image = client.images.get(ALPINE)
    except Exception as exc:
        pytest.skip(f"Podman API or {ALPINE} unavailable: {exc}")
    return client, image


class ThreadedGuard:
    """Runs a :class:`CellGuard` on its own event loop thread (the Docker SDK is sync)."""

    def __init__(self, guard: CellGuard, listen: Path) -> None:
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.thread.start()
        self.server = asyncio.run_coroutine_threadsafe(guard.serve(listen), self.loop).result(10)

    def stop(self) -> None:
        async def shutdown() -> None:
            self.server.close()
            await self.server.wait_closed()

        asyncio.run_coroutine_threadsafe(shutdown(), self.loop).result(10)
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(10)
        self.loop.close()


def test_podman_integration(tmp_path: Path) -> None:
    import docker

    real, image = _podman_client()
    digests = [d.split("@", 1)[1] for d in image.attrs.get("RepoDigests") or [] if "@" in d]
    if not digests:
        pytest.skip(f"{ALPINE} has no repo digest")
    suffix = uuid.uuid4().hex[:8]
    network = real.networks.create(f"cg-test-{suffix}", internal=True)
    ctx = make_ctx(
        network=network.name,
        images=(AllowedImage(name=ALPINE, digest=digests[0]),),
        scratch_dir=None,
        memory_bytes=64 << 20,
        nano_cpus=500_000_000,
        pids_limit=64,
    )
    created: list[str] = []
    with short_tmp() as d:
        listen = d / "guard.sock"
        guard = CellGuard(ctx, str(PODMAN_SOCK), DecisionLog(RUN, tmp_path / DECISIONS_FILE))
        runner = ThreadedGuard(guard, listen)
        client = docker.DockerClient(base_url=f"unix://{listen}", version="1.44", timeout=30)
        try:
            assert client.ping()
            # Allowed create: forced network, label and limits are visible on the daemon.
            sbx = client.containers.run(
                ALPINE, ["sleep", "300"], detach=True, name=f"cg-sbx-{suffix}"
            )
            created.append(sbx.id)
            attrs = real.api.inspect_container(sbx.id)
            assert attrs["Config"]["Labels"][RUN_LABEL] == RUN
            assert network.name in attrs["NetworkSettings"]["Networks"]
            assert attrs["HostConfig"]["Memory"] == 64 << 20
            assert attrs["HostConfig"]["NanoCpus"] == 500_000_000
            assert attrs["HostConfig"]["PidsLimit"] == 64
            assert attrs["Image"] == image.id  # the tag was pinned to the listed digest

            # Streams through exec work (upgrade passthrough).
            code, out = sbx.exec_run(["echo", "through-the-guard"])
            assert code == 0
            assert out.strip() == b"through-the-guard"

            # Own container is listed; inspect via the guard works.
            assert [c.id for c in client.containers.list()] == [sbx.id]

            # Privileged create and pull are denied with 403.
            with pytest.raises(docker.errors.APIError) as denied:
                client.containers.create(ALPINE, ["true"], privileged=True)
            assert denied.value.status_code == 403
            with pytest.raises(docker.errors.APIError) as pulled:
                client.images.pull("docker.io/library/busybox", tag="latest")
            assert pulled.value.status_code == 403

            # A container of another run (created on the real socket) is invisible.
            other = real.containers.create(
                ALPINE, ["true"], labels={RUN_LABEL: OTHER_RUN}, network=network.name
            )
            created.append(other.id)
            with pytest.raises(docker.errors.APIError) as foreign_inspect:
                client.api.inspect_container(other.id)
            assert foreign_inspect.value.status_code == 403

            sbx.remove(force=True)
            created.remove(sbx.id)
        finally:
            client.close()
            for cid in created:
                with contextlib.suppress(Exception):
                    real.api.remove_container(cid, force=True)
            with contextlib.suppress(Exception):
                network.remove()
            runner.stop()
            real.close()

    records = [json.loads(x) for x in (tmp_path / DECISIONS_FILE).read_text().splitlines()]
    denied_rules = {r["rule"] for r in records if not r["allowed"]}
    assert {"create.privileged", "image.pull", "target.not_owned"} <= denied_rules
    assert {r["op"] for r in records if r["allowed"]} >= {
        "container.create",
        "container.start",
        "exec.create",
        "exec.start",
        "container.remove",
    }
    assert all(r["stream"] == CELLGUARD_STREAM for r in records)
