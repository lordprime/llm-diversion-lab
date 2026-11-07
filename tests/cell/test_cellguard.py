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
import socket
import tempfile
import threading
import time
import uuid
from collections.abc import AsyncIterator, Callable, Iterator
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, urlsplit

import pytest

from cell.cellguard.policy import (
    ORIGIN,
    ORIGIN_LABEL,
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
#: The cell resolver (the catcher's DNS) every agent container is forced to use.
CELL_DNS = "10.89.0.53"
RUN = new_id("run")
OTHER_RUN = new_id("run")
CID = "c" * 64
OTHER_CID = "d" * 64


def make_ctx(**overrides: Any) -> CellContext:
    values: dict[str, Any] = {
        "run_id": RUN,
        "network": NETWORK,
        "dns": CELL_DNS,
        "images": (
            AllowedImage("strix-sandbox-0.1", "ghcr.io/usestrix/strix-sandbox", DIGEST_A),
            AllowedImage("alpine-3", "docker.io/library/alpine", DIGEST_B),
        ),
        "scratch_volume": "lab-scratch",
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


#: Labels of what this cell's guard created; runner infrastructure has only the run label.
MINE = {RUN_LABEL: RUN, ORIGIN_LABEL: ORIGIN}
INFRA = {RUN_LABEL: RUN}


def own(kind: str = "container", ident: str = CID, name: str = "mine") -> Target:
    return Target(kind=kind, id=ident, name=name, labels=MINE)


def foreign(kind: str = "container", ident: str = OTHER_CID, name: str = "theirs") -> Target:
    labels = {RUN_LABEL: OTHER_RUN, ORIGIN_LABEL: ORIGIN}
    return Target(kind=kind, id=ident, name=name, labels=labels)


IMG = f"ghcr.io/usestrix/strix-sandbox@{DIGEST_A}"
ALP = f"docker.io/library/alpine@{DIGEST_B}"


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
    assert body["Labels"] == {"purpose": "sandbox", **MINE}
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


@pytest.mark.parametrize(
    "log_config",
    [
        # journald writes agent-controlled lines into the host journal.
        {"Type": "journald"},
        {"Type": "journald", "Config": {"tag": "sshd"}},
        # none (with AutoRemove) lets an agent erase its containers' output.
        {"Type": "none"},
        # json-file/k8s-file options could lift rotation; the daemon's driver applies.
        {"Type": "json-file", "Config": {"max-size": "100g"}},
        {"Type": "json-file"},
        {"Type": "local"},
        {"Type": "k8s-file", "Config": {"max-size": "0"}},
        {"Type": "", "Config": {"max-size": "1g"}},
        # unknown drivers
        {"Type": "gelf", "Config": {"gelf-address": "udp://x:1"}},
        {"Type": "syslog"},
        {"Type": "fluentd"},
        {"Config": {"anything": "x"}},
        # malformed
        {"Type": 0},
        {"Type": "", "Config": []},
        "journald",
        [],
    ],
)
def test_agent_log_config_is_denied(log_config: Any) -> None:
    decision = create({"Image": IMG, "HostConfig": {"LogConfig": log_config}})
    assert not decision.allowed, log_config
    assert decision.rule == "create.log", decision.reason


def test_log_config_shadow_key_is_denied() -> None:
    decision = create({"Image": IMG, "HostConfig": {"LogConfig": {"Type": "", "type": "none"}}})
    assert not decision.allowed
    assert decision.rule == "body.shadow_key"


def test_empty_log_config_is_accepted_and_not_forwarded() -> None:
    # The Docker CLI sends the zero struct; the daemon's default driver applies.
    for log_config in [None, {}, {"Type": ""}, {"Type": "", "Config": {}}, {"Config": None}]:
        body = allowed_create({"Image": IMG, "HostConfig": {"LogConfig": log_config}})
        assert "LogConfig" not in body["HostConfig"], log_config
    assert "LogConfig" not in allowed_create({"Image": IMG})["HostConfig"]


def test_top_level_volumes_are_denied() -> None:
    # Volumes creates anonymous volumes without the cell's labels (Mounts carries them).
    # Podman also parses a Volumes key like a -v flag: "/host:/x" would bind the host path.
    for key in ["/data", "/:/host", "/etc:/x:rw", "relative", "/a/../b"]:
        decision = create({"Image": IMG, "Volumes": {key: {}}})
        assert not decision.allowed, key
        assert decision.rule == "create.mount"
    # A target not bound by Binds is an anonymous volume even next to binds.
    decision = create(
        {
            "Image": IMG,
            "Volumes": {"/s": {}, "/anon": {}},
            "HostConfig": {"Binds": ["lab-scratch:/s"]},
        }
    )
    assert not decision.allowed
    assert decision.rule == "create.mount"
    # A Mounts target does not excuse a Volumes entry (only Binds is mirrored by the SDK).
    decision = create(
        {
            "Image": IMG,
            "Volumes": {"/m": {}},
            "HostConfig": {"Mounts": [{"Type": "volume", "Target": "/m"}]},
        }
    )
    assert not decision.allowed


def test_empty_or_bind_mirroring_volumes_are_accepted_and_not_forwarded() -> None:
    for volumes in [None, {}]:
        body = allowed_create({"Image": IMG, "Volumes": volumes})
        assert "Volumes" not in body
    # The Docker SDK mirrors every Binds target into Volumes; that entry creates
    # nothing (the bind covers the path) and is dropped.
    body = allowed_create(
        {
            "Image": IMG,
            "Volumes": {"/s": {}, "/w": {}},
            "HostConfig": {"Binds": ["lab-scratch:/s:rw", "lab-scratch:/w:ro"]},
        }
    )
    assert "Volumes" not in body
    assert body["HostConfig"]["Binds"] == ["lab-scratch:/s:rw", "lab-scratch:/w:ro"]


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


def test_unknown_fields_are_denied_whatever_their_value() -> None:
    for value in ["please", None, [], "", 0, False, {}]:
        decision = create({"Image": IMG, "Escape": value})
        assert not decision.allowed, value
        assert decision.rule == "create.field"
        nested = create({"Image": IMG, "HostConfig": {"Escape": value}})
        assert not nested.allowed, value
    # Zero values of known fields are tolerated (the Docker CLI sends full structs)
    # and are not forwarded.
    body = allowed_create(
        {"Image": IMG, "HostConfig": {"Devices": [], "PortBindings": {}, "Runtime": ""}}
    )
    assert not {"Devices", "PortBindings", "Runtime"} & set(body["HostConfig"])


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
                "CapAdd": ["NET_RAW", "CAP_NET_RAW"],
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges", "no-new-privileges:true"],
                "NetworkMode": "default",
                "IpcMode": "private",
                "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
                "LogConfig": {"Type": "", "Config": {}},
                "Binds": ["lab-scratch:/scratch", "lab-scratch:/work:ro"],
                "Mounts": [
                    {"Type": "tmpfs", "Target": "/tmp"},  # noqa: S108
                    {"Type": "volume", "Target": "/anon"},
                    {"Type": "volume", "Source": "lab-scratch", "Target": "/s"},
                ],
            },
        }
    )
    assert body["HostConfig"]["CapAdd"] == ["NET_RAW", "CAP_NET_RAW"]
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
    alias = f"{CTX.prefix}sandbox"
    body = allowed_create(
        {
            "Image": IMG,
            "NetworkingConfig": {
                "EndpointsConfig": {
                    NETWORK: {"Aliases": [alias], "NetworkID": "x", "EndpointID": "y"}
                }
            },
        }
    )
    assert body["NetworkingConfig"] == {"EndpointsConfig": {NETWORK: {"Aliases": [alias]}}}


@pytest.mark.parametrize(
    ("image", "forwarded"),
    [
        (IMG, IMG),
        (f"ghcr.io/usestrix/strix-sandbox:0.1@{DIGEST_A}", IMG),
        ("ghcr.io/usestrix/strix-sandbox:0.1", IMG),
        ("ghcr.io/usestrix/strix-sandbox:latest", IMG),  # any tag of a listed repository
        ("ghcr.io/usestrix/strix-sandbox", IMG),
        ("strix-sandbox-0.1", IMG),  # the logical name
        ("alpine", ALP),
        ("alpine-3", ALP),
        ("docker.io/library/alpine:3.20", ALP),
        (f"alpine@{DIGEST_B}", ALP),
        (f"index.docker.io/library/alpine:3@{DIGEST_B}", ALP),
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
        "strix-sandbox-0.1:latest",  # a logical name is matched exactly
        DIGEST_A,  # a bare id is not a reference to a listed image
        "a" * 12,
        "",
        "UPPER/case",
    ],
)
def test_other_image_references_are_denied(image: str) -> None:
    assert not create({"Image": image}).allowed


def test_create_version_prefix() -> None:
    for path in ["/containers/create", "/v1.44/containers/create", "/v1.40/containers/create"]:
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
    mine = Target(kind="exec", id=exec_id, name=None, labels=MINE)
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


OWN_FILTER = [f"{RUN_LABEL}={RUN}", f"{ORIGIN_LABEL}={ORIGIN}"]


def test_container_list_is_forced_to_own_label() -> None:
    decision = evaluate(DockerRequest("GET", "/v1.44/containers/json?all=1"), CTX)
    assert decision.allowed
    query = parse_qs(urlsplit(decision.path).query)
    assert query["all"] == ["1"]
    assert json.loads(query["filters"][0]) == {"label": OWN_FILTER}

    filters = quote(json.dumps({"label": {"purpose=x": True}, "name": ["sbx"]}))
    decision = evaluate(DockerRequest("GET", f"/containers/json?filters={filters}"), CTX)
    assert decision.allowed
    forced = json.loads(parse_qs(urlsplit(decision.path).query)["filters"][0])
    assert forced == {"label": ["purpose=x", *OWN_FILTER], "name": ["sbx"]}

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
    mine = Target(kind="volume", id="v1", name="v1", labels=MINE)
    assert evaluate(DockerRequest("GET", "/volumes/v1", target=mine), CTX).allowed
    theirs = Target(kind="volume", id="v2", name="v2", labels={RUN_LABEL: OTHER_RUN})
    assert not evaluate(DockerRequest("GET", "/volumes/v2", target=theirs), CTX).allowed

    made = evaluate(
        DockerRequest("POST", "/v1.44/volumes/create", json.dumps({"Name": "work"}).encode()), CTX
    )
    assert made.allowed
    assert json.loads(made.body)["Labels"] == MINE
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


# --------------------------------------------------------------------------- review 1: bodies


# Go's encoding/json matches keys case-insensitively (last wins), so a key whose fold
# collides with a known field would undo what the policy forced.
SHADOW_CREATES = [
    {"Image": IMG, "labels": None},
    {"Image": IMG, "Labels": {}, "LABELS": {}},
    {"Image": IMG, "hostconfig": None},
    {"Image": IMG, "image": "docker.io/library/ubuntu"},
    {"Image": IMG, "networkingconfig": {"EndpointsConfig": {"other": {}}}},
    {"Image": IMG, "HostConfig": {"Memory": 1, "memory": 0}},
    {"Image": IMG, "HostConfig": {"MemorySwap": 1, "memoryswap": 0}},
    {"Image": IMG, "HostConfig": {"PidsLimit": 1, "pidslimit": 0}},
    {"Image": IMG, "HostConfig": {"NanoCpus": 1, "NANOCPUS": 0}},
    {"Image": IMG, "HostConfig": {"networkmode": ""}},
    {"Image": IMG, "HostConfig": {"privileged": True}},
    {"Image": IMG, "HostConfig": {"Privileged": False, "PRIVILEGED": False}},
    {"Image": IMG, "HostConfig": {"capadd": ["SYS_ADMIN"]}},
    {"Image": IMG, "HostConfig": {"binds": ["/:/host"]}},
    {"Image": IMG, "HostConfig": {"pidmode": "host"}},
    # Unicode simple folds: long s (U+017F) folds to s, Kelvin sign (U+212A) to k.
    {"Image": IMG, "Label\u017f": None},
    {"Image": IMG, "HostConfig": {"\u017fecurityOpt": ["seccomp=unconfined"]}},
    {"Image": IMG, "HostConfig": {"Ma\u017fkedPaths": []}},
    {"Image": IMG, "HostConfig": {"\u212aernelMemory": 1}},
    {"Image": IMG, "HostConfig": {"Pid\u017fLimit": 0}},
]


@pytest.mark.parametrize("body", SHADOW_CREATES)
def test_case_folded_shadow_keys_are_denied(body: dict[str, Any]) -> None:
    decision = create(body)
    assert not decision.allowed
    assert decision.rule == "body.shadow_key", decision.reason


@pytest.mark.parametrize(
    "key", ["driverconfig", "DRIVERCONFIG", "Driverconfig", "driverConfig", "DRIVERconfig"]
)
def test_volume_driver_config_is_denied_in_any_casing(key: str) -> None:
    driver = {"Name": "local", "Options": {"type": "none", "o": "bind", "device": "/"}}
    mount: dict[str, Any] = {"Type": "volume", "Target": "/h", "VolumeOptions": {key: driver}}
    decision = create({"Image": IMG, "HostConfig": {"Mounts": [mount]}})
    assert not decision.allowed
    assert decision.rule == "body.shadow_key"
    mount["VolumeOptions"] = {"DriverConfig": driver}
    exact = create({"Image": IMG, "HostConfig": {"Mounts": [mount]}})
    assert not exact.allowed
    assert exact.rule == "create.mount"
    # A near-miss that is no fold of a known field is still an unknown key: denied.
    mount["VolumeOptions"] = {"Driver\u212aonfig": driver}
    assert not create({"Image": IMG, "HostConfig": {"Mounts": [mount]}}).allowed


SCRATCH = "/srv/lab/scratch/cell1"


@pytest.mark.parametrize(
    "mount",
    [
        {
            "Type": "bind",
            "Source": SCRATCH,
            "Target": "/s",
            "BindOptions": {"Propagation": "rshared"},
        },
        {
            "Type": "bind",
            "Source": SCRATCH,
            "Target": "/s",
            "BindOptions": {"propagation": "rshared"},
        },
        {"Type": "bind", "Source": SCRATCH, "Target": "/s", "BindOptions": {"Escape": True}},
        {"Type": "volume", "Target": "/v", "VolumeOptions": {"Subpath": "../../x"}},
        {"Type": "volume", "Target": "/v", "VolumeOptions": {"Escape": None}},
        {"Type": "tmpfs", "Target": "/t", "TmpfsOptions": {"Options": [["exec"]]}},
        {"Type": "tmpfs", "Target": "/t", "TmpfsOptions": {"options": [["exec"]]}},
        {"Type": "tmpfs", "Target": "/t", "Source": "/etc"},
        {"Type": "tmpfs", "Target": "/t", "BindOptions": {"Propagation": "private"}},
        {"Type": "volume", "Target": "/v", "type": "bind", "Source": "/"},
        {"Type": "image", "Source": "alpine", "Target": "/i"},
        {"Type": "bind", "Source": SCRATCH, "Target": "relative"},
    ],
)
def test_nested_mount_options_are_checked(mount: dict[str, Any]) -> None:
    assert not create({"Image": IMG, "HostConfig": {"Mounts": [mount]}}).allowed


def test_forwarded_create_body_is_rebuilt_not_passed_through() -> None:
    decision = create(
        {
            "Image": "alpine",
            "Cmd": "sleep 1",
            "Env": ["A=1"],
            "Healthcheck": {"Test": ["CMD", "true"], "Interval": 1000000000},
            "ExposedPorts": {"80/tcp": {}},
            "Volumes": {},
            "HostConfig": {
                "Devices": [],
                "Runtime": "",
                "CpuQuota": 5,
                "Ulimits": [{"Name": "nofile", "Soft": 1024, "Hard": 4096}],
                "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
            },
        }
    )
    assert decision.allowed, decision.reason
    body = json.loads(decision.body)
    assert set(body) == {
        "Image",
        "Cmd",
        "Env",
        "Healthcheck",
        "ExposedPorts",
        "HostConfig",
        "Labels",
        "NetworkingConfig",
    }
    assert set(body["HostConfig"]) == {
        "Ulimits",
        "RestartPolicy",
        "NetworkMode",
        "Memory",
        "MemorySwap",
        "NanoCpus",
        "PidsLimit",
        "Dns",
    }
    assert body["Image"] == ALP
    assert not create({"Image": IMG, "Healthcheck": {"Test": ["x"], "Escape": 1}}).allowed


def test_type_confusion_is_denied() -> None:
    for host in [
        {"Memory": "0"},
        {"Memory": 1.5},
        {"Memory": True},
        {"Memory": 1 << 64},
        {"CapAdd": "SYS_ADMIN"},
        {"Privileged": "false"},
        {"Binds": "/:/host"},
        {"Mounts": {"Type": "bind"}},
    ]:
        decision = create({"Image": IMG, "HostConfig": host})
        assert not decision.allowed, host
    raw = b'{"Image": "alpine", "HostConfig": {"Memory": NaN}}'
    assert not evaluate(DockerRequest("POST", "/containers/create", raw), CTX).allowed


@pytest.mark.parametrize(
    ("ulimits", "allowed"),
    [
        ([{"Name": "nofile", "Soft": 1024, "Hard": 65536}], True),
        ([{"Name": "nproc", "Soft": 4096, "Hard": 4096}], True),
        ([{"Name": "nofile", "Soft": 1024, "Hard": 65537}], False),
        ([{"Name": "nproc", "Soft": 10, "Hard": 4097}], False),
        ([{"Name": "nofile", "Soft": 2048, "Hard": 1024}], False),
        ([{"Name": "nofile", "Soft": -1, "Hard": 1024}], False),
        ([{"Name": "rtprio", "Soft": 99, "Hard": 99}], False),
        ([{"Name": "memlock", "Soft": -1, "Hard": -1}], False),
        ([{"Name": "core", "Soft": 0, "Hard": 0}], False),
        ([{"Name": "nofile", "Soft": 1, "Hard": 1, "name": "rtprio"}], False),
        ([{"Name": "nofile", "Soft": 1}], False),
    ],
)
def test_ulimits(ulimits: list[dict[str, Any]], allowed: bool) -> None:
    decision = create({"Image": IMG, "HostConfig": {"Ulimits": ulimits}})
    assert decision.allowed is allowed, decision.reason


@pytest.mark.parametrize(
    ("policy", "allowed"),
    [
        ({"Name": "no"}, True),
        ({"Name": ""}, True),
        ({"Name": "no", "MaximumRetryCount": 0}, True),
        ({"Name": "always"}, False),
        ({"Name": "unless-stopped"}, False),
        ({"Name": "on-failure", "MaximumRetryCount": 3}, False),
        ({"Name": "no", "MaximumRetryCount": 3}, False),
        ({"Name": "no", "name": "always"}, False),
    ],
)
def test_restart_policy(policy: dict[str, Any], allowed: bool) -> None:
    decision = create({"Image": IMG, "HostConfig": {"RestartPolicy": policy}})
    assert decision.allowed is allowed, decision.reason


def test_exec_bodies_are_rebuilt() -> None:
    path = f"/v1.44/containers/{CID}/exec"
    for body in [
        {"Cmd": ["sh"], "privileged": True},
        {"Cmd": ["sh"], "Privileged": False, "PRIVILEGED": True},
        {"Cmd": ["sh"], "Escape": None},
    ]:
        decision = evaluate(DockerRequest("POST", path, json.dumps(body).encode(), own()), CTX)
        assert not decision.allowed, body
    ok = evaluate(DockerRequest("POST", path, b'{"Cmd": ["id"], "Container": "mine"}', own()), CTX)
    assert ok.allowed
    assert json.loads(ok.body) == {"Cmd": ["id"]}
    exec_id = "e" * 64
    mine = Target(kind="exec", id=exec_id, name=None, labels=MINE)
    start = f"/v1.44/exec/{exec_id}/start"
    assert not evaluate(DockerRequest("POST", start, b'{"detach": true}', mine), CTX).allowed
    assert not evaluate(DockerRequest("POST", start, b'{"Escape": 1}', mine), CTX).allowed
    started = evaluate(DockerRequest("POST", start, b'{"Detach": false, "Tty": true}', mine), CTX)
    assert started.allowed
    assert json.loads(started.body) == {"Detach": False, "Tty": True}


def test_volume_create_bodies_are_rebuilt() -> None:
    for body in [
        {"Name": "w", "labels": None},
        {"Name": "w", "driveropts": {"device": "/"}},
        {"Name": "w", "DRIVER": "nfs"},
        {"Name": "w", "Escape": None},
    ]:
        decision = evaluate(
            DockerRequest("POST", "/volumes/create", json.dumps(body).encode()), CTX
        )
        assert not decision.allowed, body


def test_body_on_a_body_less_operation_is_denied() -> None:
    body = b'{"Privileged": true, "Binds": ["/:/host"]}'
    path = f"/v1.44/containers/{CID}/start"
    decision = evaluate(DockerRequest("POST", path, body, own()), CTX)
    assert not decision.allowed
    assert decision.rule == "body.unexpected"
    assert not evaluate(DockerRequest("GET", "/_ping", b"x"), CTX).allowed
    started = evaluate(DockerRequest("POST", path, b"", own()), CTX)
    assert started.allowed and started.body == b""


@pytest.mark.parametrize("version", ["1.20", "1.24", "1.39", "0.99"])
def test_old_api_versions_are_denied(version: str) -> None:
    decision = evaluate(DockerRequest("POST", f"/v{version}/containers/{CID}/start"), CTX)
    assert not decision.allowed
    assert decision.rule == "api.version"
    assert not evaluate(DockerRequest("GET", f"/v{version}/_ping"), CTX).allowed


def test_agent_chosen_names_get_the_cell_prefix() -> None:
    prefix = CTX.prefix
    assert prefix == f"{RUN.lower()}-"
    decision = create({"Image": IMG}, "/v1.44/containers/create?name=sbx")
    assert decision.allowed
    assert parse_qs(urlsplit(decision.path).query)["name"] == [f"{prefix}sbx"]
    already = create({"Image": IMG}, f"/containers/create?name={prefix}sbx")
    assert parse_qs(urlsplit(already.path).query)["name"] == [f"{prefix}sbx"]
    unnamed = create({"Image": IMG}, "/containers/create")
    assert unnamed.allowed and unnamed.path == "/containers/create"
    assert not create({"Image": IMG}, "/containers/create?name=..x").allowed
    assert not create({"Image": IMG}, "/containers/create?name=a&name=b").allowed
    assert not create({"Image": IMG}, "/containers/create?unknown=1").allowed

    squat_body = json.dumps({"Name": "lab-scratch"}).encode()
    squat = evaluate(DockerRequest("POST", "/volumes/create", squat_body), CTX)
    assert squat.allowed
    assert json.loads(squat.body)["Name"] == f"{prefix}lab-scratch"
    anonymous = evaluate(DockerRequest("POST", "/volumes/create", b"{}"), CTX)
    assert anonymous.allowed and "Name" not in json.loads(anonymous.body)
    custom = make_ctx(name_prefix="cell7-")
    named = evaluate(DockerRequest("POST", "/volumes/create", b'{"Name": "w"}'), custom)
    assert json.loads(named.body)["Name"] == "cell7-w"


# --------------------------------------------------------------------------- review 1: lock


LOCK_FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "cellguard" / "images.lock"
PY_DIGEST = "sha256:f72a86806f92fe13a49f49aeca1db0b19ea5cf4a0470b842a01b0e14314945b8"


def test_real_images_lock_schema() -> None:
    images = load_images_lock(LOCK_FIXTURE)
    assert images == (
        AllowedImage(
            "python-3.10-bookworm", "docker.io/library/python", PY_DIGEST, ("curl", "bash")
        ),
    )
    ctx = make_ctx(images=images)
    pinned = f"docker.io/library/python@{PY_DIGEST}"
    for image in [
        "python-3.10-bookworm",
        f"docker.io/library/python@{PY_DIGEST}",
        "python:3.10-bookworm",
        "docker.io/library/python",
        f"python:3.10@{PY_DIGEST}",
    ]:
        body = json.dumps({"Image": image}).encode()
        decision = evaluate(DockerRequest("POST", "/containers/create", body), ctx)
        assert decision.allowed, image
        assert json.loads(decision.body)["Image"] == pinned
    for image in [f"ghcr.io/x/python@{PY_DIGEST}", "python-3.10-bookworm:latest", "ubuntu"]:
        body = json.dumps({"Image": image}).encode()
        assert not evaluate(DockerRequest("POST", "/containers/create", body), ctx).allowed


def test_repository_with_several_digests_matches_by_name_or_digest_only() -> None:
    images = (
        AllowedImage("py-a", "docker.io/library/python", DIGEST_A),
        AllowedImage("py-b", "docker.io/library/python", DIGEST_B),
    )
    ctx = make_ctx(images=images)

    def image_of(image: str) -> str | None:
        body = json.dumps({"Image": image}).encode()
        decision = evaluate(DockerRequest("POST", "/containers/create", body), ctx)
        return json.loads(decision.body)["Image"] if decision.allowed else None

    assert image_of("python:3.12") is None
    assert image_of("py-b") == f"docker.io/library/python@{DIGEST_B}"
    assert image_of(f"python@{DIGEST_A}") == f"docker.io/library/python@{DIGEST_A}"


# --------------------------------------------------------------------------- review 2: mounts


@pytest.mark.parametrize(
    "host_config",
    [
        # X1: a symlink planted in a bind-mounted scratch dir made <scratch>/root = host /.
        {"Binds": ["/srv/lab/scratch/cell1:/s"]},
        {"Binds": ["/srv/lab/scratch/cell1/root:/host"]},
        {"Binds": ["/var/lib/docker/volumes/lab-scratch/_data/root:/host"]},
        {"Binds": ["lab-scratch/root:/host"]},
        {"Binds": ["lab-scratch:/s:rshared"]},
        {"Binds": ["other-volume:/s"]},
        {"Mounts": [{"Type": "bind", "Source": "/srv/lab/scratch/cell1", "Target": "/s"}]},
        {
            "Mounts": [
                {
                    "Type": "volume",
                    "Source": "lab-scratch",
                    "Target": "/s",
                    "VolumeOptions": {"Subpath": "root"},
                }
            ]
        },
        {
            "Mounts": [
                {
                    "Type": "volume",
                    "Source": "lab-scratch",
                    "Target": "/s",
                    "BindOptions": {"Propagation": "private"},
                }
            ]
        },
        {"Mounts": [{"Type": "volume", "Source": "lab-scratch/root", "Target": "/s"}]},
        {"Mounts": [{"Type": "volume", "Source": "/srv/lab/scratch", "Target": "/s"}]},
    ],
)
def test_host_paths_and_subpaths_are_never_mounted(host_config: dict[str, Any]) -> None:
    decision = create({"Image": IMG, "HostConfig": host_config})
    assert not decision.allowed, host_config
    assert decision.rule in ("create.mount", "body.shadow_key"), decision.reason


def test_scratch_named_volume_and_anonymous_volumes_are_mounted_with_forced_labels() -> None:
    body = allowed_create(
        {
            "Image": IMG,
            "HostConfig": {
                "Binds": ["lab-scratch:/s", "lab-scratch:/r:ro", "lab-scratch:/n:nocopy"],
                "Mounts": [
                    {"Type": "volume", "Source": "lab-scratch", "Target": "/m"},
                    {
                        "Type": "volume",
                        "Target": "/anon",
                        "VolumeOptions": {"NoCopy": True, "Labels": {"purpose": "cache"}},
                    },
                    {"Type": "tmpfs", "Target": "/t", "TmpfsOptions": {"SizeBytes": 1 << 20}},
                ],
            },
        }
    )
    mounts = body["HostConfig"]["Mounts"]
    assert mounts[0]["VolumeOptions"]["Labels"] == MINE
    assert mounts[1]["VolumeOptions"] == {"NoCopy": True, "Labels": {"purpose": "cache", **MINE}}
    assert "VolumeOptions" not in mounts[2]
    no_scratch = make_ctx(scratch_volume=None)
    decision = evaluate(
        DockerRequest(
            "POST",
            "/containers/create",
            json.dumps({"Image": IMG, "HostConfig": {"Binds": ["lab-scratch:/s"]}}).encode(),
        ),
        no_scratch,
    )
    assert not decision.allowed


@pytest.mark.parametrize(
    "labels",
    [
        {"lab.run_id": RUN},  # anonymous-volume labels follow the same rules
        {"lab.origin": "runner"},
        {"com.docker.compose.project": "x"},
    ],
)
def test_volume_option_labels_follow_label_rules(labels: dict[str, str]) -> None:
    mount = {"Type": "volume", "Target": "/a", "VolumeOptions": {"Labels": labels}}
    if labels == {"lab.run_id": RUN}:
        assert create({"Image": IMG, "HostConfig": {"Mounts": [mount]}}).allowed
    else:
        assert not create({"Image": IMG, "HostConfig": {"Mounts": [mount]}}).allowed


# --------------------------------------------------------------------------- review 2: origin


@pytest.mark.parametrize(
    "labels",
    [
        {ORIGIN_LABEL: "runner"},
        {ORIGIN_LABEL: ORIGIN, RUN_LABEL: OTHER_RUN},
        {"com.docker.compose.project": "lab"},
        {"COM.DOCKER.compose.service": "agent"},
        {"Lab.Origin": ORIGIN},
    ],
)
def test_reserved_labels_cannot_be_set_by_the_agent(labels: dict[str, str]) -> None:
    decision = create({"Image": IMG, "Labels": labels})
    assert not decision.allowed
    assert decision.rule == "create.labels"
    volume = evaluate(
        DockerRequest("POST", "/volumes/create", json.dumps({"Labels": labels}).encode()), CTX
    )
    assert not volume.allowed


def test_created_objects_carry_the_origin_label() -> None:
    assert allowed_create({"Image": IMG})["Labels"] == MINE
    # Setting the forced values explicitly is harmless.
    assert allowed_create({"Image": IMG, "Labels": dict(MINE)})["Labels"] == MINE


@pytest.mark.parametrize(("method", "template", "op"), LIFECYCLE)
def test_runner_infrastructure_is_untouchable(method: str, template: str, op: str) -> None:
    # The runner labels the agent, target, oracle and cell-guard containers with the
    # run id but never with lab.origin=cellguard.
    infra = Target(kind="container", id=OTHER_CID, name="guard", labels=INFRA)
    decision = evaluate(DockerRequest(method, template.format(ref="guard"), target=infra), CTX)
    assert not decision.allowed
    assert decision.rule == "target.not_owned"


def test_runner_infrastructure_is_untouchable_through_exec_and_volumes() -> None:
    infra = Target(kind="container", id=OTHER_CID, name="guard", labels=INFRA)
    body = b'{"Cmd": ["cat", "/var/run/docker.sock"]}'
    path = "/v1.44/containers/guard/exec"
    assert not evaluate(DockerRequest("POST", path, body, infra), CTX).allowed
    exec_id = "e" * 64
    infra_exec = Target(kind="exec", id=exec_id, name=None, labels=INFRA)
    for method, sub in [("POST", "start"), ("POST", "resize?h=1&w=1"), ("GET", "json")]:
        body = b"{}" if sub == "start" else b""
        request = DockerRequest(method, f"/v1.44/exec/{exec_id}/{sub}", body, infra_exec)
        assert not evaluate(request, CTX).allowed, sub
    infra_volume = Target(kind="volume", id="runner-vol", name="runner-vol", labels=INFRA)
    assert not evaluate(
        DockerRequest("GET", "/volumes/runner-vol", target=infra_volume), CTX
    ).allowed
    # The scratch volume stays inspectable: it is the one volume the cell may mount.
    scratch = Target(kind="volume", id="lab-scratch", name="lab-scratch", labels=INFRA)
    assert evaluate(DockerRequest("GET", "/volumes/lab-scratch", target=scratch), CTX).allowed


def test_lists_require_both_labels() -> None:
    for path in ["/v1.44/containers/json", "/v1.44/volumes"]:
        decision = evaluate(DockerRequest("GET", path), CTX)
        filters = json.loads(parse_qs(urlsplit(decision.path).query)["filters"][0])
        assert filters["label"] == OWN_FILTER, path


# --------------------------------------------------------------------------- review 2: names


def test_only_canonical_run_ids_and_bad_prefixes_are_rejected() -> None:
    # Prefix boundaries: only canonical ids (run_ + 26 uppercase Crockford chars) are
    # accepted, so no run's prefix is a prefix of another's.
    canonical = "run_01HZY5V8QJ7K2M3N4P5R6S7T8V"
    assert make_ctx(run_id=canonical).prefix == canonical.lower() + "-"
    for bad in [
        "r",
        "r-x",
        canonical.lower(),
        canonical + "X",
        canonical[:-1],
        "run_01HZY5V8QJ7K2M3N4P5R6S7T8I",  # I is not Crockford
        "exp_01HZY5V8QJ7K2M3N4P5R6S7T8V",
    ]:
        with pytest.raises(ValueError):
            make_ctx(run_id=bad)
    for prefix in ["abc", "a-b-", "-", "c7_", "UPPER-x"]:
        with pytest.raises(ValueError):
            make_ctx(name_prefix=prefix)
    assert make_ctx(name_prefix="cell7-").prefix == "cell7-"


# --------------------------------------------------------------------------- review 2: minors


def test_gw_priority_is_accepted_and_dropped() -> None:
    body = allowed_create(
        {"Image": IMG, "NetworkingConfig": {"EndpointsConfig": {NETWORK: {"GwPriority": 5}}}}
    )
    assert body["NetworkingConfig"] == {"EndpointsConfig": {NETWORK: {}}}


def test_volume_create_query_params_are_denied() -> None:
    decision = evaluate(DockerRequest("POST", "/volumes/create?name=x", b"{}"), CTX)
    assert not decision.allowed
    assert decision.rule == "volume.query"


# --------------------------------------------------------------------------- review 3: names


def endpoint(**config: Any) -> dict[str, Any]:
    return {"NetworkingConfig": {"EndpointsConfig": {NETWORK: config}}}


@pytest.mark.parametrize(
    "fields",
    [
        # N1: names an agent container could publish in the cell network's DNS.
        endpoint(Aliases=["target"]),
        endpoint(Aliases=["tap", f"{RUN.lower()}-ok"]),
        endpoint(Aliases=["catcher"]),
        endpoint(Aliases=[f"x{RUN.lower()}-sbx"]),
        endpoint(Aliases=[f"{RUN.lower()}-../x"]),
        endpoint(DNSNames=["target"]),
        endpoint(Links=["target:target"]),
        {"Hostname": "catcher"},
        {"Hostname": "target"},
        {"Domainname": "lab"},
        {"HostConfig": {"Links": ["target:target"]}},
        # N2a: no cloning of an infrastructure container's MAC or IP.
        {"MacAddress": "02:42:ac:11:00:02"},
        endpoint(MacAddress="02:42:ac:11:00:02"),
        endpoint(IPAddress="10.89.0.2"),
        endpoint(GlobalIPv6Address="fd00::2"),
        endpoint(IPAMConfig={"IPv4Address": "10.89.0.2"}),
        endpoint(IPAMConfig={"LinkLocalIPs": ["169.254.0.2"]}),
        endpoint(DriverOpts={"com.docker.network.endpoint.sysctls": "x"}),
        # N5: the agent may not choose its resolver or shadow names via /etc/hosts.
        {"HostConfig": {"Dns": ["8.8.8.8"]}},
        {"HostConfig": {"DnsSearch": ["evil.example"]}},
        {"HostConfig": {"DnsOptions": ["ndots:9"]}},
        {"HostConfig": {"ExtraHosts": ["target:10.89.0.66"]}},
        # N2b: NET_ADMIN would let an agent take another container's IP.
        {"HostConfig": {"CapAdd": ["NET_ADMIN"]}},
        {"HostConfig": {"CapAdd": ["CAP_NET_ADMIN"]}},
        # N3: SELinux relabel flags are not accepted on binds.
        {"HostConfig": {"Binds": ["lab-scratch:/s:z"]}},
        {"HostConfig": {"Binds": ["lab-scratch:/s:Z"]}},
    ],
)
def test_names_addresses_and_resolvers_are_not_the_agents_to_choose(
    fields: dict[str, Any],
) -> None:
    decision = create({"Image": IMG, **fields})
    assert not decision.allowed, fields


def test_prefixed_names_are_allowed_and_dns_is_forced() -> None:
    prefix = CTX.prefix
    body = allowed_create(
        {
            "Image": IMG,
            "Hostname": f"{prefix}box",
            "Domainname": "",
            "MacAddress": "",
            **endpoint(Aliases=[f"{prefix}web", f"{prefix}api"], DNSNames=[], MacAddress=""),
            "HostConfig": {
                "Dns": [],
                "DnsSearch": [],
                "DnsOptions": [],
                "ExtraHosts": None,
                "CapAdd": ["NET_RAW"],
                "Binds": ["lab-scratch:/s:ro", "lab-scratch:/n:nocopy", "lab-scratch:/w:rw"],
            },
        }
    )
    assert body["Hostname"] == f"{prefix}box"
    assert body["NetworkingConfig"]["EndpointsConfig"][NETWORK] == {
        "Aliases": [f"{prefix}web", f"{prefix}api"]
    }
    assert body["HostConfig"]["Dns"] == [CELL_DNS]
    assert not {"DnsSearch", "DnsOptions", "ExtraHosts"} & set(body["HostConfig"])
    # Without a hostname the daemon uses the short id: fine.
    assert "Hostname" not in allowed_create({"Image": IMG, "Hostname": ""})
    assert allowed_create({"Image": IMG})["HostConfig"]["Dns"] == [CELL_DNS]
    assert "HostConfig.Dns" in create({"Image": IMG}).forced


def test_cell_dns_must_be_an_ip_address() -> None:
    for bad in ["", "catcher", "10.0.0", "10.0.0.1:53"]:
        with pytest.raises(ValueError):
            make_ctx(dns=bad)
    assert make_ctx(dns="fd00::53").dns == "fd00::53"


# --------------------------------------------------------------------------- images.lock


def test_load_images_lock_yaml_json_and_list(tmp_path: Path) -> None:
    entries = [
        {
            "name": "strix-sandbox-0.1",
            "image": "ghcr.io/usestrix/strix-sandbox",
            "digest": DIGEST_A,
            "expect_tools": ["nmap"],
        },
        {"name": "alpine-3", "image": "docker.io/library/alpine", "digest": DIGEST_B},
    ]
    yml = tmp_path / "images.lock"
    yml.write_text(
        "images:\n"
        "  - name: strix-sandbox-0.1\n"
        "    image: ghcr.io/usestrix/strix-sandbox\n"
        f"    digest: {DIGEST_A}\n"
        "    expect_tools: [nmap]\n"
        "  - name: alpine-3\n"
        "    image: docker.io/library/alpine\n"
        f"    digest: {DIGEST_B}\n"
    )
    js = tmp_path / "images.json"
    js.write_text(json.dumps({"images": entries}))
    expected = (
        AllowedImage("strix-sandbox-0.1", "ghcr.io/usestrix/strix-sandbox", DIGEST_A, ("nmap",)),
        AllowedImage("alpine-3", "docker.io/library/alpine", DIGEST_B, ()),
    )
    assert load_images_lock(yml) == expected
    assert load_images_lock(str(js)) == expected
    assert load_images_lock(entries) == expected


@pytest.mark.parametrize(
    "entries",
    [
        [{"name": "x", "image": "alpine", "digest": "sha256:short"}],
        [{"name": "", "image": "alpine", "digest": DIGEST_A}],
        [{"image": "alpine", "digest": DIGEST_A}],
        [{"name": "x", "digest": DIGEST_A}],  # no image repository
        [{"name": "x", "image": "UPPER", "digest": DIGEST_A}],
        [{"name": "x", "image": f"alpine@{DIGEST_B}", "digest": DIGEST_A}],
        [{"name": "x", "image": "alpine", "digest": DIGEST_A, "expect_tools": "nmap"}],
        [
            {"name": "x", "image": "alpine", "digest": DIGEST_A},
            {"name": "x", "image": "busybox", "digest": DIGEST_B},
        ],
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
    lock.write_text(f"images:\n  - name: alpine-3\n    image: alpine\n    digest: {DIGEST_B}\n")
    env = {
        "LAB_RUN_ID": RUN,
        "LAB_EVIDENCE_DIR": str(tmp_path / "ev"),
        "LAB_CELLGUARD_LISTEN": str(tmp_path / "guard.sock"),
        "LAB_CELLGUARD_UPSTREAM": "/var/run/docker.sock",
        "LAB_CELLGUARD_NETWORK": NETWORK,
        "LAB_CELLGUARD_DNS": CELL_DNS,
        "LAB_CELLGUARD_IMAGES_LOCK": str(lock),
        "LAB_CELLGUARD_SCRATCH_VOLUME": "lab-scratch",
        "LAB_CELLGUARD_MEMORY": "268435456",
        "LAB_CELLGUARD_NANO_CPUS": "500000000",
        "LAB_CELLGUARD_PIDS": "128",
        "LAB_CELLGUARD_MAX_CONNECTIONS": "8",
    }
    config = CellGuardConfig.from_env(env)
    assert config.context.run_id == RUN
    assert config.context.network == NETWORK
    assert config.context.images == (AllowedImage("alpine-3", "alpine", DIGEST_B),)
    assert config.max_connections == 8
    assert config.context.memory_bytes == 268435456
    assert config.context.pids_limit == 128
    assert config.context.prefix == f"{RUN.lower()}-"
    prefixed = CellGuardConfig.from_env({**env, "LAB_CELLGUARD_NAME_PREFIX": "c7-"})
    assert prefixed.context.prefix == "c7-"
    with pytest.raises(ValueError):  # host-path scratch binds are gone
        CellGuardConfig.from_env({**env, "LAB_CELLGUARD_SCRATCH_DIR": "/srv/scratch"})
    with pytest.raises(ValueError):
        CellGuardConfig.from_env({**env, "LAB_CELLGUARD_NAME_PREFIX": "a-b-"})
    assert config.listen == tmp_path / "guard.sock"
    assert config.context.dns == CELL_DNS
    with pytest.raises(ValueError):
        CellGuardConfig.from_env({**env, "LAB_CELLGUARD_DNS": "not-an-ip"})
    for missing in [
        "LAB_RUN_ID",
        "LAB_CELLGUARD_NETWORK",
        "LAB_CELLGUARD_IMAGES_LOCK",
        "LAB_CELLGUARD_DNS",
    ]:
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
        self.raw_heads: list[bytes] = []
        self.containers: dict[str, dict[str, Any]] = {
            "mine": {"Id": CID, "Name": "/mine", "Config": {"Labels": MINE}},
            CID: {"Id": CID, "Name": "/mine", "Config": {"Labels": MINE}},
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
            self.raw_heads.append(head)
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
        assert (method, target) == ("POST", f"/v1.44/containers/create?name={CTX.prefix}sbx")
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


def records_of(tmp_path: Path) -> list[dict[str, Any]]:
    lines = (tmp_path / DECISIONS_FILE).read_text().splitlines()
    return [json.loads(line) for line in lines]


async def test_proxy_rejects_non_ascii_content_length_with_a_record(tmp_path: Path) -> None:
    async with running_guard(tmp_path) as (_guard, daemon, sock):
        # "\xb2" is SUPERSCRIPT TWO in latin-1: str.isdigit() is True, int() fails.
        raw = b"POST /v1.44/volumes/create HTTP/1.1\r\nContent-Length: \xb2\r\n\r\n{}"
        resp = await call(sock, raw)
        assert resp.startswith(b"HTTP/1.1 400")
        assert daemon.requests == []
    assert [(r["allowed"], r["rule"]) for r in records_of(tmp_path)] == [(False, "http.400")]


async def test_proxy_fails_closed_and_records_unexpected_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(request: DockerRequest, ctx: CellContext) -> Decision:
        raise RuntimeError("boom")

    monkeypatch.setattr("cell.cellguard.proxy.evaluate", broken)
    async with running_guard(tmp_path) as (_guard, daemon, sock):
        resp = await call(sock, req("GET", "/v1.44/version"))
        assert resp.startswith(b"HTTP/1.1 500")
        assert daemon.requests == []
    records = records_of(tmp_path)
    assert [(r["allowed"], r["rule"], r["op"]) for r in records] == [
        (False, "http.500", "system.version")
    ]


async def test_proxy_caps_concurrent_connections(tmp_path: Path) -> None:
    with short_tmp() as d:
        daemon = FakeDaemon(d / "up.sock")
        await daemon.start()
        guard = CellGuard(CTX, str(daemon.sock), DecisionLog(RUN, tmp_path / DECISIONS_FILE), 1)
        server = await guard.serve(d / "guard.sock")
        try:
            _r, held = await asyncio.open_unix_connection(str(d / "guard.sock"))
            held.write(b"GET /_ping HTTP/1.1\r\n")  # an unfinished head keeps the slot busy
            await held.drain()
            await asyncio.sleep(0.1)
            resp = await call(d / "guard.sock", req("GET", "/_ping"))
            assert resp.startswith(b"HTTP/1.1 503")
            held.close()
            await asyncio.sleep(0.1)
            resp = await call(d / "guard.sock", req("GET", "/_ping"))
            assert resp.startswith(b"HTTP/1.1 200")
        finally:
            server.close()
            await server.wait_closed()
            await daemon.close()
    rules = [r["rule"] for r in records_of(tmp_path)]
    assert rules == ["http.503", "http.400", "system.ping"]  # the held head is dropped: 400


async def test_proxy_resolves_agent_names_with_the_cell_prefix(tmp_path: Path) -> None:
    async with running_guard(tmp_path) as (_guard, daemon, sock):
        prefixed = {
            "Id": "f" * 64,
            "Name": f"/{CTX.prefix}sbx",
            "Config": {"Labels": MINE},
        }
        daemon.containers[f"{CTX.prefix}sbx"] = prefixed
        # An unprefixed container of that name exists too (not this cell's): the
        # prefixed one wins.
        daemon.containers["sbx"] = daemon.containers["theirs"]
        resp = await call(sock, req("POST", "/v1.44/containers/sbx/start"))
        assert resp.startswith(b"HTTP/1.1 200")
        assert daemon.requests[-1][1] == "/v1.44/containers/" + "f" * 64 + "/start"


async def test_proxy_forces_json_content_type_on_bodies(tmp_path: Path) -> None:
    async with running_guard(tmp_path) as (_guard, daemon, sock):
        body = json.dumps({"Image": IMG}).encode()
        extra = "Content-Type: text/plain\r\nX-Other: kept\r\n"
        resp = await call(sock, req("POST", "/v1.44/containers/create", body, extra))
        assert resp.startswith(b"HTTP/1.1 201")
        _m, _t, headers, _b = daemon.requests[-1]
        assert headers["content-type"] == "application/json"
        assert headers["x-other"] == "kept"
        raw_head = daemon.raw_heads[-1].lower()
        assert raw_head.count(b"content-type:") == 1


async def test_proxy_failure_records_carry_the_method(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(request: DockerRequest, ctx: CellContext) -> Decision:
        raise RuntimeError("boom")

    monkeypatch.setattr("cell.cellguard.proxy.evaluate", broken)
    async with running_guard(tmp_path) as (_guard, _daemon, sock):
        resp = await call(sock, req("DELETE", "/v1.44/containers/mine"))
        assert resp.startswith(b"HTTP/1.1 500")
    [record] = records_of(tmp_path)
    assert (record["method"], record["rule"], record["op"]) == (
        "DELETE",
        "http.500",
        "container.remove",
    )


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


def raw_request(sock: Path, method: str, path: str, doc: dict[str, Any]) -> tuple[int, bytes]:
    """One raw HTTP request on a Unix socket (bypasses the SDK's body building)."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(30)
        conn.connect(str(sock))
        conn.sendall(req(method, path, json.dumps(doc).encode()))
        data = b""
        while chunk := conn.recv(65536):
            data += chunk
    return int(data.split(b" ", 2)[1]), data


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
    # Stand-in for the catcher's DNS (TEST-NET-1, never answers). The network's embedded
    # resolver still answers names on the cell network and forwards the rest to it.
    cell_dns = "192.0.2.53"
    # The runner's scratch volume: labelled with the run only (runner infrastructure).
    scratch = real.volumes.create(f"cg-scratch-{suffix}", labels={RUN_LABEL: RUN})
    volumes: list[str] = [scratch.name]
    ctx = make_ctx(
        network=network.name,
        images=(AllowedImage("alpine-3.20", "docker.io/library/alpine", digests[0]),),
        scratch_volume=scratch.name,
        dns=cell_dns,
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
            # Container A mounts the scratch named volume and plants the reviewer's
            # symlink (X1 step A): <scratch>/root -> /.
            plant = "ln -s / /s/root && echo from-a > /s/marker && sleep 300"
            sbx = client.containers.run(
                ALPINE,
                ["sh", "-c", plant],
                detach=True,
                name=f"cg-sbx-{suffix}",
                volumes={scratch.name: {"bind": "/s", "mode": "rw"}},
            )
            created.append(sbx.id)
            attrs = real.api.inspect_container(sbx.id)
            assert attrs["Config"]["Labels"][RUN_LABEL] == RUN
            assert attrs["Config"]["Labels"][ORIGIN_LABEL] == ORIGIN
            assert network.name in attrs["NetworkSettings"]["Networks"]
            assert attrs["HostConfig"]["Memory"] == 64 << 20
            assert attrs["HostConfig"]["NanoCpus"] == 500_000_000
            assert attrs["HostConfig"]["PidsLimit"] == 64
            assert attrs["Image"] == image.id  # the tag was pinned to the listed digest
            # The agent's name got the cell prefix; the unprefixed name still resolves.
            assert attrs["Name"].lstrip("/") == f"{ctx.prefix}cg-sbx-{suffix}"
            assert client.containers.get(f"cg-sbx-{suffix}").id == sbx.id

            # C1: case-folded shadow keys that would drop the label and limits are denied
            # before the daemon sees them; no container appears.
            before = {c.id for c in real.containers.list(all=True)}
            shadow = {
                "Image": ALPINE,
                "Cmd": ["true"],
                "HostConfig": {
                    "Memory": 1,
                    "MemorySwap": 1,
                    "PidsLimit": 1,
                    "memory": 0,
                    "memoryswap": 0,
                    "pidslimit": 0,
                },
                "Labels": {},
                "labels": None,
            }
            status, reply = raw_request(listen, "POST", "/v1.44/containers/create", shadow)
            assert status == 403, reply
            assert b"body.shadow_key" in reply
            assert {c.id for c in real.containers.list(all=True)} == before

            # Volume create: forced label and prefixed name.
            volume = client.volumes.create(name=f"cg-vol-{suffix}")
            volumes.append(volume.name)
            assert volume.name == f"{ctx.prefix}cg-vol-{suffix}"
            assert real.volumes.get(volume.name).attrs["Labels"][RUN_LABEL] == RUN
            assert real.volumes.get(volume.name).attrs["Labels"][ORIGIN_LABEL] == ORIGIN

            for _ in range(50):
                if sbx.exec_run(["test", "-L", "/s/root"]).exit_code == 0:
                    break
                time.sleep(0.1)
            else:
                pytest.fail("container A did not plant the symlink")

            # X1 step B: binding the symlink's host path, or the volume with a subpath,
            # is denied before the daemon sees it.
            mountpoint = real.volumes.get(scratch.name).attrs["Mountpoint"]
            with pytest.raises(docker.errors.APIError) as step_b:
                client.containers.create(
                    ALPINE, ["ls", "/host/etc"], volumes={f"{mountpoint}/root": {"bind": "/host"}}
                )
            assert step_b.value.status_code == 403
            subpath = {
                "Image": ALPINE,
                "Cmd": ["ls", "/host/etc"],
                "HostConfig": {
                    "Mounts": [
                        {
                            "Type": "volume",
                            "Source": scratch.name,
                            "Target": "/host",
                            "VolumeOptions": {"Subpath": "root"},
                        }
                    ]
                },
            }
            status, reply = raw_request(listen, "POST", "/v1.44/containers/create", subpath)
            assert status == 403, reply

            # The scratch named volume itself works: a second container reads A's file.
            reader = client.containers.run(
                ALPINE,
                ["cat", "/s/marker"],
                detach=True,
                volumes={scratch.name: {"bind": "/s", "mode": "ro"}},
            )
            created.append(reader.id)
            assert reader.wait(timeout=30)["StatusCode"] == 0
            assert reader.logs().strip() == b"from-a"

            # N5: the resolver is forced to the cell's.
            assert real.api.inspect_container(sbx.id)["HostConfig"]["Dns"] == [cell_dns]

            # N1: cell service names cannot be claimed as an alias or a hostname...
            def create_raw(extra: dict[str, Any], query: str = "") -> tuple[int, bytes]:
                doc = {"Image": ALPINE, "Cmd": ["sleep", "300"], **extra}
                return raw_request(listen, "POST", f"/v1.44/containers/create{query}", doc)

            alias_target = {
                "NetworkingConfig": {"EndpointsConfig": {network.name: {"Aliases": ["target"]}}}
            }
            for hijack in (alias_target, {"Hostname": "catcher"}):
                status, reply = create_raw(hijack)
                assert status == 403, reply
            # ...while a prefixed alias is allowed and resolves through the cell resolver.
            alias = f"{ctx.prefix}web"
            prefixed = {
                "NetworkingConfig": {"EndpointsConfig": {network.name: {"Aliases": [alias]}}}
            }
            status, reply = create_raw(prefixed, "?name=web")
            assert status == 201, reply
            web = real.containers.get(f"{ctx.prefix}web")
            created.append(web.id)
            client.api.start(web.id)
            # getent, not busybox nslookup (which fails with EMSGSIZE on rootless Podman).
            resolved = sbx.exec_run(["getent", "hosts", alias])
            assert resolved.exit_code == 0, resolved.output
            web_ip = real.api.inspect_container(web.id)["NetworkSettings"]["Networks"][
                network.name
            ]["IPAddress"]
            assert resolved.output.split()[0].decode() == web_ip

            # I1: an agent-chosen log driver (journald writes into the host journal)
            # and M2: top-level Volumes (unlabelled anonymous volumes) are denied before
            # the daemon sees them; no container appears.
            before = {c.id for c in real.containers.list(all=True)}
            marker = f"MARK-{suffix}"
            journald = {
                "Cmd": ["echo", marker],
                "HostConfig": {"LogConfig": {"Type": "journald"}},
            }
            status, reply = create_raw(journald)
            assert status == 403, reply
            assert b"create.log" in reply
            status, reply = create_raw({"Volumes": {"/anon": {}}})
            assert status == 403, reply
            assert {c.id for c in real.containers.list(all=True)} == before

            # X2: runner infrastructure (run label only, e.g. the cell-guard container) is
            # invisible and untouchable.
            infra = real.containers.create(
                ALPINE, ["sleep", "300"], labels={RUN_LABEL: RUN}, network=network.name
            )
            created.append(infra.id)
            for attempt in (
                lambda: client.api.inspect_container(infra.id),
                lambda: client.api.exec_create(infra.id, ["true"]),
                lambda: client.api.remove_container(infra.id, force=True),
            ):
                with pytest.raises(docker.errors.APIError) as untouchable:
                    attempt()
                assert untouchable.value.status_code == 403
            assert infra.id not in {c.id for c in client.containers.list(all=True)}

            # Streams through exec work (upgrade passthrough).
            code, out = sbx.exec_run(["echo", "through-the-guard"])
            assert code == 0
            assert out.strip() == b"through-the-guard"

            # Own containers are listed; the runner's are not.
            assert {c.id for c in client.containers.list(all=True)} == {sbx.id, reader.id, web.id}

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
            # Also sweep anything labelled with this test's run: a create that succeeded
            # but whose start failed never reached ``created``.
            with contextlib.suppress(Exception):
                mine = real.containers.list(all=True, filters={"label": f"{RUN_LABEL}={RUN}"})
                created.extend(c.id for c in mine if c.id not in created)
                own_volumes = real.volumes.list(filters={"label": f"{RUN_LABEL}={RUN}"})
                volumes.extend(v.name for v in own_volumes if v.name not in volumes)
            for cid in created:
                with contextlib.suppress(Exception):
                    real.api.remove_container(cid, force=True)
            for name in volumes:
                with contextlib.suppress(Exception):
                    real.volumes.get(name).remove(force=True)
            with contextlib.suppress(Exception):
                network.remove()
            runner.stop()
            real.close()

    records = [json.loads(x) for x in (tmp_path / DECISIONS_FILE).read_text().splitlines()]
    denied_rules = {r["rule"] for r in records if not r["allowed"]}
    expected = {
        "create.privileged",
        "image.pull",
        "target.not_owned",
        "create.mount",
        "create.log",
    }
    assert expected <= denied_rules
    assert {r["op"] for r in records if r["allowed"]} >= {
        "container.create",
        "container.start",
        "exec.create",
        "exec.start",
        "container.remove",
    }
    assert all(r["stream"] == CELLGUARD_STREAM for r in records)
