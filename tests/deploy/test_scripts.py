"""Deploy scripts and the Ansible LXC profile (docs/DEPLOYMENT.md §0, §4).

Static and local checks only: nothing here reaches a lab host. Every script is run
with ``LAB_SSH_BIN=false`` so an accidental remote call fails at once instead of
dialling out.

External linters (shellcheck, shfmt, ansible-lint, ansible-playbook) are used from
``PATH`` if present, else from uv's tool cache with ``uvx --offline`` (no network in
tests), else the test is skipped with the reason.
"""

from __future__ import annotations

import ast
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Mapping
from functools import cache
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
DEPLOY = ROOT / "deploy"
ANSIBLE = DEPLOY / "ansible"
SITE = ANSIBLE / "site.yml"
HOSTS_EXAMPLE = DEPLOY / "hosts.example.yml"
ENV_EXAMPLE = ROOT / ".env.example"

REQUIRED_SCRIPTS = ("bootstrap.sh", "secrets.sh", "release.sh", "status.sh", "tunnel.sh", "lib.sh")
LXC_ROLES = ("base", "storage", "docker", "sysctl", "firewall", "access", "caddy")
SCRIPTS = sorted(DEPLOY.glob("*.sh"))

# A placeholder that looks like a key but is not one (low entropy on purpose).
PLACEHOLDER_KEY = "sk-ant-placeholder-value-not-a-key"
PLACEHOLDER_BUDGET = "123.45"


def _run(
    cmd: list[str], *, env: Mapping[str, str] | None = None, cwd: Path = ROOT, stdin: str = ""
) -> subprocess.CompletedProcess[str]:
    """Run a local command (never a shell string) with a hard timeout."""
    return subprocess.run(  # noqa: S603 -- fixed argv built by the tests
        cmd, cwd=cwd, env=env, input=stdin, capture_output=True, text=True, timeout=600
    )


def _script_env(**extra: str) -> dict[str, str]:
    """Environment for running deploy scripts locally: no SSH, test Python for YAML."""
    env = dict(os.environ)
    env.update(
        LAB_SSH_BIN="false",
        LAB_PYTHON=sys.executable,
        LAB_HOSTS_FILE=str(HOSTS_EXAMPLE),
        NO_COLOR="1",
    )
    env.update(extra)
    return env


# The same pins as CI (.github/workflows/ci.yml), for the local uvx fallback.
ANSIBLE_CORE = "ansible-core==2.22.0"
ANSIBLE_LINT = "ansible-lint==26.11.0"
SHELLCHECK_PY = "shellcheck-py==0.11.0.1"
SHFMT_PY = "shfmt-py==4.2.0"


@cache
def _tool(name: str, uvx_from: str) -> tuple[str, ...] | None:
    """The argv prefix for a linter, or None if it is not available offline."""
    found = shutil.which(name)
    if found:
        return (found,)
    uvx = shutil.which("uvx")
    if not uvx:
        return None
    cmd = (uvx, "--offline", "--quiet", "--from", uvx_from, name)
    try:
        probe = _run([*cmd, "--version"])
    except (OSError, subprocess.TimeoutExpired):
        return None
    return cmd if probe.returncode == 0 else None


REQUIRE_TOOLS = os.environ.get("LAB_REQUIRE_TOOLS") == "1"


def _missing(reason: str) -> None:
    """Skip locally; fail in CI (LAB_REQUIRE_TOOLS=1), where every tool is installed."""
    if REQUIRE_TOOLS:
        pytest.fail(f"{reason} (LAB_REQUIRE_TOOLS=1)")
    pytest.skip(reason)


def _require_tool(name: str, uvx_from: str) -> tuple[str, ...]:
    cmd = _tool(name, uvx_from)
    if cmd is None:
        _missing(f"{name} not installed and not in the uv tool cache (uvx --from {uvx_from})")
        raise AssertionError("unreachable")
    return cmd


@cache
def _netns_prefix() -> tuple[str, ...] | None:
    """argv prefix that runs a command in a throwaway network namespace, or None.

    Unprivileged (`unshare -rn`) where user namespaces are allowed; else `sudo -n
    unshare -n` (GitHub runners restrict unprivileged user namespaces).
    """
    for prefix in (("unshare", "-rn"), ("sudo", "-n", "unshare", "-n")):
        if shutil.which(prefix[0]) is None:
            continue
        try:
            # Probe with nft itself: a namespace where nft is denied is no use.
            if _run([*prefix, "nft", "list", "ruleset"]).returncode == 0:
                return prefix
        except (OSError, subprocess.TimeoutExpired):
            continue
    return None


def _require_netns() -> tuple[str, ...]:
    if shutil.which("nft") is None or shutil.which("iptables-restore") is None:
        _missing("nft and iptables-restore are needed to exercise the firewall")
    prefix = _netns_prefix()
    if prefix is None:
        _missing("cannot create a throwaway network namespace (unshare)")
        raise AssertionError("unreachable")
    return prefix


def _load_yaml(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- files


def test_required_files_exist() -> None:
    for name in REQUIRED_SCRIPTS:
        assert (DEPLOY / name).is_file(), f"deploy/{name} missing"
    assert SITE.is_file()
    assert HOSTS_EXAMPLE.is_file()
    assert ENV_EXAMPLE.is_file()
    for role in (*LXC_ROLES, "sysbox"):
        assert (ANSIBLE / "roles" / role / "tasks" / "main.yml").is_file(), role


def test_real_inventory_is_not_committed() -> None:
    tracked = _run(["git", "ls-files", "--error-unmatch", "deploy/hosts.yml"])
    assert tracked.returncode != 0, "deploy/hosts.yml is the real inventory: never commit it"
    ignored = _run(["git", "check-ignore", "-q", "deploy/hosts.yml"])
    assert ignored.returncode == 0, "deploy/hosts.yml must stay git-ignored"


# ------------------------------------------------------------------------- scripts


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_script_sets_strict_mode(script: Path) -> None:
    text = script.read_text(encoding="utf-8")
    assert text.startswith("#!/usr/bin/env bash\n"), "Bash shebang on line 1"
    assert re.search(r"^set -Eeuo pipefail$", text, re.MULTILINE), "set -Eeuo pipefail"
    assert os.access(script, os.X_OK), "executable bit"


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
@pytest.mark.parametrize("flag", ["--help", "-h"])
def test_script_has_help(script: Path, flag: str) -> None:
    # --help must work with no hosts.yml and no network: it is parsed before anything else.
    env = _script_env(LAB_HOSTS_FILE="/nonexistent/hosts.yml")
    result = _run(["bash", str(script), flag], env=env)
    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith("Usage:"), result.stdout
    assert result.stderr == ""


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_shellcheck_clean(script: Path) -> None:
    shellcheck = _require_tool("shellcheck", SHELLCHECK_PY)
    result = _run([*shellcheck, "--external-sources", "--severity=style", str(script)], cwd=DEPLOY)
    assert result.returncode == 0, result.stdout + result.stderr


def _helper_scripts() -> list[str]:
    """Scripts that run on the lab host: deploy/remote/*.sh and role files."""
    return sorted(str(p) for p in (*DEPLOY.glob("remote/*.sh"), *ANSIBLE.rglob("*.sh")))


def test_helper_scripts_shellcheck_clean() -> None:
    shellcheck = _require_tool("shellcheck", SHELLCHECK_PY)
    files = _helper_scripts()
    assert files, "helper scripts expected under deploy/remote and deploy/ansible"
    result = _run([*shellcheck, "--severity=style", *files])
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("script", sorted(DEPLOY.glob("remote/*.sh")), ids=lambda p: p.name)
def test_remote_script_sets_strict_mode(script: Path) -> None:
    text = script.read_text(encoding="utf-8")
    assert re.search(r"^set -Eeuo pipefail$", text, re.MULTILINE)


def test_shfmt_formatted() -> None:
    shfmt = _require_tool("shfmt", SHFMT_PY)
    result = _run([*shfmt, "-d", *(str(p) for p in SCRIPTS), *_helper_scripts()])
    assert result.returncode == 0, result.stdout + result.stderr


def test_unknown_host_is_refused() -> None:
    result = _run(["bash", str(DEPLOY / "status.sh"), "no-such-host"], env=_script_env())
    assert result.returncode != 0
    assert "no-such-host" in result.stderr
    assert "not in" in result.stderr


def test_unknown_host_key_is_refused(tmp_path: Path) -> None:
    hosts = tmp_path / "hosts.yml"
    hosts.write_text(
        "lab1:\n  address: 192.0.2.10\n  ssh_user: root\n  isolation: lxc\n"
        "  access: twingate\n  max_paralel_cells: 1\n",
        encoding="utf-8",
    )
    result = _run(
        ["bash", str(DEPLOY / "status.sh"), "lab1"], env=_script_env(LAB_HOSTS_FILE=str(hosts))
    )
    assert result.returncode != 0
    assert "max_paralel_cells" in result.stderr


def _git(repo: Path, *args: str) -> None:
    result = _run(
        [
            "git",
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "tag.gpgsign=false",
            *args,
        ],
        cwd=repo,
    )
    assert result.returncode == 0, result.stderr


@pytest.fixture
def scratch_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    (repo / "README").write_text("x\n", encoding="utf-8")
    _git(repo, "add", "README")
    _git(repo, "commit", "-q", "-m", "init")
    return repo


def test_release_refuses_missing_tag(scratch_repo: Path) -> None:
    env = _script_env(LAB_REPO_ROOT=str(scratch_repo))
    result = _run(["bash", str(DEPLOY / "release.sh"), "lab1", "--tag", "v9.9.9"], env=env)
    assert result.returncode != 0
    assert "tag v9.9.9 does not exist" in result.stderr


def test_release_refuses_dirty_tree(scratch_repo: Path) -> None:
    _git(scratch_repo, "tag", "v0.0.1")
    (scratch_repo / "README").write_text("changed\n", encoding="utf-8")
    env = _script_env(LAB_REPO_ROOT=str(scratch_repo))
    result = _run(["bash", str(DEPLOY / "release.sh"), "lab1", "--tag", "v0.0.1"], env=env)
    assert result.returncode != 0
    assert "working tree is dirty" in result.stderr


def test_release_requires_tag_argument() -> None:
    result = _run(["bash", str(DEPLOY / "release.sh"), "lab1"], env=_script_env())
    assert result.returncode == 2
    assert "--tag" in result.stderr


def test_release_rejects_malformed_tag(scratch_repo: Path) -> None:
    env = _script_env(LAB_REPO_ROOT=str(scratch_repo))
    result = _run(["bash", str(DEPLOY / "release.sh"), "lab1", "--tag", "v1;rm -rf /"], env=env)
    assert result.returncode == 2
    assert "not a release tag" in result.stderr


IMAGES_LOCK = """\
images:
  - name: python-3.10-bookworm
    image: docker.io/library/python
    digest: sha256:f72a86806f92fe13a49f49aeca1db0b19ea5cf4a0470b842a01b0e14314945b8
    expect_tools: [curl, bash]
"""


@pytest.fixture
def fake_ssh(tmp_path: Path) -> tuple[Path, Path]:
    """An `ssh` stand-in that logs its argv and runs the remote command locally with sh."""
    log = tmp_path / "ssh.log"
    fake = tmp_path / "fake-ssh"
    fake.write_text(
        '#!/usr/bin/env bash\nprintf \'%s\\n\' "$@" >"$FAKE_SSH_LOG"\nexec sh -c "${@: -1}"\n',
        encoding="utf-8",
    )
    fake.chmod(0o755)
    return fake, log


def test_lab_remote_ships_the_script_over_ssh(fake_ssh: tuple[Path, Path]) -> None:
    fake, log = fake_ssh
    env = _script_env(LAB_SSH_BIN=str(fake), FAKE_SSH_LOG=str(log), PATH="/usr/bin:/bin")
    result = _run(
        [
            "bash",
            "-c",
            'source "$1" && lab_load_host lab1 && lab_remote doctor.sh',
            "-",
            "deploy/lib.sh",
        ],
        env=env,
    )
    # doctor.sh ran (remotely, here locally) and found no labctl: exit 3.
    assert result.returncode == 3, result.stderr
    assert "labctl is not installed" in result.stderr
    argv = log.read_text(encoding="utf-8").splitlines()
    assert argv[:6] == ["-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "-p", "22"]
    assert argv[6] == "root@192.168.1.145"
    assert argv[7].startswith('bash -c "$(printf %s ')  # no sudo when ssh_user is root


def test_release_reaches_the_host_only_after_local_checks(
    scratch_repo: Path, fake_ssh: tuple[Path, Path]
) -> None:
    fake, log = fake_ssh
    compose = scratch_repo / "deploy" / "compose"
    compose.mkdir(parents=True)
    (compose / "control-plane.yml").write_text("services: {}\n", encoding="utf-8")
    (scratch_repo / "deploy" / "images.lock").write_text(IMAGES_LOCK, encoding="utf-8")
    _git(scratch_repo, "add", "deploy")
    _git(scratch_repo, "commit", "-q", "-m", "release files")
    _git(scratch_repo, "tag", "v0.1.0-m0")
    env = _script_env(LAB_REPO_ROOT=str(scratch_repo), LAB_SSH_BIN=str(fake), FAKE_SSH_LOG=str(log))
    result = _run(["bash", str(DEPLOY / "release.sh"), "lab1", "--tag", "v0.1.0-m0"], env=env)
    # The fake host has no /srv/lab, so the remote preflight refuses.
    assert result.returncode != 0
    assert "/srv/lab/releases is missing: run bootstrap.sh first" in result.stderr
    assert 'FAILED at step "Preflight on lab1"' in result.stderr


def test_release_refuses_an_unpinned_images_lock(scratch_repo: Path) -> None:
    compose = scratch_repo / "deploy" / "compose"
    compose.mkdir(parents=True)
    (compose / "control-plane.yml").write_text("services: {}\n", encoding="utf-8")
    (scratch_repo / "deploy" / "images.lock").write_text(
        "images:\n  - name: x\n    image: ghcr.io/example/x\n    digest: latest\n",
        encoding="utf-8",
    )
    _git(scratch_repo, "add", "deploy")
    _git(scratch_repo, "commit", "-q", "-m", "release files")
    _git(scratch_repo, "tag", "v0.1.0")
    env = _script_env(LAB_REPO_ROOT=str(scratch_repo))
    result = _run(["bash", str(DEPLOY / "release.sh"), "lab1", "--tag", "v0.1.0"], env=env)
    assert result.returncode != 0
    assert "has no pinned image@digest" in result.stderr


def test_secrets_validate_only_prints_names_never_values(tmp_path: Path) -> None:
    values = tmp_path / "values.env"
    values.write_text(
        f"ANTHROPIC_API_KEY={PLACEHOLDER_KEY}\nLAB_BUDGET_USD={PLACEHOLDER_BUDGET}\n",
        encoding="utf-8",
    )
    result = _run(
        ["bash", str(DEPLOY / "secrets.sh"), "lab1", "--from-file", str(values), "--validate-only"],
        env=_script_env(),
    )
    out = result.stdout + result.stderr
    assert result.returncode == 0, out
    assert "ANTHROPIC_API_KEY" in out
    assert "LAB_BUDGET_USD" in out
    assert PLACEHOLDER_KEY not in out
    assert PLACEHOLDER_BUDGET not in out


@pytest.mark.parametrize(
    ("line", "name"),
    [
        ("LAB_BUDGET_USD=lots", "LAB_BUDGET_USD"),
        ("ANTHROPIC_API_KEY=has space", "ANTHROPIC_API_KEY"),
        ("ANTHROPIC_API_KEY=not-anthropic-format", "ANTHROPIC_API_KEY"),
        ("LAB_MAX_PARALLEL=0", "LAB_MAX_PARALLEL"),
        ("LAB_MAX_PARALLEL=5", "LAB_MAX_PARALLEL"),  # above lab1's max_parallel_cells (1)
        ("NOTIFY_WEBHOOK_URL=http://plain.example.invalid/x", "NOTIFY_WEBHOOK_URL"),
        ("NOT_IN_ENV_EXAMPLE=1", "NOT_IN_ENV_EXAMPLE"),
    ],
)
def test_secrets_rejects_bad_values_without_echoing_them(
    tmp_path: Path, line: str, name: str
) -> None:
    base = {"ANTHROPIC_API_KEY": PLACEHOLDER_KEY, "LAB_BUDGET_USD": PLACEHOLDER_BUDGET}
    key, _, bad_value = line.partition("=")
    base[key] = bad_value
    values = tmp_path / "values.env"
    values.write_text("".join(f"{k}={v}\n" for k, v in base.items()), encoding="utf-8")
    result = _run(
        ["bash", str(DEPLOY / "secrets.sh"), "lab1", "--from-file", str(values), "--validate-only"],
        env=_script_env(),
    )
    out = result.stdout + result.stderr
    assert result.returncode != 0, out
    assert name in result.stderr
    if len(bad_value) > 3:  # a one-digit value would match line numbers and "lab1"
        assert bad_value not in out


def test_secrets_requires_required_variables(tmp_path: Path) -> None:
    values = tmp_path / "values.env"
    values.write_text(f"LAB_BUDGET_USD={PLACEHOLDER_BUDGET}\n", encoding="utf-8")
    result = _run(
        ["bash", str(DEPLOY / "secrets.sh"), "lab1", "--from-file", str(values), "--validate-only"],
        env=_script_env(),
    )
    assert result.returncode != 0
    assert "ANTHROPIC_API_KEY" in result.stderr


def test_tunnel_is_informational_under_twingate() -> None:
    result = _run(["bash", str(DEPLOY / "tunnel.sh"), "lab1"], env=_script_env())
    assert result.returncode == 0, result.stderr
    assert "Twingate" in result.stdout
    assert "https://192.168.1.145/" in result.stdout


# ------------------------------------------------------------------- .env.example

ENV_LINE = re.compile(r"^([A-Z][A-Z0-9_]*)=(.*)$")
ENV_TYPES = {"secret", "usd", "int", "url", "email", "host", "port", "text"}


def _env_example() -> dict[str, tuple[str, set[str]]]:
    """name -> (value, tags) where tags are the [..] markers in the comment above."""
    entries: dict[str, tuple[str, set[str]]] = {}
    comment: list[str] = []
    for raw in ENV_EXAMPLE.read_text(encoding="utf-8").splitlines():
        if raw.startswith("#"):
            comment.append(raw)
            continue
        match = ENV_LINE.match(raw)
        if match:
            assert match.group(1) not in entries, f"duplicate {match.group(1)}"
            tags = set(re.findall(r"\[([a-z]+)\]", comment[-1] if comment else ""))
            entries[match.group(1)] = (match.group(2), tags)
        else:
            assert raw.strip() == "", f"unexpected line in .env.example: {raw!r}"
        comment = []
    return entries


def test_env_example_lists_every_variable_empty_with_a_comment() -> None:
    entries = _env_example()
    for name in (
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "LAB_BUDGET_USD",
        "LAB_MAX_PARALLEL",
        "NOTIFY_WEBHOOK_URL",
        "NOTIFY_NTFY_TOPIC",
    ):
        assert name in entries, name
    for name, (value, tags) in entries.items():
        assert value == "", f"{name} must be empty in .env.example"
        assert len(tags & {"required", "optional"}) == 1, f"{name}: [required] or [optional]"
        assert len(tags & ENV_TYPES) == 1, f"{name}: exactly one type tag of {sorted(ENV_TYPES)}"
    required = {n for n, (_, tags) in entries.items() if "required" in tags}
    assert required == {"ANTHROPIC_API_KEY", "LAB_BUDGET_USD"}


# ------------------------------------------------------------------ hosts.example


def test_hosts_example_is_the_lxc_profile() -> None:
    hosts = _load_yaml(HOSTS_EXAMPLE)
    lab1 = hosts["lab1"]
    assert lab1["address"] == "192.168.1.145"
    assert lab1["ssh_user"] == "root"
    assert lab1["isolation"] == "lxc"
    assert lab1["access"] == "twingate"
    assert lab1["allow_containerd_pin"] is False
    assert lab1["cloudflare_tunnel"] is False
    assert lab1["max_parallel_cells"] == 1


# ------------------------------------------------------------------------ ansible


class _When:
    """Evaluate the small subset of Jinja used in role-level ``when`` conditions.

    Supports names, string/bool/int literals, ``==``/``!=``/``in``/``not in``,
    ``and``/``or``/``not`` and the ``| bool`` filter. Anything else fails the test,
    so a condition the evaluator cannot read is never silently treated as true.
    """

    def __init__(self, hostvars: Mapping[str, Any]) -> None:
        self.vars = hostvars

    def __call__(self, condition: str | bool | list[str | bool]) -> bool:
        if isinstance(condition, list):
            return all(self(c) for c in condition)
        if isinstance(condition, bool):
            return condition
        return bool(self._eval(ast.parse(condition, mode="eval").body))

    def _eval(self, node: ast.expr) -> Any:
        match node:
            case ast.Constant(value=value):
                return value
            case ast.Name(id=name):
                assert name in self.vars, f"condition uses undefined variable {name!r}"
                return self.vars[name]
            case ast.List(elts=elts):
                return [self._eval(e) for e in elts]
            case ast.BoolOp(op=ast.And(), values=values):
                return all(self._eval(v) for v in values)
            case ast.BoolOp(op=ast.Or(), values=values):
                return any(self._eval(v) for v in values)
            case ast.UnaryOp(op=ast.Not(), operand=operand):
                return not self._eval(operand)
            case ast.BinOp(left=left, op=ast.BitOr(), right=ast.Name(id="bool")):
                value = self._eval(left)
                assert isinstance(value, bool), f"| bool on non-boolean {value!r}"
                return value
            case ast.Compare(left=left, ops=[op], comparators=[right]):
                lhs, rhs = self._eval(left), self._eval(right)
                match op:
                    case ast.Eq():
                        return lhs == rhs
                    case ast.NotEq():
                        return lhs != rhs
                    case ast.In():
                        return lhs in rhs
                    case ast.NotIn():
                        return lhs not in rhs
        raise AssertionError(f"unsupported construct in when: {ast.dump(node)}")


def _active_roles(hostvars: Mapping[str, Any]) -> list[str]:
    plays = _load_yaml(SITE)
    assert isinstance(plays, list)
    assert len(plays) == 1, "site.yml is one play"
    play = plays[0]
    evaluate = _When(hostvars)
    active: list[str] = []
    for entry in play["roles"]:
        assert isinstance(entry, dict), "roles are listed as {role: ..., when: ...} mappings"
        if "when" not in entry or evaluate(entry["when"]):
            active.append(entry["role"])
    return active


def _lab1_vars(**override: Any) -> dict[str, Any]:
    hostvars = dict(_load_yaml(HOSTS_EXAMPLE)["lab1"])
    hostvars.update(override)
    return hostvars


def test_site_lxc_profile_skips_sysbox_and_runs_the_lxc_roles() -> None:
    active = _active_roles(_lab1_vars())
    assert "sysbox" not in active
    for role in ("docker", "firewall", "caddy", *LXC_ROLES):
        assert role in active, role
    assert active.index("base") == 0
    # Fail closed: the host firewall (and the docker.service drop-in requiring it)
    # exists before Docker is installed and first started.
    assert active.index("firewall") < active.index("docker")
    assert "cloudflared" not in active  # cloudflare_tunnel: false


def test_site_sysbox_profile_runs_sysbox() -> None:
    active = _active_roles(_lab1_vars(isolation="sysbox"))
    assert "sysbox" in active


def test_site_every_listed_role_exists() -> None:
    play = _load_yaml(SITE)[0]
    for entry in play["roles"]:
        assert (ANSIBLE / "roles" / entry["role"] / "tasks" / "main.yml").is_file(), entry


def test_sysbox_role_refuses_to_run_in_lxc_profile() -> None:
    # Belt and braces: even if site.yml's condition were removed, the role itself stops.
    text = (ANSIBLE / "roles" / "sysbox" / "tasks" / "main.yml").read_text(encoding="utf-8")
    assert "isolation == 'sysbox'" in text


def test_sysctl_role_sets_ipv6_off_and_only_verifies_host_settings() -> None:
    role = ANSIBLE / "roles" / "sysctl"
    template = (role / "templates" / "90-lab.conf.j2").read_text(encoding="utf-8")
    assert re.search(r"^net\.ipv6\.conf\.all\.disable_ipv6 = 1$", template, re.MULTILINE)
    assert re.search(r"^net\.ipv6\.conf\.default\.disable_ipv6 = 1$", template, re.MULTILINE)
    assert "vm.max_map_count" not in template, "host-only: verified, never set in the LXC"
    defaults = _load_yaml(role / "defaults" / "main.yml")
    assert defaults["sysctl_verify_host"]["vm.max_map_count"] == 262144


def test_docker_role_pins_29_minor_and_never_29_1_0() -> None:
    role = ANSIBLE / "roles" / "docker"
    defaults = _load_yaml(role / "defaults" / "main.yml")
    assert re.fullmatch(r"29\.\d+", str(defaults["docker_ce_minor"]))
    assert defaults["docker_ce_forbidden_versions"] == ["29.1.0"]
    assert defaults["docker_compose_min_version"] == "2.24.0"
    tasks = (role / "tasks" / "main.yml").read_text(encoding="utf-8")
    assert "docker_ce_forbidden_versions" in tasks
    assert "ip_unprivileged_port_start" in (role / "tasks" / "cve_2025_52881.yml").read_text(
        encoding="utf-8"
    )


def test_docker_address_pools_do_not_overlap_cells_or_the_lan() -> None:
    group_vars = _load_yaml(ANSIBLE / "group_vars" / "all.yml")
    cells = [ipaddress.ip_network(n) for n in group_vars["lab_cell_networks"]]
    pools = [ipaddress.ip_network(p["base"]) for p in group_vars["docker_default_address_pools"]]
    # The home LAN (192.168.0.0/16), Twingate/CGNAT (100.64.0.0/10) and link-local.
    reserved = [
        ipaddress.ip_network(n) for n in ("192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16")
    ]
    for pool in pools:
        for other in (*cells, *reserved):
            assert not pool.overlaps(other), f"docker pool {pool} overlaps {other}"
    for cell in cells:
        for other in reserved:
            assert not cell.overlaps(other), f"cell network {cell} overlaps {other}"


def test_firewall_uses_docker_user_for_cell_egress() -> None:
    role = ANSIBLE / "roles" / "firewall"
    script = (role / "templates" / "lab-cell-egress.sh.j2").read_text(encoding="utf-8")
    assert "DOCKER-USER" in script
    assert "iptables-restore" in script
    host = (role / "templates" / "host.nft.j2").read_text(encoding="utf-8")
    assert "flush ruleset" not in host, "must never wipe Docker's rules"


def _unit(path: Path) -> dict[str, list[str]]:
    """systemd unit file -> {"Section.Key": [values]} (enough for these checks)."""
    section, out = "", {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            section = line.strip("[]")
            continue
        key, _, value = line.partition("=")
        out.setdefault(f"{section}.{key}", []).append(value)
    return out


FIREWALL_MODULES = [
    "nft_fib_inet",
    "nft_log",
    "nf_log_syslog",
    "nft_limit",
    "nft_ct",
    "nft_compat",
    "xt_comment",
]


def _task_index(tasks: list[dict[str, Any]], predicate: Any) -> int:
    return next(i for i, t in enumerate(tasks) if predicate(t))


def test_firewall_checks_modules_and_cell_networks_before_loading_rules() -> None:
    role = ANSIBLE / "roles" / "firewall"
    assert _load_yaml(role / "defaults" / "main.yml")["firewall_kernel_modules"] == FIREWALL_MODULES
    tasks = _load_yaml(role / "tasks" / "main.yml")
    modules = _task_index(tasks, lambda t: "firewall_kernel_modules" in json.dumps(t))
    networks = _task_index(tasks, lambda t: "strict=True" in json.dumps(t))
    render = _task_index(
        tasks, lambda t: t.get("ansible.builtin.template", {}).get("src") == "host.nft.j2"
    )
    assert modules < render
    assert networks < render
    # The module check names what is missing and where to load it.
    text = (role / "tasks" / "main.yml").read_text(encoding="utf-8")
    assert "modules-load.d" in text


def test_module_check_finds_loaded_and_reports_missing_modules() -> None:
    """Run the role's own module-check snippet against this machine's kernel."""
    tasks = _load_yaml(ANSIBLE / "roles" / "firewall" / "tasks" / "main.yml")
    task = tasks[_task_index(tasks, lambda t: "firewall_kernel_modules" in json.dumps(t))]
    code = task["ansible.builtin.command"]["argv"][3]
    loaded = next(p.name for p in Path("/sys/module").iterdir() if p.is_dir())
    result = _run([sys.executable, "-I", "-c", code, json.dumps([loaded, "lab_no_such_module"])])
    assert result.returncode == 0, result.stderr
    assert result.stdout.split() == ["lab_no_such_module"]


@pytest.mark.parametrize(
    ("networks", "ok"),
    [
        (["10.231.0.0/16"], True),
        (["10.231.0.0/16", "10.232.0.0/24"], True),
        (["10.231.0.1/16"], False),  # host bits set
        (["fd00::/64"], False),  # IPv4 only
        ([], False),
        (["10.231.0.0/16 , drop"], False),
    ],
)
def test_cell_network_validation_is_strict(networks: list[str], ok: bool) -> None:
    """Run the role's own validation snippet on the given value."""
    tasks = _load_yaml(ANSIBLE / "roles" / "firewall" / "tasks" / "main.yml")
    task = tasks[_task_index(tasks, lambda t: "strict=True" in json.dumps(t))]
    code = task["ansible.builtin.command"]["argv"][3]
    result = _run([sys.executable, "-I", "-c", code, json.dumps(networks)])
    assert (result.returncode == 0) is ok, result.stderr


def test_docker_cannot_start_without_the_host_firewall() -> None:
    templates = ANSIBLE / "roles" / "firewall" / "templates"
    dropin = _unit(templates / "docker-requires-lab-firewall.conf.j2")
    assert "lab-firewall.service" in dropin["Unit.Requires"]
    assert "lab-firewall.service" in dropin["Unit.After"]
    firewall = _unit(templates / "lab-firewall.service.j2")
    # Fail closed: no "-" prefix, so a failing nft load fails the unit (and Docker).
    assert all(not v.startswith("-") for v in firewall["Service.ExecStart"])
    assert firewall["Service.Type"] == ["oneshot"]
    # No ExecStop: with live-restore, cells outlive a stop of the unit, so the table
    # must stay loaded until reboot or explicit removal.
    assert "Service.ExecStop" not in firewall
    tasks = _load_yaml(ANSIBLE / "roles" / "firewall" / "tasks" / "main.yml")
    text = (ANSIBLE / "roles" / "firewall" / "tasks" / "main.yml").read_text(encoding="utf-8")
    assert "/etc/systemd/system/docker.service.d/" in text
    # The distribution nftables.service would `flush ruleset` on (re)start: masked.
    mask = next(
        t for t in tasks if t.get("ansible.builtin.systemd_service", {}).get("name") == "nftables"
    )
    assert mask["ansible.builtin.systemd_service"]["masked"] is True


def test_docker_dns_upstream_is_explicit_and_not_loopback() -> None:
    # A loopback resolver would make dockerd forward cell DNS from the host netns,
    # around the forward drop; an explicit upstream keeps it in the container netns.
    defaults = _load_yaml(ANSIBLE / "roles" / "docker" / "defaults" / "main.yml")
    assert defaults["docker_daemon_config"]["dns"] == "{{ lab_upstream_dns }}"
    assert _load_yaml(ANSIBLE / "group_vars" / "all.yml")["lab_upstream_dns"] == []
    lab1 = _load_yaml(HOSTS_EXAMPLE)["lab1"]
    assert lab1["vars"]["lab_upstream_dns"] == ["192.168.1.1"]
    tasks = (ANSIBLE / "roles" / "docker" / "tasks" / "main.yml").read_text(encoding="utf-8")
    assert "lab_upstream_dns" in tasks
    assert "127" in tasks  # loopback refused


def test_docker_key_is_checked_before_it_is_trusted() -> None:
    tasks = _load_yaml(ANSIBLE / "roles" / "docker" / "tasks" / "main.yml")
    names = [str(t.get("name", "")) for t in tasks]
    download = next(i for i, t in enumerate(tasks) if "ansible.builtin.get_url" in t)
    assert tasks[download]["ansible.builtin.get_url"]["dest"] != "/etc/apt/keyrings/docker.asc"
    check = next(i for i, n in enumerate(names) if "exactly Docker's release key" in n)
    install = next(
        i
        for i, t in enumerate(tasks)
        if t.get("ansible.builtin.copy", {}).get("dest") == "/etc/apt/keyrings/docker.asc"
    )
    assert download < check < install


def test_status_runs_the_egress_check() -> None:
    assert "lab-cell-egress check" in (DEPLOY / "remote" / "status.sh").read_text(encoding="utf-8")


def test_docker_key_check_requires_exactly_one_primary_key() -> None:
    tasks = (ANSIBLE / "roles" / "docker" / "tasks" / "main.yml").read_text(encoding="utf-8")
    assert "select('match', '^pub:')" in tasks
    assert "length == 1" in tasks


def test_docker_installed_without_recommends() -> None:
    tasks = _load_yaml(ANSIBLE / "roles" / "docker" / "tasks" / "main.yml")
    install = next(t for t in tasks if str(t.get("name", "")).startswith("Install Docker CE"))
    assert install["ansible.builtin.apt"]["install_recommends"] is False


def test_caddy_password_never_in_argv() -> None:
    tasks = (ANSIBLE / "roles" / "caddy" / "tasks" / "main.yml").read_text(encoding="utf-8")
    assert "--plaintext" not in tasks


def test_ssh_root_login_is_per_profile() -> None:
    defaults = _load_yaml(ANSIBLE / "roles" / "base" / "defaults" / "main.yml")
    expr = defaults["base_ssh_permit_root_login"]
    assert "isolation == 'lxc'" in expr
    assert "'prohibit-password'" in expr
    assert "'no'" in expr
    site = SITE.read_text(encoding="utf-8")
    # The sysbox/VM profile provisions with a sudo user, never root.
    assert "isolation == 'lxc' or ansible_user != 'root'" in site
    assert "ssh_user: admin" in HOSTS_EXAMPLE.read_text(encoding="utf-8")


def test_backup_repo_is_accepted_with_a_warning(tmp_path: Path) -> None:
    hosts = tmp_path / "hosts.yml"
    hosts.write_text(
        "lab1:\n  address: 192.0.2.10\n  ssh_user: root\n  isolation: lxc\n"
        "  access: twingate\n  backup_repo: s3:https://backup.example.invalid/lab\n",
        encoding="utf-8",
    )
    result = _run(
        ["bash", str(DEPLOY / "tunnel.sh"), "lab1"], env=_script_env(LAB_HOSTS_FILE=str(hosts))
    )
    assert result.returncode == 0, result.stderr
    assert "backup_repo" in result.stderr
    assert "not built in M0" in result.stderr


# ---------------------------------------------- remote scripts, run against a fake root

FAKE_DOCKER = """\
#!/usr/bin/env bash
printf '%s\\n' "$*" >>"$FAKE_DOCKER_LOG"
case "$*" in
*"config --services"*)
    [[ ${FAKE_CONFIG_FAIL:-0} == 1 ]] && exit 1
    printf 'db\\napi\\nworker\\nmigrate\\n' ;;
*"config --images"*) printf '%s\\n' $FAKE_IMAGES ;;
*"config --format json"*) printf '%s\\n' "$FAKE_CONFIG_JSON" ;;
*"ps --status running --services"*) [[ ${FAKE_DB_DOWN:-0} == 1 ]] || echo db ;;
*"pg_dump"*) echo DUMPDATA ;;
*"pg_restore --list"*) [[ ${FAKE_LIST_FAIL:-0} == 1 ]] && exit 1 ;;
*"pg_restore"*) [[ ${FAKE_RESTORE_FAIL:-0} == 1 ]] && exit 1 ;;
*"RENAME TO"*) [[ ${FAKE_SWAP_FAIL:-0} == 1 ]] && exit 1 ;;
*"run --rm --no-deps migrate"*) [[ ${FAKE_MIGRATE_FAIL:-0} == 1 ]] && exit 1 ;;
*" up "*) [[ ${FAKE_UP_FAIL:-0} == 1 ]] && exit 1 ;;
esac
exit 0
"""

PINNED = "ghcr.io/example/api@sha256:" + "a" * 64


@pytest.fixture
def lab_root(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    """A fake /srv/lab with releases v0.0.9 (current) and v0.1.0, and a fake docker."""
    root = tmp_path / "srv-lab"
    for tag in ("v0.0.9", "v0.1.0"):
        compose = root / "releases" / tag / "deploy" / "compose"
        compose.mkdir(parents=True)
        (compose / "control-plane.yml").write_text("services: {}\n", encoding="utf-8")
    (root / "secrets").mkdir(mode=0o700)
    (root / "secrets" / "lab.env").write_text("A=b\n", encoding="utf-8")
    (root / "backups").mkdir()
    (root / "current").symlink_to(root / "releases" / "v0.0.9")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    docker = bindir / "docker"
    docker.write_text(FAKE_DOCKER, encoding="utf-8")
    docker.chmod(0o755)
    env = dict(
        os.environ,
        LAB_ROOT=str(root),
        LAB_OWNER=_run(["id", "-un"]).stdout.strip(),
        PATH=f"{bindir}:{os.environ['PATH']}",
        FAKE_DOCKER_LOG=str(tmp_path / "docker.log"),
        FAKE_IMAGES=PINNED,
    )
    return root, env


def _docker_log(env: Mapping[str, str]) -> list[str]:
    return Path(env["FAKE_DOCKER_LOG"]).read_text(encoding="utf-8").splitlines()


def _first(log: list[str], *needles: str) -> int:
    return _index(log, *needles)


def test_migrate_stops_writers_then_dumps_then_migrates_without_deps(
    lab_root: tuple[Path, dict[str, str]],
) -> None:
    root, env = lab_root
    result = _run(["bash", str(DEPLOY / "remote" / "release.sh"), "migrate", "v0.1.0"], env=env)
    assert result.returncode == 0, result.stderr
    log = _docker_log(env)
    stop = _first(log, f"{root}/current/", " stop api worker")
    dump = _first(log, "exec -T db", "pg_dump")
    migrate = _first(log, "releases/v0.1.0/", "run --rm --no-deps migrate")
    assert stop < dump < migrate
    assert not any(" stop " in line and " db" in line for line in log), "db keeps running"
    assert (root / "releases" / ".state" / "pending-dump").is_file()


def test_migrate_refuses_without_a_dump_when_a_release_is_deployed(
    lab_root: tuple[Path, dict[str, str]],
) -> None:
    root, env = lab_root
    state = root / "releases" / ".state"
    state.mkdir()
    (state / "previous").write_text(f"{root}/releases/v0.0.9\n", encoding="utf-8")
    result = _run(
        ["bash", str(DEPLOY / "remote" / "release.sh"), "migrate", "v0.1.0"],
        env={**env, "FAKE_DB_DOWN": "1"},
    )
    assert result.returncode != 0
    assert "pre-migration dump" in result.stderr
    assert not any("run --rm --no-deps migrate" in line for line in _docker_log(env))


def test_migrate_fails_closed_when_the_services_cannot_be_read(
    lab_root: tuple[Path, dict[str, str]],
) -> None:
    _, env = lab_root
    result = _run(
        ["bash", str(DEPLOY / "remote" / "release.sh"), "migrate", "v0.1.0"],
        env={**env, "FAKE_CONFIG_FAIL": "1"},
    )
    assert result.returncode != 0
    assert not any("run --rm --no-deps migrate" in line for line in _docker_log(env))
    assert not any("pg_dump" in line for line in _docker_log(env))


def test_migrate_failure_reports_the_state(lab_root: tuple[Path, dict[str, str]]) -> None:
    root, env = lab_root
    result = _run(
        ["bash", str(DEPLOY / "remote" / "release.sh"), "migrate", "v0.1.0"],
        env={**env, "FAKE_MIGRATE_FAIL": "1"},
    )
    assert result.returncode != 0
    assert "migrate failed" in result.stderr
    assert f"current -> {root}/releases/v0.0.9" in result.stderr
    assert f"{root}/backups/pre-v0.1.0-" in result.stderr  # the dump path


@pytest.fixture
def failed_release(lab_root: tuple[Path, dict[str, str]]) -> tuple[Path, dict[str, str], Path]:
    """v0.1.0 is current and failed; v0.0.9 is the rollback target; a dump exists."""
    root, env = lab_root
    (root / "current").unlink()
    (root / "current").symlink_to(root / "releases" / "v0.1.0")
    state = root / "releases" / ".state"
    state.mkdir()
    (state / "previous").write_text(f"{root}/releases/v0.0.9\n", encoding="utf-8")
    dump = root / "backups" / "pre.dump"
    dump.write_text("DUMP", encoding="utf-8")
    (state / "pending-dump").write_text(f"{dump}\n", encoding="utf-8")
    return root, env, dump


def _rollback(env: Mapping[str, str], **fail: str) -> subprocess.CompletedProcess[str]:
    return _run(["bash", str(DEPLOY / "remote" / "release.sh"), "rollback"], env={**env, **fail})


def test_rollback_restores_into_a_scratch_db_before_touching_the_live_one(
    failed_release: tuple[Path, dict[str, str], Path],
) -> None:
    root, env, _ = failed_release
    result = _rollback(env)
    assert result.returncode == 0, result.stderr
    log = _docker_log(env)
    stop = _first(log, " stop api worker")
    precheck = _first(log, "exec -T db", "pg_restore --list")
    scratch = _first(log, "exec -T db", 'CREATE DATABASE :"rb"', "CONNECTION LIMIT 0")
    restore = _first(log, "exec -T db", "pg_restore --single-transaction --exit-on-error", '_rb"')
    swap = _first(log, "exec -T db", 'DROP DATABASE :"db"', 'RENAME TO :"db"')
    up = _first(log, " up -d")
    assert stop < precheck < scratch < restore < swap < up
    assert not any("--no-owner" in line for line in log)
    assert os.readlink(root / "current") == f"{root}/releases/v0.0.9"
    assert not (root / "releases" / ".state" / "pending-dump").exists()


@pytest.mark.parametrize("failure", ["FAKE_LIST_FAIL", "FAKE_RESTORE_FAIL"])
def test_rollback_with_a_bad_dump_leaves_the_live_db_untouched(
    failed_release: tuple[Path, dict[str, str], Path], failure: str
) -> None:
    root, env, dump = failed_release
    result = _rollback(env, **{failure: "1"})
    assert result.returncode != 0
    assert str(dump) in result.stderr
    assert f"current -> {root}/releases/v0.1.0" in result.stderr
    assert "database: untouched" in result.stderr
    log = _docker_log(env)
    assert not any('DROP DATABASE :"db"' in line for line in log), "live DB never dropped"
    assert not any(" up -d" in line for line in log), "no start on a bad restore"
    if failure == "FAKE_RESTORE_FAIL":
        restore = _first(log, "pg_restore --single-transaction")
        cleanup = [
            i
            for i, line in enumerate(log)
            if 'DROP DATABASE IF EXISTS :"rb"' in line and "CREATE" not in line
        ]
        assert cleanup and cleanup[0] > restore, "the scratch database is dropped again"
    else:
        assert not any("CREATE DATABASE" in line for line in log)


def test_rollback_swap_failure_points_at_the_restored_copy(
    failed_release: tuple[Path, dict[str, str], Path],
) -> None:
    _, env, dump = failed_release
    result = _rollback(env, FAKE_SWAP_FAIL="1")
    assert result.returncode != 0
    assert "_rb" in result.stderr
    assert str(dump) in result.stderr
    assert not any(" up -d" in line for line in _docker_log(env))


def test_rollback_reports_when_the_old_release_cannot_start(
    lab_root: tuple[Path, dict[str, str]],
) -> None:
    root, env = lab_root
    state = root / "releases" / ".state"
    state.mkdir()
    (state / "previous").write_text(f"{root}/releases/v0.0.9\n", encoding="utf-8")
    result = _run(
        ["bash", str(DEPLOY / "remote" / "release.sh"), "rollback"],
        env={**env, "FAKE_UP_FAIL": "1"},
    )
    assert result.returncode != 0
    assert "did not start" in result.stderr


@pytest.mark.parametrize(
    ("images", "ok"),
    [(PINNED, True), ("ghcr.io/example/api:latest", False), (f"{PINNED} postgres:17", False)],
)
def test_compose_pull_requires_pinned_images(
    lab_root: tuple[Path, dict[str, str]], images: str, ok: bool
) -> None:
    _, env = lab_root
    result = _run(
        ["bash", str(DEPLOY / "remote" / "release.sh"), "compose-pull", "v0.1.0"],
        env={**env, "FAKE_IMAGES": images},
    )
    assert (result.returncode == 0) is ok, result.stderr
    if not ok:
        assert "not pinned by digest" in result.stderr


@pytest.mark.parametrize(
    ("services", "ok"),
    [
        # A built service may carry a local tag; a pulled one must be pinned.
        (
            {"api": {"build": {"context": "."}, "image": "lab/api:dev"}, "db": {"image": PINNED}},
            True,
        ),
        ({"api": {"build": {"context": "."}}, "db": {"image": "postgres:17"}}, False),
    ],
)
def test_allow_build_still_requires_pinned_pulled_images(
    lab_root: tuple[Path, dict[str, str]], services: dict[str, Any], ok: bool
) -> None:
    _, env = lab_root
    result = _run(
        ["bash", str(DEPLOY / "remote" / "release.sh"), "compose-pull", "v0.1.0", "allow-build"],
        env={**env, "FAKE_CONFIG_JSON": json.dumps({"services": services})},
    )
    assert (result.returncode == 0) is ok, result.stderr
    if not ok:
        assert "postgres:17" in result.stderr


@pytest.mark.parametrize(
    ("stdin", "ok"),
    [
        ("SET ANTHROPIC_API_KEY=sk-ant-x-12345678\nKEEP A\nEND 2\n", True),
        ("SET ANTHROPIC_API_KEY=sk-ant-x-12345678\nKEEP A\n", False),  # truncated: no END
        ("SET ANTHROPIC_API_KEY=sk-ant-x-12345678\nKEEP A\nEND 3\n", False),  # count mismatch
    ],
)
def test_secrets_write_needs_the_end_marker(
    lab_root: tuple[Path, dict[str, str]], stdin: str, ok: bool
) -> None:
    root, env = lab_root
    env_file = root / "secrets" / "lab.env"
    result = _run(["bash", str(DEPLOY / "remote" / "secrets.sh"), "write"], env=env, stdin=stdin)
    assert (result.returncode == 0) is ok, result.stderr
    content = env_file.read_text(encoding="utf-8")
    if ok:
        assert "ANTHROPIC_API_KEY=sk-ant-x-12345678" in content
        assert "\nA=b\n" in content
        assert oct(env_file.stat().st_mode & 0o777) == "0o600"
    else:
        assert content == "A=b\n", "a failed write leaves lab.env untouched"
        assert "12345678" not in result.stderr
    assert not list((root / "secrets").glob(".lab.env.*")), "no temp file left behind"


# ------------------------------------------------- firewall, rendered and loaded

RENDER_PLAYBOOK = """\
- name: Render the firewall templates
  hosts: localhost
  connection: local
  gather_facts: false
  vars_files:
    - {ansible}/group_vars/all.yml
    - {ansible}/roles/firewall/defaults/main.yml
  tasks:
    - name: Render
      ansible.builtin.template:
        src: "{ansible}/roles/firewall/templates/{{{{ item.src }}}}"
        dest: "{out}/{{{{ item.dest }}}}"
        mode: "0644"
      loop:
        - {{src: host.nft.j2, dest: host.nft}}
        - {{src: lab-cell-egress.sh.j2, dest: lab-cell-egress.sh}}
"""


def _render_firewall(out: Path, **extra_vars: Any) -> Path:
    playbook_cmd = _require_tool("ansible-playbook", ANSIBLE_CORE)
    out.mkdir(parents=True, exist_ok=True)
    play = out / "render.yml"
    play.write_text(RENDER_PLAYBOOK.format(ansible=ANSIBLE, out=out), encoding="utf-8")
    extra = out / "extra.json"
    extra.write_text(json.dumps({"ansible_port": 22, **extra_vars}), encoding="utf-8")
    result = _run([*playbook_cmd, "-i", "localhost,", str(play), "-e", f"@{extra}"])
    assert result.returncode == 0, result.stdout + result.stderr
    return out


@pytest.fixture(scope="module")
def firewall_default(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return _render_firewall(tmp_path_factory.mktemp("fw-default"))


@pytest.fixture(scope="module")
def firewall_gateway(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return _render_firewall(
        tmp_path_factory.mktemp("fw-gateway"),
        lab_cell_networks=["10.231.0.0/16", "10.232.0.0/16"],
        lab_llm_gateway_address="172.20.0.10",
        lab_llm_gateway_port=4000,
    )


def _in_netns(script: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    prefix = _require_netns()
    return _run([*prefix, "bash", "-c", script], cwd=cwd)


def _chain(listing: str, name: str) -> list[str]:
    """The rule lines of one chain from `nft list table` output."""
    match = re.search(rf"chain {name} {{\n(.*?)\n\t}}", listing, re.DOTALL)
    assert match, f"chain {name} missing:\n{listing}"
    return [line.strip() for line in match.group(1).splitlines() if line.strip()]


def _index(rules: list[str], *needles: str) -> int:
    for i, rule in enumerate(rules):
        if all(n in rule for n in needles):
            return i
    raise AssertionError(f"no rule with {needles} in {rules}")


@pytest.mark.parametrize("variant", ["firewall_default", "firewall_gateway"])
def test_host_nft_passes_nft_check(variant: str, request: pytest.FixtureRequest) -> None:
    rendered: Path = request.getfixturevalue(variant)
    result = _in_netns("nft --check --file host.nft", rendered)
    assert result.returncode == 0, result.stderr


def test_host_nft_ruleset_fails_closed_for_cells(firewall_default: Path) -> None:
    result = _in_netns(
        "nft --file host.nft && nft --file host.nft && nft list table inet lab_host",
        firewall_default,
    )
    assert result.returncode == 0, result.stderr
    listing = result.stdout
    assert "elements = { 10.231.0.0/16 }" in listing

    # Strict reverse-path filter on cell bridges, before conntrack (priority raw): a
    # cell with NET_RAW cannot forge a source that does not route back via its bridge.
    prerouting = _chain(listing, "prerouting")
    assert "type filter hook prerouting priority raw" in prerouting[0]
    # nft prints the existence test as `oif missing` (older) or `check missing` (newer).
    rpf = [r.replace("iif check missing", "iif oif missing") for r in prerouting]
    _index(rpf, 'iifname "labc*"', "fib saddr . iif oif missing", "drop")

    # Cells are matched by ingress interface AND by source address.
    forward = _chain(listing, "forward")
    assert "type filter hook forward" in forward[0]
    v6 = _index(forward, "meta nfproto ipv6", "drop")
    within = _index(
        forward,
        'iifname "labc*" oifname "labc*"',
        "ip saddr @cell_nets ip daddr @cell_nets",
        "accept",
    )
    log = _index(forward, 'iifname "labc*"', 'log prefix "lab-drop')
    drop_iface = _index(forward, 'iifname "labc*"', "counter", "drop")
    drop_addr = _index(forward, "ip saddr @cell_nets", "counter", "drop", "off a cell bridge")
    assert v6 < within < log < drop_iface < drop_addr
    assert not any("accept" in r and "labc" not in r for r in forward[1:]), "accepts are per-bridge"
    assert not any("172.20.0.10" in r for r in forward), "no gateway exception by default"

    inbound = _chain(listing, "input")
    assert "policy drop" in inbound[0]
    v6_in = _index(inbound, "meta nfproto ipv6", "drop")
    cell_iface = _index(inbound, 'iifname "labc*"', "counter", "drop")
    cell_addr = _index(inbound, "ip saddr @cell_nets", "counter", "drop")
    established = _index(inbound, "ct state established,related accept")
    ssh = _index(inbound, "tcp dport")
    assert v6_in < cell_iface < cell_addr < established < ssh, "drops before any accept"
    assert any('log prefix "lab-drop' in r for r in inbound)


def test_host_nft_gateway_exception(firewall_gateway: Path) -> None:
    result = _in_netns("nft --file host.nft && nft list table inet lab_host", firewall_gateway)
    assert result.returncode == 0, result.stderr
    forward = _chain(result.stdout, "forward")
    gateway = _index(
        forward, 'iifname "labc*"', "ip saddr @cell_nets", "172.20.0.10", "dport 4000", "accept"
    )
    drop = _index(forward, 'iifname "labc*"', "counter", "drop")
    assert gateway < drop


EGRESS_SCRIPT = """\
set -euo pipefail
nft --file host.nft
iptables -N DOCKER-USER
iptables -A DOCKER-USER -s 10.231.5.0/24 -j ACCEPT
iptables -A FORWARD -j DOCKER-USER
bash lab-cell-egress.sh apply
bash lab-cell-egress.sh apply
iptables -S DOCKER-USER
"""


def test_docker_user_layer_applies_atomically_and_idempotently(firewall_gateway: Path) -> None:
    result = _in_netns(EGRESS_SCRIPT, firewall_gateway)
    assert result.returncode == 0, result.stdout + result.stderr
    rules = [r for r in result.stdout.splitlines() if r.startswith("-A DOCKER-USER")]
    tag = "-m comment --comment lab-cell-egress"
    cells = ("10.231.0.0/16", "10.232.0.0/16")
    expected = []
    # Accepts are per cell bridge (ingress interface labc*) AND per cell address.
    for src in cells:
        for dst in cells:
            expected.append(f"-A DOCKER-USER -s {src} -d {dst} -i labc+ -o labc+ {tag} -j RETURN")
        expected.append(
            f"-A DOCKER-USER -s {src} -d 172.20.0.10/32 -i labc+ -p tcp -m tcp --dport 4000"
            f" {tag} -j RETURN"
        )
    expected.append(f"-A DOCKER-USER -i labc+ {tag} -j DROP")
    expected += [f"-A DOCKER-USER -s {src} {tag} -j DROP" for src in cells]
    # The stale ACCEPT rule is gone and nothing is duplicated after two applies.
    assert rules == [*expected, "-A DOCKER-USER -j RETURN"]
    assert "OK: cell egress rules" in result.stdout


def test_egress_check_detects_a_changed_docker_user_chain(firewall_default: Path) -> None:
    script = (
        "nft --file host.nft && iptables -N DOCKER-USER && iptables -A FORWARD -j DOCKER-USER"
        " && bash lab-cell-egress.sh apply"
        " && iptables -R DOCKER-USER 1 -s 10.231.0.0/16 -j ACCEPT"
        " && bash lab-cell-egress.sh check"
    )
    result = _in_netns(script, firewall_default)
    assert result.returncode != 0
    assert "DOCKER-USER differs" in result.stderr


def test_egress_check_fails_without_the_host_table(firewall_default: Path) -> None:
    script = (
        "iptables -N DOCKER-USER && iptables -A FORWARD -j DOCKER-USER && "
        "bash lab-cell-egress.sh apply"
    )
    result = _in_netns(script, firewall_default)
    assert result.returncode != 0
    assert "lab_host" in result.stderr


@pytest.fixture
def rendered_inventory(tmp_path: Path) -> Path:
    out = tmp_path / "inventory.json"
    result = _run(
        [
            "bash",
            "-c",
            'source "$1" && lab_render_inventory lab1 "$2"',
            "-",
            "deploy/lib.sh",
            str(out),
        ],
        env=_script_env(),
    )
    assert result.returncode == 0, result.stderr
    return out


def test_inventory_rendered_from_hosts_example(rendered_inventory: Path) -> None:
    inventory = _load_yaml(rendered_inventory)
    lab1 = inventory["all"]["hosts"]["lab1"]
    assert lab1["ansible_host"] == "192.168.1.145"
    assert lab1["ansible_user"] == "root"
    assert lab1["isolation"] == "lxc"
    assert lab1["max_parallel_cells"] == 1


def test_ansible_syntax_check(rendered_inventory: Path) -> None:
    playbook = _require_tool("ansible-playbook", ANSIBLE_CORE)
    env = dict(os.environ, ANSIBLE_CONFIG=str(ANSIBLE / "ansible.cfg"))
    result = _run([*playbook, "--syntax-check", "-i", str(rendered_inventory), str(SITE)], env=env)
    assert result.returncode == 0, result.stdout + result.stderr


def test_ansible_lint_clean() -> None:
    lint = _require_tool("ansible-lint", ANSIBLE_LINT)
    env = dict(os.environ, ANSIBLE_CONFIG=str(ANSIBLE / "ansible.cfg"))
    result = _run([*lint, "--offline", "-c", str(ANSIBLE / ".ansible-lint"), str(ANSIBLE)], env=env)
    assert result.returncode == 0, result.stdout + result.stderr
