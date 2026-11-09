"""``labctl``: the lab's command line (docs/TRACKING.md §3.3).

Commands (each takes ``--json`` for scripting):

* ``labctl doctor [--cell-range CIDR]``: host readiness checks (:mod:`control.cli.doctor`).
* ``labctl status``: release, runs by status, experiments, last self-test, disk.
* ``labctl runs ls [-n N] [--status S] [--experiment ID]``: runs, newest first.
* ``labctl run show RUN_ID``: one run with its evidence counts.
* ``labctl selftest [--quick]``: **not built yet** (Task 15b-2); exits 2.

Exit status: 0 success; 1 a check failed, the database is unreachable or the run does
not exist; 2 usage error (an unparsable ``DATABASE_URL`` included) and the selftest stub.

Every command first calls :func:`~control.core.logging.configure_logging` (redacted
JSON on **stderr**, level WARNING), so any log line, ours or a library's, is redacted
and never mixes with the command's output on stdout. The database is only read (see
:mod:`control.cli.queries`); where it is comes from :mod:`control.cli.settings`.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from ipaddress import IPv4Network
from typing import Any, Final

from sqlalchemy import Engine, pool
from sqlalchemy.exc import ArgumentError, SQLAlchemyError
from sqlalchemy.orm import Session

from control.cli import doctor, queries
from control.cli.settings import ConfigError, LabSettings, read_env_file
from control.core.logging import configure_logging, redact_text
from control.core.models import RunStatus
from control.core.selftest_status import SelftestStatusError, read_selftest_status
from control.db.engine import create_db_engine

__all__ = ["EXIT_FAIL", "EXIT_OK", "EXIT_USAGE", "build_parser", "main"]

EXIT_OK: Final = 0
EXIT_FAIL: Final = 1
EXIT_USAGE: Final = 2

SELFTEST_STUB_MESSAGE: Final = "labctl selftest: not built yet (Task 15b-2)"


class _Failure(Exception):
    """A command failed; the message goes to stderr and labctl exits ``code`` (1)."""

    def __init__(self, message: str, code: int = EXIT_FAIL) -> None:
        super().__init__(message)
        self.code = code


# --------------------------------------------------------------------- helpers


def _out(text: str) -> None:
    sys.stdout.write(text if text.endswith("\n") else text + "\n")


def _json(data: Any) -> None:
    _out(json.dumps(data, indent=2, sort_keys=True, default=str))


def _engine(settings: LabSettings) -> Engine:
    try:
        url = settings.database_url()
        return create_db_engine(url, poolclass=pool.NullPool, connect_args={"connect_timeout": 10})
    except ArgumentError:
        # an unparsable DATABASE_URL: a usage error; never echo the URL (it may hold
        # a password)
        raise _Failure("DATABASE_URL is not a valid database URL", EXIT_USAGE) from None
    except (ConfigError, ValueError) as exc:
        raise _Failure(str(exc)) from None


def _with_db[T](settings: LabSettings, fn: Callable[[Session], T]) -> T:
    engine = _engine(settings)
    try:
        with queries.read_only_session(engine) as session:
            return fn(session)
    except SQLAlchemyError as exc:
        reason = getattr(exc, "orig", None) or exc
        raise _Failure(
            "database error: " + redact_text(f"{type(reason).__name__}: {reason}".splitlines()[0])
        ) from None
    finally:
        engine.dispose()


def _when(ts: float | None) -> str:
    if ts is None:
        return "-"
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _dt(value: datetime | None) -> str:
    return "-" if value is None else value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------- doctor


def _cmd_doctor(args: argparse.Namespace, settings: LabSettings) -> int:
    cfg = doctor.DoctorConfig(settings=settings, cell_range=args.cell_range)
    results = doctor.run_doctor(cfg)
    _out(doctor.render_json(results) if args.json else doctor.render_text(results))
    return doctor.exit_code(results)


# --------------------------------------------------------------------- status


def _release(settings: LabSettings) -> str | None:
    try:
        return read_env_file(settings.release_file).get("tag") or None
    except (OSError, UnicodeDecodeError):
        return None


def _cmd_status(args: argparse.Namespace, settings: LabSettings) -> int:
    counts, experiments = _with_db(
        settings, lambda s: (queries.run_status_counts(s), queries.experiment_count(s))
    )
    try:
        selftest: dict[str, Any] | None = read_selftest_status(
            settings.selftest_status_file
        ).to_json()
        selftest_error = None
    except SelftestStatusError as exc:
        selftest, selftest_error = None, str(exc)
    disk: dict[str, Any] | None = None
    if settings.lab_root.exists():
        usage = shutil.disk_usage(settings.lab_root)
        disk = {
            "path": str(settings.lab_root),
            "free_bytes": usage.free,
            "total_bytes": usage.total,
        }
    data = {
        "release": _release(settings),
        "experiments": experiments,
        "runs": counts,
        "selftest": selftest,
        "selftest_error": selftest_error,
        "disk": disk,
        "spend": None,  # not tracked in M0
    }
    if args.json:
        _json(data)
        return EXIT_OK

    _out(f"release: {data['release'] or 'none'}")
    _out(f"experiments: {experiments}")
    _out("runs: " + ", ".join(f"{k} {v}" for k, v in counts.items()))
    if selftest_error:
        _out(f"self-test: status unreadable ({selftest_error})")
    elif selftest is None or selftest["last_run"] is None:
        _out("self-test: never run")
    else:
        last, ok = selftest["last_run"], selftest["last_success"]
        mode = "quick" if last["quick"] else "full"
        verdict = "passed" if last["passed"] else "FAILED"
        _out(f"self-test: last {mode} run {verdict} at {_when(last['finished_at'])}")
        _out(f"self-test: last success at {_when(ok['finished_at']) if ok else 'never'}")
    if disk:
        free, total = disk["free_bytes"] / 2**30, disk["total_bytes"] / 2**30
        _out(f"disk: {free:.1f} GiB free of {total:.1f} GiB ({disk['path']})")
    _out("spend: not tracked yet (M0)")
    return EXIT_OK


# --------------------------------------------------------------------- runs ls


_RUN_COLUMNS: Final = (
    "run_id",
    "experiment_id",
    "arm",
    "target_id",
    "agent_id",
    "status",
    "end_status",
    "outcome",
    "created_at",
)


def _cmd_runs_ls(args: argparse.Namespace, settings: LabSettings) -> int:
    runs = _with_db(
        settings,
        lambda s: queries.list_runs(
            s, limit=args.limit, status=args.status, experiment_id=args.experiment
        ),
    )
    if args.json:
        _json([r.to_json() for r in runs])
        return EXIT_OK
    if not runs:
        _out("no runs")
        return EXIT_OK
    rows = [
        [
            r.run_id,
            r.experiment_id,
            r.arm,
            r.target_id,
            r.agent_id,
            r.status,
            r.end_status or "-",
            "-" if r.outcome is None else str(r.outcome).lower(),
            _dt(r.created_at),
        ]
        for r in runs
    ]
    widths = [max(len(c), *(len(row[i]) for row in rows)) for i, c in enumerate(_RUN_COLUMNS)]
    for row in [list(_RUN_COLUMNS), *rows]:
        _out("  ".join(cell.ljust(w) for cell, w in zip(row, widths, strict=True)).rstrip())
    return EXIT_OK


# --------------------------------------------------------------------- run show


def _cmd_run_show(args: argparse.Namespace, settings: LabSettings) -> int:
    detail = _with_db(settings, lambda s: queries.get_run(s, args.run_id))
    if detail is None:
        raise _Failure(f"no such run: {args.run_id}")
    data = detail.to_json()
    if args.json:
        _json(data)
        return EXIT_OK
    scalar = [
        "run_id", "experiment_id", "pair_id", "arm", "schedule_index", "attempt", "target_id",
        "agent_id", "model_id", "status", "end_status", "outcome", "oracle_message", "tag",
        "manifest_sha256", "created_at", "started_at", "finished_at", "decided_at",
        "placements", "artifacts", "rejected_batches",
    ]  # fmt: skip
    width = max(map(len, scalar))
    for key in scalar:
        value = data[key]
        shown = "-" if value is None else str(value).lower() if isinstance(value, bool) else value
        _out(f"{key.ljust(width)}  {shown}")
    hb = data["last_heartbeat"]
    _out(
        f"{'heartbeat'.ljust(width)}  "
        + ("-" if hb is None else f"{hb['phase']} (seq {hb['seq']}, {hb['ts']})")
    )
    _out("events:" + ("" if data["events"] else " none"))
    for kind, n in data["events"].items():
        _out(f"  {kind}: {n}")
    _out("labels:" + ("" if data["labels"] else " none"))
    for label in data["labels"]:
        value = str(label["value"]).lower()
        _out(f"  {label['stage']}: {value} ({label['labeler']} {label['labeler_version']})")
    return EXIT_OK


# --------------------------------------------------------------------- selftest stub


def _cmd_selftest(args: argparse.Namespace, settings: LabSettings) -> int:
    sys.stderr.write(SELFTEST_STUB_MESSAGE + "\n")
    return EXIT_USAGE


# --------------------------------------------------------------------- parser


def _positive(value: str) -> int:
    n = int(value)
    if n < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return n


def _cell_range(value: str) -> IPv4Network:
    try:
        return IPv4Network(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="labctl", description="LLM Diversion Lab control CLI (read-only except selftest)."
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMAND", required=True)

    def add(
        name: str, help_: str, handler: Callable[..., int], parent: Any = sub
    ) -> argparse.ArgumentParser:
        p: argparse.ArgumentParser = parent.add_parser(name, help=help_, description=help_)
        p.set_defaults(handler=handler)
        return p

    p = add("doctor", "check that this host is ready to run the lab", _cmd_doctor)
    p.add_argument("--json", action="store_true", help="JSON output")
    p.add_argument(
        "--cell-range",
        type=_cell_range,
        default=doctor.DEFAULT_CELL_RANGE,
        help=f"LAB_CELL_NETWORKS must lie inside this (default {doctor.DEFAULT_CELL_RANGE})",
    )

    p = add("status", "summary: release, runs, experiments, last self-test, disk", _cmd_status)
    p.add_argument("--json", action="store_true", help="JSON output")

    runs = sub.add_parser("runs", help="list runs", description="list runs")
    runs_sub = runs.add_subparsers(dest="runs_command", metavar="COMMAND", required=True)
    p = add("ls", "list runs, newest first", _cmd_runs_ls, parent=runs_sub)
    p.add_argument("-n", "--limit", type=_positive, default=50, help="at most N runs (default 50)")
    p.add_argument(
        "--status", type=RunStatus, choices=list(RunStatus), help="only runs in this status"
    )
    p.add_argument("--experiment", metavar="ID", help="only runs of this experiment")
    p.add_argument("--json", action="store_true", help="JSON output")

    run = sub.add_parser("run", help="show one run", description="show one run")
    run_sub = run.add_subparsers(dest="run_command", metavar="COMMAND", required=True)
    p = add("show", "show one run and its evidence counts", _cmd_run_show, parent=run_sub)
    p.add_argument("run_id", metavar="RUN_ID")
    p.add_argument("--json", action="store_true", help="JSON output")

    p = add("selftest", "instrumentation self-test (not built yet: Task 15b-2)", _cmd_selftest)
    p.add_argument("--quick", action="store_true", help="one target only")
    return parser


def _dispatch(args: argparse.Namespace) -> int:
    settings = LabSettings.from_environ()
    try:
        return int(args.handler(args, settings))
    except _Failure as exc:
        sys.stderr.write(f"labctl {args.command}: {exc}\n")
        return exc.code


def main(argv: Sequence[str] | None = None) -> int:
    """Run labctl; returns the exit status (also used as the console-script entry)."""
    configure_logging(level="WARNING", stream=sys.stderr)
    try:
        args = build_parser().parse_args(argv)
    except SystemExit as exc:  # argparse: --help (0) or a usage error (2)
        return exc.code if isinstance(exc.code, int) else EXIT_USAGE
    return _dispatch(args)


if __name__ == "__main__":
    raise SystemExit(main())
