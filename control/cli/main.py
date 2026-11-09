"""``labctl``: the lab's command line (docs/TRACKING.md §3.3).

Commands (each takes ``--json`` for scripting):

* ``labctl doctor [--cell-range CIDR]``: host readiness checks (:mod:`control.cli.doctor`).
* ``labctl status``: release, runs by status, experiments, last self-test, disk.
* ``labctl runs ls [-n N] [--status S] [--experiment ID]``: runs, newest first.
* ``labctl run show RUN_ID``: one run with its evidence counts.
* ``labctl selftest [--quick] [--json]``: the instrumentation self-test
  (:mod:`control.runner.selftest`): one injected and one control DVGA cell with the
  scripted agent and the stub LLM, a containment probe, and the checks; the result is
  recorded in the self-test status file (``labctl status``, ``/metrics``), after an
  "in progress" marker recorded before it starts. SIGTERM and SIGHUP end it through
  ``SystemExit`` (exit 128 + signal), so its cell is still torn down.

Exit status: 0 success (the self-test passed); 1 a check failed, the self-test failed
(an unusable ``DATABASE_URL`` included: it is recorded), the database is unreachable or
the run does not exist; 2 usage error (for the read-only commands, an unparsable
``DATABASE_URL`` too). Never 3: ``deploy/remote/release.sh`` reads 3 as "labctl
is not installed".

Every command first calls :func:`~control.core.logging.configure_logging` (redacted
JSON on **stderr**, level WARNING), so any log line, ours or a library's, is redacted
and never mixes with the command's output on stdout. The database is only read (see
:mod:`control.cli.queries`); where it is comes from :mod:`control.cli.settings`.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import shutil
import signal
import sys
import time
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
from control.core.selftest_status import (
    SelftestResult,
    SelftestStatusError,
    read_selftest_status,
    record_selftest_result,
)
from control.db.engine import create_db_engine
from control.runner import selftest

__all__ = ["EXIT_FAIL", "EXIT_OK", "EXIT_USAGE", "build_parser", "main"]

EXIT_OK: Final = 0
EXIT_FAIL: Final = 1
EXIT_USAGE: Final = 2


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
        if not last["passed"] and last["summary"]:  # e.g. still in progress, or aborted
            _out(f"self-test: {last['summary'][:300]}")
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
    "invalid_reason",
    "end_status",
    "outcome",
    "dev",
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
            r.invalid_reason or "-",
            r.end_status or "-",
            "-" if r.outcome is None else str(r.outcome).lower(),
            "yes" if r.dev else "no",
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
        "agent_id", "model_id", "status", "invalid_reason", "invalid_detail", "end_status",
        "outcome", "oracle_message", "tag", "dev", "manifest_sha256", "created_at",
        "started_at", "finished_at", "decided_at", "placements", "artifacts",
        "rejected_batches",
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


# --------------------------------------------------------------------- selftest


def _exit_on_signals() -> dict[int, Any]:
    """Make SIGTERM and SIGHUP (a stopped service, a dropped SSH session) raise
    ``SystemExit(128 + signal)``, so ``finally`` blocks run: the runner tears the cell
    down. Returns the previous handlers."""

    def _exit(signum: int, _frame: Any) -> None:
        raise SystemExit(128 + signum)

    return {sig: signal.signal(sig, _exit) for sig in (signal.SIGTERM, signal.SIGHUP)}


def _record(settings: LabSettings, result: SelftestResult) -> None:
    try:
        record_selftest_result(result, settings.selftest_status_file)
    except OSError as exc:
        raise _Failure(
            f"the result could not be recorded in {settings.selftest_status_file}: {exc}"
        ) from None


def _cmd_selftest(args: argparse.Namespace, settings: LabSettings) -> int:
    """Run the self-test, record its result once, print it; 0 passed, 1 failed.

    Every failure past argument parsing is recorded, a bad ``DATABASE_URL`` and an
    internal error included (exit 1; exit 2 is only for argparse usage errors). Before
    it runs, an "in progress" result (failed) is recorded, so a self-test that is
    killed never leaves an earlier pass as the last run; SIGTERM and SIGHUP end it
    through ``SystemExit`` (the cell is torn down) and record it as aborted.
    """
    # progress (runs, phases, problems) goes to stderr; the result to stdout
    configure_logging(level="INFO", stream=sys.stderr)
    started = time.time()
    _record(
        settings,
        SelftestResult(
            False,
            started,
            args.quick,
            f"in progress since {_when(started)} (if this stays, the self-test was aborted)",
        ),
    )
    previous = _exit_on_signals()
    try:
        report = _selftest_report(args, settings)
    except Exception as exc:  # never unrecorded
        report = selftest.failed_report(
            args.quick, "internal", redact_text(f"{type(exc).__name__}: {exc}")[:300]
        )
    except BaseException as exc:  # SystemExit (a signal), KeyboardInterrupt
        code = exc.code if isinstance(exc, SystemExit) else type(exc).__name__
        # if this cannot be written, the in-progress marker stays: it reads as aborted too
        with contextlib.suppress(OSError):
            record_selftest_result(
                SelftestResult(
                    False,
                    time.time(),
                    args.quick,
                    f"aborted ({code}) after starting at {_when(started)}",
                ),
                settings.selftest_status_file,
            )
        raise
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    try:
        _out(
            json.dumps(report.to_json(), indent=2, default=str)
            if args.json
            else report.render_text()
        )
    finally:
        _record(
            settings,
            SelftestResult(report.passed, report.finished_at, args.quick, report.summary),
        )
    return EXIT_OK if report.passed else EXIT_FAIL


def _selftest_report(args: argparse.Namespace, settings: LabSettings) -> selftest.SelftestReport:
    try:
        engine = _engine(settings)
    except _Failure as exc:  # no database (or an unparsable URL): a failed self-test
        return selftest.failed_report(args.quick, "configuration", str(exc))
    try:
        context = selftest.LabContext(
            lab_root=settings.lab_root,
            environ=settings.environ,
            collector_url=settings.collector_url,
            engine=engine,
        )
        return selftest.run_lab_selftest(context, quick=args.quick)
    finally:
        engine.dispose()


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

    p = add(
        "selftest",
        "instrumentation self-test: an injected and a control cell, containment probe",
        _cmd_selftest,
    )
    p.add_argument(
        "--quick",
        action="store_true",
        help="first target only, containment probed in one cell (after a deploy)",
    )
    p.add_argument("--json", action="store_true", help="JSON output")
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
