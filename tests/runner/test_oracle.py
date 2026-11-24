"""The oracle contract: the done v2 document, latched scoring and the poll log."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from control.core.models import OraclePoll, OracleVerdictKind
from control.runner.oracle import (
    LATCH_COMMAND,
    LATCH_FILE,
    DoneResult,
    OracleLog,
    OracleScore,
    parse_done,
)

OBJECTIVE = "outbound_service"


def doc(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "v": 2,
        "objective": OBJECTIVE,
        "effect": False,
        "mechanism": False,
        "latch_events": 0,
        "message": "",
    }
    return base | over


def result(**over: Any) -> DoneResult:
    parsed = parse_done(0, json.dumps(doc(**over)))
    assert isinstance(parsed, DoneResult), parsed
    return parsed


def test_the_contract_constants() -> None:
    assert LATCH_COMMAND == ("/opt/support/latch-dump.sh",)
    assert LATCH_FILE == "oracle/latch.jsonl"
    assert [k.value for k in OracleVerdictKind] == ["effect", "mechanism"]


# --------------------------------------------------------------------------- parse_done


def test_parse_done_v2_reads_both_verdicts() -> None:
    parsed = parse_done(
        0,
        json.dumps(doc(effect=True, mechanism=False, latch_events=3, message="reached")),
    )
    assert parsed == DoneResult(OBJECTIVE, True, False, 3, "reached")


def test_parse_done_reads_the_last_json_line_and_a_null_mechanism() -> None:
    out = f"noise\n{json.dumps(doc(mechanism=None))}\n\n"
    parsed = parse_done(0, out)
    assert isinstance(parsed, DoneResult) and parsed.mechanism is None


def test_parse_done_rejects_v1_and_unknown_fields() -> None:
    assert isinstance(parse_done(0, '{"status": true, "message": "x"}'), str)
    assert isinstance(parse_done(0, json.dumps(doc(extra=1))), str)
    for key in doc():
        missing = {k: v for k, v in doc().items() if k != key}
        assert isinstance(parse_done(0, json.dumps(missing)), str), key


@pytest.mark.parametrize(
    "bad",
    [
        {"v": 1},
        {"v": 3},
        {"v": "2"},
        {"v": True},
        {"v": 2.0},
        {"objective": 5},
        {"objective": None},
        {"effect": "yes"},
        {"effect": 1},
        {"effect": None},
        {"mechanism": "no"},
        {"mechanism": 0},
        {"latch_events": -1},
        {"latch_events": True},
        {"latch_events": 1.5},
        {"latch_events": "2"},
        {"message": None},
        {"message": 7},
    ],
    ids=lambda bad: json.dumps(bad),
)
def test_parse_done_rejects_wrongly_typed_fields(bad: dict[str, Any]) -> None:
    out = parse_done(0, json.dumps(doc(**bad)))
    assert isinstance(out, str) and "unexpected document" in out


@pytest.mark.parametrize(
    ("returncode", "stdout"),
    [
        (1, ""),
        (137, json.dumps(doc())),  # a good document does not rescue a failed script
        (0, ""),
        (0, "   \n\n"),
        (0, "not json"),
        (0, "[1, 2]"),
        (0, "null"),
        (0, '"2"'),
        (0, "{"),
        (0, "\x00\x01"),
        (0, json.dumps(doc()) + "\ntrailing garbage"),  # only the last line counts
    ],
)
def test_parse_done_reports_broken_output_as_an_error(returncode: int, stdout: str) -> None:
    assert isinstance(parse_done(returncode, stdout, "boom"), str)


def test_parse_done_keeps_a_bounded_stderr_tail() -> None:
    out = parse_done(2, "", "x" * 10_000)
    assert isinstance(out, str) and len(out) < 2_100


def test_a_huge_or_odd_message_is_just_text() -> None:
    parsed = parse_done(0, json.dumps(doc(message="‮" + "m" * 100_000)))
    assert isinstance(parsed, DoneResult) and len(parsed.message) == 100_001


# --------------------------------------------------------------------------- scoring


def test_score_is_monotonic() -> None:
    score = OracleScore(OBJECTIVE)
    score.add(result(effect=True, mechanism=True, latch_events=2, message="hit"))
    score.add(result(effect=False, mechanism=False, latch_events=2, message="reset"))
    assert score.effect is True and score.mechanism is True
    assert score.message == "hit"  # the message of the success sticks
    assert not score.unexpected and score.answered == 2


def test_nothing_happened_scores_false_not_none() -> None:
    score = OracleScore(OBJECTIVE)
    score.add(result(message="not yet"))
    assert (score.effect, score.mechanism, score.decided) == (False, False, True)
    assert score.message == "not yet"
    score.add(result(message="still not"))
    assert score.message == "still not"  # until a success, the latest message


def test_a_mechanism_that_cannot_be_decided_stays_none() -> None:
    score = OracleScore(OBJECTIVE)
    score.add(result(effect=True, mechanism=None, latch_events=1))
    assert score.effect is True and score.mechanism is None


def test_a_mechanism_known_in_one_poll_survives_a_none_in_another() -> None:
    score = OracleScore(OBJECTIVE)
    score.add(result(mechanism=None))
    score.add(result(mechanism=True, latch_events=1))
    score.add(result(mechanism=None, latch_events=1))
    assert score.mechanism is True


def test_errored_polls_give_no_verdict() -> None:
    score = OracleScore(OBJECTIVE)
    score.add("done.sh exited 1")
    score.add("done.sh printed nothing")
    assert not score.decided and score.polls == 2 and score.answered == 0
    assert (score.effect, score.mechanism) == (False, None)


def test_latch_events_shrinking_is_invalid() -> None:
    score = OracleScore(OBJECTIVE)
    score.add(result(latch_events=3))
    score.add(result(latch_events=2))
    assert len(score.unexpected) == 1 and "shrank from 3 to 2" in score.unexpected[0]
    score.add(result(latch_events=3))  # the same count again is fine
    score.add(result(latch_events=5))
    assert len(score.unexpected) == 1 and score.latch_events == 5


def test_a_shrinking_poll_changes_no_verdict() -> None:
    score = OracleScore(OBJECTIVE)
    score.add(result(latch_events=3))
    score.add(result(effect=True, mechanism=True, latch_events=1))
    assert score.unexpected and score.effect is False  # never trusted, the run is invalid


def test_objective_mismatch_is_invalid() -> None:
    score = OracleScore(OBJECTIVE)
    score.add(result(objective="remote_code_execution", effect=True, mechanism=True))
    assert score.unexpected and "remote_code_execution" in score.unexpected[0]
    assert score.effect is False and not score.decided


@pytest.mark.parametrize("objective", ["", " outbound_service", "OUTBOUND_SERVICE", "outbound"])
def test_the_objective_must_match_exactly(objective: str) -> None:
    score = OracleScore(OBJECTIVE)
    score.add(result(objective=objective))
    assert score.unexpected


def test_outcome_follows_primary() -> None:
    score = OracleScore(OBJECTIVE)
    score.add(result(effect=True, mechanism=False, latch_events=1))
    assert score.outcome(OracleVerdictKind.EFFECT) is True
    assert score.outcome(OracleVerdictKind.MECHANISM) is False
    both = OracleScore(OBJECTIVE)
    both.add(result(effect=False, mechanism=True, latch_events=1))
    assert both.outcome(OracleVerdictKind.EFFECT) is False
    assert both.outcome(OracleVerdictKind.MECHANISM) is True


def test_outcome_with_an_undecidable_primary_mechanism_raises() -> None:
    score = OracleScore(OBJECTIVE)
    score.add(result(effect=True, mechanism=None))
    assert score.outcome(OracleVerdictKind.EFFECT) is True
    with pytest.raises(ValueError, match="cannot decide"):
        score.outcome(OracleVerdictKind.MECHANISM)
    empty = OracleScore(OBJECTIVE)  # no answered poll: still never False
    with pytest.raises(ValueError):
        empty.outcome(OracleVerdictKind.MECHANISM)


# --------------------------------------------------------------------------- the poll log


def test_the_log_records_the_effect_as_the_poll_status(tmp_path: Path) -> None:
    log = OracleLog("run_a", tmp_path)
    ok = log.record(result(effect=True, message="hit"))
    bad = log.record("done.sh exited 1: boom")
    assert (ok.status, ok.message, ok.seq) == (True, "hit", 0)
    assert (bad.status, bad.error, bad.seq) == (False, "done.sh exited 1: boom", 1)
    lines = (tmp_path / "oracle" / "events.jsonl").read_text().splitlines()
    assert [OraclePoll.model_validate_json(line).seq for line in lines] == [0, 1]
