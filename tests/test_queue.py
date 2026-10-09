import pytest

from builders import at, zabbix_problem
from tia import db, intake, queue
from tia.config import Config
from tia.models import AnalysisState, Source
from tia.normalize import normalize_zabbix


def _ingest(conn, cfg, rules, now, n, severity=2, clock=1790661060):
    raw = zabbix_problem(event_id=f"e{n}", trigger_id=f"t{n}", severity=severity, clock=clock)
    return intake.apply(conn, normalize_zabbix(raw, cfg, rules), now, cfg).incident_id


def _state(conn, incident_id):
    return conn.execute("SELECT analysis_state FROM incidents WHERE id = ?", (incident_id,)).fetchone()[0]


def _queued(conn, cfg, rules, now, n, **kwargs):
    incident_id = _ingest(conn, cfg, rules, now, n, **kwargs)
    queue.promote_held(conn, at(now, 60))
    return incident_id


def test_held_incident_is_promoted_when_the_hold_ends(conn, cfg, rules, now):
    incident_id = _ingest(conn, cfg, rules, now, 1)
    assert queue.promote_held(conn, at(now, 59)) == 0
    assert _state(conn, incident_id) == AnalysisState.HELD
    assert queue.promote_held(conn, at(now, 60)) == 1
    assert _state(conn, incident_id) == AnalysisState.QUEUED


def test_nothing_waiting_gives_none(conn, cfg, now):
    assert queue.next_candidate(conn, now, cfg) is None


def test_held_incident_is_not_a_candidate(conn, cfg, rules, now):
    _ingest(conn, cfg, rules, now, 1)
    assert queue.next_candidate(conn, at(now, 10), cfg) is None


def test_order_is_priority_then_severity_then_age(conn, cfg, rules, now):
    old_warning = _queued(conn, cfg, rules, now, 1, severity=2, clock=1790661000)
    new_warning = _queued(conn, cfg, rules, now, 2, severity=2, clock=1790661050)
    high = _queued(conn, cfg, rules, now, 3, severity=4, clock=1790661055)
    order = []
    for _ in range(3):
        row = queue.next_candidate(conn, at(now, 70), cfg)
        order.append(row["id"])
        queue.start(conn, row["id"], at(now, 70))
        queue.complete(conn, row["id"], at(now, 80), urgency="経過観察", kind="性能", summary="s")
    assert order == [high, old_warning, new_warning]
    assert queue.next_candidate(conn, at(now, 90), cfg) is None


def test_prioritized_incident_goes_first_and_leaves_the_hold(conn, cfg, rules, now):
    _queued(conn, cfg, rules, now, 1, severity=4)
    waiting = _ingest(conn, cfg, rules, at(now, 61), 2, severity=2)
    queue.prioritize(conn, waiting, at(now, 62))
    assert queue.next_candidate(conn, at(now, 63), cfg)["id"] == waiting


def test_only_one_incident_runs_at_a_time(conn, cfg, rules, now):
    first = _queued(conn, cfg, rules, now, 1)
    second = _queued(conn, cfg, rules, now, 2)
    queue.start(conn, first, at(now, 70))
    with pytest.raises(queue.StateError, match="同時に解析するのは 1 件"):
        queue.start(conn, second, at(now, 71))


def test_complete_stores_the_result(conn, cfg, rules, now):
    incident_id = _queued(conn, cfg, rules, now, 1)
    queue.start(conn, incident_id, at(now, 70))
    queue.complete(conn, incident_id, at(now, 160), urgency="今日中", kind="性能", summary="要約", analysis_id=7)
    row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    assert (row["analysis_state"], row["urgency"], row["kind"], row["summary"], row["latest_analysis_id"]) == (
        AnalysisState.DONE, "今日中", "性能", "要約", 7)


def test_three_retries_then_failed(conn, cfg, rules, now):
    incident_id = _queued(conn, cfg, rules, now, 1)
    clock = at(now, 70)
    waits = []
    for _ in range(3):
        queue.start(conn, incident_id, clock)
        assert queue.fail(conn, incident_id, clock, "LLM が応答しない", cfg) == AnalysisState.RETRY_WAIT
        row = conn.execute("SELECT next_retry_at FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        waits.append(row["next_retry_at"])
        assert queue.next_candidate(conn, clock, cfg) is None
        clock = at(clock, cfg.queue_retry_delays_sec[len(waits) - 1])
        assert queue.next_candidate(conn, clock, cfg)["id"] == incident_id
    queue.start(conn, incident_id, clock)
    assert queue.fail(conn, incident_id, clock, "LLM が応答しない", cfg) == AnalysisState.FAILED
    row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    assert row["analysis_state"] == AnalysisState.FAILED
    assert row["fail_reason"] == "LLM が応答しない"
    assert row["attempt_count"] == 4
    assert waits == ["2026-09-29T05:59:10+00:00", "2026-09-29T06:04:10+00:00", "2026-09-29T06:19:10+00:00"]


def test_no_retries_configured_fails_at_once(conn, rules, now):
    cfg = Config(queue_retry_delays_sec=())
    incident_id = _queued(conn, cfg, rules, now, 1)
    queue.start(conn, incident_id, at(now, 70))
    assert queue.fail(conn, incident_id, at(now, 71), "x", cfg) == AnalysisState.FAILED


def test_incident_resolved_long_ago_is_skipped(conn, cfg, rules, now):
    incident_id = _queued(conn, cfg, rules, now, 1)
    intake.resolve(conn, Source.ZABBIX, "e1", at(now, 120), at(now, 120))
    assert queue.next_candidate(conn, at(now, 120 + 21600), cfg)["id"] == incident_id
    assert queue.next_candidate(conn, at(now, 120 + 21601), cfg) is None
    row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    assert (row["analysis_state"], row["skip_reason"]) == (AnalysisState.SKIPPED, "resolved_too_long")


def test_followup_is_queued_once_for_a_long_open_problem(conn, cfg, rules, now):
    incident_id = _queued(conn, cfg, rules, now, 1, clock=1790661420)
    queue.start(conn, incident_id, at(now, 70))
    queue.complete(conn, incident_id, at(now, 160), urgency="今日中", kind="性能", summary="s")
    assert queue.schedule_followups(conn, at(now, 160 + 7199), cfg) == 0
    assert queue.schedule_followups(conn, at(now, 160 + 7200), cfg) == 1
    row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    assert (row["analysis_state"], row["queue_reason"]) == (AnalysisState.QUEUED, "followup")
    queue.start(conn, incident_id, at(now, 7370))
    queue.complete(conn, incident_id, at(now, 7460), urgency="今日中", kind="性能", summary="s")
    assert queue.schedule_followups(conn, at(now, 20000), cfg) == 0


def test_resolved_problem_gets_no_followup(conn, cfg, rules, now):
    incident_id = _queued(conn, cfg, rules, now, 1, clock=1790661420)
    queue.start(conn, incident_id, at(now, 70))
    queue.complete(conn, incident_id, at(now, 160), urgency="今日中", kind="性能", summary="s")
    intake.resolve(conn, Source.ZABBIX, "e1", at(now, 200), at(now, 200))
    assert queue.schedule_followups(conn, at(now, 9000), cfg) == 0


def test_manual_skip_and_requeue(conn, cfg, rules, now):
    incident_id = _queued(conn, cfg, rules, now, 1)
    queue.skip_manually(conn, incident_id, at(now, 70), "試験用の機器")
    row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    assert (row["analysis_state"], row["skip_reason"]) == (AnalysisState.SKIPPED, "manual: 試験用の機器")
    queue.requeue(conn, incident_id, at(now, 80))
    assert _state(conn, incident_id) == AnalysisState.QUEUED


@pytest.mark.parametrize("operation", ["complete", "fail", "release", "prioritize", "skip", "requeue"])
def test_operations_reject_the_wrong_state(conn, cfg, rules, now, operation):
    incident_id = _queued(conn, cfg, rules, now, 1)
    queue.start(conn, incident_id, at(now, 70))
    if operation in ("complete", "fail", "release"):
        queue.complete(conn, incident_id, at(now, 80), urgency="無視可", kind="ノイズ", summary="s")
    calls = {
        "complete": lambda: queue.complete(conn, incident_id, now, urgency="a", kind="b", summary="c"),
        "fail": lambda: queue.fail(conn, incident_id, now, "x", cfg),
        "release": lambda: queue.release(conn, incident_id, now, "x"),
        "prioritize": lambda: queue.prioritize(conn, incident_id, now),
        "skip": lambda: queue.skip_manually(conn, incident_id, now, "x"),
        "requeue": lambda: queue.requeue(conn, incident_id, now),
    }
    with pytest.raises(queue.StateError):
        calls[operation]()


def test_unknown_incident_is_an_error(conn, now):
    with pytest.raises(queue.StateError, match="がない"):
        queue.start(conn, 999, now)


def _incident(conn, incident_id):
    return conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()


def _event_types(conn, incident_id):
    return [r["type"] for r in conn.execute("SELECT type FROM events WHERE incident_id = ? ORDER BY id",
                                            (incident_id,))]


def test_release_returns_a_running_incident_without_using_an_attempt(conn, cfg, rules, now):
    incident_id = _queued(conn, cfg, rules, now, 1)
    queue.start(conn, incident_id, at(now, 70))
    queue.release(conn, incident_id, at(now, 75), "llm_unreachable")
    row = _incident(conn, incident_id)
    assert (row["analysis_state"], row["attempt_count"], row["next_retry_at"]) == (AnalysisState.QUEUED, 0, None)
    assert _event_types(conn, incident_id)[-1] == "released"
    detail = conn.execute("SELECT detail_json FROM events WHERE incident_id = ? ORDER BY id DESC LIMIT 1",
                          (incident_id,)).fetchone()[0]
    assert "llm_unreachable" in detail
    assert queue.next_candidate(conn, at(now, 76), cfg)["id"] == incident_id


def test_five_releases_in_a_row_never_fail_the_incident(conn, cfg, rules, now):
    incident_id = _queued(conn, cfg, rules, now, 1)
    for n in range(5):
        queue.start(conn, incident_id, at(now, 70 + n * 10))
        queue.release(conn, incident_id, at(now, 75 + n * 10), "llm_unreachable")
        assert _state(conn, incident_id) == AnalysisState.QUEUED
    assert _incident(conn, incident_id)["attempt_count"] == 0
    queue.start(conn, incident_id, at(now, 200))
    assert queue.fail(conn, incident_id, at(now, 210), "timeout", cfg) == AnalysisState.RETRY_WAIT
    assert _incident(conn, incident_id)["next_retry_at"] == "2026-09-29T06:01:30+00:00"


def test_release_keeps_the_attempts_already_used(conn, cfg, rules, now):
    incident_id = _queued(conn, cfg, rules, now, 1)
    queue.start(conn, incident_id, at(now, 70))
    queue.fail(conn, incident_id, at(now, 80), "timeout", cfg)
    queue.start(conn, incident_id, at(now, 140))
    queue.release(conn, incident_id, at(now, 150), "llm_unreachable")
    assert _incident(conn, incident_id)["attempt_count"] == 1


def test_running_incident_is_recovered_after_a_restart(tmp_path, cfg, rules, now):
    path = tmp_path / "tia.sqlite"
    before = db.connect(path)
    one = _queued(before, cfg, rules, now, 1, severity=4)
    two = _queued(before, cfg, rules, now, 2)
    queue.start(before, one, at(now, 70))
    before.close()
    after = db.connect(path)
    assert queue.recover_running(after, at(now, 300)) == 1
    assert queue.recover_running(after, at(now, 301)) == 0
    assert _state(after, one) == AnalysisState.QUEUED
    assert _event_types(after, one)[-1] == "released"
    candidate = queue.next_candidate(after, at(now, 310), cfg)
    assert candidate["id"] == one
    queue.start(after, candidate["id"], at(now, 311))
    assert [_state(after, one), _state(after, two)] == [AnalysisState.RUNNING, AnalysisState.QUEUED]
    after.close()


def test_complete_records_when_the_analysis_finished(conn, cfg, rules, now):
    incident_id = _queued(conn, cfg, rules, now, 1)
    assert _incident(conn, incident_id)["analyzed_at"] is None
    queue.start(conn, incident_id, at(now, 70))
    queue.complete(conn, incident_id, at(now, 160), urgency="今日中", kind="性能", summary="s")
    assert _incident(conn, incident_id)["analyzed_at"] == "2026-09-29T05:59:40+00:00"


def test_problem_open_for_hours_gets_no_followup_right_after_the_analysis(conn, cfg, rules, now):
    incident_id = _queued(conn, cfg, rules, now, 1, clock=1790661420 - 3 * 3600)
    queue.start(conn, incident_id, at(now, 70))
    queue.complete(conn, incident_id, at(now, 160), urgency="今日中", kind="性能", summary="s")
    assert queue.schedule_followups(conn, at(now, 165), cfg) == 0
    assert _state(conn, incident_id) == AnalysisState.DONE
    assert queue.schedule_followups(conn, at(now, 160 + 7200), cfg) == 1


def _analysed_and_resolved(conn, cfg, rules, now):
    incident_id = _queued(conn, cfg, rules, now, 1)
    queue.start(conn, incident_id, at(now, 70))
    queue.complete(conn, incident_id, at(now, 160), urgency="今日中", kind="性能", summary="s")
    intake.resolve(conn, Source.ZABBIX, "e1", at(now, 200), at(now, 200))
    return incident_id


def test_requeued_incident_is_analysed_even_if_it_recovered_long_ago(conn, cfg, rules, now):
    incident_id = _analysed_and_resolved(conn, cfg, rules, now)
    later = 200 + 7 * 3600
    queue.requeue(conn, incident_id, at(now, later))
    candidate = queue.next_candidate(conn, at(now, later + 5), cfg)
    assert candidate is not None and candidate["id"] == incident_id
    row = _incident(conn, incident_id)
    assert (row["analysis_state"], row["queue_reason"], row["skip_reason"]) == (AnalysisState.QUEUED, "manual", None)


def test_prioritized_incident_is_analysed_even_if_it_recovered_long_ago(conn, cfg, rules, now):
    incident_id = _queued(conn, cfg, rules, now, 1)
    intake.resolve(conn, Source.ZABBIX, "e1", at(now, 120), at(now, 120))
    queue.prioritize(conn, incident_id, at(now, 130))
    candidate = queue.next_candidate(conn, at(now, 120 + 7 * 3600), cfg)
    assert candidate is not None and candidate["id"] == incident_id
    assert _state(conn, incident_id) == AnalysisState.QUEUED



def test_validation_failures_are_not_retried_but_timeouts_are(conn, cfg, rules, now):
    """推奨の中身による失敗は、同じ入力でやり直しても直らない。再試行は通信と時間切れだけ。"""
    incident_id = _queued(conn, cfg, rules, now, 1)
    queue.start(conn, incident_id, at(now, 70))
    assert queue.fail(conn, incident_id, at(now, 71), "validation: $.impact", cfg, retry=False) == AnalysisState.FAILED
    row = conn.execute("SELECT analysis_state, attempt_count FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    assert (row["analysis_state"], row["attempt_count"]) == (AnalysisState.FAILED, 1)
    kinds = [r["type"] for r in conn.execute("SELECT type FROM events WHERE incident_id = ? ORDER BY id", (incident_id,))]
    assert "retry_scheduled" not in kinds and kinds[-1] == "analysis_failed"
    other = _queued(conn, cfg, rules, now, 2)
    queue.start(conn, other, at(now, 80))
    assert queue.fail(conn, other, at(now, 81), "timeout", cfg) == AnalysisState.RETRY_WAIT
