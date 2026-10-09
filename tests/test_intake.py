from builders import at, wazuh_hit, zabbix_problem
from tia import intake, queue
from tia.models import AnalysisState, ProblemStatus, Source
from tia.normalize import normalize_wazuh, normalize_zabbix


def _row(conn, incident_id):
    return conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()


def _events(conn, incident_id):
    return [r["type"] for r in conn.execute("SELECT type FROM events WHERE incident_id = ? ORDER BY id",
                                            (incident_id,))]


def test_new_zabbix_alert_is_held(conn, cfg, rules, now):
    result = intake.apply(conn, normalize_zabbix(zabbix_problem(), cfg, rules), now, cfg)
    row = _row(conn, result.incident_id)
    assert result.outcome == "created"
    assert row["analysis_state"] == AnalysisState.HELD
    assert row["held_until"] == "2026-09-29T05:58:00+00:00"
    assert row["occurrence_count"] == 1
    assert _events(conn, result.incident_id) == ["detected"]


def test_new_wazuh_alert_is_held_longer(conn, cfg, rules, now):
    result = intake.apply(conn, normalize_wazuh(wazuh_hit(), cfg, rules), now, cfg)
    assert _row(conn, result.incident_id)["held_until"] == "2026-09-29T05:59:00+00:00"


def test_same_alert_twice_changes_nothing(conn, cfg, rules, now):
    alert = normalize_zabbix(zabbix_problem(), cfg, rules)
    first = intake.apply(conn, alert, now, cfg)
    second = intake.apply(conn, alert, at(now, 30), cfg)
    assert second == intake.IntakeResult(first.incident_id, "duplicate")
    assert conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0] == 1
    assert _row(conn, first.incident_id)["occurrence_count"] == 1


def test_below_threshold_is_stored_as_skipped(conn, cfg, rules, now):
    result = intake.apply(conn, normalize_zabbix(zabbix_problem(severity=1), cfg, rules), now, cfg)
    row = _row(conn, result.incident_id)
    assert result.outcome == "skipped"
    assert row["analysis_state"] == AnalysisState.SKIPPED
    assert row["skip_reason"] == "below_threshold"


def test_recurrence_within_30_minutes_is_counted(conn, cfg, rules, now):
    first = intake.apply(conn, normalize_zabbix(zabbix_problem(event_id="1"), cfg, rules), now, cfg)
    again = intake.apply(conn, normalize_zabbix(zabbix_problem(event_id="2", clock=1790661960), cfg, rules),
                         at(now, 900), cfg)
    row = _row(conn, first.incident_id)
    assert again == intake.IntakeResult(first.incident_id, "recurred")
    assert row["occurrence_count"] == 2
    assert row["last_occurrence_at"] == "2026-09-29T06:06:00+00:00"
    assert conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0] == 1


def test_recurrence_after_30_minutes_is_a_new_incident(conn, cfg, rules, now):
    first = intake.apply(conn, normalize_zabbix(zabbix_problem(event_id="1"), cfg, rules), now, cfg)
    intake.resolve(conn, Source.ZABBIX, "1", at(now, 120), at(now, 130))
    later = intake.apply(conn, normalize_zabbix(zabbix_problem(event_id="2", clock=1790664000), cfg, rules),
                         at(now, 3600), cfg)
    assert later.outcome == "created"
    assert later.incident_id != first.incident_id


def test_skipped_incident_does_not_absorb_a_recurrence(conn, cfg, rules, now):
    intake.apply(conn, normalize_zabbix(zabbix_problem(event_id="1", severity=1), cfg, rules), now, cfg)
    result = intake.apply(conn, normalize_zabbix(zabbix_problem(event_id="2", severity=3), cfg, rules),
                          at(now, 60), cfg)
    assert result.outcome == "created"


def test_recurred_alert_is_remembered(conn, cfg, rules, now):
    intake.apply(conn, normalize_zabbix(zabbix_problem(event_id="1"), cfg, rules), now, cfg)
    second = normalize_zabbix(zabbix_problem(event_id="2"), cfg, rules)
    intake.apply(conn, second, at(now, 60), cfg)
    assert intake.apply(conn, second, at(now, 90), cfg).outcome == "duplicate"
    assert conn.execute("SELECT occurrence_count FROM incidents").fetchone()[0] == 2


def test_severity_increase_queues_one_followup(conn, cfg, rules, now):
    first = intake.apply(conn, normalize_zabbix(zabbix_problem(event_id="1", severity=2), cfg, rules), now, cfg)
    conn.execute("UPDATE incidents SET analysis_state = 'done' WHERE id = ?", (first.incident_id,))
    intake.apply(conn, normalize_zabbix(zabbix_problem(event_id="2", severity=4), cfg, rules), at(now, 60), cfg)
    row = _row(conn, first.incident_id)
    assert row["analysis_state"] == AnalysisState.QUEUED
    assert row["severity"] == 4
    assert row["source_severity"] == "Zabbix High"
    assert row["followup_done"] == 1
    conn.execute("UPDATE incidents SET analysis_state = 'done' WHERE id = ?", (first.incident_id,))
    intake.apply(conn, normalize_zabbix(zabbix_problem(event_id="3", severity=5), cfg, rules), at(now, 120), cfg)
    assert _row(conn, first.incident_id)["analysis_state"] == AnalysisState.DONE


def test_resolve_marks_the_incident(conn, cfg, rules, now):
    result = intake.apply(conn, normalize_zabbix(zabbix_problem(), cfg, rules), now, cfg)
    assert intake.resolve(conn, Source.ZABBIX, "48213", at(now, 240), at(now, 250)) is True
    row = _row(conn, result.incident_id)
    assert row["problem_status"] == ProblemStatus.RESOLVED
    assert row["resolved_at"] == "2026-09-29T06:01:00+00:00"
    assert intake.resolve(conn, Source.ZABBIX, "48213", at(now, 240), at(now, 260)) is False
    assert _events(conn, result.incident_id) == ["detected", "resolved"]


def test_resolve_of_unknown_alert_is_ignored(conn, now):
    assert intake.resolve(conn, Source.ZABBIX, "nope", now, now) is False


def test_duplicate_that_arrives_resolved_marks_recovery(conn, cfg, rules, now):
    result = intake.apply(conn, normalize_zabbix(zabbix_problem(), cfg, rules), now, cfg)
    resolved = normalize_zabbix(zabbix_problem(r_eventid="9", r_clock="1790661300"), cfg, rules)
    assert intake.apply(conn, resolved, at(now, 300), cfg).outcome == "duplicate"
    assert _row(conn, result.incident_id)["problem_status"] == ProblemStatus.RESOLVED


def test_recurrence_reopens_a_resolved_incident(conn, cfg, rules, now):
    first = intake.apply(conn, normalize_zabbix(zabbix_problem(event_id="1"), cfg, rules), now, cfg)
    intake.resolve(conn, Source.ZABBIX, "1", at(now, 120), at(now, 120))
    intake.apply(conn, normalize_zabbix(zabbix_problem(event_id="2"), cfg, rules), at(now, 300), cfg)
    row = _row(conn, first.incident_id)
    assert row["problem_status"] == ProblemStatus.OPEN
    assert row["resolved_at"] is None
    assert "reopened" in _events(conn, first.incident_id)


def test_wazuh_burst_becomes_one_incident_with_a_count(conn, cfg, rules, now):
    for n in range(12):
        intake.apply(conn, normalize_wazuh(wazuh_hit(alert_id=f"w-{n}"), cfg, rules), at(now, n * 10), cfg)
    row = conn.execute("SELECT * FROM incidents").fetchall()
    assert len(row) == 1
    assert row[0]["occurrence_count"] == 12


T0 = 1790658000  # 2026-09-29T05:00:00Z


def _refs(conn, incident_id):
    return {r["external_id"]: r["resolved_at"] for r in conn.execute(
        "SELECT external_id, resolved_at FROM alert_refs WHERE incident_id = ?", (incident_id,))}


def test_backlog_of_wazuh_alerts_becomes_one_incident(conn, cfg, rules, now):
    arrival = at(now, 180)  # 06:00:00。収集が 1 時間止まっていた
    for n in range(12):
        stamp = f"2026-09-29T05:{n // 6:02d}:{n % 6 * 10:02d}.000+0000"
        intake.apply(conn, normalize_wazuh(wazuh_hit(alert_id=f"w-{n}", timestamp=stamp), cfg, rules), arrival, cfg)
    rows = conn.execute("SELECT * FROM incidents").fetchall()
    assert len(rows) == 1
    assert rows[0]["occurrence_count"] == 12
    assert rows[0]["started_at"] == "2026-09-29T05:00:00+00:00"
    assert rows[0]["last_occurrence_at"] == "2026-09-29T05:01:50+00:00"


def _long_problem_that_recovered(conn, cfg, rules, now):
    """05:00 に始まり 05:40 に復旧した問題。"""
    first = intake.apply(conn, normalize_zabbix(zabbix_problem(event_id="1", clock=T0), cfg, rules),
                         at(now, -3360), cfg)
    intake.resolve(conn, Source.ZABBIX, "1", at(now, -1020), at(now, -1000))
    assert _row(conn, first.incident_id)["resolved_at"] == "2026-09-29T05:40:00+00:00"
    return first


def test_recurrence_5_minutes_after_recovery_of_a_long_problem_is_counted(conn, cfg, rules, now):
    first = _long_problem_that_recovered(conn, cfg, rules, now)
    again = intake.apply(conn, normalize_zabbix(zabbix_problem(event_id="2", clock=T0 + 45 * 60), cfg, rules),
                         at(now, -700), cfg)
    assert again == intake.IntakeResult(first.incident_id, "recurred")
    assert _row(conn, first.incident_id)["problem_status"] == ProblemStatus.OPEN


def test_recurrence_31_minutes_after_recovery_is_a_new_incident(conn, cfg, rules, now):
    first = _long_problem_that_recovered(conn, cfg, rules, now)
    later = intake.apply(conn, normalize_zabbix(zabbix_problem(event_id="2", clock=T0 + 71 * 60), cfg, rules),
                         at(now, 900), cfg)
    assert later.outcome == "created"
    assert later.incident_id != first.incident_id


def test_open_problem_absorbs_a_recurrence_however_late(conn, cfg, rules, now):
    first = intake.apply(conn, normalize_zabbix(zabbix_problem(event_id="1"), cfg, rules), now, cfg)
    later = intake.apply(conn, normalize_zabbix(zabbix_problem(event_id="2", clock=1790664000), cfg, rules),
                         at(now, 3600), cfg)
    assert later == intake.IntakeResult(first.incident_id, "recurred")


def test_alert_far_older_than_the_incident_is_not_absorbed(conn, cfg, rules, now):
    first = intake.apply(conn, normalize_wazuh(wazuh_hit(alert_id="w-1"), cfg, rules), now, cfg)
    old = normalize_wazuh(wazuh_hit(alert_id="w-0", timestamp="2026-09-29T03:00:00.000+0000"), cfg, rules)
    late = intake.apply(conn, old, at(now, 60), cfg)
    assert late.outcome == "created"
    assert _row(conn, first.incident_id)["occurrence_count"] == 1


def test_resolving_an_old_alert_keeps_the_incident_open(conn, cfg, rules, now):
    first = intake.apply(conn, normalize_zabbix(zabbix_problem(event_id="1"), cfg, rules), now, cfg)
    intake.apply(conn, normalize_zabbix(zabbix_problem(event_id="2", clock=1790661360), cfg, rules),
                 at(now, 60), cfg)
    intake.resolve(conn, Source.ZABBIX, "1", at(now, 90), at(now, 100))
    row = _row(conn, first.incident_id)
    assert row["problem_status"] == ProblemStatus.OPEN
    assert row["resolved_at"] is None
    assert _refs(conn, first.incident_id) == {"1": "2026-09-29T05:58:30+00:00", "2": None}
    intake.resolve(conn, Source.ZABBIX, "2", at(now, 240), at(now, 250))
    row = _row(conn, first.incident_id)
    assert row["problem_status"] == ProblemStatus.RESOLVED
    assert row["resolved_at"] == "2026-09-29T06:01:00+00:00"
    assert _events(conn, first.incident_id) == ["detected", "recurred", "resolved"]


def test_recovery_that_arrives_late_does_not_move_the_recovery_time_back(conn, cfg, rules, now):
    first = intake.apply(conn, normalize_zabbix(zabbix_problem(event_id="1"), cfg, rules), now, cfg)
    intake.apply(conn, normalize_zabbix(zabbix_problem(event_id="2", clock=1790661360), cfg, rules),
                 at(now, 60), cfg)
    intake.resolve(conn, Source.ZABBIX, "2", at(now, 240), at(now, 250))
    intake.resolve(conn, Source.ZABBIX, "1", at(now, 90), at(now, 260))
    row = _row(conn, first.incident_id)
    assert row["problem_status"] == ProblemStatus.RESOLVED
    assert row["resolved_at"] == "2026-09-29T06:01:00+00:00"


def test_recurrence_that_arrives_recovered_keeps_an_open_incident_open(conn, cfg, rules, now):
    first = intake.apply(conn, normalize_zabbix(zabbix_problem(event_id="1"), cfg, rules), now, cfg)
    flap = normalize_zabbix(zabbix_problem(event_id="2", clock=1790661360, r_eventid="9", r_clock="1790661390"),
                            cfg, rules)
    assert intake.apply(conn, flap, at(now, 60), cfg).outcome == "recurred"
    assert _row(conn, first.incident_id)["problem_status"] == ProblemStatus.OPEN


def test_resolved_alert_without_a_recovery_time_uses_now(conn, cfg, rules, now):
    alert = normalize_zabbix(zabbix_problem(r_eventid="9", r_clock="0"), cfg, rules)
    result = intake.apply(conn, alert, now, cfg)
    row = _row(conn, result.incident_id)
    assert row["problem_status"] == ProblemStatus.RESOLVED
    assert row["resolved_at"] == "2026-09-29T05:57:00+00:00"
    assert _refs(conn, result.incident_id) == {"48213": "2026-09-29T05:57:00+00:00"}


def test_manually_skipped_incident_absorbs_a_recurrence_and_stays_skipped(conn, cfg, rules, now):
    first = intake.apply(conn, normalize_zabbix(zabbix_problem(event_id="1", severity=2), cfg, rules), now, cfg)
    queue.skip_manually(conn, first.incident_id, at(now, 30), "保守作業")
    again = intake.apply(conn, normalize_zabbix(zabbix_problem(event_id="2", severity=4), cfg, rules),
                         at(now, 60), cfg)
    row = _row(conn, first.incident_id)
    assert again == intake.IntakeResult(first.incident_id, "recurred")
    assert row["analysis_state"] == AnalysisState.SKIPPED
    assert row["occurrence_count"] == 2
    assert row["severity"] == 4
    assert "followup_queued" not in _events(conn, first.incident_id)
    assert conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0] == 1


def test_severity_followup_records_why_it_was_queued(conn, cfg, rules, now):
    first = intake.apply(conn, normalize_zabbix(zabbix_problem(event_id="1", severity=2), cfg, rules), now, cfg)
    assert _row(conn, first.incident_id)["queue_reason"] == "initial"
    conn.execute("UPDATE incidents SET analysis_state = 'done' WHERE id = ?", (first.incident_id,))
    intake.apply(conn, normalize_zabbix(zabbix_problem(event_id="2", severity=4), cfg, rules), at(now, 60), cfg)
    assert _row(conn, first.incident_id)["queue_reason"] == "followup"



def test_earlier_alert_that_arrives_later_moves_the_start_back(conn, cfg, rules, now):
    first = intake.apply(conn, normalize_wazuh(wazuh_hit(alert_id="w-2"), cfg, rules), now, cfg)
    early = normalize_wazuh(wazuh_hit(alert_id="w-1", timestamp="2026-09-29T05:50:00.000+0000"), cfg, rules)
    assert intake.apply(conn, early, at(now, 10), cfg) == intake.IntakeResult(first.incident_id, "recurred")
    row = _row(conn, first.incident_id)
    assert row["started_at"] == "2026-09-29T05:50:00+00:00"
    assert row["last_occurrence_at"] == "2026-09-29T05:56:01+00:00"


def test_reopen_cancels_a_recorded_recovery(conn, now, cfg, rules):
    alert = normalize_zabbix(zabbix_problem(), cfg, rules)
    created = intake.apply(conn, alert, now, cfg)
    assert intake.resolve(conn, Source.ZABBIX, "48213", at(now, 60), at(now, 60)) is True
    assert intake.reopen(conn, Source.ZABBIX, "48213", at(now, 90)) is True
    row = conn.execute("SELECT problem_status, resolved_at FROM incidents WHERE id = ?",
                       (created.incident_id,)).fetchone()
    assert (row["problem_status"], row["resolved_at"]) == ("open", None)
    kinds = [r["type"] for r in conn.execute("SELECT type FROM events ORDER BY id")]
    assert kinds == ["detected", "resolved", "reopened"]


def test_reopen_of_an_open_or_unknown_alert_changes_nothing(conn, now, cfg, rules):
    intake.apply(conn, normalize_zabbix(zabbix_problem(), cfg, rules), now, cfg)
    assert intake.reopen(conn, Source.ZABBIX, "48213", at(now, 30)) is False
    assert intake.reopen(conn, Source.ZABBIX, "99999", at(now, 30)) is False
    assert [r["type"] for r in conn.execute("SELECT type FROM events ORDER BY id")] == ["detected"]


def test_reopen_keeps_the_incident_open_while_another_alert_is_open(conn, now, cfg, rules):
    intake.apply(conn, normalize_zabbix(zabbix_problem(), cfg, rules), now, cfg)
    intake.apply(conn, normalize_zabbix(zabbix_problem(event_id="48230", clock=1790661100), cfg, rules),
                 at(now, 30), cfg)
    intake.resolve(conn, Source.ZABBIX, "48213", at(now, 60), at(now, 60))
    assert intake.reopen(conn, Source.ZABBIX, "48213", at(now, 90)) is True
    kinds = [r["type"] for r in conn.execute("SELECT type FROM events ORDER BY id")]
    assert "reopened" not in kinds and "resolved" not in kinds
