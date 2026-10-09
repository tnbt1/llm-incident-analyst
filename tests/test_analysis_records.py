"""解析の記録と移行 3。"""
import json
import sqlite3
from datetime import timedelta

import pytest
from builders import zabbix_problem

from tia import db, intake
from tia.analysis import records
from tia.normalize import normalize_zabbix


def _incident(conn, cfg, rules, now, event_id="48213", severity=2):
    alert = normalize_zabbix(zabbix_problem(event_id=event_id, severity=severity), cfg, rules)
    return intake.apply(conn, alert, now, cfg).incident_id


def test_migration_3_applies_on_a_database_made_by_plan_02(tmp_path):
    path = tmp_path / "old.sqlite"
    conn = sqlite3.connect(path, isolation_level=None)
    for number, sql in db.MIGRATIONS[:2]:
        conn.executescript(f"BEGIN;\n{sql}\nPRAGMA user_version = {number};\nCOMMIT;")
    conn.close()
    conn = db.connect(path)
    assert db.schema_version(conn) == db.MIGRATIONS[-1][0] >= 3
    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert {"analyses", "cases"} <= tables
    columns = {row[1] for row in conn.execute("PRAGMA table_info(incidents)")}
    assert {"confirmed_at", "confirmed_verdict"} <= columns
    assert db.migrate(conn) == db.MIGRATIONS[-1][0]
    conn.close()


def test_begin_records_the_trigger_and_starts_in_the_context_phase(conn, cfg, rules, now):
    incident_id = _incident(conn, cfg, rules, now)
    analysis_id = records.begin(conn, incident_id, "initial", "example/model-27b", now)
    row = records.get(conn, analysis_id)
    assert (row["incident_id"], row["trigger"], row["status"], row["phase"], row["attempt"]) == (
        incident_id, "initial", "running", "context", 1)
    assert row["model"] == "example/model-27b"
    assert row["started_at"] == "2026-09-29T05:57:00+00:00"


def test_unknown_trigger_is_refused(conn, cfg, rules, now):
    incident_id = _incident(conn, cfg, rules, now)
    with pytest.raises(records.RecordError, match="きっかけ"):
        records.begin(conn, incident_id, "whim", "m", now)


def test_progress_updates_phase_and_tokens(conn, cfg, rules, now):
    analysis_id = records.begin(conn, _incident(conn, cfg, rules, now), "initial", "m", now)
    records.progress(conn, analysis_id, "inference", now + timedelta(seconds=3), tokens_so_far=40)
    row = records.get(conn, analysis_id)
    assert (row["phase"], row["tokens_so_far"], row["updated_at"]) == ("inference", 40, "2026-09-29T05:57:03+00:00")
    records.progress(conn, analysis_id, "validation", now + timedelta(seconds=9))
    assert records.get(conn, analysis_id)["tokens_so_far"] == 40


def test_finish_done_stores_the_result_and_the_duration(conn, cfg, rules, now):
    analysis_id = records.begin(conn, _incident(conn, cfg, rules, now), "initial", "m", now)
    records.finish(conn, analysis_id, now + timedelta(seconds=95), status="done", result={"summary": "s"},
                   prompt_tokens=8000, completion_tokens=600, tokens_per_sec=7.1, prompt_hash="abc",
                   knowledge_version="20260929-000000000000", context={"parts": []})
    row = records.get(conn, analysis_id)
    assert (row["status"], row["phase"], row["duration_ms"]) == ("done", "finished", 95000)
    assert json.loads(row["result_json"]) == {"summary": "s"}
    assert (row["prompt_tokens"], row["completion_tokens"], row["tokens_per_sec"]) == (8000, 600, 7.1)
    assert (row["prompt_hash"], row["knowledge_version"]) == ("abc", "20260929-000000000000")
    assert json.loads(row["context_json"]) == {"parts": []}


def test_finish_keeps_the_context_attached_earlier(conn, cfg, rules, now):
    analysis_id = records.begin(conn, _incident(conn, cfg, rules, now), "initial", "m", now)
    records.attach_context(conn, analysis_id, now, context={"parts": ["a"]}, prompt_hash="h1",
                           knowledge_version="v1", prompt_tokens=100)
    assert records.get(conn, analysis_id)["phase"] == "inference"
    records.finish(conn, analysis_id, now, status="failed", error_kind="timeout", error="240 秒")
    row = records.get(conn, analysis_id)
    assert (json.loads(row["context_json"]), row["prompt_hash"], row["knowledge_version"], row["prompt_tokens"]) == (
        {"parts": ["a"]}, "h1", "v1", 100)
    assert (row["status"], row["error_kind"], row["error"]) == ("failed", "timeout", "240 秒")


def test_finish_requires_what_each_outcome_needs(conn, cfg, rules, now):
    analysis_id = records.begin(conn, _incident(conn, cfg, rules, now), "initial", "m", now)
    with pytest.raises(records.RecordError, match="結果"):
        records.finish(conn, analysis_id, now, status="done")
    with pytest.raises(records.RecordError, match="理由"):
        records.finish(conn, analysis_id, now, status="failed")
    with pytest.raises(records.RecordError, match="終わり方"):
        records.finish(conn, analysis_id, now, status="running", error_kind="x")
    records.finish(conn, analysis_id, now, status="released", error_kind="unreachable", error="x" * 1000)
    assert len(records.get(conn, analysis_id)["error"]) == records.ERROR_LIMIT
    with pytest.raises(records.RecordError, match="running のときだけ"):
        records.finish(conn, analysis_id, now, status="done", result={})
    with pytest.raises(records.RecordError, match="running のときだけ"):
        records.progress(conn, analysis_id, "validation", now)


def test_latest_done_and_listing(conn, cfg, rules, now):
    incident_id = _incident(conn, cfg, rules, now)
    first = records.begin(conn, incident_id, "initial", "m", now)
    records.finish(conn, first, now, status="failed", error_kind="timeout", error="x")
    second = records.begin(conn, incident_id, "retry", "m", now, attempt=2)
    records.finish(conn, second, now, status="done", result={"summary": "ok"})
    third = records.begin(conn, incident_id, "replay", "m", now)
    assert [row["id"] for row in records.for_incident(conn, incident_id)] == [first, second, third]
    assert records.latest_done(conn, incident_id)["id"] == second
    assert records.result_of(records.get(conn, second)) == {"summary": "ok"}
    assert records.result_of(records.get(conn, third)) is None


def test_running_rows_are_closed_at_startup(conn, cfg, rules, now):
    incident_id = _incident(conn, cfg, rules, now)
    left = records.begin(conn, incident_id, "initial", "m", now)
    done = records.begin(conn, incident_id, "replay", "m", now)
    records.finish(conn, done, now, status="done", result={})
    assert records.abandon_running(conn, now + timedelta(seconds=30)) == 1
    row = records.get(conn, left)
    assert (row["status"], row["error_kind"], row["duration_ms"]) == ("released", "restart", 30000)
    assert records.abandon_running(conn, now) == 0


def test_failure_inside_the_callers_transaction_undoes_the_record(conn, cfg, rules, now):
    incident_id = _incident(conn, cfg, rules, now)
    with pytest.raises(RuntimeError):
        with db.transaction(conn):
            records.begin(conn, incident_id, "initial", "m", now)
            raise RuntimeError("呼び出し側の失敗")
    assert records.for_incident(conn, incident_id) == []
    assert not conn.in_transaction
