"""確認の結果の保存。移行 4 の `probes` 表。"""
from datetime import UTC, datetime

from tia import db
from tia.probes import store


def _incident(conn):
    conn.execute("INSERT INTO incidents (source, external_id, fingerprint, host, type, title, severity, source_severity, "
                 "problem_status, analysis_state, started_at, last_occurrence_at, created_at, updated_at, raw_json) "
                 "VALUES ('zabbix', '1', 'f', 'example-app01', 'disk', 't', 2, 'Warning', 'open', 'queued', "
                 "'2026-10-08T00:00:00+00:00', '2026-10-08T00:00:00+00:00', '2026-10-08T00:00:00+00:00', "
                 "'2026-10-08T00:00:00+00:00', '{}')")
    return conn.execute("SELECT id FROM incidents").fetchone()[0]


def test_migration_4_creates_the_probes_table(conn):
    assert db.schema_version(conn) == db.MIGRATIONS[-1][0] >= 4
    columns = {row[1] for row in conn.execute("PRAGMA table_info(probes)")}
    assert {"incident_id", "analysis_id", "name", "target", "command", "trigger", "started_at", "duration_ms",
            "status", "output", "error"} <= columns


def test_insert_and_read_back(conn):
    incident_id = _incident(conn)
    now = datetime(2026, 10, 8, 1, 0, tzinfo=UTC)
    with db.transaction(conn):
        first = store.insert(conn, incident_id, None, "disk", "example-app01", "initial", now, 120, "ok",
                             "Filesystem Size", None, command="df -h /")
        store.insert(conn, incident_id, 7, "uptime_load", "example-app01", "operator", now, 5, "timeout", "",
                     "10 秒で打ち切った")
    rows = store.for_incident(conn, incident_id)
    assert [r["name"] for r in rows] == ["disk", "uptime_load"] and rows[0]["id"] == first
    assert rows[1]["status"] == "timeout" and rows[1]["error"] == "10 秒で打ち切った"
    assert rows[0]["command"] == "df -h /" and rows[1]["command"] is None
    assert [r["name"] for r in store.for_analysis(conn, 7)] == ["uptime_load"]
    assert store.for_incident(conn, incident_id + 1) == []


def test_only_known_statuses_and_triggers_are_stored(conn):
    import pytest

    incident_id = _incident(conn)
    now = datetime(2026, 10, 8, 1, 0, tzinfo=UTC)
    with pytest.raises(ValueError):
        store.insert(conn, incident_id, None, "disk", "x", "initial", now, 1, "weird", "", None)
    with pytest.raises(ValueError):
        store.insert(conn, incident_id, None, "disk", "x", "robot", now, 1, "ok", "", None)


def test_migration_4_applies_to_an_older_database(tmp_path):
    import sqlite3

    path = tmp_path / "old.sqlite"
    raw = sqlite3.connect(path)
    for number, sql in db.MIGRATIONS[:3]:
        raw.executescript(sql)
        raw.execute(f"PRAGMA user_version = {number}")
    raw.commit()
    raw.close()
    conn = db.connect(path)
    try:
        assert db.schema_version(conn) == db.MIGRATIONS[-1][0]
        assert conn.execute("SELECT count(*) FROM probes").fetchone()[0] == 0
        assert db.migrate(conn) == db.MIGRATIONS[-1][0]
    finally:
        conn.close()
