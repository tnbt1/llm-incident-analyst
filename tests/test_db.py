import sqlite3

import pytest

from tia import db


def test_migration_creates_tables(conn):
    names = {row["name"] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert {"incidents", "alert_refs", "events", "collector_state"} <= names
    assert db.schema_version(conn) == len(db.MIGRATIONS)


def test_migration_is_idempotent(conn):
    assert db.migrate(conn) == len(db.MIGRATIONS)


def test_reopening_a_file_keeps_data(tmp_path):
    path = tmp_path / "tia.sqlite"
    first = db.connect(path)
    first.execute("INSERT INTO collector_state (source, watermark) VALUES ('zabbix', '1')")
    first.commit()
    first.close()
    second = db.connect(path)
    assert second.execute("SELECT watermark FROM collector_state").fetchone()["watermark"] == "1"
    second.close()


def test_same_external_id_cannot_be_stored_twice(conn):
    sql = ("INSERT INTO incidents (source, external_id, fingerprint, host, type, source_severity, severity, "
           "title, started_at, problem_status, last_occurrence_at, analysis_state, raw_json, created_at, "
           "updated_at) VALUES ('zabbix','1','f','h','cpu','Zabbix Warning',2,'t','a','open','a','held','{}',"
           "'a','a')")
    conn.execute(sql)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(sql)
