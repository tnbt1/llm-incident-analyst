"""保存の層の契約。関数は呼び出し側のまとまりを壊さず、同時に解析するのは 1 件。"""
import pytest

from builders import at, zabbix_problem
from tia import db, intake, queue
from tia.normalize import normalize_zabbix


def _alert(cfg, rules, n, **kwargs):
    return normalize_zabbix(zabbix_problem(event_id=f"e{n}", trigger_id=f"t{n}", **kwargs), cfg, rules)


def _queued(conn, cfg, rules, now, n):
    incident_id = intake.apply(conn, _alert(cfg, rules, n), now, cfg).incident_id
    queue.promote_held(conn, at(now, 60))
    return incident_id


def test_sorting_does_not_need_temporary_files(conn):
    assert conn.execute("PRAGMA temp_store").fetchone()[0] == 2


def test_waiting_for_a_lock_has_a_limit(conn):
    assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 5000


def test_callers_failure_undoes_the_functions_inside(conn, cfg, rules, now):
    with pytest.raises(RuntimeError):
        with db.transaction(conn):
            conn.execute("INSERT INTO collector_state (source, watermark) VALUES ('zabbix', '1')")
            intake.apply(conn, _alert(cfg, rules, 1), now, cfg)
            raise RuntimeError("収集の途中で失敗")
    assert conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM collector_state").fetchone()[0] == 0


def test_functions_failure_keeps_the_callers_pending_work(conn, now):
    with db.transaction(conn):
        conn.execute("INSERT INTO collector_state (source, watermark) VALUES ('zabbix', '1')")
        with pytest.raises(queue.StateError):
            queue.start(conn, 999, now)
    assert conn.execute("SELECT watermark FROM collector_state").fetchone()["watermark"] == "1"


def test_nothing_is_left_open_after_a_function_returns(conn, cfg, rules, now):
    intake.apply(conn, _alert(cfg, rules, 1), now, cfg)
    assert conn.in_transaction is False


def test_only_one_incident_runs_across_connections(tmp_path, cfg, rules, now):
    path = tmp_path / "tia.sqlite"
    first, second = db.connect(path), db.connect(path)
    one = _queued(first, cfg, rules, now, 1)
    two = _queued(first, cfg, rules, now, 2)
    queue.start(first, one, at(now, 70))
    with pytest.raises(queue.StateError, match="同時に解析するのは 1 件"):
        queue.start(second, two, at(now, 71))
    states = [r[0] for r in second.execute("SELECT analysis_state FROM incidents ORDER BY id")]
    assert states == ["running", "queued"]
    first.close()
    second.close()


def test_the_database_itself_refuses_a_second_running_row(conn, cfg, rules, now):
    _queued(conn, cfg, rules, now, 1)
    _queued(conn, cfg, rules, now, 2)
    conn.execute("UPDATE incidents SET analysis_state = 'running' WHERE id = 1")
    import sqlite3
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE incidents SET analysis_state = 'running' WHERE id = 2")
