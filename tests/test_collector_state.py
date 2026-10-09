import sqlite3
from datetime import timedelta

import pytest

from builders import at
from tia import db
from tia.collectors import state
from tia.collectors.base import SourceError
from tia.config import Config
from tia.models import Source


def test_migration_2_keeps_the_rows_of_version_1(tmp_path):
    path = tmp_path / "tia.sqlite"
    old = sqlite3.connect(path)
    old.executescript(f"BEGIN;\n{db.MIGRATIONS[0][1]}\nPRAGMA user_version = 1;\nCOMMIT;")
    old.execute("INSERT INTO collector_state (source, watermark, last_ok_at) VALUES "
                "('wazuh', 'w-9', '2026-09-29T05:00:00+00:00')")
    old.commit()
    old.close()
    conn = db.connect(path)
    try:
        assert db.schema_version(conn) == len(db.MIGRATIONS)
        kept = state.get(conn, Source.WAZUH)
        assert (kept.watermark, kept.consecutive_failures, kept.next_poll_at) == ("w-9", 0, None)
        assert kept.last_ok_at.isoformat() == "2026-09-29T05:00:00+00:00"
    finally:
        conn.close()


def test_open_alerts_have_an_index(conn):
    plan = conn.execute("EXPLAIN QUERY PLAN SELECT external_id FROM alert_refs "
                        "WHERE source = 'zabbix' AND resolved_at IS NULL").fetchall()
    assert any("idx_alert_refs_open" in row["detail"] for row in plan)


def test_unknown_source_has_an_empty_state(conn, now):
    empty = state.get(conn, Source.ZABBIX)
    assert (empty.watermark, empty.last_ok_at, empty.consecutive_failures) == (None, None, 0)
    assert state.is_due(empty, now, Config())


def test_success_stores_the_position_and_the_next_time(conn, now):
    state.record_success(conn, Source.ZABBIX, now, at(now, 30), "48217")
    stored = state.get(conn, Source.ZABBIX)
    assert (stored.watermark, stored.last_ok_at, stored.last_poll_at) == ("48217", now, now)
    assert stored.next_poll_at == at(now, 30)
    assert not state.is_due(stored, at(now, 29), Config())
    assert state.is_due(stored, at(now, 30), Config())


def test_success_without_a_position_keeps_the_old_one(conn, now):
    state.set_watermark(conn, Source.WAZUH, "p-1")
    state.record_success(conn, Source.WAZUH, now, at(now, 60))
    assert state.get(conn, Source.WAZUH).watermark == "p-1"


def test_failure_keeps_the_position_and_counts_up(conn, now):
    state.record_success(conn, Source.ZABBIX, now, at(now, 30), "48217")
    assert state.record_failure(conn, Source.ZABBIX, at(now, 30), "timeout", "10 秒以内に応答がない",
                                at(now, 60)) == 1
    assert state.record_failure(conn, Source.ZABBIX, at(now, 60), "server", "HTTP 502", at(now, 120)) == 2
    stored = state.get(conn, Source.ZABBIX)
    assert (stored.watermark, stored.last_ok_at, stored.consecutive_failures) == ("48217", now, 2)
    assert (stored.last_error_kind, stored.last_error, stored.last_error_at) == ("server", "HTTP 502", at(now, 60))
    assert stored.last_poll_at == at(now, 60)


def test_success_resets_the_count_and_keeps_the_last_error_as_history(conn, now):
    state.record_failure(conn, Source.WAZUH, now, "tls", "証明書を検証できない", at(now, 60))
    state.record_success(conn, Source.WAZUH, at(now, 60), at(now, 120))
    stored = state.get(conn, Source.WAZUH)
    assert (stored.consecutive_failures, stored.last_error_kind) == (0, "tls")


def test_stored_error_is_cleaned_and_cut(conn, now):
    state.record_failure(conn, Source.ZABBIX, now, "rpc", "bad\x00\x1b[31m" + "x" * 500, at(now, 30))
    stored = state.get(conn, Source.ZABBIX)
    assert "\x00" not in stored.last_error and len(stored.last_error) == 200


def test_failure_does_not_touch_the_callers_transaction(conn, now):
    with pytest.raises(RuntimeError):
        with db.transaction(conn):
            state.record_failure(conn, Source.ZABBIX, now, "timeout", "遅い", at(now, 30))
            raise RuntimeError("呼び出し側の失敗")
    assert state.get(conn, Source.ZABBIX).consecutive_failures == 0


@pytest.mark.parametrize(("failures", "seconds"), [(1, 30), (2, 60), (3, 120), (4, 240), (5, 480), (6, 600),
                                                   (7, 600), (500, 600)])
def test_wait_doubles_and_stops_at_the_limit(failures, seconds):
    wait = state.backoff(Config(), 30, failures, SourceError("timeout", "遅い"))
    assert wait == timedelta(seconds=seconds)


@pytest.mark.parametrize("kind", ["auth", "credential"])
def test_credential_problem_waits_long_from_the_first_failure(kind):
    assert state.backoff(Config(), 30, 1, SourceError(kind, "認証")) == timedelta(seconds=900)


def test_wait_follows_the_servers_request_up_to_the_limit():
    cfg = Config()
    assert state.backoff(cfg, 60, 1, SourceError("throttled", "混雑", retry_after=120)) == timedelta(seconds=120)
    assert state.backoff(cfg, 60, 1, SourceError("throttled", "混雑", retry_after=86400)) == timedelta(seconds=600)
    assert state.backoff(cfg, 60, 3, SourceError("throttled", "混雑", retry_after=5)) == timedelta(seconds=240)


def test_limit_shorter_than_the_interval_waits_one_interval():
    cfg = Config(collector_backoff_max_sec=10)
    assert state.backoff(cfg, 60, 4, SourceError("server", "HTTP 500")) == timedelta(seconds=60)


def test_health_lists_both_sources_even_before_the_first_poll(conn, now, cfg):
    report = state.health(conn, now, cfg)
    assert [h.state.source for h in report] == [Source.ZABBIX, Source.WAZUH]
    assert [(h.seconds_since_ok, h.healthy) for h in report] == [(None, False), (None, False)]


def test_health_turns_bad_on_failure_and_on_silence(conn, now, cfg):
    state.record_success(conn, Source.ZABBIX, now, at(now, 30), "1")
    state.record_success(conn, Source.WAZUH, now, at(now, 60))
    zabbix, wazuh = state.health(conn, at(now, 90), cfg)
    assert (zabbix.seconds_since_ok, zabbix.healthy) == (90, True)
    assert (wazuh.seconds_since_ok, wazuh.healthy) == (90, True)
    zabbix, wazuh = state.health(conn, at(now, 91), cfg)
    assert (zabbix.healthy, wazuh.healthy) == (False, True)
    state.record_failure(conn, Source.WAZUH, at(now, 60), "timeout", "遅い", at(now, 120))
    assert state.health(conn, at(now, 61), cfg)[1].healthy is False


# 時計が先へずれていた間に保存した時刻。時計が直った後に、収集を止めない。

def test_next_time_further_ahead_than_any_wait_is_not_trusted(conn, now, cfg):
    wrong = at(now, 9 * 3600)
    state.record_success(conn, Source.ZABBIX, wrong, at(wrong, 30), "1")
    stored = state.get(conn, Source.ZABBIX)
    assert state.is_due(stored, now, cfg)
    assert state.is_due(stored, at(now, 3600), cfg)


def test_longest_wait_the_collector_can_set_is_respected(conn, now, cfg):
    # 既定では、認証の失敗の後の 900 秒が最も長い。
    state.record_failure(conn, Source.WAZUH, now, "auth", "認証に失敗した", at(now, 900))
    stored = state.get(conn, Source.WAZUH)
    assert not state.is_due(stored, now, cfg)
    assert not state.is_due(stored, at(now, 899), cfg)
    assert state.is_due(stored, at(now, 900), cfg)
    state.record_failure(conn, Source.WAZUH, now, "auth", "認証に失敗した", at(now, 901))
    assert state.is_due(state.get(conn, Source.WAZUH), now, cfg)


def test_longest_wait_follows_the_settings(conn, now, cfg):
    from dataclasses import replace

    patient = replace(cfg, collector_backoff_max_sec=7200)
    state.record_failure(conn, Source.ZABBIX, now, "server", "HTTP 503", at(now, 7200))
    stored = state.get(conn, Source.ZABBIX)
    assert not state.is_due(stored, now, patient)
    assert state.is_due(stored, now, cfg)


def test_health_does_not_trust_a_success_dated_in_the_future(conn, now, cfg):
    wrong = at(now, 9 * 3600)
    state.record_success(conn, Source.ZABBIX, wrong, at(wrong, 30), "1")
    zabbix = state.health(conn, at(now, 3600), cfg)[0]
    assert (zabbix.healthy, zabbix.seconds_since_ok) == (False, -28800)
    assert "時計" in zabbix.reason
    state.record_success(conn, Source.ZABBIX, at(now, 3600), at(now, 3630), "1")
    assert state.health(conn, at(now, 3601), cfg)[0].healthy is True
