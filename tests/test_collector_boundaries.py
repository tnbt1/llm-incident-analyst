"""保存のまとまりの境目。途中で失敗したら、まとまりの全部が残らないこと。

どのテストも、まとまりを外すと失敗する。
"""
import sqlite3
from dataclasses import replace

import pytest

from builders import at, zabbix_problem
from fakes import FakeServer, FakeWazuh, FakeZabbix
from tia import db, grouping, intake, queue
from tia.collectors import state
from tia.collectors import wazuh as wazuh_collector
from tia.collectors import zabbix as zabbix_collector
from tia.collectors.base import PollReport
from tia.collectors.endpoints import WazuhEndpoint, ZabbixEndpoint
from tia.collectors.runner import run_cycle
from tia.collectors.wazuh import WazuhPoller
from tia.collectors.zabbix import ZabbixPoller
from tia.models import Source
from tia.normalize import normalize_zabbix

NOW = 1790661420


class Boom(RuntimeError):
    pass


def fail_on_call(monkeypatch, module, name, number):
    """module.name を、number 回目の呼び出しで失敗させる。それまでは本物を呼ぶ。"""
    real = getattr(module, name)
    calls = []

    def wrapper(*args, **kwargs):
        calls.append(args)
        if len(calls) == number:
            raise Boom(name)
        return real(*args, **kwargs)

    monkeypatch.setattr(module, name, wrapper)
    return calls


@pytest.fixture
def file_conn(tmp_path):
    """別の接続から、確定した内容だけを確かめるための保存先。"""
    path = tmp_path / "tia.sqlite"
    conn = db.connect(path)
    yield conn, path
    conn.close()


def committed(path, sql):
    other = sqlite3.connect(path)
    try:
        return [tuple(row) for row in other.execute(sql)]
    finally:
        other.close()


@pytest.fixture
def wazuh(server_tls, ca_file, tmp_path):
    fake = FakeWazuh()
    password = tmp_path / "wazuh_password"
    password.write_text(fake.password + "\n", encoding="utf-8")
    with FakeServer(fake.handle, tls=server_tls) as server:
        fake.poller = WazuhPoller(WazuhEndpoint(server.url, fake.user, password, ca_file))
        yield fake


@pytest.fixture
def zabbix(tmp_path):
    fake = FakeZabbix()
    token = tmp_path / "zabbix_token"
    token.write_text(fake.token + "\n", encoding="utf-8")
    with FakeServer(fake.handle) as server:
        fake.poller = ZabbixPoller(ZabbixEndpoint(server.url + "/api_jsonrpc.php", token))
        yield fake


def stamp(second):
    return f"2026-09-29T05:56:{second:02d}.000+0000"


def add_alerts(wazuh, count):
    for number in range(count):
        wazuh.add(f"w-{number:03d}", stamp(number), srcip=f"192.0.2.{number}")


def add_problems(zabbix, count, first=48300):
    for number in range(count):
        zabbix.add_problem(first + number, trigger_id=23000 + number, clock=NOW - 3600 * (number + 1))


def test_wazuh_page_and_its_position_are_saved_together(file_conn, now, cfg, rules, wazuh, monkeypatch):
    conn, path = file_conn
    add_alerts(wazuh, 3)
    fail_on_call(monkeypatch, state, "set_watermark", 1)
    with pytest.raises(Boom):
        wazuh.poller.poll(conn, now, cfg, rules)
    assert not conn.in_transaction
    assert committed(path, "SELECT COUNT(*) FROM incidents") == [(0,)]
    assert committed(path, "SELECT COUNT(*) FROM alert_refs") == [(0,)]
    assert committed(path, "SELECT watermark FROM collector_state") == []


def test_wazuh_page_that_fails_in_the_middle_leaves_nothing(file_conn, now, cfg, rules, wazuh, monkeypatch):
    conn, path = file_conn
    add_alerts(wazuh, 3)
    fail_on_call(monkeypatch, intake, "apply", 3)
    with pytest.raises(Boom):
        wazuh.poller.poll(conn, now, cfg, rules)
    assert not conn.in_transaction
    assert committed(path, "SELECT COUNT(*) FROM incidents") == [(0,)]
    assert committed(path, "SELECT watermark FROM collector_state") == []


def test_wazuh_pages_before_the_failing_one_stay_with_their_position(file_conn, now, cfg, rules, wazuh,
                                                                     monkeypatch):
    conn, path = file_conn
    add_alerts(wazuh, 5)
    fail_on_call(monkeypatch, state, "set_watermark", 2)
    with pytest.raises(Boom):
        wazuh.poller.poll(conn, now, replace(cfg, wazuh_page_size=2), rules)
    assert committed(path, "SELECT external_id FROM incidents ORDER BY id") == [("w-000",), ("w-001",)]
    (stored,) = committed(path, "SELECT watermark FROM collector_state")
    assert wazuh_collector.Position.load(stored[0]).after[0] == 1790661361000
    monkeypatch.undo()
    assert wazuh.poller.poll(conn, at(now, 60), replace(cfg, wazuh_page_size=2), rules).counts["created"] == 3
    assert committed(path, "SELECT COUNT(*) FROM incidents") == [(5,)]


def test_wazuh_reread_page_that_fails_in_the_middle_leaves_nothing(file_conn, now, cfg, rules, wazuh, monkeypatch):
    conn, path = file_conn
    add_alerts(wazuh, 4)
    small = replace(cfg, wazuh_page_size=2, wazuh_max_pages=1)
    wazuh.poller.poll(conn, now, small, rules)
    wazuh.add("w-late-1", "2026-09-29T05:56:00.500+0000", srcip="198.51.100.11")
    wazuh.add("w-late-2", "2026-09-29T05:56:00.600+0000", srcip="198.51.100.12")
    before = committed(path, "SELECT watermark FROM collector_state")
    fail_on_call(monkeypatch, intake, "apply", 3)
    with pytest.raises(Boom):
        wazuh.poller.poll(conn, at(now, 60), replace(small, wazuh_page_size=3), rules)
    assert not conn.in_transaction
    assert committed(path, "SELECT COUNT(*) FROM incidents") == [(2,)]
    assert committed(path, "SELECT watermark FROM collector_state") == before


def test_zabbix_listing_that_fails_in_the_middle_leaves_nothing(file_conn, now, cfg, rules, zabbix, monkeypatch):
    conn, path = file_conn
    add_problems(zabbix, 3)
    fail_on_call(monkeypatch, intake, "apply", 3)
    with pytest.raises(Boom):
        zabbix.poller.poll(conn, now, cfg, rules)
    assert not conn.in_transaction
    assert committed(path, "SELECT COUNT(*) FROM incidents") == [(0,)]
    assert committed(path, "SELECT COUNT(*) FROM alert_refs") == [(0,)]


def test_zabbix_page_and_its_continuation_are_saved_together(file_conn, now, cfg, rules, zabbix, monkeypatch):
    conn, path = file_conn
    add_problems(zabbix, 6)
    small = replace(cfg, zabbix_page_size=2, zabbix_max_pages=2)
    fail_on_call(monkeypatch, state, "set_cursor", 1)
    with pytest.raises(Boom):
        zabbix.poller.poll(conn, now, small, rules)
    assert not conn.in_transaction
    assert committed(path, "SELECT COUNT(*) FROM incidents") == [(0,)]
    assert committed(path, "SELECT cursor FROM collector_state") == []
    monkeypatch.undo()
    assert zabbix.poller.poll(conn, at(now, 30), small, rules).counts == {"fetched": 4, "created": 4}
    assert zabbix.poller.poll(conn, at(now, 60), small, rules).counts == {"fetched": 2, "created": 2}


def test_zabbix_recoveries_and_reopenings_of_one_listing_are_saved_together(file_conn, now, cfg, rules, zabbix,
                                                                            monkeypatch):
    conn, path = file_conn
    add_problems(zabbix, 3)
    zabbix.poller.poll(conn, now, cfg, rules)
    zabbix.recover(48300, 48400, NOW + 5)
    zabbix.recover(48301, 48401, NOW + 6)
    fail_on_call(monkeypatch, intake, "resolve", 2)
    with pytest.raises(Boom):
        zabbix.poller.poll(conn, at(now, 30), cfg, rules)
    assert not conn.in_transaction
    assert committed(path, "SELECT problem_status FROM incidents ORDER BY id") == [("open",)] * 3
    assert committed(path, "SELECT COUNT(*) FROM alert_refs WHERE resolved_at IS NOT NULL") == [(0,)]


def test_vanished_problems_of_one_round_are_settled_together(file_conn, now, cfg, rules, zabbix, monkeypatch):
    conn, path = file_conn
    add_problems(zabbix, 3)
    zabbix.poller.poll(conn, now, cfg, rules)
    before = committed(path, "SELECT round FROM collector_state WHERE source = 'zabbix'")
    for number, event_id in enumerate((48300, 48301)):
        zabbix.recover(event_id, 48400 + number, NOW + 5 + number)
        zabbix.expire(event_id)
    fail_on_call(monkeypatch, intake, "resolve", 2)
    with pytest.raises(Boom):
        zabbix.poller.poll(conn, at(now, 30), cfg, rules)
    assert not conn.in_transaction
    assert committed(path, "SELECT problem_status FROM incidents ORDER BY id") == [("open",)] * 3
    assert committed(path, "SELECT round FROM collector_state WHERE source = 'zabbix'") == before
    monkeypatch.undo()
    assert zabbix.poller.poll(conn, at(now, 60), cfg, rules).counts == {"fetched": 1, "known": 1, "resolved": 2}


def test_round_is_finished_together_with_what_it_settled(file_conn, now, cfg, rules, zabbix, monkeypatch):
    conn, path = file_conn
    add_problems(zabbix, 2)
    zabbix.poller.poll(conn, now, cfg, rules)
    zabbix.recover(48300, 48400, NOW + 5)
    zabbix.expire(48300)
    fail_on_call(monkeypatch, state, "finish_round", 1)
    with pytest.raises(Boom):
        zabbix.poller.poll(conn, at(now, 30), cfg, rules)
    assert not conn.in_transaction
    assert committed(path, "SELECT problem_status FROM incidents ORDER BY id") == [("open",), ("open",)]


def held_incident(conn, now, cfg, rules):
    intake.apply(conn, normalize_zabbix(zabbix_problem(), cfg, rules), now, cfg)


@pytest.mark.parametrize(("module", "name"), [(queue, "promote_held"), (queue, "schedule_followups")])
def test_housekeeping_is_one_unit(file_conn, now, cfg, rules, monkeypatch, module, name):
    conn, path = file_conn
    for number in range(5):
        intake.apply(conn, normalize_zabbix(zabbix_problem(
            event_id=str(48300 + number), trigger_id=str(23000 + number), host=f"host{number}",
            clock=NOW - 30 + number), cfg, rules), now, cfg)
    fail_on_call(monkeypatch, module, name, 1)
    report = run_cycle(conn, [], at(now, 61), cfg, rules)
    assert report.tidy.error == "想定外の失敗（Boom）"
    assert not conn.in_transaction
    # 連鎖の判定が作った親も、順番待ちへの繰り上げも、残らない。
    assert committed(path, "SELECT COUNT(*) FROM incidents") == [(5,)]
    assert committed(path, "SELECT DISTINCT analysis_state, group_id FROM incidents") == [("held", None)]
    monkeypatch.undo()
    done = run_cycle(conn, [], at(now, 62), cfg, rules)
    assert done.tidy.error is None and done.tidy.group_id is not None
    assert committed(path, "SELECT COUNT(*) FROM incidents") == [(6,)]


def test_poll_that_leaves_a_unit_open_does_not_swallow_what_follows(file_conn, now, cfg, rules):
    conn, path = file_conn

    class Careless:
        source = Source.ZABBIX

        def poll(self, conn, now, cfg, rules, should_stop):
            conn.execute("BEGIN")
            intake.apply(conn, normalize_zabbix(zabbix_problem(), cfg, rules), now, cfg)
            raise Boom("途中でやめた")

    class Fine:
        source = Source.WAZUH

        def poll(self, conn, now, cfg, rules, should_stop):
            return PollReport(Source.WAZUH)

    report = run_cycle(conn, [Careless(), Fine()], now, cfg, rules)
    assert [(run.source, run.status) for run in report.runs] == [(Source.ZABBIX, "failed"), (Source.WAZUH, "ok")]
    assert not conn.in_transaction
    # 失敗の記録と、もう片方の成功の記録が、確定している。途中の取り込みは残らない。
    assert committed(path, "SELECT source, consecutive_failures, last_error_kind FROM collector_state "
                           "ORDER BY source") == [("wazuh", 0, None), ("zabbix", 1, "internal")]
    assert committed(path, "SELECT COUNT(*) FROM incidents") == [(0,)]


def test_failed_record_of_a_result_leaves_no_unit_open(file_conn, now, cfg, rules, monkeypatch):
    conn, path = file_conn

    def broken(*args, **kwargs):
        conn.execute("BEGIN")
        raise Boom("記録できない")

    monkeypatch.setattr(state, "record_success", broken)

    class Fine:
        source = Source.ZABBIX

        def poll(self, conn, now, cfg, rules, should_stop):
            return PollReport(Source.ZABBIX)

    report = run_cycle(conn, [Fine()], now, cfg, rules)
    assert report.runs[0].status == "failed"
    assert report.tidy.error is None
    assert not conn.in_transaction


def test_housekeeping_that_cannot_be_committed_leaves_no_unit_open(file_conn, now, cfg, rules, monkeypatch):
    # 確定の段階で失敗すると、まとまりは開いたまま残る。次の周期が、その中で動かないこと。
    from tia.collectors import runner

    conn, path = file_conn
    held_incident(conn, now, cfg, rules)

    def uncommitted(conn, now, cfg):
        conn.execute("BEGIN IMMEDIATE")
        queue.promote_held(conn, now)
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(runner, "tidy", uncommitted)
    report = run_cycle(conn, [], at(now, 61), cfg, rules)
    assert report.tidy.error == "想定外の失敗（OperationalError）"
    assert not conn.in_transaction
    assert committed(path, "SELECT analysis_state FROM incidents") == [("held",)]
    monkeypatch.undo()
    assert run_cycle(conn, [], at(now, 62), cfg, rules).tidy.promoted == 1
    assert committed(path, "SELECT analysis_state FROM incidents") == [("queued",)]
