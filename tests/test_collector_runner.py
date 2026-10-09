import logging
import sqlite3
import threading
from dataclasses import replace

from builders import at, wazuh_hit, zabbix_problem
from tia import db, intake, queue
from tia.collectors import state
from tia.collectors.base import PollReport, SourceError
from tia.collectors.endpoints import load_endpoints
from tia.collectors.runner import Tidy, build_pollers, run_cycle, run_loop
from tia.models import Source
from tia.normalize import normalize_wazuh, normalize_zabbix


class Stub:
    """収集の代わり。呼ばれるたびに、用意した答えを先頭から 1 つ使う。"""

    def __init__(self, source, *answers):
        self.source = source
        self.answers = list(answers)
        self.calls = []

    def poll(self, conn, now, cfg, rules, should_stop):
        self.calls.append(now)
        answer = self.answers.pop(0) if self.answers else PollReport(self.source)
        if isinstance(answer, Exception):
            raise answer
        return answer(conn, now, cfg, rules) if callable(answer) else answer


def statuses(report):
    return [(run.source, run.status) for run in report.runs]


def test_pollers_are_built_for_the_configured_sources(tmp_path):
    assert build_pollers(load_endpoints({})) == []
    both = build_pollers(load_endpoints({"TIA_ZABBIX_URL": "http://zabbix/api_jsonrpc.php",
                                         "TIA_WAZUH_URL": "https://wazuh.indexer:9200"}))
    assert [p.source for p in both] == [Source.ZABBIX, Source.WAZUH]
    only = build_pollers(load_endpoints({"TIA_WAZUH_URL": "https://wazuh.indexer:9200"}))
    assert [p.source for p in only] == [Source.WAZUH]


def test_each_source_is_polled_and_the_result_is_recorded(conn, now, cfg, rules):
    zabbix = Stub(Source.ZABBIX, PollReport(Source.ZABBIX, {"fetched": 2, "created": 2}, True, "48217"))
    wazuh = Stub(Source.WAZUH)
    report = run_cycle(conn, [zabbix, wazuh], now, cfg, rules)
    assert statuses(report) == [(Source.ZABBIX, "ok"), (Source.WAZUH, "ok")]
    assert report.failed is False
    assert report.runs[0].report.counts == {"fetched": 2, "created": 2}
    stored = state.get(conn, Source.ZABBIX)
    assert (stored.watermark, stored.last_ok_at, stored.next_poll_at) == ("48217", now, at(now, 30))
    assert state.get(conn, Source.WAZUH).next_poll_at == at(now, 60)


def test_source_is_polled_again_only_when_its_time_has_come(conn, now, cfg, rules):
    zabbix, wazuh = Stub(Source.ZABBIX), Stub(Source.WAZUH)
    run_cycle(conn, [zabbix, wazuh], now, cfg, rules)
    assert statuses(run_cycle(conn, [zabbix, wazuh], at(now, 5), cfg, rules)) == [
        (Source.ZABBIX, "waiting"), (Source.WAZUH, "waiting")]
    assert statuses(run_cycle(conn, [zabbix, wazuh], at(now, 30), cfg, rules)) == [
        (Source.ZABBIX, "ok"), (Source.WAZUH, "waiting")]
    assert statuses(run_cycle(conn, [zabbix, wazuh], at(now, 60), cfg, rules)) == [
        (Source.ZABBIX, "ok"), (Source.WAZUH, "ok")]
    assert (zabbix.calls, wazuh.calls) == ([now, at(now, 30), at(now, 60)], [now, at(now, 60)])


def test_forced_cycle_ignores_the_wait(conn, now, cfg, rules):
    zabbix = Stub(Source.ZABBIX, SourceError("auth", "認証に失敗した（HTTP 401）"))
    run_cycle(conn, [zabbix], now, cfg, rules)
    assert statuses(run_cycle(conn, [zabbix], at(now, 5), cfg, rules)) == [(Source.ZABBIX, "waiting")]
    assert statuses(run_cycle(conn, [zabbix], at(now, 5), cfg, rules, force=True)) == [(Source.ZABBIX, "ok")]


def test_failing_source_does_not_stop_the_other(conn, now, cfg, rules, caplog):
    zabbix = Stub(Source.ZABBIX, SourceError("timeout", "10 秒以内に応答がない"))
    wazuh = Stub(Source.WAZUH, PollReport(Source.WAZUH, {"fetched": 1, "created": 1}))
    with caplog.at_level(logging.INFO, logger="tia.collect"):
        report = run_cycle(conn, [zabbix, wazuh], now, cfg, rules)
    assert statuses(report) == [(Source.ZABBIX, "failed"), (Source.WAZUH, "ok")]
    assert report.failed is True
    assert (report.runs[0].error_kind, report.runs[0].error) == ("timeout", "10 秒以内に応答がない")
    stored = state.get(conn, Source.ZABBIX)
    assert (stored.consecutive_failures, stored.last_error_kind, stored.last_ok_at) == (1, "timeout", None)
    assert stored.next_poll_at == at(now, 30)
    assert state.get(conn, Source.WAZUH).last_ok_at == now
    messages = [r.getMessage() for r in caplog.records]
    assert any("zabbix の収集に失敗した（timeout、1 回目）" in m for m in messages)
    assert any("wazuh を収集した: created=1 fetched=1" in m for m in messages)


def test_wait_grows_with_repeated_failures_and_success_resets_it(conn, now, cfg, rules, caplog):
    zabbix = Stub(Source.ZABBIX, *[SourceError("server", "相手の側の誤り（HTTP 503）") for _ in range(4)])
    moment, waits = now, []
    for _ in range(4):
        run_cycle(conn, [zabbix], moment, cfg, rules)
        stored = state.get(conn, Source.ZABBIX)
        waits.append(int((stored.next_poll_at - moment).total_seconds()))
        moment = stored.next_poll_at
    assert waits == [30, 60, 120, 240]
    with caplog.at_level(logging.INFO, logger="tia.collect"):
        assert statuses(run_cycle(conn, [zabbix], moment, cfg, rules)) == [(Source.ZABBIX, "ok")]
    stored = state.get(conn, Source.ZABBIX)
    assert (stored.consecutive_failures, stored.next_poll_at) == (0, at(moment, 30))
    assert any("復帰した" in r.getMessage() for r in caplog.records)


def test_credential_failure_is_not_retried_for_a_long_time(conn, now, cfg, rules):
    wazuh = Stub(Source.WAZUH, SourceError("auth", "認証に失敗した（HTTP 401）"))
    run_cycle(conn, [wazuh], now, cfg, rules)
    for seconds in (60, 300, 899):
        assert statuses(run_cycle(conn, [wazuh], at(now, seconds), cfg, rules)) == [(Source.WAZUH, "waiting")]
    assert statuses(run_cycle(conn, [wazuh], at(now, 900), cfg, rules)) == [(Source.WAZUH, "ok")]
    assert len(wazuh.calls) == 2


def test_unexpected_failure_is_contained_and_its_text_is_not_kept(conn, now, cfg, rules, caplog):
    zabbix = Stub(Source.ZABBIX, RuntimeError("Illegal header value b'Bearer zbx-token-0123456789abcdef'"))
    wazuh = Stub(Source.WAZUH)
    with caplog.at_level(logging.INFO, logger="tia.collect"):
        report = run_cycle(conn, [zabbix, wazuh], now, cfg, rules)
    assert statuses(report) == [(Source.ZABBIX, "failed"), (Source.WAZUH, "ok")]
    assert (report.runs[0].error_kind, report.runs[0].error) == ("internal", "想定外の失敗（RuntimeError）")
    assert state.get(conn, Source.ZABBIX).last_error == "想定外の失敗（RuntimeError）"
    assert "zbx-token" not in caplog.text
    assert "test_collector_runner.py" in caplog.text


def test_failure_inside_a_poll_undoes_only_its_own_unfinished_work(conn, now, cfg, rules):
    def half_done(conn, now, cfg, rules):
        with db.transaction(conn):
            intake.apply(conn, normalize_zabbix(zabbix_problem(event_id="1"), cfg, rules), now, cfg)
        with db.transaction(conn):
            intake.apply(conn, normalize_zabbix(zabbix_problem(event_id="2", trigger_id="9"), cfg, rules), now, cfg)
            raise SourceError("server", "相手の側の誤り（HTTP 502）")

    report = run_cycle(conn, [Stub(Source.ZABBIX, half_done)], now, cfg, rules)
    assert statuses(report) == [(Source.ZABBIX, "failed")]
    assert [r["external_id"] for r in conn.execute("SELECT external_id FROM incidents")] == ["1"]
    assert not conn.in_transaction


def test_locked_database_fails_the_cycle_without_raising(tmp_path, now, cfg, rules):
    path = tmp_path / "tia.sqlite"
    conn, other = db.connect(path), sqlite3.connect(path, isolation_level=None)
    conn.execute("PRAGMA busy_timeout = 50")
    try:
        other.execute("BEGIN IMMEDIATE")
        report = run_cycle(conn, [Stub(Source.ZABBIX), Stub(Source.WAZUH)], now, cfg, rules)
        assert statuses(report) == [(Source.ZABBIX, "failed"), (Source.WAZUH, "failed")]
        assert report.tidy.error == "想定外の失敗（OperationalError）"
        assert report.failed is True
        assert not conn.in_transaction
        other.execute("ROLLBACK")
        assert run_cycle(conn, [Stub(Source.ZABBIX)], at(now, 5), cfg, rules).failed is False
    finally:
        other.close()
        conn.close()


def events_of(conn, incident_id):
    return [r["type"] for r in conn.execute("SELECT type FROM events WHERE incident_id = ? ORDER BY id",
                                            (incident_id,))]


def test_chain_is_judged_before_the_wait_ends(conn, now, cfg, rules):
    def four(conn, now, cfg, rules):
        for number in range(4):
            raw = zabbix_problem(event_id=str(100 + number), trigger_id=str(200 + number), clock=1790661360 + number)
            intake.apply(conn, normalize_zabbix(raw, cfg, rules), now, cfg)
        return PollReport(Source.ZABBIX, {"created": 4})

    def fifth(conn, now, cfg, rules):
        raw = zabbix_problem(event_id="104", trigger_id="204", clock=1790661420)
        intake.apply(conn, normalize_zabbix(raw, cfg, rules), now, cfg)
        return PollReport(Source.ZABBIX, {"created": 1})

    zabbix = Stub(Source.ZABBIX, four, PollReport(Source.ZABBIX), fifth)
    assert run_cycle(conn, [zabbix], now, cfg, rules).tidy == Tidy()
    run_cycle(conn, [zabbix], at(now, 30), cfg, rules)
    report = run_cycle(conn, [zabbix], at(now, 60), cfg, rules)
    assert report.tidy.group_id is not None
    assert report.tidy.promoted == 0
    members = conn.execute("SELECT id, analysis_state FROM incidents WHERE source = 'zabbix' ORDER BY id").fetchall()
    assert [m["analysis_state"] for m in members] == ["grouped"] * 5
    assert all(events_of(conn, m["id"]) == ["detected", "grouped"] for m in members)


def test_waiting_incidents_are_promoted_and_followups_are_scheduled(conn, now, cfg, rules):
    def two(conn, now, cfg, rules):
        intake.apply(conn, normalize_zabbix(zabbix_problem(), cfg, rules), now, cfg)
        intake.apply(conn, normalize_wazuh(wazuh_hit(), cfg, rules), now, cfg)
        return PollReport(Source.ZABBIX, {"created": 2})

    zabbix = Stub(Source.ZABBIX, two)
    assert run_cycle(conn, [zabbix], now, cfg, rules).tidy.promoted == 0
    assert run_cycle(conn, [zabbix], at(now, 60), cfg, rules).tidy.promoted == 1
    assert run_cycle(conn, [zabbix], at(now, 120), cfg, rules).tidy.promoted == 1
    queue.start(conn, 1, at(now, 130))
    queue.complete(conn, 1, at(now, 200), urgency="medium", kind="performance", summary="要約")
    assert run_cycle(conn, [zabbix], at(now, 7399), cfg, rules).tidy.followups == 0
    assert run_cycle(conn, [zabbix], at(now, 7400), cfg, rules).tidy.followups == 1
    assert conn.execute("SELECT analysis_state FROM incidents WHERE id = 1").fetchone()[0] == "queued"


class Clock:
    def __init__(self, start):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now = at(self.now, int(seconds))


def test_loop_returns_interrupted_analyses_to_the_queue_once(conn, now, cfg, rules):
    intake.apply(conn, normalize_zabbix(zabbix_problem(), cfg, rules), now, cfg)
    queue.promote_held(conn, at(now, 60))
    queue.start(conn, 1, at(now, 61))
    clock, stop, seen = Clock(at(now, 100)), threading.Event(), []

    def on_cycle(report):
        seen.append(conn.execute("SELECT analysis_state, attempt_count FROM incidents").fetchone())
        if len(seen) == 2:
            queue.start(conn, 1, clock())
        if len(seen) == 3:
            stop.set()

    cycles = run_loop(conn, [Stub(Source.ZABBIX)], cfg, rules, stop, clock=clock, wait=clock.advance,
                      on_cycle=on_cycle)
    assert cycles == 3
    assert [tuple(row) for row in seen] == [("queued", 0), ("queued", 0), ("running", 1)]
    assert events_of(conn, 1).count("released") == 1


def test_loop_ticks_at_the_configured_pace_and_polls_on_schedule(conn, now, cfg, rules):
    clock, stop = Clock(now), threading.Event()
    zabbix, wazuh = Stub(Source.ZABBIX), Stub(Source.WAZUH)
    waits = []

    def wait(seconds):
        waits.append(seconds)
        clock.advance(seconds)
        if len(waits) == 13:
            stop.set()

    cycles = run_loop(conn, [zabbix, wazuh], cfg, rules, stop, clock=clock, wait=wait)
    assert cycles == 13
    assert set(waits) == {5}
    assert zabbix.calls == [now, at(now, 30), at(now, 60)]
    assert wazuh.calls == [now, at(now, 60)]


def test_stop_during_a_cycle_skips_the_remaining_sources_and_still_tidies(conn, now, cfg, rules):
    stop = threading.Event()

    def stopping(conn, now, cfg, rules):
        stop.set()
        return PollReport(Source.ZABBIX)

    zabbix, wazuh, reports = Stub(Source.ZABBIX, stopping), Stub(Source.WAZUH), []
    cycles = run_loop(conn, [zabbix, wazuh], cfg, rules, stop, clock=Clock(now), wait=lambda seconds: None,
                      on_cycle=reports.append)
    assert cycles == 1
    assert statuses(reports[0]) == [(Source.ZABBIX, "ok"), (Source.WAZUH, "stopped")]
    assert reports[0].tidy.error is None
    assert wazuh.calls == []


def test_loop_that_is_stopped_before_it_starts_does_nothing(conn, now, cfg, rules):
    stop = threading.Event()
    stop.set()
    zabbix = Stub(Source.ZABBIX)
    assert run_loop(conn, [zabbix], cfg, rules, stop, clock=Clock(now)) == 0
    assert zabbix.calls == []


def test_tick_follows_the_setting(conn, now, cfg, rules):
    clock, stop, waits = Clock(now), threading.Event(), []

    def wait(seconds):
        waits.append(seconds)
        stop.set()

    run_loop(conn, [Stub(Source.ZABBIX)], replace(cfg, collector_tick_sec=2), rules, stop, clock=clock, wait=wait)
    assert waits == [2]


def test_listing_that_does_not_finish_is_reported_as_unhealthy(conn, now, cfg, rules, caplog, tmp_path):
    from fakes import FakeServer, FakeZabbix
    from tia.collectors.endpoints import ZabbixEndpoint
    from tia.collectors.zabbix import ZabbixPoller

    fake = FakeZabbix()
    for number in range(18):
        fake.add_problem(48300 + number, trigger_id=23000 + number, clock=1790661420 - 3600 * (number + 1))
    small = replace(cfg, zabbix_page_size=2, zabbix_max_pages=2)
    token = tmp_path / "token"
    token.write_text(fake.token + "\n", encoding="utf-8")
    with FakeServer(fake.handle) as server, caplog.at_level(logging.INFO, logger="tia.collect"):
        poller = ZabbixPoller(ZabbixEndpoint(server.url + "/api_jsonrpc.php", token))
        for number in range(3):
            run_cycle(conn, [poller], at(now, 30 * number), small, rules)
        fine = state.health(conn, at(now, 61), small)[0]
        assert (fine.healthy, fine.reason) == (True, None)
        run_cycle(conn, [poller], at(now, 90), small, rules)
        bad = state.health(conn, at(now, 91), small)[0]
        assert bad.healthy is False
        assert "読み切れない状態が 4 回続いている" in bad.reason
        run_cycle(conn, [poller], at(now, 120), small, rules)
        good = state.health(conn, at(now, 121), small)[0]
        assert (good.healthy, good.reason) == (True, None)
    assert conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0] == 18
    warned = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING and "読み切れない" in r.getMessage()]
    assert len(warned) == 1
    assert any("読み切った" in r.getMessage() for r in caplog.records if r.levelno == logging.INFO)


def test_collection_resumes_at_once_after_the_clock_is_corrected(tmp_path, now, cfg, rules):
    from contextlib import closing

    path = tmp_path / "tia.sqlite"
    zabbix = Stub(Source.ZABBIX)
    wrong = at(now, 9 * 3600)
    with closing(db.connect(path)) as first:
        assert statuses(run_cycle(first, [zabbix], wrong, cfg, rules)) == [(Source.ZABBIX, "ok")]
    with closing(db.connect(path)) as second:
        assert statuses(run_cycle(second, [zabbix], now, cfg, rules)) == [(Source.ZABBIX, "ok")]
        assert statuses(run_cycle(second, [zabbix], at(now, 10), cfg, rules)) == [(Source.ZABBIX, "waiting")]
        assert statuses(run_cycle(second, [zabbix], at(now, 30), cfg, rules)) == [(Source.ZABBIX, "ok")]
    assert zabbix.calls == [wrong, now, at(now, 30)]


def start_up_lines(conn, now, cfg, rules, caplog, pollers):
    stop = threading.Event()
    stop.set()
    with caplog.at_level(logging.INFO, logger="tia.collect"):
        run_loop(conn, pollers, cfg, rules, stop, clock=Clock(now))
    return [r.getMessage() for r in caplog.records if "次の収集" in r.getMessage() or "すぐに収集" in r.getMessage()]


def test_loop_says_at_start_when_each_source_will_be_polled(conn, now, cfg, rules, caplog):
    state.record_success(conn, Source.ZABBIX, at(now, -10), at(now, 20), "1")
    lines = start_up_lines(conn, now, cfg, rules, caplog, [Stub(Source.ZABBIX), Stub(Source.WAZUH)])
    assert lines == ["zabbix の次の収集は 2026-09-29T05:57:20+00:00（20 秒後）。通常の間隔",
                     "wazuh はすぐに収集する。まだ一度も収集していない"]


def test_loop_says_at_start_that_it_waits_after_failures(conn, now, cfg, rules, caplog):
    for number in range(3):
        state.record_failure(conn, Source.ZABBIX, at(now, -300), "timeout", "10 秒以内に応答がない", at(now, 120))
    state.record_failure(conn, Source.WAZUH, at(now, -60), "auth", "認証に失敗した（HTTP 401）", at(now, 840))
    lines = start_up_lines(conn, now, cfg, rules, caplog, [Stub(Source.ZABBIX), Stub(Source.WAZUH)])
    assert lines == [
        "zabbix の次の収集は 2026-09-29T05:59:00+00:00（120 秒後）。失敗が 3 回続いた後の待ち（timeout）",
        "wazuh の次の収集は 2026-09-29T06:11:00+00:00（840 秒後）。認証の失敗の後の待ち（auth）。"
        "秘密を直した場合は tia collect --once で確かめられる"]


def test_loop_says_at_start_that_a_time_too_far_ahead_is_ignored(conn, now, cfg, rules, caplog):
    wrong = at(now, 9 * 3600)
    state.record_success(conn, Source.ZABBIX, wrong, at(wrong, 30), "1")
    lines = start_up_lines(conn, now, cfg, rules, caplog, [Stub(Source.ZABBIX)])
    assert lines == ["zabbix はすぐに収集する。保存してある次の収集の時刻 2026-09-29T14:57:30+00:00 が先すぎる。"
                     "時計がずれていた可能性がある"]


def test_loop_says_at_start_that_the_time_has_come(conn, now, cfg, rules, caplog):
    state.record_success(conn, Source.ZABBIX, at(now, -60), at(now, -30), "1")
    lines = start_up_lines(conn, now, cfg, rules, caplog, [Stub(Source.ZABBIX)])
    assert lines == ["zabbix はすぐに収集する。収集の時刻を過ぎている"]


def test_source_that_fails_at_the_same_position_three_times_is_called_out(conn, now, cfg, rules, caplog):
    broken = SourceError("invalid_response", "応答が JSON でない")
    wazuh = Stub(Source.WAZUH, PollReport(Source.WAZUH, {"fetched": 1, "created": 1}, True, '{"ts": 1, "after": null}'),
                 broken, broken, broken, broken)
    moment = now
    with caplog.at_level(logging.INFO, logger="tia.collect"):
        for number in range(5):
            run_cycle(conn, [wazuh], moment, cfg, rules)
            moment = state.get(conn, Source.WAZUH).next_poll_at
            if number == 2:
                early = state.health(conn, moment, cfg)[1]
                assert early.reason == "失敗が 2 回続いている（invalid_response）"
    loud = [r.getMessage() for r in caplog.records if r.levelno == logging.ERROR]
    assert len(loud) == 1
    assert "wazuh は同じ位置で 3 回続けて失敗した（invalid_response）" in loud[0]
    health = state.health(conn, moment, cfg)[1]
    assert health.healthy is False
    assert health.reason == "同じ位置で 4 回続けて失敗している（invalid_response）。この先のアラートを取り込めない"


def test_failures_at_different_positions_are_not_taken_for_a_stuck_source(conn, now, cfg, rules, caplog):
    def moved(position):
        def poll(conn, now, cfg, rules):
            state.set_watermark(conn, Source.WAZUH, position)
            raise SourceError("partial", "インデクサーの検索の一部が失敗した")
        return poll

    wazuh = Stub(Source.WAZUH, moved("a"), moved("b"), moved("c"), moved("d"))
    moment = now
    with caplog.at_level(logging.INFO, logger="tia.collect"):
        for _ in range(4):
            run_cycle(conn, [wazuh], moment, cfg, rules)
            moment = state.get(conn, Source.WAZUH).next_poll_at
    assert [r for r in caplog.records if r.levelno == logging.ERROR] == []
    assert state.health(conn, moment, cfg)[1].reason == "失敗が 4 回続いている（partial）"


def test_source_that_cannot_be_reached_is_not_called_stuck(conn, now, cfg, rules, caplog):
    down = SourceError("unreachable", "接続できない")
    zabbix = Stub(Source.ZABBIX, down, down, down, down)
    moment = now
    with caplog.at_level(logging.INFO, logger="tia.collect"):
        for _ in range(4):
            run_cycle(conn, [zabbix], moment, cfg, rules)
            moment = state.get(conn, Source.ZABBIX).next_poll_at
    assert [r for r in caplog.records if r.levelno == logging.ERROR] == []
    assert state.health(conn, moment, cfg)[0].reason == "失敗が 4 回続いている（unreachable）"


def test_success_clears_the_count_of_failures_at_one_position(conn, now, cfg, rules):
    broken = SourceError("invalid_response", "応答が JSON でない")
    wazuh = Stub(Source.WAZUH, broken, broken, PollReport(Source.WAZUH), broken)
    moment = now
    for _ in range(4):
        run_cycle(conn, [wazuh], moment, cfg, rules)
        moment = state.get(conn, Source.WAZUH).next_poll_at
    assert state.get(conn, Source.WAZUH).stuck_failures == 1
