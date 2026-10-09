"""ライブ更新。変化の検出、進捗、保存先が混んでいるとき、多くの接続、切断。"""
import json
import sqlite3
import threading
import time
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from web_fixtures import (BASE_URL, NOW, Clock, Probe, bundle_dir, client, ids, make_db, probe, serve, web_app,  # noqa: F401
                         web_clock, web_db)

from tia import db
from tia.analysis import records
from tia.config import Config
from tia.web import actions, events, queries
from tia.web.app import create_app
from tia.web.health import HealthMonitor


def _watcher(path, clock, monitor=None, cfg=None):
    conn = events.open_read(path)
    return conn, events.Watcher(conn, cfg or Config(), monitor or HealthMonitor(None, path.parent, Config(), clock), clock)


def _names(frames):
    return [f.decode().split("\n")[0].replace("event: ", "") for f in frames if f.startswith(b"event:")]


def test_first_step_reports_the_running_progress_and_then_nothing(web_db, web_clock):
    conn, watcher = _watcher(web_db[0], web_clock)
    try:
        assert _names(watcher.step(0.0)) == ["progress"], "稼働の確認がまだなら health は出ない"
        assert watcher.step(1.0) == []
    finally:
        conn.close()


def test_a_change_names_the_parts_and_the_incident(web_db, web_clock, ids):
    conn, watcher = _watcher(web_db[0], web_clock)
    writer = db.connect(web_db[0])
    try:
        watcher.step(0.0)
        actions.mark_read(writer, ids["done_today"], NOW + timedelta(seconds=3))
        names = _names(watcher.step(1.0))
        assert names == ["rail", "band", "list", f"incident-{ids['done_today']}"]
        assert watcher.step(1.0) == []
    finally:
        writer.close()
        conn.close()


def test_progress_of_the_running_analysis_is_an_event(web_db, web_clock, ids):
    conn, watcher = _watcher(web_db[0], web_clock)
    writer = db.connect(web_db[0])
    try:
        watcher.step(0.0)
        records.progress(writer, ids["running_analysis"], "inference", NOW + timedelta(seconds=2), tokens_so_far=400)
        frames = watcher.step(1.0)
        names = _names(frames)
        # 進捗は progress のイベントだけで届く。一覧や詳細を取り直させる名前は出ない
        assert names == ["progress"], names
        progress = next(f for f in frames if f.startswith(b"event: progress"))
        payload = json.loads(progress.decode().split("data: ", 1)[1].strip())
        assert payload["id"] == ids["running"] and payload["tokens"] == 400 and payload["percent"] == 33
        assert payload["rail"].endswith("400 / 1200 tok") and payload["detail"].startswith("400 / 1200")
    finally:
        writer.close()
        conn.close()


def test_health_refresh_is_an_event(web_db, web_clock, probe, bundle_dir):
    monitor = HealthMonitor(probe, bundle_dir, Config(), web_clock)
    conn, watcher = _watcher(web_db[0], web_clock, monitor)
    try:
        watcher.step(0.0)
        web_clock.now = NOW + timedelta(seconds=30)
        monitor.refresh()
        assert _names(watcher.step(1.0)) == ["health"]
    finally:
        conn.close()


def test_keepalive_comment_after_fifteen_quiet_seconds(web_db, web_clock):
    conn, watcher = _watcher(web_db[0], web_clock)
    try:
        watcher.step(0.0)
        for _ in range(14):
            assert watcher.step(1.0) == []
        assert watcher.step(1.0) == [b": keep-alive\n\n"]
        assert watcher.step(1.0) == []
    finally:
        conn.close()


def test_a_writer_holding_the_lock_does_not_block_the_watcher(web_db, web_clock):
    conn, watcher = _watcher(web_db[0], web_clock)
    writer = db.connect(web_db[0])
    try:
        watcher.step(0.0)
        writer.execute("BEGIN IMMEDIATE")
        writer.execute("UPDATE incidents SET read_at = ?, updated_at = ? WHERE id = 1",
                       ("2026-09-29T06:00:00+00:00", "2026-09-29T06:00:00+00:00"))
        started = time.monotonic()
        assert watcher.step(1.0) == [], "確定していない書き込みは見えない"
        assert time.monotonic() - started < 2
        writer.execute("COMMIT")
        assert "list" in _names(watcher.step(1.0))
    finally:
        writer.close()
        conn.close()


def test_a_locked_database_is_skipped_not_fatal(web_db, web_clock, monkeypatch):
    conn, watcher = _watcher(web_db[0], web_clock)
    try:
        watcher.step(0.0)
        calls = {"n": 0}
        real = queries.mark

        def flaky(connection):
            calls["n"] += 1
            if calls["n"] == 1:
                raise sqlite3.OperationalError("database is locked")
            return real(connection)

        monkeypatch.setattr(queries, "mark", flaky)
        assert watcher.step(1.0) == [], "混んでいる回は飛ばす"
        writer = db.connect(web_db[0])
        actions.mark_read(writer, 1, NOW + timedelta(seconds=5))
        writer.close()
        assert "list" in _names(watcher.step(1.0)), "次の回で変化を拾う"
    finally:
        conn.close()


def test_read_connection_cannot_write(web_db):
    conn = events.open_read(web_db[0])
    try:
        with pytest.raises(sqlite3.OperationalError):
            conn.execute("UPDATE incidents SET read_at = 'x'")
    finally:
        conn.close()


def test_stream_sends_retry_then_events_and_closes_after_the_limit(web_db, web_clock, probe, bundle_dir, ids):
    app = create_app(web_db[0], Config(web_sse_max_sec=2, web_cookie_secure=False), bundle_dir=bundle_dir,
                     llm_probe=probe, clock=web_clock)

    def write_later():
        time.sleep(0.5)
        writer = db.connect(web_db[0])
        actions.mark_read(writer, ids["done_today"], NOW + timedelta(seconds=3))
        writer.close()

    threading.Thread(target=write_later, daemon=True).start()
    with TestClient(app, base_url=BASE_URL) as test_client:
        started = time.monotonic()
        response = test_client.get("/events")
        elapsed = time.monotonic() - started
    assert response.status_code == 200 and response.headers["content-type"].startswith("text/event-stream")
    assert response.headers["cache-control"] == "no-store"
    body = response.text
    assert body.startswith("retry: 3000\n\n") and body.rstrip().endswith(": reconnect")
    assert f"event: incident-{ids['done_today']}\ndata: {ids['done_today']}\n\n" in body
    assert "event: list\n" in body and "event: rail\n" in body and "event: band\n" in body
    assert 1.5 <= elapsed < 6, "上限で閉じる"


def test_many_clients_watch_at_once(web_db, web_clock):
    watchers = [_watcher(web_db[0], web_clock) for _ in range(20)]
    writer = db.connect(web_db[0])
    try:
        for _, watcher in watchers:
            watcher.step(0.0)
        actions.mark_read(writer, 1, NOW + timedelta(seconds=3))
        results = []

        def run(watcher):
            results.append(_names(watcher.step(1.0)))

        threads = [threading.Thread(target=run, args=(w,)) for _, w in watchers]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)
        assert len(results) == 20 and all("list" in r for r in results)
    finally:
        writer.close()
        for conn, _ in watchers:
            conn.close()


def test_stream_closes_its_connection_when_the_client_leaves(web_app, monkeypatch):
    import httpx

    opened = []
    real = events.open_read

    def tracking(path):
        conn = real(path)
        opened.append(conn)
        return conn

    monkeypatch.setattr(events, "open_read", tracking)
    with serve(web_app) as base:
        with httpx.Client(timeout=5) as http, http.stream("GET", base + "/events") as response:
            assert response.status_code == 200
            first = next(response.iter_lines())
            assert first == "retry: 3000"
        # ここで接続を閉じた。サーバー側は次の確認で気づき、保存先の接続を閉じる
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            try:
                opened[0].execute("SELECT 1")
            except sqlite3.ProgrammingError:
                break
            time.sleep(0.1)
    assert len(opened) == 1
    with pytest.raises(sqlite3.ProgrammingError):
        opened[0].execute("SELECT 1")
