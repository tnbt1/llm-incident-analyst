"""司令塔の部品。見張り、夜間の予定、束の入れ替え、ロック。"""
import logging
import threading
import time
from datetime import UTC, date, datetime
from zoneinfo import ZoneInfo

import pytest
from knowledge_helpers import build_fixture

from tia.analysis import worker
from tia.knowledge.bundle import load_bundle
from tia.ops.service import EXIT_COMPONENT, EXIT_OK, BundleReloader, InstanceLock, LockError, Supervisor, next_run

JST = ZoneInfo("Asia/Tokyo")


def test_supervisor_returns_0_when_stopped_by_the_signal():
    stop = threading.Event()
    sup = Supervisor(stop, grace_sec=5)
    sup.spawn("a", lambda: stop.wait(10))
    threading.Timer(0.2, stop.set).start()
    assert sup.wait() == EXIT_OK and sup.failed is None


def test_a_failing_component_stops_the_whole_process_with_code_3(caplog):
    stop = threading.Event()
    sup = Supervisor(stop, grace_sec=5)
    sup.spawn("quiet", lambda: stop.wait(10))

    def boom():
        time.sleep(0.1)
        raise RuntimeError("壊れた")

    sup.spawn("loud", boom)
    assert sup.wait() == EXIT_COMPONENT
    assert sup.failed == "loud" and stop.is_set()
    assert "loud が倒れた: RuntimeError" in caplog.text and "壊れた" in caplog.text


def test_component_that_returns_without_a_stop_is_a_failure(caplog):
    stop = threading.Event()
    sup = Supervisor(stop, grace_sec=5)
    sup.spawn("ends", lambda: None)
    assert sup.wait() == EXIT_COMPONENT and sup.failed == "ends"
    assert "ends が止める合図なしに終わった" in caplog.text


def test_system_exit_inside_a_component_is_a_failure_unless_stopping():
    stop = threading.Event()
    sup = Supervisor(stop, grace_sec=5)
    sup.spawn("exits", lambda: (_ for _ in ()).throw(SystemExit(1)))
    assert sup.wait() == EXIT_COMPONENT and sup.failed == "exits"


def test_non_essential_component_failure_is_only_logged(caplog):
    stop = threading.Event()
    sup = Supervisor(stop, grace_sec=5)
    sup.spawn("side", lambda: (_ for _ in ()).throw(RuntimeError("x")), essential=False)
    sup.spawn("main", lambda: stop.wait(10))
    threading.Timer(0.3, stop.set).start()
    assert sup.wait() == EXIT_OK and sup.failed is None
    assert "side が倒れた" in caplog.text


def test_supervisor_runs_the_stop_hooks_once():
    stop = threading.Event()
    sup = Supervisor(stop, grace_sec=5)
    calls = []
    sup.on_stop(lambda: calls.append(1))
    sup.spawn("a", lambda: stop.wait(10))
    threading.Timer(0.1, stop.set).start()
    sup.wait()
    sup.request_stop()
    assert calls == [1]


def test_supervisor_reports_threads_that_ignore_the_grace(caplog):
    stop = threading.Event()
    sup = Supervisor(stop, grace_sec=0.3)
    sup.spawn("stubborn", lambda: time.sleep(2))
    threading.Timer(0.1, stop.set).start()
    assert sup.wait() == EXIT_OK
    assert "止まらなかった: stubborn" in caplog.text


def test_next_run_is_today_or_tomorrow_in_the_zone():
    at_0300 = datetime(2026, 10, 6, 18, 0, tzinfo=UTC)  # 日本時間 03:00
    assert next_run(at_0300, "04:30", JST) == datetime(2026, 10, 6, 19, 30, tzinfo=UTC)
    at_0500 = datetime(2026, 10, 6, 20, 0, tzinfo=UTC)  # 日本時間 05:00
    assert next_run(at_0500, "04:30", JST) == datetime(2026, 10, 7, 19, 30, tzinfo=UTC)
    exactly = datetime(2026, 10, 6, 19, 30, tzinfo=UTC)
    assert next_run(exactly, "04:30", JST) == datetime(2026, 10, 7, 19, 30, tzinfo=UTC)


def test_lock_is_exclusive_and_released_when_the_process_ends(tmp_path):
    db = tmp_path / "tia.sqlite"
    first = InstanceLock(db)
    first.acquire()
    with pytest.raises(LockError, match="別の司令塔"):
        InstanceLock(db).acquire()
    assert InstanceLock.is_held(db)
    first.release()
    assert not InstanceLock.is_held(db)
    second = InstanceLock(db)
    second.acquire()
    second.release()


def test_bundle_reloader_swaps_the_bundle_when_current_changes(tmp_path, caplog):
    caplog.set_level(logging.INFO, logger="tia.run")
    built = build_fixture(tmp_path)
    root = built.path.parent
    deps = worker.Deps(client=None, bundle=load_bundle(root))
    reloader = BundleReloader(deps, root, every_sec=0)
    assert reloader.tick() is None
    newer = build_fixture(tmp_path, today=date(2026, 10, 6))  # 新しい版を作り、current を向け直す
    assert newer.version != built.version
    assert reloader.tick() == newer.version
    assert deps.bundle.version == newer.version
    assert "入れ替えた" in caplog.text


def test_bundle_reloader_keeps_the_old_bundle_when_the_new_one_is_broken(tmp_path, caplog):
    built = build_fixture(tmp_path)
    root = built.path.parent
    deps = worker.Deps(client=None, bundle=load_bundle(root))
    reloader = BundleReloader(deps, root, every_sec=0)
    (root / "current").write_text("20261006-000000000000\n", encoding="utf-8")
    assert reloader.tick() is None
    assert deps.bundle.version == built.version
    assert "知識の束を読み直せない" in caplog.text
    assert reloader.tick() is None
    assert caplog.text.count("知識の束を読み直せない") == 1  # 同じ失敗は 1 回だけ


def test_bundle_reloader_waits_between_checks(tmp_path):
    built = build_fixture(tmp_path)
    root = built.path.parent
    deps = worker.Deps(client=None, bundle=load_bundle(root))
    reloader = BundleReloader(deps, root, every_sec=60)
    assert reloader.tick() is None
    build_fixture(tmp_path, today=date(2026, 10, 6))
    assert reloader.tick() is None  # 60 秒たっていないので見ない
