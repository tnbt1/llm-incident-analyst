"""ワーカー。待ち行列から取り、解析し、記録する流れ。偽の LLM に対して。"""
import json
import logging
import threading
import time
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from builders import zabbix_problem
from fakes import FakeLlm, FakeServer, unused_port
from knowledge_helpers import build_fixture

from tia import db, intake, queue
from tia.analysis import records, worker
from tia.analysis.llm import LlmClient
from tia.collectors.endpoints import LlmEndpoint
from tia.knowledge.bundle import load_bundle
from tia.normalize import normalize_zabbix


class Clock:
    """テストが進める時計。"""

    def __init__(self, start: datetime) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: int) -> None:
        self.now += timedelta(seconds=seconds)


@pytest.fixture
def bundle(tmp_path):
    return load_bundle(build_fixture(tmp_path).path)


@pytest.fixture
def fake():
    return FakeLlm()


@pytest.fixture
def clock(now):
    return Clock(now)


def _deps(server, fake, cfg, bundle):
    endpoint = LlmEndpoint(server.url + "/openai", Path("/x"), fake.model)
    return worker.Deps(LlmClient(endpoint, cfg, api_key=fake.key), bundle)


def _queued(conn, cfg, rules, clock, event_id="48213", trigger_id="23456", host="example-router01", severity=2):
    alert = normalize_zabbix(zabbix_problem(event_id=event_id, trigger_id=trigger_id, host=host, severity=severity),
                             cfg, rules)
    incident_id = intake.apply(conn, alert, clock(), cfg).incident_id
    clock.advance(cfg.zabbix_hold_sec + 1)
    queue.promote_held(conn, clock())
    return incident_id


def _state(conn, incident_id):
    row = conn.execute("SELECT analysis_state, attempt_count, urgency, kind, summary, latest_analysis_id, fail_reason "
                       "FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    return dict(row)


def test_nothing_to_do_is_idle(conn, cfg, bundle, fake, clock):
    with FakeServer(fake.handle) as server:
        outcome = worker.run_once(conn, cfg, _deps(server, fake, cfg, bundle), clock)
    assert outcome.kind == "idle" and fake.requests == []


def test_successful_analysis_is_stored_and_the_incident_becomes_done(conn, cfg, rules, bundle, fake, clock):
    incident_id = _queued(conn, cfg, rules, clock)
    with FakeServer(fake.handle) as server:
        outcome = worker.run_once(conn, cfg, _deps(server, fake, cfg, bundle), clock)
    assert outcome.kind == "done" and outcome.incident_id == incident_id
    state = _state(conn, incident_id)
    assert (state["analysis_state"], state["attempt_count"], state["urgency"], state["kind"]) == (
        "done", 1, "today", "performance")
    assert state["summary"].startswith("example-router01 の CPU")
    row = records.get(conn, outcome.analysis_id)
    assert (row["status"], row["phase"], row["trigger"], row["model"]) == ("done", "finished", "initial",
                                                                            "example/model-27b")
    assert row["knowledge_version"] == bundle.version and len(row["prompt_hash"]) == 16
    assert (row["prompt_tokens"], row["tokens_per_sec"]) == (1234, 7.0)
    assert row["completion_tokens"] == row["tokens_so_far"] > 0
    result = json.loads(row["result_json"])
    assert [check["verified"] for check in result["recommended_checks"]] == [False, False]
    ctx = json.loads(row["context_json"])
    assert [p["name"] for p in ctx["parts"]][0] == "rules" and ctx["parts"][-1]["name"] == "dynamic"
    assert state["latest_analysis_id"] == outcome.analysis_id
    kinds = [r["type"] for r in conn.execute("SELECT type FROM events WHERE incident_id = ? ORDER BY id",
                                             (incident_id,))]
    assert kinds[-2:] == ["analysis_started", "analysis_done"]
    body = fake.requests[0]
    assert body["messages"][0]["role"] == "system" and "<alert_data>" in body["messages"][1]["content"]
    assert body["chat_template_kwargs"] == {"enable_thinking": False} and body["cache_prompt"] is True


def test_recommended_command_from_the_documents_is_marked_verified(conn, cfg, rules, bundle, fake, clock):
    # テスト用の束のホスト名（vm-monitor01）に合わせる
    incident_id = _queued(conn, cfg, rules, clock, host="vm-monitor01")
    conn.execute("UPDATE incidents SET type = 'disk', title = 'Disk space is critically low' WHERE id = ?",
                 (incident_id,))
    fake.output["recommended_checks"] = [{"purpose": "容量", "where": "monitor01", "command": "sudo df -h / /var/lib/docker"},
                                         {"purpose": "空き", "where": "monitor01", "command": "free -h"}]
    with FakeServer(fake.handle) as server:
        outcome = worker.run_once(conn, cfg, _deps(server, fake, cfg, bundle), clock)
    result = records.result_of(records.get(conn, outcome.analysis_id))
    assert [check["verified"] for check in result["recommended_checks"]] == [True, False]


def test_validation_failure_is_regenerated_once_then_fails_without_a_retry(conn, cfg, rules, bundle, fake, clock):
    incident_id = _queued(conn, cfg, rules, clock)
    fake.modes = ["schema_violation", "schema_violation"]
    with FakeServer(fake.handle) as server:
        outcome = worker.run_once(conn, cfg, _deps(server, fake, cfg, bundle), clock)
    assert outcome.kind == "failed"
    assert len(fake.requests) == 2
    second = fake.requests[1]
    assert second["temperature"] == 0.0
    assert second["messages"][-2]["role"] == "assistant" and "検証に失敗した" in second["messages"][-1]["content"]
    assert "impact" in second["messages"][-1]["content"]
    state = _state(conn, incident_id)
    assert (state["analysis_state"], state["attempt_count"]) == ("failed", 1)
    assert state["fail_reason"].startswith("validation: $.impact")
    row = records.get(conn, outcome.analysis_id)
    assert (row["status"], row["error_kind"]) == ("failed", "validation")
    kinds = [r["type"] for r in conn.execute("SELECT type FROM events WHERE incident_id = ? ORDER BY id",
                                             (incident_id,))]
    assert "regenerated" in kinds and kinds[-1] == "analysis_failed"


def test_regeneration_that_succeeds_completes_the_analysis(conn, cfg, rules, bundle, fake, clock):
    incident_id = _queued(conn, cfg, rules, clock)
    fake.modes = ["invalid_json", "ok"]
    with FakeServer(fake.handle) as server:
        outcome = worker.run_once(conn, cfg, _deps(server, fake, cfg, bundle), clock)
    assert outcome.kind == "done" and len(fake.requests) == 2
    assert _state(conn, incident_id)["analysis_state"] == "done"


def test_reserved_tag_in_the_output_never_becomes_a_done_analysis(conn, cfg, rules, bundle, fake, clock):
    incident_id = _queued(conn, cfg, rules, clock)
    fake.modes = ["reserved_tag", "reserved_tag"]
    with FakeServer(fake.handle) as server:
        outcome = worker.run_once(conn, cfg, _deps(server, fake, cfg, bundle), clock)
    assert outcome.kind == "failed"
    assert _state(conn, incident_id)["urgency"] is None
    # 失敗した出力は残すが、画面の結果としては使わない（status が failed）
    row = records.get(conn, outcome.analysis_id)
    assert row["status"] == "failed" and records.failed_output(row) is not None


def test_timeout_counts_as_an_attempt(conn, cfg, rules, bundle, fake, clock):
    incident_id = _queued(conn, cfg, rules, clock)
    fake.modes = ["slow"]
    fake.slow_pause = 0.5
    quick = replace(cfg, llm_timeout_sec=1)
    with FakeServer(fake.handle) as server:
        outcome = worker.run_once(conn, quick, _deps(server, fake, quick, bundle), clock)
    assert outcome.kind == "retry_wait" and outcome.detail.startswith("timeout")
    state = _state(conn, incident_id)
    assert (state["analysis_state"], state["attempt_count"]) == ("retry_wait", 1)


def test_unreachable_llm_releases_without_using_an_attempt(conn, cfg, rules, bundle, fake, clock):
    incident_id = _queued(conn, cfg, rules, clock)
    endpoint = LlmEndpoint(f"http://127.0.0.1:{unused_port()}/openai", Path("/x"), fake.model)
    quick = replace(cfg, llm_connect_timeout_sec=1)
    deps = worker.Deps(LlmClient(endpoint, quick, api_key=fake.key), bundle)
    outcome = worker.run_once(conn, quick, deps, clock)
    assert outcome.kind == "released" and outcome.detail.startswith("unreachable")
    state = _state(conn, incident_id)
    assert (state["analysis_state"], state["attempt_count"]) == ("queued", 0)
    rows = records.for_incident(conn, incident_id)
    assert len(rows) == 1 and rows[0]["status"] == "released" and rows[0]["error_kind"] == "unreachable"
    kinds = [r["type"] for r in conn.execute("SELECT type FROM events WHERE incident_id = ? ORDER BY id",
                                             (incident_id,))]
    assert kinds[-1] == "released"


def test_loop_waits_while_the_llm_is_unreachable_instead_of_spinning(conn, cfg, rules, bundle, fake, clock):
    """C-1: 届かない間は待つ。3 秒で解析の行は 2 つまで、出来事も増え続けない。"""
    incident_id = _queued(conn, cfg, rules, clock)
    endpoint = LlmEndpoint(f"http://127.0.0.1:{unused_port()}/openai", Path("/x"), fake.model)
    quick = replace(cfg, llm_connect_timeout_sec=1, worker_backoff_min_sec=1)
    deps = worker.Deps(LlmClient(endpoint, quick, api_key=fake.key), bundle)
    stop = threading.Event()
    threading.Timer(3.0, stop.set).start()
    started = time.monotonic()
    worker.run_loop(conn, quick, deps, stop, clock)
    assert time.monotonic() - started < 5
    assert len(records.for_incident(conn, incident_id)) <= 2
    events = conn.execute("SELECT COUNT(*) FROM events WHERE incident_id = ? AND type IN ('analysis_started', "
                          "'released')", (incident_id,)).fetchone()[0]
    assert events <= 4
    assert _state(conn, incident_id)["analysis_state"] == "queued"


def test_backoff_grows_doubles_caps_and_resets():
    backoff = worker.Backoff(min_sec=5, max_sec=600, auth_sec=900)
    assert not backoff.active
    waits = [backoff.failed("unreachable") for _ in range(9)]
    assert waits == [5, 10, 20, 40, 80, 160, 320, 600, 600]
    backoff.reset()
    assert not backoff.active and backoff.failed("server") == 5
    assert backoff.failed("auth") == 900 and backoff.failed("unreachable") == 600


def test_credential_failure_waits_the_long_backoff(conn, cfg, rules, bundle, fake, clock):
    _queued(conn, cfg, rules, clock)
    fake.modes = ["unauthorized"] * 50
    stop = threading.Event()
    with FakeServer(fake.handle) as server:
        deps = _deps(server, fake, cfg, bundle)
        threading.Timer(2.0, stop.set).start()
        worker.run_loop(conn, replace(cfg, worker_backoff_min_sec=1), deps, stop, clock)
    assert len(fake.requests) == 1


def test_stop_interrupts_the_backoff_wait(conn, cfg, rules, bundle, fake, clock):
    _queued(conn, cfg, rules, clock)
    endpoint = LlmEndpoint(f"http://127.0.0.1:{unused_port()}/openai", Path("/x"), fake.model)
    quick = replace(cfg, llm_connect_timeout_sec=1, worker_backoff_min_sec=60)
    deps = worker.Deps(LlmClient(endpoint, quick, api_key=fake.key), bundle)
    stop = threading.Event()
    threading.Timer(1.0, stop.set).start()
    started = time.monotonic()
    worker.run_loop(conn, quick, deps, stop, clock)
    assert time.monotonic() - started < 3


def test_success_after_backoff_resets_the_wait(conn, cfg, rules, bundle, fake, clock, caplog):
    _queued(conn, cfg, rules, clock, event_id="1", trigger_id="1")
    _queued(conn, cfg, rules, clock, event_id="2", trigger_id="2")
    fake.modes = ["http_500"]
    stop = threading.Event()
    with FakeServer(fake.handle) as server, caplog.at_level(logging.INFO, logger="tia.analyze"):
        deps = _deps(server, fake, cfg, bundle)
        threading.Timer(4.0, stop.set).start()
        worker.run_loop(conn, replace(cfg, worker_backoff_min_sec=1, worker_idle_sec=1), deps, stop, clock)
    assert conn.execute("SELECT COUNT(*) FROM incidents WHERE analysis_state = 'done'").fetchone()[0] == 2
    assert "待つ" in caplog.text and "届くようになった" in caplog.text


@pytest.mark.parametrize("mode, kind", [("http_500", "server"), ("unauthorized", "auth")])
def test_server_and_credential_failures_release(conn, cfg, rules, bundle, fake, clock, mode, kind, caplog):
    incident_id = _queued(conn, cfg, rules, clock)
    fake.modes = [mode]
    with FakeServer(fake.handle) as server, caplog.at_level(logging.WARNING):
        outcome = worker.run_once(conn, cfg, _deps(server, fake, cfg, bundle), clock)
    assert outcome.kind == "released" and outcome.detail.startswith(kind)
    assert _state(conn, incident_id)["analysis_state"] == "queued"
    assert fake.key not in caplog.text


def test_stop_during_the_request_releases_and_returns_quickly(conn, cfg, rules, bundle, fake, clock):
    incident_id = _queued(conn, cfg, rules, clock)
    fake.modes = ["delay"]
    fake.delay = 10
    stop = threading.Event()
    threading.Timer(0.5, stop.set).start()
    with FakeServer(fake.handle) as server:
        started = time.monotonic()
        outcome = worker.run_once(conn, replace(cfg, llm_timeout_sec=30), _deps(server, fake, cfg, bundle), clock,
                                  stop)
        elapsed = time.monotonic() - started
    assert outcome.kind == "released" and outcome.detail.startswith("stopped")
    assert elapsed < 4
    assert _state(conn, incident_id)["analysis_state"] == "queued"
    assert worker.run_once(conn, cfg, _deps(server, fake, cfg, bundle), clock, stop).kind == "idle"


def test_progress_is_written_while_the_answer_streams(conn, cfg, rules, bundle, fake, clock):
    _queued(conn, cfg, rules, clock)
    fake.pause = 0.02
    fake.chunk_size = 4
    seen: list[tuple[str, int]] = []
    original = records.progress

    def spy(conn_, analysis_id, phase, now, *, tokens_so_far=None):
        seen.append((phase, tokens_so_far))
        original(conn_, analysis_id, phase, now, tokens_so_far=tokens_so_far)

    worker.records.progress = spy
    try:
        with FakeServer(fake.handle) as server:
            outcome = worker.run_once(conn, replace(cfg, worker_progress_every_chunks=10),
                                      _deps(server, fake, cfg, bundle), clock)
    finally:
        worker.records.progress = original
    assert outcome.kind == "done"
    inference = [tokens for phase, tokens in seen if phase == "inference"]
    assert len(inference) >= 3 and inference == sorted(inference)
    assert seen[-1][0] == "validation"


def test_restart_recovers_running_work(conn, cfg, rules, bundle, fake, clock, tmp_path):
    path = tmp_path / "tia.sqlite"
    first = db.connect(path)
    incident_id = _queued(first, cfg, rules, clock)
    queue.start(first, incident_id, clock())
    records.begin(first, incident_id, "initial", "m", clock())
    first.close()
    second = db.connect(path)
    assert worker.recover(second, clock) == (1, 1)
    assert _state(second, incident_id)["analysis_state"] == "queued"
    assert records.for_incident(second, incident_id)[0]["status"] == "released"
    with FakeServer(fake.handle) as server:
        assert worker.run_once(second, cfg, _deps(server, fake, cfg, bundle), clock).kind == "done"
    second.close()


def test_loop_analyses_until_told_to_stop(conn, cfg, rules, bundle, fake, clock):
    _queued(conn, cfg, rules, clock, event_id="1", trigger_id="1")
    _queued(conn, cfg, rules, clock, event_id="2", trigger_id="2")
    stop = threading.Event()
    with FakeServer(fake.handle) as server:
        deps = _deps(server, fake, cfg, bundle)
        threading.Timer(3.0, stop.set).start()
        count = worker.run_loop(conn, replace(cfg, worker_idle_sec=1), deps, stop, clock)
    assert count == 2
    assert conn.execute("SELECT COUNT(*) FROM incidents WHERE analysis_state = 'done'").fetchone()[0] == 2


def test_replay_adds_an_analysis_without_touching_the_state(conn, cfg, rules, bundle, fake, clock):
    incident_id = _queued(conn, cfg, rules, clock)
    with FakeServer(fake.handle) as server:
        deps = _deps(server, fake, cfg, bundle)
        worker.run_once(conn, cfg, deps, clock)
        before = _state(conn, incident_id)
        fake.output = {**fake.output, "classification": {"kind": "noise", "urgency": "ignore"}}
        outcome = worker.replay(conn, incident_id, cfg, deps, clock)
    assert outcome.kind == "done"
    assert _state(conn, incident_id) == before
    rows = records.for_incident(conn, incident_id)
    assert [r["trigger"] for r in rows] == ["initial", "replay"]
    assert records.result_of(rows[1])["classification"]["urgency"] == "ignore"
    with pytest.raises(ValueError, match="がない"):
        worker.replay(conn, 999, cfg, deps, clock)


def test_followup_and_manual_triggers_are_recorded(conn, cfg, rules, bundle, fake, clock):
    incident_id = _queued(conn, cfg, rules, clock)
    with FakeServer(fake.handle) as server:
        deps = _deps(server, fake, cfg, bundle)
        worker.run_once(conn, cfg, deps, clock)
        queue.requeue(conn, incident_id, clock())
        worker.run_once(conn, cfg, deps, clock)
        clock.advance(cfg.intake_followup_after_sec + 1)
        queue.schedule_followups(conn, clock(), cfg)
        worker.run_once(conn, cfg, deps, clock)
    assert [r["trigger"] for r in records.for_incident(conn, incident_id)] == ["initial", "manual", "followup"]


def test_unexpected_failure_does_not_leave_the_incident_running(conn, cfg, rules, bundle, fake, clock, monkeypatch):
    incident_id = _queued(conn, cfg, rules, clock)

    def broken(*args, **kwargs):
        raise KeyError("壊れた文脈")

    monkeypatch.setattr(worker, "assemble", broken)
    with FakeServer(fake.handle) as server:
        outcome = worker.run_once(conn, cfg, _deps(server, fake, cfg, bundle), clock)
    assert outcome.kind == "retry_wait" and outcome.detail == "internal: KeyError"
    state = _state(conn, incident_id)
    assert state["analysis_state"] == "retry_wait" and state["fail_reason"] == "internal: KeyError"
    assert records.for_incident(conn, incident_id)[0]["status"] == "failed"


def test_length_asks_once_for_a_shorter_answer_then_fails_as_length(conn, cfg, rules, bundle, fake, clock):
    incident_id = _queued(conn, cfg, rules, clock)
    fake.modes = ["length", "length"]
    with FakeServer(fake.handle) as server:
        outcome = worker.run_once(conn, cfg, _deps(server, fake, cfg, bundle), clock)
    assert outcome.kind == "failed" and outcome.detail.startswith("length")
    assert len(fake.requests) == 2
    note = fake.requests[1]["messages"][-1]["content"]
    assert "短く" in note
    state = _state(conn, incident_id)
    assert (state["analysis_state"], state["attempt_count"]) == ("failed", 1)
    row = records.for_incident(conn, incident_id)[-1]
    assert row["error_kind"] == "length"


def test_length_followed_by_a_good_answer_completes(conn, cfg, rules, bundle, fake, clock):
    incident_id = _queued(conn, cfg, rules, clock)
    fake.modes = ["length", "ok"]
    with FakeServer(fake.handle) as server:
        outcome = worker.run_once(conn, cfg, _deps(server, fake, cfg, bundle), clock)
    assert outcome.kind == "done" and _state(conn, incident_id)["analysis_state"] == "done"


@pytest.mark.parametrize("mode", ["non_json", "error_json_200", "error_in_stream"])
def test_wrong_route_or_server_error_releases_without_an_attempt(conn, cfg, rules, bundle, fake, clock, mode):
    incident_id = _queued(conn, cfg, rules, clock)
    fake.modes = [mode]
    with FakeServer(fake.handle) as server:
        outcome = worker.run_once(conn, cfg, _deps(server, fake, cfg, bundle), clock)
    assert outcome.kind == "released" and outcome.detail.startswith("invalid_response")
    assert "途中で切れた" not in outcome.detail
    assert _state(conn, incident_id) | {"attempt_count": 0} == _state(conn, incident_id)
    assert _state(conn, incident_id)["analysis_state"] == "queued"


def test_output_with_control_characters_is_regenerated_from_the_cleaned_text(conn, cfg, rules, bundle, fake, clock):
    """M-2: 制御文字や特殊な印を含む出力は検証失敗。作り直しに渡す前の出力は無害にしたもの。"""
    incident_id = _queued(conn, cfg, rules, clock)
    fake.modes = ["control_chars", "control_chars"]
    with FakeServer(fake.handle) as server:
        outcome = worker.run_once(conn, cfg, _deps(server, fake, cfg, bundle), clock)
    assert outcome.kind == "failed" and outcome.detail.startswith("validation")
    assert len(fake.requests) == 2
    fed_back = fake.requests[1]["messages"][-2]["content"]
    assert "\x1b" not in fed_back and "\x00" not in fed_back and "<|im_start|>" not in fed_back
    stored = conn.execute("SELECT result_json, error FROM analyses WHERE incident_id = ?", (incident_id,)).fetchall()
    assert all("\x1b" not in (row["result_json"] or "") and "\x1b" not in (row["error"] or "") for row in stored)


def test_progress_write_failure_does_not_lose_the_inference(conn, cfg, rules, bundle, fake, clock, caplog):
    """M-7: 進捗の書き込みが鍵待ちで失敗しても、推論は続き、解析は完了する。"""
    import sqlite3
    incident_id = _queued(conn, cfg, rules, clock)
    fake.pause = 0.02
    fake.chunk_size = 4
    original = records.progress
    failures = {"count": 0}

    def locked(conn_, analysis_id, phase, now, *, tokens_so_far=None):
        if phase == "inference":
            failures["count"] += 1
            raise sqlite3.OperationalError("database is locked")
        original(conn_, analysis_id, phase, now, tokens_so_far=tokens_so_far)

    worker.records.progress = locked
    try:
        with FakeServer(fake.handle) as server, caplog.at_level(logging.WARNING, logger="tia.analyze"):
            outcome = worker.run_once(conn, replace(cfg, worker_progress_every_chunks=10),
                                      _deps(server, fake, cfg, bundle), clock)
    finally:
        worker.records.progress = original
    assert outcome.kind == "done" and failures["count"] >= 3
    assert _state(conn, incident_id)["analysis_state"] == "done"
    assert caplog.text.count("進捗を保存できない") == 1


def test_destructive_check_is_excluded_and_the_analysis_is_done_without_regeneration(conn, cfg, rules, bundle, fake, clock):
    """禁止のコマンドが混ざっても、ほかが正しければ 1 回で完了し、除外を記録と経過に残す。"""
    incident_id = _queued(conn, cfg, rules, clock)
    fake.output["recommended_checks"] = [{"purpose": "利用者の状態", "where": "app01", "command": "passwd -S monitor-tunnel"},
                                         {"purpose": "負荷", "where": "app01", "command": "uptime"}]
    with FakeServer(fake.handle) as server:
        outcome = worker.run_once(conn, cfg, _deps(server, fake, cfg, bundle), clock)
    assert outcome.kind == "done" and len(fake.requests) == 1
    result = records.result_of(records.get(conn, outcome.analysis_id))
    assert [c["command"] for c in result["recommended_checks"]] == ["uptime"]
    assert result["excluded_checks"][0]["reason"] == "利用者とパスワードの変更"
    assert _state(conn, incident_id)["analysis_state"] == "done"
    kinds = [r["type"] for r in conn.execute("SELECT type FROM events WHERE incident_id = ? ORDER BY id", (incident_id,))]
    assert "checks_excluded" in kinds and "regenerated" not in kinds
    detail = conn.execute("SELECT detail_json FROM events WHERE incident_id = ? AND type = 'checks_excluded'",
                          (incident_id,)).fetchone()[0]
    assert '"count": 1' in detail


def test_only_destructive_checks_is_done_with_no_recommendation(conn, cfg, rules, bundle, fake, clock):
    _queued(conn, cfg, rules, clock)
    fake.modes = ["destructive"]
    with FakeServer(fake.handle) as server:
        outcome = worker.run_once(conn, cfg, _deps(server, fake, cfg, bundle), clock)
    assert outcome.kind == "done"
    result = records.result_of(records.get(conn, outcome.analysis_id))
    assert result["recommended_checks"] == [] and len(result["excluded_checks"]) == 1


def test_validation_failure_keeps_the_output_and_is_not_retried(conn, cfg, rules, bundle, fake, clock):
    incident_id = _queued(conn, cfg, rules, clock)
    fake.modes = ["schema_violation", "schema_violation"]
    with FakeServer(fake.handle) as server:
        outcome = worker.run_once(conn, cfg, _deps(server, fake, cfg, bundle), clock)
    assert outcome.kind == "failed" and len(fake.requests) == 2
    state = _state(conn, incident_id)
    assert state["analysis_state"] == "failed" and state["fail_reason"].startswith("validation: $.impact")
    row = records.get(conn, outcome.analysis_id)
    assert row["status"] == "failed" and row["result_json"]
    assert "summary" in records.failed_output(row)
    kinds = [r["type"] for r in conn.execute("SELECT type FROM events WHERE incident_id = ? ORDER BY id", (incident_id,))]
    assert "retry_scheduled" not in kinds and kinds[-1] == "analysis_failed"
    detail = conn.execute("SELECT detail_json FROM events WHERE incident_id = ? AND type = 'analysis_failed'",
                          (incident_id,)).fetchone()[0]
    assert '"kind": "validation"' in detail


def test_length_failure_is_not_retried_either(conn, cfg, rules, bundle, fake, clock):
    incident_id = _queued(conn, cfg, rules, clock)
    fake.modes = ["length", "length"]
    with FakeServer(fake.handle) as server:
        outcome = worker.run_once(conn, cfg, _deps(server, fake, cfg, bundle), clock)
    assert outcome.kind == "failed" and _state(conn, incident_id)["analysis_state"] == "failed"


def test_timeout_is_still_retried(conn, cfg, rules, bundle, fake, clock):
    incident_id = _queued(conn, cfg, rules, clock)
    fake.modes = ["slow"]
    fake.slow_pause = 0.5
    quick = replace(cfg, llm_timeout_sec=1)
    with FakeServer(fake.handle) as server:
        outcome = worker.run_once(conn, quick, _deps(server, fake, quick, bundle), clock)
    assert outcome.kind == "retry_wait" and _state(conn, incident_id)["analysis_state"] == "retry_wait"


def test_failed_incident_without_retries_can_be_requeued(conn, cfg, rules, bundle, fake, clock):
    incident_id = _queued(conn, cfg, rules, clock)
    fake.modes = ["schema_violation", "schema_violation"]
    with FakeServer(fake.handle) as server:
        worker.run_once(conn, cfg, _deps(server, fake, cfg, bundle), clock)
    queue.requeue(conn, incident_id, clock())
    with FakeServer(fake.handle) as server:
        outcome = worker.run_once(conn, cfg, _deps(server, fake, cfg, bundle), clock)
    assert outcome.kind == "done" and _state(conn, incident_id)["analysis_state"] == "done"


class StubRunner:
    """確認の実行器の代わり。plan と run だけを持つ。"""

    def __init__(self, results=None, *, raises=None):
        from tia.probes.catalog import Catalog

        self.catalog = Catalog.load(Path(__file__).resolve().parents[1] / "config" / "probes.yaml")
        self.results = results
        self.raises = raises
        self.calls = []

    def plan(self, incident):
        return self.catalog.for_incident(incident["host"], incident["type"], incident["source"])

    def run(self, probes, incident, *, stop=None):
        from tia.probes.runner import ProbeResult

        self.calls.append([p.name for p in probes])
        if self.raises:
            raise self.raises
        if self.results is not None:
            return self.results
        now = datetime(2026, 9, 29, 5, 58, tzinfo=UTC)
        return [ProbeResult(p.name, incident["host"] if p.where == "host" else p.where, "ok" if i % 2 == 0 else "timeout",
                            f"output of {p.name}" if i % 2 == 0 else "", None if i % 2 == 0 else "10 秒で打ち切った",
                            5, now, f"cmd {p.name}") for i, p in enumerate(probes)]


def _probe_deps(server, fake, cfg, bundle, runner):
    endpoint = LlmEndpoint(server.url + "/openai", Path("/x"), fake.model)
    return worker.Deps(LlmClient(endpoint, cfg, api_key=fake.key), bundle, probes=runner)


def test_stage_one_probes_run_before_inference_and_are_stored(conn, cfg, rules, bundle, fake, clock):
    from tia.probes import store

    incident_id = _queued(conn, cfg, rules, clock, host="example-app01")
    conn.execute("UPDATE incidents SET type = 'disk' WHERE id = ?", (incident_id,))
    runner = StubRunner()
    with FakeServer(fake.handle) as server:
        outcome = worker.run_once(conn, cfg, _probe_deps(server, fake, cfg, bundle, runner), clock)
    assert outcome.kind == "done"
    assert runner.calls and {"disk", "compose_ps", "zabbix_trigger"} <= set(runner.calls[0])
    rows = store.for_analysis(conn, outcome.analysis_id)
    assert [r["name"] for r in rows] == runner.calls[0]
    assert all(r["trigger"] == "initial" and r["incident_id"] == incident_id for r in rows)
    kinds = [r["type"] for r in conn.execute("SELECT type FROM events WHERE incident_id = ? ORDER BY id", (incident_id,))]
    assert "probed" in kinds and kinds.index("analysis_started") < kinds.index("probed") < kinds.index("analysis_done")
    detail = json.loads(conn.execute("SELECT detail_json FROM events WHERE type = 'probed'").fetchone()[0])
    assert detail["analysis_id"] == outcome.analysis_id and detail["count"] == len(rows) and detail["failed"]
    prompt = fake.requests[0]["messages"][1]["content"]
    assert "<probe_data" in prompt and "output of uptime_load" in prompt and "10 秒で打ち切った" in prompt
    ctx = json.loads(records.get(conn, outcome.analysis_id)["context_json"])
    assert any(p["name"] == "probes" for p in ctx["parts"])


def test_probe_failure_never_fails_the_analysis(conn, cfg, rules, bundle, fake, clock):
    incident_id = _queued(conn, cfg, rules, clock, host="example-app01")
    with FakeServer(fake.handle) as server:
        outcome = worker.run_once(conn, cfg, _probe_deps(server, fake, cfg, bundle, StubRunner(raises=RuntimeError("ssh"))),
                                  clock)
    assert outcome.kind == "done"
    assert conn.execute("SELECT COUNT(*) FROM probes").fetchone()[0] == 0
    assert "probe_data" not in fake.requests[0]["messages"][1]["content"]
    assert _state(conn, incident_id)["analysis_state"] == "done"


def test_probes_are_not_run_when_disabled_or_without_a_runner(conn, cfg, rules, bundle, fake, clock):
    _queued(conn, cfg, rules, clock, host="example-app01")
    runner = StubRunner()
    with FakeServer(fake.handle) as server:
        outcome = worker.run_once(conn, replace(cfg, probes_enabled=False), _probe_deps(server, fake, cfg, bundle, runner),
                                  clock)
    assert outcome.kind == "done" and runner.calls == []
    assert conn.execute("SELECT COUNT(*) FROM events WHERE type = 'probed'").fetchone()[0] == 0


def test_replay_runs_the_probes_with_the_replay_trigger_and_picks_up_operator_results(conn, cfg, rules, bundle, fake,
                                                                                      clock):
    from tia.probes import store

    incident_id = _queued(conn, cfg, rules, clock, host="example-app01")
    runner = StubRunner()
    with FakeServer(fake.handle) as server:
        deps = _probe_deps(server, fake, cfg, bundle, runner)
        first = worker.run_once(conn, cfg, deps, clock)
        # 運用者が画面から取った結果。どの解析にもまだ添えていない
        with db.transaction(conn):
            store.insert(conn, incident_id, None, "uptime_load", "example-app01", "operator", clock(), 3, "ok",
                         "operator saw this", None, command="uptime")
        second = worker.replay(conn, incident_id, cfg, deps, clock)
    assert first.kind == "done" and second.kind == "done"
    rows = store.for_analysis(conn, second.analysis_id)
    assert {r["trigger"] for r in rows} == {"replay", "operator"}
    assert "operator saw this" in fake.requests[-1]["messages"][1]["content"]
    assert store.unattached(conn, incident_id) == []
