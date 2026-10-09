"""`tia analyze` と `tia show`。偽の LLM と、テスト用の束に対して。"""
import json
import os
import signal
import subprocess
import sys
import time
from contextlib import closing
from pathlib import Path

import pytest
from fakes import FakeLlm, FakeServer
from knowledge_helpers import build_fixture

from tia import db as tia_db
from tia.analysis.cli import parse_incident
from tia.cli import main

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "zabbix_problems.json"
NOW = "2026-09-29T05:57:00+00:00"
LATER = "2026-09-29T05:59:00+00:00"


@pytest.fixture
def fake():
    return FakeLlm()


@pytest.fixture
def ready(tmp_path, fake, monkeypatch):
    """取り込み済みのデータベース、束、鍵のファイル、環境変数。"""
    db = tmp_path / "tia.sqlite"
    assert main(["ingest", "--db", str(db), "--source", "zabbix", "--file", str(FIXTURE), "--now", NOW,
                 "--type-rules", str(ROOT / "config" / "type-rules.yaml")]) == 0
    bundle = build_fixture(tmp_path).path
    key_file = tmp_path / "key"
    key_file.write_text(fake.key + "\n")
    monkeypatch.setenv("TIA_LLM_API_KEY_FILE", str(key_file))
    monkeypatch.delenv("TIA_LLM_MODEL", raising=False)
    return db, bundle, key_file


def test_parse_incident_accepts_both_spellings():
    assert parse_incident("I-0007") == 7 and parse_incident("7") == 7 and parse_incident("i-12") == 12
    with pytest.raises(ValueError):
        parse_incident("seven")


def test_once_analyses_the_first_queued_incident(ready, fake, monkeypatch, capsys):
    db, bundle, _ = ready
    with FakeServer(fake.handle) as server:
        monkeypatch.setenv("TIA_LLM_URL", server.url + "/openai")
        code = main(["analyze", "--db", str(db), "--knowledge", str(bundle), "--once", "--now", LATER])
    assert code == 0
    out = capsys.readouterr().out
    assert out.startswith("I-0001 done analysis=1")
    assert len(fake.requests) == 1
    code = main(["show", "--db", str(db), "I-0001", "--result"])
    out = capsys.readouterr().out
    assert code == 0
    assert "I-0001 done open zabbix example-router01 cpu" in out
    assert "緊急度 今日中 種別 性能" in out
    assert "analysis_started" in out and "analysis_done" in out
    assert "#1 initial done finished" in out and "入力 1234" in out
    assert json.loads(out.split("最新の結果:\n", 1)[1])["classification"]["urgency"] == "today"


def test_once_with_nothing_queued_says_so(ready, fake, monkeypatch, capsys):
    db, bundle, _ = ready
    with FakeServer(fake.handle) as server:
        monkeypatch.setenv("TIA_LLM_URL", server.url + "/openai")
        assert main(["analyze", "--db", str(db), "--knowledge", str(bundle), "--once", "--now", NOW]) == 0
    assert capsys.readouterr().out.strip() == "解析するものがない"
    assert fake.requests == []


def test_failed_analysis_exits_with_one(ready, fake, monkeypatch, capsys):
    db, bundle, _ = ready
    fake.modes = ["schema_violation", "schema_violation"]
    with FakeServer(fake.handle) as server:
        monkeypatch.setenv("TIA_LLM_URL", server.url + "/openai")
        code = main(["analyze", "--db", str(db), "--knowledge", str(bundle), "--once", "--now", LATER])
    assert code == 1
    assert "failed analysis=1 validation" in capsys.readouterr().out


def test_replay_keeps_the_state_and_prints_the_new_analysis(ready, fake, monkeypatch, capsys):
    db, bundle, _ = ready
    with FakeServer(fake.handle) as server:
        monkeypatch.setenv("TIA_LLM_URL", server.url + "/openai")
        assert main(["analyze", "--db", str(db), "--knowledge", str(bundle), "--once", "--now", LATER]) == 0
        assert main(["analyze", "--db", str(db), "--knowledge", str(bundle), "--replay", "I-0001", "--now", LATER]) == 0
        assert main(["analyze", "--db", str(db), "--knowledge", str(bundle), "--replay", "I-0999"]) == 2
    out = capsys.readouterr()
    assert "I-0001 done analysis=2" in out.out
    assert "再生できない" in out.err
    main(["show", "--db", str(db), "1"])
    shown = capsys.readouterr().out
    assert "解析: 2 件" in shown and "#2 replay done" in shown


@pytest.mark.parametrize("problem", ["key", "bundle", "url"])
def test_configuration_problems_exit_with_two_without_showing_secrets(ready, fake, monkeypatch, capsys, tmp_path,
                                                                       problem):
    db, bundle, key_file = ready
    if problem == "key":
        monkeypatch.setenv("TIA_LLM_API_KEY_FILE", str(tmp_path / "missing"))
    if problem == "bundle":
        bundle = tmp_path / "no-bundle"
    if problem == "url":
        monkeypatch.setenv("TIA_LLM_URL", "http://user:secret-pass@127.0.0.1/openai")
    with FakeServer(fake.handle) as server:
        if problem != "url":
            monkeypatch.setenv("TIA_LLM_URL", server.url + "/openai")
        code = main(["analyze", "--db", str(db), "--knowledge", str(bundle), "--once", "--now", LATER])
    assert code == 2
    err = capsys.readouterr().err
    assert err.startswith("設定の誤り") and fake.key not in err and "secret-pass" not in err


def test_show_unknown_incident_exits_with_one(ready, capsys):
    db, _, _ = ready
    assert main(["show", "--db", str(db), "I-0042"]) == 1
    assert "I-0042 はない" in capsys.readouterr().err


def test_service_stops_on_sigterm_and_resumes_without_duplicates(ready, fake, tmp_path):
    db, bundle, key_file = ready
    with FakeServer(fake.handle) as server:
        env = {**os.environ, "TIA_LLM_URL": server.url + "/openai", "TIA_LLM_API_KEY_FILE": str(key_file),
               "PYTHONPATH": str(ROOT / "src")}
        command = [sys.executable, "-m", "tia.cli", "analyze", "--db", str(db), "--knowledge", str(bundle)]
        with subprocess.Popen(command, env=env, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True) as process:
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline and len(fake.requests) < 1:
                time.sleep(0.1)
            time.sleep(1.0)
            process.send_signal(signal.SIGTERM)
            _, err = process.communicate(timeout=15)
        assert process.returncode == 0
        assert "止める合図を受けて終了した" in err
    with closing(tia_db.connect(db)) as conn:
        done = conn.execute("SELECT COUNT(*) FROM incidents WHERE analysis_state = 'done'").fetchone()[0]
    assert done >= 1
    assert len(fake.requests) == done


def _run_tia(args, env, cwd=ROOT):
    return [sys.executable, "-m", "tia.cli", *args], {**os.environ, **env, "PYTHONPATH": str(ROOT / "src")}


def _wait_for_request(fake, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and len(fake.requests) < 1:
        time.sleep(0.1)
    assert fake.requests, "LLM への要求が始まらない"


def test_once_interrupted_mid_request_releases_and_the_next_once_works(ready, fake):
    """I-1: --once の途中で止められても、次の --once は普通に動く。"""
    db, bundle, key_file = ready
    fake.modes = ["delay"]
    fake.delay = 30
    with FakeServer(fake.handle) as server:
        env = {"TIA_LLM_URL": server.url + "/openai", "TIA_LLM_API_KEY_FILE": str(key_file)}
        command, environ = _run_tia(["analyze", "--db", str(db), "--knowledge", str(bundle), "--once", "--now", LATER],
                                    env)
        with subprocess.Popen(command, env=environ, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True) as process:
            _wait_for_request(fake)
            time.sleep(0.5)
            process.send_signal(signal.SIGTERM)
            out, err = process.communicate(timeout=15)
        assert process.returncode == 1 and "Traceback" not in err
        assert "released" in out and "stopped" in out
        with closing(tia_db.connect(db)) as conn:
            states = conn.execute("SELECT analysis_state, attempt_count FROM incidents WHERE id = 1").fetchone()
            analyses = conn.execute("SELECT status FROM analyses").fetchall()
        assert tuple(states) == ("queued", 0)
        assert [row["status"] for row in analyses] == ["released"]
        # 2 回目は普通に解析できる
        fake.modes = []
        command, environ = _run_tia(["analyze", "--db", str(db), "--knowledge", str(bundle), "--once", "--now", LATER],
                                    env)
        result = subprocess.run(command, env=environ, cwd=ROOT, capture_output=True, text=True, timeout=60)
        assert result.returncode == 0, result.stderr
        assert "I-0001 done" in result.stdout and "Traceback" not in result.stderr


def test_once_after_a_crash_recovers_the_running_incident(ready, fake, capsys):
    """解析中のまま残った行は、--once でも起動時に片付ける。"""
    db, bundle, key_file = ready
    with closing(tia_db.connect(db)) as conn:
        from tia import queue
        from tia.analysis import records
        from datetime import datetime
        now = datetime.fromisoformat(LATER)
        queue.promote_held(conn, now)
        queue.start(conn, 1, now)
        records.begin(conn, 1, "initial", "m", now)
    with FakeServer(fake.handle) as server:
        with pytest.MonkeyPatch.context() as mp:
            mp.setenv("TIA_LLM_URL", server.url + "/openai")
            code = main(["analyze", "--db", str(db), "--knowledge", str(bundle), "--once", "--now", LATER])
    out, err = capsys.readouterr()
    assert code == 0 and "I-0001 done" in out and "Traceback" not in err


def test_replay_interrupted_leaves_no_running_row(ready, fake):
    db, bundle, key_file = ready
    with FakeServer(fake.handle) as server:
        env = {"TIA_LLM_URL": server.url + "/openai", "TIA_LLM_API_KEY_FILE": str(key_file)}
        command, environ = _run_tia(["analyze", "--db", str(db), "--knowledge", str(bundle), "--once", "--now", LATER],
                                    env)
        assert subprocess.run(command, env=environ, cwd=ROOT, capture_output=True, text=True, timeout=60).returncode == 0
        fake.modes = ["delay"]
        fake.delay = 30
        command, environ = _run_tia(["analyze", "--db", str(db), "--knowledge", str(bundle), "--replay", "I-0001"], env)
        with subprocess.Popen(command, env=environ, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True) as process:
            _wait_for_request(fake, timeout=30)
            while len(fake.requests) < 2 and time.monotonic() < time.monotonic() + 20:
                if len(fake.requests) >= 2:
                    break
                time.sleep(0.1)
            time.sleep(0.5)
            process.send_signal(signal.SIGINT)
            out, err = process.communicate(timeout=15)
        assert process.returncode == 1 and "Traceback" not in err
    with closing(tia_db.connect(db)) as conn:
        running = conn.execute("SELECT COUNT(*) FROM analyses WHERE status = 'running'").fetchone()[0]
        state = conn.execute("SELECT analysis_state FROM incidents WHERE id = 1").fetchone()[0]
    assert running == 0 and state == "done"


def test_state_error_is_a_sentence_not_a_traceback(ready, fake, capsys):
    db, bundle, key_file = ready
    with closing(tia_db.connect(db)) as conn:
        from tia import queue
        from datetime import datetime
        now = datetime.fromisoformat(LATER)
        queue.promote_held(conn, now)
        queue.start(conn, 1, now)
    # 別のプロセスが解析中（解析の行はない）という形。recover は行のないものも戻すので、ここでは recover を飛ばした
    # 直後の start の衝突だけを見る
    from tia.analysis import worker
    import tia.analysis.cli as analyze_cli

    def fake_recover(conn, clock):
        return (0, 0)

    with FakeServer(fake.handle) as server, pytest.MonkeyPatch.context() as mp:
        mp.setenv("TIA_LLM_URL", server.url + "/openai")
        mp.setattr(worker, "recover", fake_recover)
        code = main(["analyze", "--db", str(db), "--knowledge", str(bundle), "--once", "--now", LATER])
    out, err = capsys.readouterr()
    assert code == 1 and "Traceback" not in err and "解析中" in (out + err)


def test_url_that_is_not_the_proxy_route_is_refused_at_start(ready, fake, monkeypatch, capsys):
    db, bundle, key_file = ready
    with FakeServer(fake.handle) as server:
        monkeypatch.setenv("TIA_LLM_URL", server.url + "/api")
        code = main(["analyze", "--db", str(db), "--knowledge", str(bundle), "--once", "--now", LATER])
    out, err = capsys.readouterr()
    assert code == 2 and "/openai" in err and fake.requests == []


def test_other_route_is_allowed_by_the_setting(ready, fake, monkeypatch, capsys, tmp_path):
    db, bundle, key_file = ready
    settings = tmp_path / "analyzer.yaml"
    settings.write_text("llm:\n  allow_other_route: true\n")
    with FakeServer(fake.handle) as server:
        monkeypatch.setenv("TIA_LLM_URL", server.url + "/openai-v2")
        code = main(["analyze", "--db", str(db), "--knowledge", str(bundle), "--once", "--now", LATER,
                     "--config", str(settings)])
    out, err = capsys.readouterr()
    # 経路は通るが、偽の LLM はその場所を知らないので、届かないことが表示される
    assert code in (0, 1) and "設定の誤り" not in err


def test_health_is_logged_at_start(ready, fake, monkeypatch, caplog):
    import logging
    db, bundle, key_file = ready
    with FakeServer(fake.handle) as server, caplog.at_level(logging.INFO, logger="tia.analyze"):
        monkeypatch.setenv("TIA_LLM_URL", server.url + "/openai")
        code = main(["analyze", "--db", str(db), "--knowledge", str(bundle), "--once", "--now", LATER])
    assert code == 0
    assert "LLM の確認" in caplog.text and "届く" in caplog.text
    assert fake.paths[:2] == ["/health", "/openai/models"]


def test_show_prints_excluded_checks_and_the_output_of_a_failed_analysis(ready, fake, monkeypatch, capsys):
    db, bundle, _ = ready
    fake.output["recommended_checks"] = [{"purpose": "利用者の状態", "where": "app01", "command": "passwd -S monitor-tunnel"},
                                         {"purpose": "負荷", "where": "app01", "command": "uptime"}]
    with FakeServer(fake.handle) as server:
        monkeypatch.setenv("TIA_LLM_URL", server.url + "/openai")
        assert main(["analyze", "--db", str(db), "--knowledge", str(bundle), "--once", "--now", LATER]) == 0
        fake.modes = ["schema_violation", "schema_violation"]
        assert main(["analyze", "--db", str(db), "--knowledge", str(bundle), "--replay", "I-0001", "--now", LATER]) == 1
    capsys.readouterr()
    assert main(["show", "--db", str(db), "I-0001"]) == 0
    out = capsys.readouterr().out
    excluded_line = next(line for line in out.splitlines() if "規則により除外した確認" in line)
    assert excluded_line.strip() == "規則により除外した確認: 利用者の状態（利用者とパスワードの変更）"
    assert "passwd -S" not in excluded_line
    assert "失敗した出力: #2" in out and '"summary"' in out
