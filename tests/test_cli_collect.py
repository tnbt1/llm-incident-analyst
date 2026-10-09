import os
import signal
import subprocess
import sys
import time
from contextlib import closing
from pathlib import Path

import pytest

from fakes import FakeServer, FakeWazuh, FakeZabbix, Reply, SlowHeaderServer
from tia import db
from tia.cli import main

ROOT = Path(__file__).resolve().parents[1]
NOW = "2026-09-29T05:57:00+00:00"
CLOCK = 1790661420


@pytest.fixture
def sources(tmp_path, server_tls, ca_file, monkeypatch):
    """偽の Zabbix とインデクサーを立て、接続先を環境変数に入れる。"""
    zabbix, wazuh = FakeZabbix(), FakeWazuh()
    with FakeServer(zabbix.handle) as zabbix_server, FakeServer(wazuh.handle, tls=server_tls) as wazuh_server:
        token = tmp_path / "zabbix_api_token"
        token.write_text(zabbix.token + "\n", encoding="utf-8")
        password = tmp_path / "wazuh_indexer_password"
        password.write_text(wazuh.password + "\n", encoding="utf-8")
        for name in list(os.environ):
            if name.startswith("TIA_"):
                monkeypatch.delenv(name)
        monkeypatch.setenv("TIA_ZABBIX_URL", zabbix_server.url + "/api_jsonrpc.php")
        monkeypatch.setenv("TIA_ZABBIX_TOKEN_FILE", str(token))
        monkeypatch.setenv("TIA_WAZUH_URL", wazuh_server.url)
        monkeypatch.setenv("TIA_WAZUH_PASSWORD_FILE", str(password))
        monkeypatch.setenv("TIA_WAZUH_CA_FILE", str(ca_file))
        zabbix.add_problem(48213, clock=CLOCK - 360)
        zabbix.add_problem(48220, trigger_id=23600, severity=1, clock=CLOCK - 50, host="example-monitor01",
                           keys=(), tags=())
        wazuh.add("w-001", "2026-09-29T05:56:01.000+0000")
        wazuh.add("w-002", "2026-09-29T05:56:21.000+0000")
        yield zabbix, wazuh


def collect(path, *extra):
    return main(["collect", "--db", str(path), "--type-rules", str(ROOT / "config" / "type-rules.yaml"), *extra])


def rows(path, sql):
    with closing(db.connect(path)) as conn:
        return [tuple(row) for row in conn.execute(sql)]


def test_one_cycle_collects_both_sources_and_reports_counts(tmp_path, sources, capsys):
    path = tmp_path / "tia.sqlite"
    assert collect(path, "--once", "--now", NOW) == 0
    assert capsys.readouterr().out.splitlines() == [
        "zabbix ok created=1 fetched=2 skipped=1",
        "wazuh ok created=1 fetched=2 recurred=1",
        "tidy promoted=0 group=- followups=0",
    ]
    assert rows(path, "SELECT source, external_id, analysis_state, occurrence_count FROM incidents ORDER BY id") == [
        ("zabbix", "48213", "held", 1), ("zabbix", "48220", "skipped", 1), ("wazuh", "w-001", "held", 2)]


def test_running_it_again_adds_nothing(tmp_path, sources, capsys):
    path = tmp_path / "tia.sqlite"
    collect(path, "--once", "--now", NOW)
    capsys.readouterr()
    assert collect(path, "--once", "--now", "2026-09-29T05:57:05+00:00") == 0
    assert capsys.readouterr().out.splitlines() == [
        "zabbix ok fetched=2 known=2",
        "wazuh ok duplicate=2 fetched=2",
        "tidy promoted=0 group=- followups=0",
    ]
    assert rows(path, "SELECT COUNT(*), SUM(occurrence_count) FROM incidents") == [(3, 4)]


def test_failure_of_one_source_is_reported_and_the_other_is_collected(tmp_path, sources, capsys):
    zabbix, wazuh = sources
    wazuh.password = "changed-on-the-server-0123456789"
    path = tmp_path / "tia.sqlite"
    assert collect(path, "--once", "--now", NOW) == 1
    out = capsys.readouterr()
    assert out.out.splitlines() == [
        "zabbix ok created=1 fetched=2 skipped=1",
        "wazuh failed auth 認証に失敗した（HTTP 401）",
        "tidy promoted=0 group=- followups=0",
    ]
    assert "indexer-password" not in out.out + out.err
    assert rows(path, "SELECT source, consecutive_failures, last_error_kind FROM collector_state ORDER BY source") == [
        ("wazuh", 1, "auth"), ("zabbix", 0, None)]


def test_secrets_do_not_reach_the_output_or_the_database(tmp_path, sources, capsys):
    zabbix, wazuh = sources
    zabbix.replies.append(Reply(body={"jsonrpc": "2.0", "id": 1, "error": {
        "code": -32602, "message": "Invalid params.", "data": f"header was Bearer {zabbix.token}"}}))
    wazuh.replies.append(Reply(status=400, body=f"bad request for analyzer_ro:{wazuh.password}"))
    path = tmp_path / "tia.sqlite"
    assert collect(path, "--once", "--now", NOW) == 1
    out = capsys.readouterr()
    stored = Path(path).read_bytes()
    for secret in (zabbix.token, wazuh.password):
        assert secret not in out.out + out.err
        assert secret.encode() not in stored
    assert "***" in out.out


def test_without_a_source_nothing_is_started(tmp_path, monkeypatch, capsys):
    for name in list(os.environ):
        if name.startswith("TIA_"):
            monkeypatch.delenv(name)
    assert collect(tmp_path / "tia.sqlite", "--once") == 2
    assert "TIA_ZABBIX_URL" in capsys.readouterr().err
    assert not (tmp_path / "tia.sqlite").exists()


@pytest.mark.parametrize(("name", "value"), [("TIA_WAZUH_URL", "http://wazuh.indexer:9200"),
                                             ("TIA_ZABBIX_URL", "http://user:pass-0123456789@zabbix/api")])
def test_wrong_address_is_refused_with_the_name_of_the_setting(tmp_path, monkeypatch, capsys, name, value):
    monkeypatch.setenv(name, value)
    assert collect(tmp_path / "tia.sqlite", "--once") == 2
    err = capsys.readouterr().err
    assert name in err
    assert "pass-0123456789" not in err


def test_wrong_setting_is_refused_with_its_key(tmp_path, sources, capsys):
    config = tmp_path / "analyzer.yaml"
    config.write_text("collector:\n  timeout_sec: 0\n", encoding="utf-8")
    assert collect(tmp_path / "tia.sqlite", "--once", "--config", str(config)) == 2
    assert "collector.timeout_sec" in capsys.readouterr().err


def test_fixed_time_needs_a_time_zone(tmp_path, sources, capsys):
    assert collect(tmp_path / "tia.sqlite", "--once", "--now", "2026-09-29T05:57:00") == 2
    assert "タイムゾーン" in capsys.readouterr().err


def test_fixed_time_is_only_for_one_cycle(tmp_path, sources, capsys):
    with pytest.raises(SystemExit) as caught:
        collect(tmp_path / "tia.sqlite", "--now", NOW)
    assert caught.value.code == 2
    assert "--once" in capsys.readouterr().err


def start(path, config):
    env = {**os.environ, "PYTHONUNBUFFERED": "1", "PYTHONDONTWRITEBYTECODE": "1"}
    return subprocess.Popen(
        [sys.executable, "-m", "tia.cli", "collect", "--db", str(path), "--config", str(config),
         "--type-rules", str(ROOT / "config" / "type-rules.yaml")],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def stop(process, number=signal.SIGTERM):
    """止める合図を送り、終了コードと出力を返す。応答がなければ強制終了する。"""
    try:
        process.send_signal(number)
        out, err = process.communicate(timeout=20)
    except subprocess.TimeoutExpired:
        process.kill()
        out, err = process.communicate()
    return process.returncode, out, err


def wait_until(condition, process, seconds=20.0):
    """条件が成り立つまで待つ。プロセスが先に終わったら、待つのをやめる。"""
    limit = time.monotonic() + seconds
    while time.monotonic() < limit and process.poll() is None:
        if condition():
            return True
        time.sleep(0.05)
    return bool(condition())


@pytest.fixture
def service(tmp_path, sources):
    """実際の時計で動かす準備。いま起きたアラートを入れ、間隔を最短にする。"""
    zabbix, wazuh = sources
    wazuh.docs.clear()
    recent = time.strftime("%Y-%m-%dT%H:%M:%S.000+0000", time.gmtime(time.time() - 30))
    wazuh.add("w-101", recent)
    wazuh.add("w-102", recent, srcip="192.0.2.6")
    config = tmp_path / "analyzer.yaml"
    config.write_text("zabbix:\n  poll_interval_sec: 5\nwazuh:\n  poll_interval_sec: 5\n"
                      "collector:\n  tick_sec: 1\n", encoding="utf-8")
    return tmp_path / "tia.sqlite", config


def stored(path):
    return path.exists() and rows(path, "SELECT COUNT(*), SUM(occurrence_count) FROM incidents")


@pytest.mark.parametrize("number", [signal.SIGTERM, signal.SIGINT])
def test_service_collects_until_it_is_told_to_stop(sources, service, number):
    zabbix, wazuh = sources
    path, config = service
    with start(path, config) as process:
        collected = wait_until(lambda: stored(path) == [(4, 4)], process)
        code, out, err = stop(process, number)
    assert collected
    assert code == 0
    assert "止める合図を受けて終了した" in err
    assert zabbix.token not in out + err and wazuh.password not in out + err


def test_restarted_service_resumes_without_duplicates(sources, service):
    zabbix, wazuh = sources
    path, config = service
    with start(path, config) as process:
        collected = wait_until(lambda: stored(path) == [(4, 4)], process)
        stop(process)
    assert collected
    asked, searched = len(zabbix.calls), len(wazuh.searches)
    zabbix.add_problem(48300, trigger_id=23900, clock=int(time.time()) - 5, name="Disk space is low",
                       keys=("vfs.fs.size[/,pused]",), tags=(("component", "storage"),))
    with start(path, config) as process:
        resumed = wait_until(lambda: len(zabbix.calls) > asked and len(wazuh.searches) > searched
                             and stored(path) == [(5, 5)], process)
        code, _, _ = stop(process)
    assert resumed
    assert code == 0
    assert stored(path) == [(5, 5)]


# 要求の途中で止める合図が来た場合。要求の制限時間（ここでは 2 秒）のうちに終わる。

def only_zabbix(tmp_path, monkeypatch, url):
    token = tmp_path / "zabbix_api_token"
    token.write_text("zbx-token-0123456789abcdef\n", encoding="utf-8")
    for name in list(os.environ):
        if name.startswith("TIA_"):
            monkeypatch.delenv(name)
    monkeypatch.setenv("TIA_ZABBIX_URL", url)
    monkeypatch.setenv("TIA_ZABBIX_TOKEN_FILE", str(token))
    config = tmp_path / "analyzer.yaml"
    config.write_text("zabbix:\n  poll_interval_sec: 5\ncollector:\n  tick_sec: 1\n  timeout_sec: 2\n"
                      "  connect_timeout_sec: 2\n", encoding="utf-8")
    return tmp_path / "tia.sqlite", config


def stop_and_time(process):
    started = time.monotonic()
    code, out, err = stop(process)
    return code, err, time.monotonic() - started


def test_stop_during_a_refusal_sent_slowly_ends_the_service(tmp_path, monkeypatch):
    reply = Reply(status=503, body=b"e" * 200, drip=(1, 1.0))
    with FakeServer(lambda request: reply) as server:
        path, config = only_zabbix(tmp_path, monkeypatch, server.url + "/api_jsonrpc.php")
        with start(path, config) as process:
            asked = wait_until(lambda: bool(server.requests), process)
            time.sleep(0.3)
            code, err, seconds = stop_and_time(process)
    assert asked
    assert (code, seconds < 8) == (0, True)
    assert "止める合図を受けて終了した" in err


def test_stop_in_the_middle_of_a_request_ends_the_service(tmp_path, monkeypatch):
    with SlowHeaderServer(pause=0.2, padding=200) as server:
        path, config = only_zabbix(tmp_path, monkeypatch, server.url + "api_jsonrpc.php")
        with start(path, config) as process:
            time.sleep(1.0)
            code, err, seconds = stop_and_time(process)
    assert (code, seconds < 8) == (0, True)
    assert "zabbix の収集に失敗した（timeout" in err
    assert "止める合図を受けて終了した" in err


def test_stop_while_the_answer_is_still_arriving_ends_the_service(tmp_path, monkeypatch):
    body = b'{"jsonrpc": "2.0", "id": 1, "result": [], "pad": "' + b"x" * 200 + b'"}'
    with FakeServer(lambda request: Reply(body=body, drip=(1, 0.5))) as server:
        path, config = only_zabbix(tmp_path, monkeypatch, server.url + "/api_jsonrpc.php")
        with start(path, config) as process:
            asked = wait_until(lambda: bool(server.requests), process)
            time.sleep(0.3)
            code, err, seconds = stop_and_time(process)
    assert asked
    assert (code, seconds < 8) == (0, True)
    assert "止める合図を受けて終了した" in err


def test_one_cycle_with_a_fixed_time_in_the_future_does_not_silence_later_runs(tmp_path, sources, capsys):
    from tia.collectors import state
    from tia.config import Config
    from tia.models import Source, from_iso

    path = tmp_path / "tia.sqlite"
    assert collect(path, "--once", "--now", "2026-09-30T00:00:00+00:00") == 0
    with closing(db.connect(path)) as conn:
        for source in (Source.ZABBIX, Source.WAZUH):
            assert state.is_due(state.get(conn, source), from_iso(NOW), Config())


def test_secret_sent_back_in_another_shape_does_not_reach_the_output_or_the_database(tmp_path, sources, capsys,
                                                                                     monkeypatch):
    import json
    import urllib.parse

    zabbix, wazuh = sources
    wazuh.password = 'pa"ss\\word 日本-0123456789'
    Path(os.environ["TIA_WAZUH_PASSWORD_FILE"]).write_text(wazuh.password + "\n", encoding="utf-8")
    shown = [json.dumps(wazuh.password), urllib.parse.quote(wazuh.password), urllib.parse.quote_plus(wazuh.password)]
    wazuh.replies.append(Reply(status=400, body={"error": {"reason": "bad " + " ".join(shown)}}))
    path = tmp_path / "tia.sqlite"
    assert collect(path, "--once", "--now", NOW) == 1
    out = capsys.readouterr()
    stored = Path(path).read_bytes()
    for shape in [wazuh.password, *(s.strip('"') for s in shown)]:
        assert shape not in out.out + out.err
        assert shape.encode() not in stored
    assert "wazuh failed client" in out.out and "***" in out.out
