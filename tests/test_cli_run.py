"""`tia run`。収集、解析、画面が 1 つのプロセスで動き、合図で止まり、2 つ目は断られる。"""
import json
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from contextlib import closing
from pathlib import Path

import pytest
from fakes import FakeLlm, FakeServer, FakeWazuh, FakeZabbix
from knowledge_helpers import build_fixture

from tia import db

ROOT = Path(__file__).resolve().parents[1]


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


@pytest.fixture
def stack(tmp_path, server_tls, ca_file, monkeypatch):
    """偽の 3 系統、束、鍵、設定、環境変数。いま起きたアラートを入れる。"""
    zabbix, wazuh, llm = FakeZabbix(), FakeWazuh(), FakeLlm()
    with FakeServer(zabbix.handle) as zs, FakeServer(wazuh.handle, tls=server_tls) as ws, FakeServer(llm.handle) as ls:
        for name in list(os.environ):
            if name.startswith("TIA_"):
                monkeypatch.delenv(name)
        for name, value in {"zabbix_api_token": zabbix.token, "wazuh_indexer_password": wazuh.password,
                            "openwebui_api_key": llm.key}.items():
            (tmp_path / name).write_text(value + "\n", encoding="utf-8")
        monkeypatch.setenv("TIA_ZABBIX_URL", zs.url + "/api_jsonrpc.php")
        monkeypatch.setenv("TIA_ZABBIX_TOKEN_FILE", str(tmp_path / "zabbix_api_token"))
        monkeypatch.setenv("TIA_WAZUH_URL", ws.url)
        monkeypatch.setenv("TIA_WAZUH_PASSWORD_FILE", str(tmp_path / "wazuh_indexer_password"))
        monkeypatch.setenv("TIA_WAZUH_CA_FILE", str(ca_file))
        monkeypatch.setenv("TIA_LLM_URL", ls.url + "/openai")
        monkeypatch.setenv("TIA_LLM_API_KEY_FILE", str(tmp_path / "openwebui_api_key"))
        now = int(time.time())
        zabbix.add_problem(48213, clock=now - 400)
        recent = time.strftime("%Y-%m-%dT%H:%M:%S.000+0000", time.gmtime(now - 30))
        wazuh.add("w-101", recent)
        bundle = build_fixture(tmp_path).path.parent
        config = tmp_path / "analyzer.yaml"
        config.write_text("zabbix:\n  poll_interval_sec: 5\n  hold_sec: 1\nwazuh:\n  poll_interval_sec: 5\n  hold_sec: 1\n"
                          "collector:\n  tick_sec: 1\nworker:\n  idle_sec: 1\nweb:\n  cookie_secure: false\n"
                          "  health_interval_sec: 5\n", encoding="utf-8")
        yield {"zabbix": zabbix, "wazuh": wazuh, "llm": llm, "db": tmp_path / "tia.sqlite", "config": config,
               "bundle": bundle, "port": free_port()}


def command(stack, *extra):
    return [sys.executable, "-m", "tia.cli", "run", "--db", str(stack["db"]), "--config", str(stack["config"]),
            "--type-rules", str(ROOT / "config" / "type-rules.yaml"), "--knowledge", str(stack["bundle"]),
            "--host", "127.0.0.1", "--port", str(stack["port"]), *extra]


class _Service(subprocess.Popen):
    """`with` を抜けるときに、生きていれば必ず止める。テストの途中で例外が出ても、子を待ち続けない。"""

    def __exit__(self, *exc) -> None:
        if self.poll() is None:
            self.terminate()
            try:
                self.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                self.kill()
        super().__exit__(*exc)


def start(stack, *extra):
    env = {**os.environ, "PYTHONUNBUFFERED": "1", "PYTHONDONTWRITEBYTECODE": "1"}
    return _Service(command(stack, *extra), env=env, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def stop(process, number=signal.SIGTERM, timeout=35):
    """止める合図を送り、終了コード、出力、かかった秒数を返す。応答がなければ強制終了する。"""
    started = time.monotonic()
    try:
        if process.poll() is None:
            process.send_signal(number)
        out, err = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        out, err = process.communicate()
    return process.returncode, out, err, time.monotonic() - started


def wait_until(condition, process, seconds=40.0):
    """条件が成り立つまで待つ。プロセスが先に終わったら、待つのをやめる。問い合わせの失敗は数えない。"""
    limit = time.monotonic() + seconds
    while time.monotonic() < limit and process.poll() is None:
        try:
            if condition():
                return True
        except Exception:  # noqa: BLE001 - 立ち上がる前の問い合わせは失敗してよい
            pass
        time.sleep(0.1)
    try:
        return bool(condition())
    except Exception:  # noqa: BLE001
        return False


def http(port, path):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=3) as response:
            return response.status, response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8")


def states(path):
    if not path.exists():
        return []
    with closing(db.connect(path)) as conn:
        return [tuple(row) for row in conn.execute("SELECT id, analysis_state FROM incidents ORDER BY id")]


def test_run_collects_analyses_and_serves_the_screen(stack):
    port = stack["port"]
    with start(stack) as process:
        up = wait_until(lambda: http(port, "/healthz")[0] in (200, 503), process)
        analysed = wait_until(lambda: any(state == "done" for _, state in states(stack["db"])), process, 60)
        page = http(port, "/")
        healthy = wait_until(lambda: http(port, "/healthz")[0] == 200, process, 30)
        body = json.loads(http(port, "/healthz")[1])
        code, out, err, seconds = stop(process)
    assert up and analysed
    assert page[0] == 200 and "Incident Analyst" in page[1]
    assert healthy, body
    assert code == 0 and seconds < 30
    assert "司令塔を起動した" in err and "止める合図" in err and "終了コード 0" in err
    assert "LLM の確認: モデル" in err  # 起動時の確認の結果は、稼働の確認のスレッドから記録に出る
    assert stack["llm"].key not in out + err and stack["zabbix"].token not in out + err
    assert not Path(str(stack["db"]) + ".lock").exists() or True  # ロックのファイルは残ってよい。鍵は外れている
    from tia.ops.lock import InstanceLock

    assert not InstanceLock.is_held(stack["db"])


def test_sigterm_during_inference_releases_and_exits_in_time(stack):
    stack["llm"].modes = ["slow"] * 20
    stack["llm"].slow_pause = 1.0
    with start(stack) as process:
        running = wait_until(lambda: any(state == "running" for _, state in states(stack["db"])), process, 60)
        code, out, err, seconds = stop(process)
    assert running
    assert code == 0 and seconds < 30
    assert all(state != "running" for _, state in states(stack["db"]))
    with closing(db.connect(stack["db"])) as conn:
        assert conn.execute("SELECT COUNT(*) FROM analyses WHERE status = 'released'").fetchone()[0] >= 1
        assert conn.execute("SELECT COUNT(*) FROM analyses WHERE status = 'running'").fetchone()[0] == 0


def test_second_instance_is_refused_with_code_4(stack):
    with start(stack) as first:
        assert wait_until(lambda: http(stack["port"], "/healthz")[0] in (200, 503), first)
        second_stack = {**stack, "port": free_port()}
        with start(second_stack) as second:
            out, err = second.communicate(timeout=30)
        assert second.returncode == 4
        assert "別の司令塔が動いている" in err and "pid" in err
        code, _, _, _ = stop(first)
    assert code == 0


def test_port_in_use_ends_with_code_3(stack):
    with socket.socket() as blocker:
        blocker.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        blocker.bind(("127.0.0.1", stack["port"]))
        blocker.listen(1)
        with start(stack) as process:
            out, err = process.communicate(timeout=60)
    assert process.returncode == 3
    assert "web が倒れた" in err or "画面が起動しない" in err


def test_sigterm_during_a_silent_llm_check_ends_within_seconds(stack, monkeypatch):
    """起動時の LLM の確認が応答のない待受に当たっても、主スレッドは塞がれず、合図から数秒で終わる（I-6）。"""
    with socket.socket() as silent:
        silent.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        silent.bind(("127.0.0.1", 0))
        silent.listen(5)  # 受けるだけで何も返さない
        monkeypatch.setenv("TIA_LLM_URL", f"http://127.0.0.1:{silent.getsockname()[1]}/openai")
        with start(stack) as process:
            assert wait_until(lambda: http(stack["port"], "/healthz")[0] in (200, 503), process)
            time.sleep(3)
            code, out, err, seconds = stop(process, timeout=20)
    assert code == 0, err[-800:]
    assert seconds < 10, seconds
    assert "司令塔を起動した" in err  # 確認が終わる前に起動が済んでいる


def test_open_event_streams_end_cleanly_when_the_service_stops(stack):
    """SSE を開いたまま止めても、流れは「: shutdown」で終わり、記録にトレースバックは出ない（I-7）。"""
    import threading
    from http.client import HTTPConnection  # 補助関数 http() を隠さないよう、名前を限って読み込む

    received: dict[int, bytes] = {}

    def listen(index: int) -> None:
        conn = HTTPConnection("127.0.0.1", stack["port"], timeout=30)
        conn.request("GET", "/events", headers={"Accept": "text/event-stream"})
        response = conn.getresponse()
        chunks = []
        try:
            while True:
                piece = response.read1(4096) if hasattr(response, "read1") else response.read(4096)
                if not piece:
                    break
                chunks.append(piece)
        except Exception:  # noqa: BLE001 - 切断は終わりの合図
            pass
        received[index] = b"".join(chunks)
        conn.close()

    with start(stack) as process:
        up = wait_until(lambda: http(stack["port"], "/healthz")[0] in (200, 503), process)
        if not up:
            process.terminate()
            pytest.fail("起動しない: " + process.communicate(timeout=15)[1][-2500:])
        threads = [threading.Thread(target=listen, args=(i,), daemon=True) for i in range(6)]
        for thread in threads:
            thread.start()
        time.sleep(2.5)  # retry と最初のイベントを受け取るまで
        code, out, err, seconds = stop(process)
        for thread in threads:
            thread.join(timeout=10)
    assert code == 0 and seconds < 10, (code, seconds)
    assert len(received) == 6
    assert all(b"retry: 3000" in body and b": shutdown" in body for body in received.values()), received
    assert "Exception in ASGI application" not in err and "Traceback" not in err, err[-1500:]
    assert "timeout graceful shutdown exceeded" not in err


def test_run_without_sources_is_refused(stack, monkeypatch):
    monkeypatch.delenv("TIA_ZABBIX_URL")
    monkeypatch.delenv("TIA_WAZUH_URL")
    with start(stack) as process:
        out, err = process.communicate(timeout=30)
    assert process.returncode == 2 and "収集する系統がない" in err
    assert not stack["db"].exists()


def test_wrong_llm_route_is_refused_at_start(stack, monkeypatch):
    monkeypatch.setenv("TIA_LLM_URL", os.environ["TIA_LLM_URL"].replace("/openai", "/api"))
    with start(stack) as process:
        out, err = process.communicate(timeout=30)
    assert process.returncode == 2 and "/openai" in err


def test_no_analysis_runs_without_an_llm_and_is_not_degraded_by_it(stack, monkeypatch):
    monkeypatch.delenv("TIA_LLM_URL")
    monkeypatch.delenv("TIA_LLM_API_KEY_FILE")
    port = stack["port"]
    with start(stack, "--no-analysis") as process:
        healthy = wait_until(lambda: http(port, "/healthz")[0] == 200, process, 60)
        body = json.loads(http(port, "/healthz")[1])
        code, out, err, _ = stop(process)
    assert healthy, body
    assert body["llm"]["ok"] is None
    assert code == 0 and "解析 なし" in err
    assert all(state != "done" for _, state in states(stack["db"]))


def test_run_stops_within_the_grace_period_while_idle(stack):
    with start(stack) as process:
        assert wait_until(lambda: http(stack["port"], "/healthz")[0] in (200, 503), process)
        code, _, err, seconds = stop(process, signal.SIGINT)
    assert code == 0 and seconds < 10
    assert "止める合図" in err


def test_run_without_a_probe_key_disables_the_probes_with_a_warning_and_still_analyses(stack):
    """鍵がなければ確認は無効。解析は動く。"""
    with start(stack) as process:
        assert wait_until(lambda: http(stack["port"], "/healthz")[0] in (200, 503), process)
        assert wait_until(lambda: any(state == "done" for _, state in states(stack["db"])), process, seconds=60)
        code, out, err, _ = stop(process)
    assert code == 0
    assert "確認を無効にする" in err and "/run/secrets/probe_ssh_key" in err
    with closing(db.connect(stack["db"])) as conn:
        assert conn.execute("SELECT COUNT(*) FROM probes").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM events WHERE type = 'probed'").fetchone()[0] == 0


def test_run_with_a_probe_key_records_the_probes(stack, tmp_path, monkeypatch):
    """鍵、カタログ、ホスト鍵があれば確認が動く。VM には届かないので ssh は失敗で終わるが、Zabbix と Wazuh の確認は
    偽に対して成功し、probes の表と probed の出来事が残る。"""
    key = tmp_path / "probe_key"
    key.write_text("not a key\n", encoding="utf-8")
    fake_ssh = tmp_path / "ssh"
    fake_ssh.write_text("#!/bin/sh\necho 'ssh: connect to host: Connection refused' >&2\nexit 255\n", encoding="utf-8")
    fake_ssh.chmod(0o755)
    monkeypatch.setenv("TIA_PROBE_SSH_BIN", str(fake_ssh))  # 本物の VM には向けない
    known_hosts = tmp_path / "probes_known_hosts"
    known_hosts.write_text("192.0.2.6 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC56RBdo7OBzYhyfrFKTbLaRMroij82uNAlb9XQVwcEq\n",
                           encoding="utf-8")
    config = stack["config"]
    config.write_text(config.read_text(encoding="utf-8") + f"probes:\n  key_file: {key}\n  catalog: {ROOT / 'config' / 'probes.yaml'}\n"
                      f"  known_hosts: {known_hosts}\n  total_budget_sec: 10\n  timeout_sec: 3\n",
                      encoding="utf-8")
    with start(stack) as process:
        assert wait_until(lambda: any(state == "done" for _, state in states(stack["db"])), process, seconds=90)
        code, out, err, _ = stop(process)
    assert code == 0
    assert "確認を有効にした" in err
    with closing(db.connect(stack["db"])) as conn:
        rows = conn.execute("SELECT name, target, status FROM probes ORDER BY id").fetchall()
        assert rows, err
        by = {r["name"]: r for r in rows}
        assert by["zabbix_trigger"]["status"] == "ok" and by["zabbix_host_problems"]["status"] == "ok"
        assert by["uptime_load"]["status"] in ("unreachable", "timeout", "refused")
        assert conn.execute("SELECT COUNT(*) FROM events WHERE type = 'probed'").fetchone()[0] >= 1
