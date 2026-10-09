"""画面の骨格。応答のヘッダー、Cookie、/healthz、稼働の確認のスレッド。ページの描画は test_web_pages。"""
import re
import time
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from web_fixtures import (BASE_URL, NOW, Clock, Probe, bundle_dir, client, collector_rows, ids, make_db,  # noqa: F401
                         probe, web_app, web_clock, web_db)

from tia import db
from tia.analysis.llm import LlmHealth
from tia.config import Config
from tia.web.app import create_app

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "src" / "tia" / "web" / "templates"
STATIC = ROOT / "src" / "tia" / "web" / "static"
ROUTES = ["/healthz", "/static/app.css", "/nothing-here", "/static/missing.css"]


@pytest.mark.parametrize("path", ROUTES)
def test_every_response_carries_the_security_headers(client, path):
    response = client.get(path)
    csp = response.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "unsafe-inline" not in csp.split("style-src-attr")[0]
    assert "frame-ancestors 'none'" in csp and "default-src 'none'" in csp
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["x-frame-options"] == "DENY"


def test_dynamic_answers_are_not_cached_but_static_files_may_be(client):
    assert client.get("/healthz").headers["cache-control"] == "no-store"
    assert client.get("/nothing-here").headers["cache-control"] == "no-store"
    assert "no-store" not in client.get("/static/app.css").headers.get("cache-control", "")


def test_session_cookie_is_httponly_strict_and_secure(web_app):
    with TestClient(web_app, base_url=BASE_URL) as fresh:
        response = fresh.get("/healthz")
        cookie = response.headers["set-cookie"]
        assert "tia_sid=" in cookie and "HttpOnly" in cookie and "SameSite=strict" in cookie.lower().replace("samesite=strict", "SameSite=strict")
        assert "Secure" in cookie
        again = fresh.get("/healthz")
        assert "set-cookie" not in again.headers


def test_unknown_path_is_a_404_page_and_json_for_json_clients(client):
    response = client.get("/nothing-here")
    assert response.status_code == 404 and "<title>404" in response.text and "Not Found" in response.text
    as_json = client.get("/nothing-here", headers={"Accept": "application/json"})
    assert as_json.status_code == 404 and as_json.json() == {"detail": "Not Found"}


def test_static_files_reference_no_external_host():
    for path in STATIC.rglob("*.css"):
        assert "http://" not in path.read_text(encoding="utf-8") and "https://" not in path.read_text(encoding="utf-8"), path
    for name in ("app.js", "theme.js"):
        text = (STATIC / name).read_text(encoding="utf-8")
        assert "http://" not in text and "https://" not in text


def test_healthz_is_ok_when_everything_is_fine(client):
    response = client.get("/healthz")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok" and body["problems"] == []
    assert body["llm"]["ok"] is True and body["knowledge"]["ok"] is True
    assert body["collectors"]["zabbix"]["ok"] and body["collectors"]["wazuh"]["seconds_since_ok"] == 41
    assert body["queue"]["depth"] == 4 and body["queue"]["running"]["incident_id"] == 10
    assert body["database"]["writable"] is True


def test_healthz_reports_the_llm_down(client, web_app, probe):
    probe.result = LlmHealth(False, "unreachable: 届かない")
    web_app.state.tia.monitor.refresh()
    response = client.get("/healthz")
    assert response.status_code == 503
    assert response.json()["problems"] == ["llm: unreachable: 届かない"]


def test_healthz_reports_a_probe_that_raises_without_dying(client, web_app, probe):
    probe.result = RuntimeError("boom secret")
    web_app.state.tia.monitor.refresh()
    body = client.get("/healthz").json()
    assert body["llm"]["ok"] is False and "RuntimeError" in body["llm"]["detail"] and "secret" not in body["llm"]["detail"]


def test_healthz_reports_a_missing_bundle(web_db, web_clock, probe, tmp_path):
    app = create_app(web_db[0], Config(), bundle_dir=tmp_path / "none", llm_probe=probe, clock=web_clock)
    app.state.tia.monitor.refresh()
    with TestClient(app, base_url=BASE_URL) as test_client:
        body = test_client.get("/healthz").json()
    assert body["status"] == "degraded" and body["knowledge"]["ok"] is False
    assert any(p.startswith("knowledge:") for p in body["problems"])


def test_healthz_reports_a_silent_collector(web_db, web_clock, probe, bundle_dir):
    conn = db.connect(web_db[0])
    conn.execute("DELETE FROM collector_state WHERE source = 'wazuh'")
    conn.close()
    app = create_app(web_db[0], Config(), bundle_dir=bundle_dir, llm_probe=probe, clock=web_clock)
    app.state.tia.monitor.refresh()
    with TestClient(app, base_url=BASE_URL) as test_client:
        body = test_client.get("/healthz").json()
    assert body["collectors"]["wazuh"]["ok"] is False and "wazuh: まだ一度も成功していない" in body["problems"]


def test_healthz_reports_too_little_free_space(web_db, web_clock, probe, bundle_dir):
    app = create_app(web_db[0], Config(web_min_free_mb=1000000), bundle_dir=bundle_dir, llm_probe=probe, clock=web_clock)
    app.state.tia.monitor.refresh()
    with TestClient(app, base_url=BASE_URL) as test_client:
        body = test_client.get("/healthz").json()
    assert body["database"]["ok"] is False and body["status"] == "degraded"


def test_monitor_thread_refreshes_on_its_own(web_db, web_clock, probe, bundle_dir):
    import time

    app = create_app(web_db[0], Config(), bundle_dir=bundle_dir, llm_probe=probe, clock=web_clock,
                     monitor_interval_sec=0.05)
    try:
        for _ in range(100):
            if probe.calls >= 2:
                break
            time.sleep(0.02)
        assert probe.calls >= 2
        assert app.state.tia.monitor.snapshot().llm.ok is True
    finally:
        app.state.tia.monitor.stop()


def test_healthz_is_not_fooled_by_a_writer_holding_the_lock(client, web_db):
    """I-8: 書き込み中は「混んでいる」であって「書けない」ではない。5 秒も待たない。"""
    writer = db.connect(web_db[0])
    writer.execute("BEGIN IMMEDIATE")
    try:
        started = time.monotonic()
        response = client.get("/healthz")
        seconds = time.monotonic() - started
    finally:
        writer.execute("ROLLBACK")
        writer.close()
    body = response.json()
    assert seconds < 2, seconds
    assert body["database"]["ok"] is True and body["database"]["writable"] is True
    assert "混んでいる" in body["database"]["detail"]
    assert not any(p.startswith("database:") for p in body["problems"])


def test_healthz_reports_an_llm_that_cannot_be_configured(web_db, web_clock, bundle_dir):
    """I-4: 鍵が読めない、宛先が壊れている、は「確認中」ではなく失敗。"""
    app = create_app(web_db[0], Config(), bundle_dir=bundle_dir, llm_probe=None,
                     llm_probe_error="鍵のファイルがない: /run/secrets/openwebui_api_key", clock=web_clock)
    app.state.tia.monitor.refresh()
    with TestClient(app, base_url=BASE_URL) as test_client:
        response = test_client.get("/healthz")
    body = response.json()
    assert response.status_code == 503
    assert body["llm"]["ok"] is False and body["llm"]["kind"] == "config"
    assert any(p.startswith("llm: 接続先が未設定") for p in body["problems"])


def test_healthz_llm_is_null_only_before_the_first_probe(web_db, web_clock, bundle_dir):
    app = create_app(web_db[0], Config(), bundle_dir=bundle_dir, llm_probe=None, clock=web_clock)
    app.state.tia.monitor.refresh()
    with TestClient(app, base_url=BASE_URL) as test_client:
        body = test_client.get("/healthz").json()
    assert body["llm"]["ok"] is None and not any(p.startswith("llm:") for p in body["problems"])


@pytest.mark.parametrize("kind, detail, expected", [
    ("unreachable", "unreachable: 接続できない", "切断"),
    ("timeout", "timeout: 10 秒以内に応答がない", "切断"),
    ("auth", "auth: 認証に失敗した（HTTP 401）", "鍵"),
    ("tls", "tls: 相手の証明書を検証できない", "証明書"),
    ("server", "server: 応答を読めなかった", "要確認"),
])
def test_tunnel_chip_is_classified_by_the_kind_of_the_failure(client, web_app, probe, kind, detail, expected):
    """M-9: トンネルの札は LlmHealth.kind で決める。文の中身では決めない。"""
    probe.result = LlmHealth(False, detail, kind)
    web_app.state.tia.monitor.refresh()
    html = client.get("/partials/health").text
    chip = html.split("トンネル")[1][:120]
    assert expected in chip, chip
    assert client.get("/healthz").json()["llm"]["kind"] == kind
