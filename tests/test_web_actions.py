"""画面からの操作。同じ画面からの要求だけを受け、状態を変え、経過に残す。"""
import json
import time
import urllib.error

import pytest
from fastapi.testclient import TestClient
from web_fixtures import (BASE_URL, NOW, Clock, Probe, bundle_dir, client, ids, make_db, post, probe, serve, token_of,  # noqa: F401
                         web_app, web_clock, web_db)

from tia import db


def _state(path, incident_id):
    conn = db.connect(path)
    try:
        row = conn.execute("SELECT analysis_state, priority, read_at, skip_reason, queue_reason, confirmed_verdict "
                           "FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        events = [r["type"] for r in conn.execute("SELECT type FROM events WHERE incident_id = ? ORDER BY id", (incident_id,))]
        return dict(row), events
    finally:
        conn.close()


def _toast(response) -> dict:
    return json.loads(response.headers["hx-trigger"])["tia-toast"]


def test_post_without_the_token_is_refused(client, web_db, ids):
    response = post(client, f"/incidents/{ids['queued_disk']}/prioritize", None)
    assert response.status_code == 403 and "画面の印が合わない" in response.text
    assert _state(web_db[0], ids["queued_disk"])[0]["priority"] == 0


def test_post_with_a_token_of_another_session_is_refused(client, web_app, ids):
    other = TestClient(web_app, base_url=BASE_URL)
    with other:
        foreign = token_of(other)
    token_of(client)
    response = post(client, f"/incidents/{ids['queued_disk']}/prioritize", foreign)
    assert response.status_code == 403


@pytest.mark.parametrize("headers", [{"Origin": "https://evil.test", "Sec-Fetch-Site": "cross-site"},
                                     {"Origin": "https://evil.test"}, {"Sec-Fetch-Site": "cross-site"},
                                     {"Origin": "null"}])
def test_post_from_another_site_is_refused(client, ids, headers):
    token = token_of(client)
    response = post(client, f"/incidents/{ids['queued_disk']}/prioritize", token, origin=None, **headers)
    assert response.status_code == 403 and "別のサイト" in response.text


def test_post_without_browser_headers_but_with_the_token_is_accepted(client, ids):
    token = token_of(client)
    response = post(client, f"/incidents/{ids['queued_disk']}/prioritize", token, origin=None, htmx=False)
    assert response.status_code == 200 and response.json()["ok"] is True


def test_prioritize_moves_the_incident_to_the_front(client, web_db, ids):
    token = token_of(client)
    response = post(client, f"/incidents/{ids['queued_disk']}/prioritize", token)
    assert response.status_code == 200 and _toast(response)["ok"] is True
    assert "先に解析する" in _toast(response)["message"]
    row, events = _state(web_db[0], ids["queued_disk"])
    assert row["priority"] == 1 and events[-1] == "prioritized"
    assert 'id="detail"' in response.text and "先に解析する指定" in response.text
    again = post(client, f"/incidents/{ids['queued_disk']}/prioritize", token)
    assert again.status_code == 200 and _toast(again)["ok"] is True, "二重に送られても害がない"
    assert _state(web_db[0], ids["queued_disk"])[0]["priority"] == 1


def test_skip_needs_a_reason_and_records_it(client, web_db, ids):
    token = token_of(client)
    missing = post(client, f"/incidents/{ids['queued']}/skip", token, {"reason": "   "})
    assert _toast(missing)["ok"] is False and "理由" in _toast(missing)["message"]
    assert _state(web_db[0], ids["queued"])[0]["analysis_state"] == "queued"
    done = post(client, f"/incidents/{ids['queued']}/skip", token, {"reason": "<b>検証中</b>"})
    assert _toast(done)["ok"] is True
    row, events = _state(web_db[0], ids["queued"])
    assert row["analysis_state"] == "skipped" and row["skip_reason"] == "manual: <b>検証中</b>" and events[-1] == "skipped"
    assert "&lt;b&gt;検証中&lt;/b&gt;" in done.text and "<b>検証中</b>" not in done.text


def test_reanalyze_requeues_done_failed_and_skipped(client, web_db, ids):
    token = token_of(client)
    for key in ("done_watch", "failed", "skipped_manual"):
        response = post(client, f"/incidents/{ids[key]}/reanalyze", token)
        assert _toast(response)["ok"] is True, key
        row, events = _state(web_db[0], ids[key])
        assert row["analysis_state"] == "queued" and row["queue_reason"] == "manual" and events[-1] == "requeued"
    refused = post(client, f"/incidents/{ids['running']}/reanalyze", token)
    assert _toast(refused)["ok"] is False and "解析中" in _toast(refused)["message"]


def test_wrong_state_without_htmx_is_a_409(client, ids):
    token = token_of(client)
    response = post(client, f"/incidents/{ids['running']}/prioritize", token, htmx=False)
    assert response.status_code == 409
    assert "この操作は" in response.text or "いまの状態" in response.text


def test_unknown_incident_and_unknown_action(client, ids):
    token = token_of(client)
    assert post(client, "/incidents/999/prioritize", token).status_code == 404
    assert post(client, "/incidents/999/prioritize", token, htmx=False).status_code == 404
    assert client.post(f"/incidents/{ids['queued']}/explode", data={"_token": token}).status_code in (404, 405)


def test_feedback_is_recorded_as_an_event(client, web_db, ids):
    token = token_of(client)
    helpful = post(client, f"/incidents/{ids['done_today']}/feedback", token, {"verdict": "helpful"})
    assert _toast(helpful)["message"] == "評価を記録した" and "評価: 役に立った" in helpful.text
    bad = post(client, f"/incidents/{ids['done_today']}/feedback", token, {"verdict": "corrected", "note": ""})
    assert _toast(bad)["ok"] is False and "原因の文" in _toast(bad)["message"]
    corrected = post(client, f"/incidents/{ids['done_today']}/feedback", token,
                     {"verdict": "corrected", "note": "<script>x</script> 本当の原因"})
    assert _toast(corrected)["ok"] is True
    row, events = _state(web_db[0], ids["done_today"])
    assert events.count("feedback") == 2 and "&lt;script&gt;x&lt;/script&gt; 本当の原因" in corrected.text
    too_early = post(client, f"/incidents/{ids['queued']}/feedback", token, {"verdict": "helpful"})
    assert _toast(too_early)["ok"] is False


def test_case_registration_uses_the_edited_fields(client, web_db, ids):
    token = token_of(client)
    response = post(client, f"/incidents/{ids['done_today']}/case", token,
                    {"verdict": "corrected", "cause": "APP02 の MOD 構成による定常値", "symptoms": "", "confirmation": "free -m で確認",
                     "action": "閾値を 95% に上げるか検討"})
    assert _toast(response)["message"] == "事例として登録した" and "事例として登録済み" in response.text
    row, events = _state(web_db[0], ids["done_today"])
    assert row["confirmed_verdict"] == "corrected" and events[-1] == "case_registered"
    conn = db.connect(web_db[0])
    case = conn.execute("SELECT * FROM cases WHERE incident_id = ?", (ids["done_today"],)).fetchone()
    conn.close()
    assert case["cause"] == "APP02 の MOD 構成による定常値" and case["action"] == "閾値を 95% に上げるか検討"
    assert case["symptoms"].startswith("APP02 VM のメモリ使用率"), "空の欄は下書きの値"
    refused = post(client, f"/incidents/{ids['queued']}/case", token, {"verdict": "correct"})
    assert _toast(refused)["ok"] is False


def test_case_registration_without_a_cause_is_refused(client, web_db, ids):
    token = token_of(client)
    conn = db.connect(web_db[0])
    conn.execute("UPDATE analyses SET result_json = ? WHERE incident_id = ?",
                 (json.dumps({"summary": "x", "probable_causes": []}), ids["done_ignore"]))
    conn.close()
    response = post(client, f"/incidents/{ids['done_ignore']}/case", token, {"verdict": "correct"})
    assert _toast(response)["ok"] is False and "原因" in _toast(response)["message"]


def test_opening_marks_as_read_through_the_read_action(client, web_db, ids):
    token = token_of(client)
    assert _state(web_db[0], ids["done_today"])[0]["read_at"] is None
    response = client.post(f"/incidents/{ids['done_today']}/read", headers={"HX-Request": "true", "X-TIA-Token": token,
                                                                          "Origin": BASE_URL, "Sec-Fetch-Site": "same-origin"})
    # 既読は背景の処理。トーストの指示は付けない
    assert response.status_code == 200 and "hx-trigger" not in response.headers
    row, events = _state(web_db[0], ids["done_today"])
    assert row["read_at"] is not None and "read" not in events, "既読は経過に残さない"
    again = client.post(f"/incidents/{ids['done_today']}/read", headers={"HX-Request": "true", "X-TIA-Token": token,
                                                                       "Origin": BASE_URL, "Sec-Fetch-Site": "same-origin"})
    assert again.status_code == 200
    assert "未確認 1 件" in client.get("/partials/rail").text


def test_get_never_changes_state(client, web_db, ids):
    before = _state(web_db[0], ids["done_today"])
    for path in (f"/incidents/{ids['done_today']}", f"/partials/incidents/{ids['done_today']}",
                 f"/partials/incidents/{ids['done_today']}/case-form", "/partials/list", "/partials/rail"):
        client.get(path)
    assert _state(web_db[0], ids["done_today"]) == before
    assert client.get(f"/incidents/{ids['done_today']}/prioritize").status_code == 405


def test_every_action_names_itself_the_same_way_everywhere(client, web_db, ids):
    token = token_of(client)
    response = post(client, f"/incidents/{ids['queued_disk']}/skip", token, {"reason": "作業中"})
    assert _toast(response)["message"] == "対象外にした"
    detail = client.get(f"/partials/incidents/{ids['queued_disk']}").text
    assert "対象外にした" in detail and "対象外: 作業中" in detail


def test_busy_database_does_not_block_other_requests_and_is_a_503(web_db, web_clock, probe, bundle_dir, ids):
    """I-1: 書き込みの鍵を持たれている間も、静的ファイルと SSE は待たされず、操作は 503 と理由で返る。"""
    import http.client
    import threading
    import urllib.request
    from urllib.parse import urlsplit

    from tia.config import Config
    from tia.web.app import create_app

    # http で Cookie を送るので、secure を外したアプリを使う
    app = create_app(web_db[0], Config(web_cookie_secure=False), bundle_dir=bundle_dir, llm_probe=probe, clock=web_clock)
    with serve(app) as base:
        # 画面を 1 回読んで Cookie と印を得る
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor())
        with opener.open(base + "/") as page:
            html = page.read().decode()
        start = html.index('name="tia-token" content="') + len('name="tia-token" content="')
        token = html[start:html.index('"', start)]
        writer = db.connect(web_db[0])
        writer.execute("BEGIN IMMEDIATE")
        try:
            result: dict = {}

            def act():
                body = f"_token={token}&verdict=helpful".encode()
                req = urllib.request.Request(f"{base}/incidents/{ids['done_today']}/feedback", data=body, method="POST",
                                             headers={"Content-Type": "application/x-www-form-urlencoded",
                                                      "Origin": base, "Sec-Fetch-Site": "same-origin"})
                started = time.monotonic()
                try:
                    with opener.open(req, timeout=20) as response:
                        result["status"], result["body"] = response.status, response.read().decode()
                except urllib.error.HTTPError as exc:
                    result["status"], result["body"] = exc.code, exc.read().decode()
                result["seconds"] = time.monotonic() - started

            worker = threading.Thread(target=act)
            worker.start()
            time.sleep(0.5)
            # 操作が鍵を待っている間に、静的ファイルと SSE の最初の行が 1 秒以内に届く
            started = time.monotonic()
            with urllib.request.urlopen(base + "/static/theme.js", timeout=5) as static:
                assert static.status == 200
            static_seconds = time.monotonic() - started
            host = urlsplit(base)
            sse = http.client.HTTPConnection(host.hostname, host.port, timeout=5)
            started = time.monotonic()
            sse.request("GET", "/events")
            response = sse.getresponse()
            first = response.read(6)  # chunked をほどいた最初の 6 バイト
            sse_seconds = time.monotonic() - started
            sse.close()
            assert static_seconds < 1 and sse_seconds < 1, (static_seconds, sse_seconds)
            assert first.startswith(b"retry:")
            worker.join(timeout=30)
        finally:
            writer.execute("ROLLBACK")
            writer.close()
    assert result["status"] == 503, result
    assert "保存先が混んでいる" in result["body"]


def test_feedback_and_case_apply_to_the_shown_analysis_not_to_a_later_replay(client, web_db, ids):
    """I-5: 再生の後も、評価と事例は画面に出ている解析（インシデントが指す解析）に付く。"""
    from datetime import timedelta

    from web_helpers import MODEL, _result

    from tia.analysis import records

    iid = ids["done_today"]
    conn = db.connect(web_db[0])
    replay = records.begin(conn, iid, "replay", MODEL, NOW - timedelta(seconds=60))
    records.finish(conn, replay, NOW - timedelta(seconds=30), status="done",
                   result=_result(classification={"kind": "noise", "urgency": "ignore"}, summary="再生の要約",
                                  probable_causes=[{"cause": "再生で出た原因", "confidence": "low", "evidence": ""}]),
                   prompt_tokens=100, completion_tokens=50, tokens_per_sec=7.0)
    pointed = conn.execute("SELECT latest_analysis_id FROM incidents WHERE id = ?", (iid,)).fetchone()[0]
    conn.close()
    assert pointed != replay
    token = token_of(client)
    post(client, f"/incidents/{iid}/feedback", token, {"verdict": "helpful"})
    response = post(client, f"/incidents/{iid}/case", token, {"verdict": "correct"})
    assert _toast(response)["ok"] is True, _toast(response)
    conn = db.connect(web_db[0])
    try:
        feedback = json.loads(conn.execute("SELECT detail_json FROM events WHERE incident_id = ? AND type = 'feedback' "
                                           "ORDER BY id DESC LIMIT 1", (iid,)).fetchone()[0])
        case = conn.execute("SELECT cause FROM cases WHERE incident_id = ?", (iid,)).fetchone()
    finally:
        conn.close()
    assert feedback["analysis_id"] == pointed
    assert case["cause"] != "再生で出た原因"
