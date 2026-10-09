"""ページと部品の描画。構造、文字列のエスケープ、リンクの扱い、日本語の表示。"""
import re
from datetime import timedelta
from pathlib import Path

import pytest
from web_fixtures import (BASE_URL, HOSTILE, NOW, Clock, Probe, bundle_dir, client, ids, make_db,  # noqa: F401
                         probe, web_app, web_clock, web_db)

from fastapi.testclient import TestClient

from tia.config import Config
from tia.web.app import create_app
from tia.web.filters import linkify
from tia.web.routes import check

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "src" / "tia" / "web" / "templates"

RAW_MARKERS = ["<script>alert", "<img src=x onerror", "</alert_data>", "<doc>", "<b>証拠</b>", "<i>範囲</i>", "<u>場所</u>",
               "<s>x</s>"]


def _no_raw_html(html: str) -> None:
    for marker in RAW_MARKERS:
        assert marker not in html, marker
    assert "javascript:" not in html.replace("javascript:alert(1))", "").replace("(javascript:alert(1)", "") or \
        'href="javascript:' not in html


def test_inbox_has_the_fixed_structure(client):
    html = client.get("/").text
    for needle in ('class="app-head"', 'id="health"', 'id="rail" aria-label="解析パイプライン"', 'id="band"',
                   'id="list"', 'id="pane"', 'class="legend"', 'Incident Analyst'):
        assert needle in html, needle
    assert "example-tenant production" not in html and "5 台を監視" not in html
    assert html.count('class="station"') == 3 and html.count('class="side') == 2
    assert "進行中" in html and "本日の解析済み" in html and "解析できなかったもの" in html
    assert "左の一覧から 1 件を選ぶ" in html
    assert 'lang="ja"' in html and 'data-theme-toggle' in html


def test_list_rows_follow_the_design(client, ids):
    html = client.get("/").text
    running = re.search(rf'<a class="row" href="/incidents/{ids["running"]}".*?</a>', html, re.S).group(0)
    assert 'data-state="run"' in running and '<span class="spin"></span>' in running
    assert "推論中" in running and 'class="meter"' in running and "発生中 6 分" in running
    assert '<span class="host">example-router01</span>' in running and "<time>14:51</time>" in running
    done = re.search(rf'<a class="row is-unread" href="/incidents/{ids["done_today"]}".*?</a>', html, re.S).group(0)
    assert 'data-u="today"' in done and '<span class="urg" data-u="today">今日中</span>' in done
    assert '<span class="src">Zabbix</span>' in done and "#pg-mem" in done
    group = re.search(rf'<a class="row[^"]*" href="/incidents/{ids["group"]}".*?</a>', html, re.S).group(0)
    assert "6 件を束ねた" in group
    assert f'href="/incidents/{ids["icmp1"]}"' not in html, "束の構成要素は一覧に出ない"
    assert 'hx-get="/partials/incidents/' in running and 'hx-target="#pane"' in running


def test_hostile_strings_are_shown_as_text_everywhere(client, ids):
    for path in ("/", f"/incidents/{ids['done_now_hostile']}", f"/partials/incidents/{ids['done_now_hostile']}",
                 "/partials/list", "/partials/band"):
        html = client.get(path).text
        _no_raw_html(html)
        assert "&lt;script&gt;alert" in html or path == "/partials/band"
    detail = client.get(f"/partials/incidents/{ids['done_now_hostile']}").text
    assert "&lt;/alert_data&gt;" in detail and "&lt;doc&gt;" in detail
    assert 'href="https://example.test/a?b=1"' in detail or "https://example.test/a?b=1" in detail
    assert 'href="javascript:' not in detail and "**bold**" in detail, "Markdown は描かない"
    assert '<a href="https://example.test/x" rel="noopener noreferrer nofollow" target="_blank">' in detail
    assert 'title="' in client.get("/partials/band").text


def test_linkify_only_links_http_and_https():
    out = str(linkify("see https://a.test/x, http://b.test/y) and javascript:alert(1) and ftp://c.test <b>x</b>"))
    assert out.count("<a ") == 2 and 'href="https://a.test/x"' in out and 'href="http://b.test/y"' in out
    assert "javascript:alert(1)" in out and 'href="javascript' not in out
    assert "ftp://c.test" in out and 'href="ftp' not in out and "&lt;b&gt;x&lt;/b&gt;" in out
    wrapped = str(linkify('<a href="https://evil.test">x</a>'))
    assert wrapped.startswith("&lt;a href=") and wrapped.count("<a ") == 1 and "noopener" in wrapped
    assert str(linkify(None)) == ""


def test_detail_of_a_done_incident_shows_the_eight_items(client, ids):
    html = client.get(f"/incidents/{ids['done_today']}").text
    for needle in ("解析の要約", "原因候補", "影響範囲", "関連", "推奨する確認", "要判断", "不足している情報", "経過",
                   "LLM に渡した文脈を表示", "この解析は役に立ちましたか", "役に立った", "外れていた", "正しい原因を記入",
                   "事例として登録する", "再解析する", "資料にある", "未検証", "確度 中", "20260929-abcdef012345", "#a3f9c0ff",
                   "監視VMの状態", "vmctl vm exec example-app02 -- free -m"):
        assert needle in html, needle
    assert 'aria-selected="true"' in html and html.count('aria-selected="true"') == 1
    assert "<title>I-0001 メモリ使用率が 90% を超過 | Incident Analyst</title>" in html
    assert 'data-unread="1"' in html


def test_detail_of_running_waiting_failed_skipped_and_group(client, ids):
    running = client.get(f"/partials/incidents/{ids['running']}").text
    assert "解析の進行" in running and "文脈収集 完了" in running and "推論中" in running and "312 / 1200 トークン" in running
    assert "緊急度は解析後に決まります" in running and "先に解析する" not in running
    waiting = client.get(f"/partials/incidents/{ids['queued_disk']}").text
    assert "処理待ち" in waiting and "先行する 2 件" in waiting and "先に解析する" in waiting and "対象外にする" in waiting
    held = client.get(f"/partials/incidents/{ids['held']}").text
    assert "続報を束ね中" in held
    failed = client.get(f"/partials/incidents/{ids['failed']}").text
    assert "解析できなかった" in failed and "LLM の応答が制限時間を超えた" in failed and "再解析する" in failed
    assert "解析の版" in failed and failed.count("timeout") >= 4
    skipped = client.get(f"/partials/incidents/{ids['skipped_manual']}").text
    assert "対象外: 検証環境の作業" in skipped and "再解析する" in skipped and "先に解析する" not in skipped
    group = client.get(f"/partials/incidents/{ids['group']}").text
    assert "束ねたインシデント" in group and "6 件を 1 件として解析" in group and group.count("ICMP 応答なし") >= 6
    member = client.get(f"/partials/incidents/{ids['icmp1']}").text
    assert "束の一部" in member and f'href="/incidents/{ids["group"]}"' in member


def test_case_and_feedback_are_shown(client, ids):
    with_case = client.get(f"/partials/incidents/{ids['done_wazuh']}").text
    assert "事例として登録済み" in with_case and "事例を登録し直す" in with_case and "事例として登録する" not in with_case
    with_feedback = client.get(f"/partials/incidents/{ids['done_watch']}").text
    assert "評価: 役に立った" in with_feedback


def test_case_form_is_prefilled_from_the_draft(client, ids):
    html = client.get(f"/partials/incidents/{ids['done_today']}/case-form").text
    assert 'name="cause"' in html and "経過観察" not in html  # 別のインシデントの下書きは出ない
    assert "FRR の経路再計算" in html and 'name="verdict" value="correct" checked' in html
    assert client.get("/partials/incidents/999/case-form").status_code == 404


def test_health_chips_show_each_component(client):
    html = client.get("/partials/health").text
    assert "LLM <b>稼働</b>" in html and "トンネル <b>接続</b>" in html
    assert "Zabbix 取得 <b>12 秒前</b>" in html and "Wazuh 取得 <b>41 秒前</b>" in html
    assert "環境カード" in html and "<b>未配置</b>" not in html
    assert "model-27b" in html


def test_health_chips_when_the_llm_is_down_or_unchecked(client, web_app, probe):
    from tia.analysis.llm import LlmHealth

    # 札は LlmHealth.kind で決まる
    probe.result = LlmHealth(False, "unreachable: 届かない", "unreachable")
    web_app.state.tia.monitor.refresh()
    html = client.get("/partials/health").text
    assert "LLM <b>停止</b>" in html and "トンネル <b>切断</b>" in html
    probe.result = LlmHealth(False, "auth: 鍵が違う", "auth")
    web_app.state.tia.monitor.refresh()
    html = client.get("/partials/health").text
    assert "トンネル <b>鍵</b>" in html
    banner = client.get("/partials/rail").text
    assert 'hx-swap-oob="true"' in banner and "LLM に届いていない" in banner


def test_rail_links_keep_the_other_filters(client):
    html = client.get("/?day=2026-09-28&host=example-router01").text
    assert 'href="/?state=wait&amp;day=2026-09-28&amp;host=example-router01"' in html
    pressed = client.get("/?state=done").text
    assert 'href="/" aria-pressed="true"' in pressed
    assert "2026-09-28 の表示" in html and "絞り込みを外す" in html


def test_band_marks_link_to_the_incident(client, ids):
    html = client.get("/partials/band").text
    assert f'href="/incidents/{ids["running"]}"' in html and 'class="mk ring"' in html and "現在 14:57" in html


def test_japanese_labels_not_identifiers(client, ids):
    html = client.get(f"/incidents/{ids['done_now_hostile']}").text
    assert "今すぐ" in html and "可用性" in html
    assert 'class="urg" data-u="now">now<' not in html


def test_legend_lists_every_type(client):
    html = client.get("/").text
    legend = html[html.index('class="legend"'):html.index("</details>", html.index('class="legend"'))]
    for label in ("CPU", "メモリ", "ディスク", "I/O", "スワップ", "ネットワーク", "コンテナ", "サービス", "認証", "利用者",
                  "ファイル変更", "パッケージ", "その他"):
        assert label in legend
    assert "#pg-service" in legend and "#pg-other" in legend


def test_pages_have_no_inline_script_and_no_external_resource(client):
    for path in ("/", "/incidents/1", "/incidents/4"):
        html = client.get(path).text
        for script in re.findall(r"<script\b[^>]*>(.*?)</script>", html, re.S):
            assert script.strip() == "", "script の中身は空（外部ファイルだけ）"
        assert all("src=" in tag for tag in re.findall(r"<script\b[^>]*>", html))
        assert not re.search(r"src=\"(https?:)?//", html), "外部のホストへの参照がない"
        assert not re.search(r"<link[^>]*href=\"(https?:)?//", html), "外部の様式や書体を読まない"
        assert "onerror=" not in html.replace("onerror=alert(1)&gt;", "")


def test_no_template_turns_autoescape_off_or_marks_text_safe():
    for path in TEMPLATES.rglob("*.html"):
        text = path.read_text(encoding="utf-8")
        assert "autoescape false" not in text and "|safe" not in text and "| safe" not in text, path


def test_missing_incident_is_a_404_page_with_the_message(client):
    response = client.get("/incidents/999")
    assert response.status_code == 404 and "I-0999 はない" in response.text and "<title>404" in response.text


def test_missing_incident_as_htmx_is_a_small_message(client):
    response = client.get("/partials/incidents/999", headers={"HX-Request": "true"})
    assert response.status_code == 404 and 'class="empty msg"' in response.text and "<html" not in response.text


@pytest.mark.parametrize("query", ["state=bogus", "day=2026-13-01", "day=yesterday"])
def test_bad_filter_is_a_400_with_direction(client, query):
    response = client.get(f"/?{query}")
    assert response.status_code == 400
    assert "YYYY-MM-DD" in response.text or "wait、run、done、fail、skip" in response.text


def test_healthz_reports_a_stalled_queue(client, web_clock):
    web_clock.now = NOW + timedelta(seconds=700)
    body = client.get("/healthz").json()
    assert body["queue"]["stalled"] is True and any(p.startswith("queue:") for p in body["problems"])
    page = client.get("/")
    assert "最も古い待ちが" in page.text and 'id="banner" class="banner"' in page.text


def test_llm_status_is_unchecked_until_the_monitor_runs(web_db, web_clock, probe, bundle_dir):
    app = create_app(web_db[0], Config(), bundle_dir=bundle_dir, llm_probe=probe, clock=web_clock)
    with TestClient(app, base_url=BASE_URL) as test_client:
        body = test_client.get("/healthz").json()
        assert body["llm"]["ok"] is None and body["llm"]["detail"] == "確認中"
        assert "llm" not in " ".join(body["problems"])
        assert "LLM <b>確認中</b>" in test_client.get("/").text
    assert probe.calls == 0


def test_check_renders_the_inbox_without_serving(web_app):
    page, body, status = check(web_app)
    assert "Incident Analyst" in page and 'data-id="10"' in page
    assert status == 200 and body["status"] == "ok"


def test_empty_database_still_renders(tmp_path, web_clock, probe, bundle_dir):
    path = tmp_path / "empty.sqlite"
    app = create_app(path, Config(), bundle_dir=bundle_dir, llm_probe=probe, clock=web_clock)
    app.state.tia.monitor.refresh()
    with TestClient(app, base_url=BASE_URL) as test_client:
        page = test_client.get("/")
        assert page.status_code == 200
        assert "進行中のものはありません" in page.text and "左の一覧から 1 件を選ぶ" in page.text
        health = test_client.get("/healthz").json()
    assert health["queue"]["depth"] == 0 and health["status"] == "degraded"
    assert set(p.split(":")[0] for p in health["problems"]) == {"zabbix", "wazuh"}


def test_excluded_checks_are_shown_without_the_command(client, web_db, ids):
    import json

    from tia import db

    conn = db.connect(web_db[0])
    row = conn.execute("SELECT latest_analysis_id FROM incidents WHERE id = ?", (ids["done_today"],)).fetchone()
    result = json.loads(conn.execute("SELECT result_json FROM analyses WHERE id = ?", (row["latest_analysis_id"],)).fetchone()[0])
    result["excluded_checks"] = [{"purpose": "利用者を消す", "where": "APP02", "command": "userdel monitor-tunnel",
                                  "reason": "利用者とパスワードの変更"}]
    conn.execute("UPDATE analyses SET result_json = ? WHERE id = ?", (json.dumps(result, ensure_ascii=False), row["latest_analysis_id"]))
    conn.commit()
    page = client.get(f"/partials/incidents/{ids['done_today']}").text
    assert "規則により除外した確認" in page and "利用者を消す" in page and "利用者とパスワードの変更" in page
    assert "userdel" not in page
    section = page[page.index("規則により除外した確認"):]
    assert "data-copy" not in section.split("</section>")[0]
    result["recommended_checks"] = []
    conn.execute("UPDATE analyses SET result_json = ? WHERE id = ?", (json.dumps(result, ensure_ascii=False), row["latest_analysis_id"]))
    conn.commit()
    page = client.get(f"/partials/incidents/{ids['done_today']}").text
    conn.close()
    assert "推奨する確認はない（1 件を規則により除外）" in page


def test_timeline_labels_the_excluded_checks_event_in_japanese(tmp_path):
    """除外の出来事は英語の型名ではなく、件数と理由の付いた日本語で出る。"""
    from datetime import datetime, timezone
    from zoneinfo import ZoneInfo

    from tia import db
    from tia.intake import add_event
    from tia.web.queries import _events

    make_db(tmp_path / "t.sqlite")
    conn = db.connect(tmp_path / "t.sqlite")
    with db.transaction(conn):
        add_event(conn, 1, datetime(2026, 10, 8, tzinfo=timezone.utc), "checks_excluded",
                  {"analysis_id": 1, "count": 2, "reasons": ["利用者とパスワードの変更"]})
    rows = [e for e in _events(conn, 1, ZoneInfo("Asia/Tokyo")) if e["type"] == "checks_excluded"]
    conn.close()
    assert rows and rows[0]["label"] == "確認を規則により除外した"
    assert "2 件" in rows[0]["note"] and "利用者とパスワードの変更" in rows[0]["note"]
