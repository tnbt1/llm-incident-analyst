"""本物のブラウザでしか見えない振る舞い。ライブ更新、入力中の保護、操作の失敗の表示。

headless の Chromium を `tests/browser.py` で動かす。Chromium がない機械では飛ばす。
"""
from __future__ import annotations

import json
import secrets
import time
from datetime import timedelta

import pytest
from browser import Browser, chromium_path
from knowledge_helpers import build_fixture
from web_fixtures import serve
from web_helpers import NOW, Clock, collector_rows, make_db

from tia import db
from tia.analysis import records
from tia.analysis.llm import LlmHealth
from tia.config import Config
from tia.models import to_iso
from tia.web.app import create_app

pytestmark = [pytest.mark.browser, pytest.mark.skipif(chromium_path() is None, reason="Chromium がない")]


@pytest.fixture
def site(tmp_path):
    """本物のサーバーとブラウザ。保存先の場所、番号、アプリ、URL を渡す。"""
    path = tmp_path / "web.sqlite"
    ids = make_db(path)
    conn = db.connect(path)
    collector_rows(conn)
    conn.close()
    bundle_dir = build_fixture(tmp_path / "kb").path.parent
    clock = Clock(NOW)
    app = create_app(path, Config(web_cookie_secure=False, web_sse_poll_sec=1), bundle_dir=bundle_dir,
                     llm_probe=lambda: LlmHealth(True, "届く"), clock=clock)
    app.state.tia.monitor.refresh()
    with serve(app) as base, Browser() as browser:
        yield {"path": path, "ids": ids, "app": app, "base": base, "browser": browser, "clock": clock}


def touch(path, incident_id: int, *, title: str | None = None, at=None) -> None:
    """インシデントを外から変える。収集や解析が書き込むのと同じ列。"""
    stamp = to_iso(at or (NOW + timedelta(seconds=5)))
    conn = db.connect(path)
    try:
        if title is not None:
            conn.execute("UPDATE incidents SET title = ?, updated_at = ? WHERE id = ?", (title, stamp, incident_id))
        else:
            conn.execute("UPDATE incidents SET updated_at = ? WHERE id = ?", (stamp, incident_id))
    finally:
        conn.close()


def wait_sse(browser: Browser, timeout: float = 10.0) -> None:
    """ページが /events につなぐまで待つ。"""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if any(r.endswith("/events") for r in browser.requests):
            time.sleep(0.3)
            return
        time.sleep(0.1)
    raise AssertionError("ページが /events につながない")


def test_every_part_is_redrawn_after_a_change(site):
    """C-1: 変化の知らせで rail、band、list の全部が取り直される（HTMX の hx-sync に捨てられない）。"""
    b, ids = site["browser"], site["ids"]
    b.goto(f"{site['base']}/incidents/{ids['done_today']}")
    wait_sse(b)
    b.requests.clear()
    touch(site["path"], ids["queued_disk"], title="変更後の題名 app01")
    b.wait_for("document.querySelector('#list').textContent.includes('変更後の題名 app01')", timeout=4)
    time.sleep(0.5)
    paths = {r.split(site["base"])[-1].split("?")[0] for r in b.requests}
    assert {"/partials/rail", "/partials/band", "/partials/list"} <= paths, paths


def test_text_being_typed_survives_a_change(site):
    """I-2: 入力中は詳細を描き直さず、「更新があります」の印を出す。"""
    b, ids = site["browser"], site["ids"]
    b.goto(f"{site['base']}/incidents/{ids['done_today']}")
    wait_sse(b)
    b.eval("document.querySelector('#pane details.inline-form').open = true")
    b.type_into("#pane textarea[name=note]", "入力の途中の文")
    touch(site["path"], ids["done_today"])
    time.sleep(2.5)
    assert b.eval("document.querySelector('#pane textarea[name=note]').value") == "入力の途中の文"
    assert b.eval("document.querySelector('#stale') && !document.querySelector('#stale').hidden")
    # 印を押すと描き直され、印は消える
    b.click("#stale")
    b.wait_for("document.querySelector('#stale').hidden", timeout=4)


def test_list_keeps_its_scroll_position_across_a_redraw(site):
    b, ids = site["browser"], site["ids"]
    b.goto(f"{site['base']}/incidents/{ids['done_today']}")
    wait_sse(b)
    scrollable = b.eval("(function(){var l=document.getElementById('list'); return l.scrollHeight - l.clientHeight;})()")
    assert scrollable > 60, "一覧がスクロールしない大きさでは、この試験は意味がない"
    b.eval("document.getElementById('list').scrollTop = 54")
    b.requests.clear()
    touch(site["path"], ids["queued_disk"], title="並びは変えずに題名だけ変える")
    b.wait_for("document.querySelector('#list').textContent.includes('並びは変えずに題名だけ変える')", timeout=4)
    assert b.eval("document.getElementById('list').scrollTop") == 54


def test_progress_updates_only_the_progress_elements(site):
    """進捗は progress のイベントだけで届き、一覧と帯は取り直さない。"""
    b, ids = site["browser"], site["ids"]
    b.goto(f"{site['base']}/incidents/{ids['running']}")
    wait_sse(b)
    b.requests.clear()
    conn = db.connect(site["path"])
    records.progress(conn, ids["running_analysis"], "inference", NOW - timedelta(seconds=3), tokens_so_far=600)
    conn.close()
    b.wait_for("document.querySelector('#rail').textContent.includes('600 / 1200')", timeout=4)
    assert b.eval("document.querySelector('#list [data-progress-for] i').style.getPropertyValue('--p')").strip() == "50%"
    assert b.eval("document.querySelector('#pane .progress-text').textContent").startswith("600 /")
    time.sleep(1.2)
    paths = [r.split(site["base"])[-1].split("?")[0] for r in b.requests]
    assert "/partials/list" not in paths and "/partials/band" not in paths and "/partials/incidents/%d" % ids["running"] not in paths, paths


def test_rejected_action_shows_the_servers_message(site):
    """I-7: 鍵が変わった後（再起動と同じ）の操作は、読み直すように言う。"""
    b, ids = site["browser"], site["ids"]
    b.goto(f"{site['base']}/incidents/{ids['done_today']}")
    wait_sse(b)
    site["app"].state.tia.secret = secrets.token_bytes(32)
    b.click("#pane form[hx-post$='/feedback'] button")
    text = b.wait_for("(function(){var t=document.getElementById('toast'); return !t.hidden && t.textContent;})()", timeout=4)
    assert "読み直" in text, text


def test_automatic_mark_read_shows_no_toast(site):
    """M-5: 未確認の件を開いても、トーストは出ない。既読の印だけが消える。"""
    b, ids = site["browser"], site["ids"]
    b.goto(f"{site['base']}/incidents/{ids['done_today']}")
    wait_sse(b)
    b.wait_for("document.querySelector('#pane .detail').dataset.unread === '0'", timeout=4)
    time.sleep(0.8)
    assert b.eval("document.getElementById('toast').hidden") is True
