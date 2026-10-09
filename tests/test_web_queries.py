"""画面のための読み取り。数、節、帯、詳細、変化の印。"""
from datetime import UTC, date, datetime, timedelta
from zoneinfo import ZoneInfo

import pytest
from web_helpers import HOSTILE, MODEL, NOW, _result, collector_rows, make_db  # noqa: F401

from tia import db, queue
from tia.analysis import records
from tia.config import Config
from tia.models import to_iso
from tia.web import queries

TZ = ZoneInfo("Asia/Tokyo")


@pytest.fixture
def populated(tmp_path):
    path = tmp_path / "q.sqlite"
    ids = make_db(path)
    conn = db.connect(path)
    try:
        yield conn, ids
    finally:
        conn.close()


def test_times_are_shown_in_the_configured_zone():
    assert queries.clock_text("2026-09-29T05:57:00+00:00", TZ) == "14:57"
    assert queries.clock_text(None, TZ) == "—"
    assert queries.day_bounds(date(2026, 9, 29), TZ) == ("2026-09-28T15:00:00+00:00", "2026-09-29T15:00:00+00:00")


def test_day_parameter_defaults_to_today_in_the_zone_and_rejects_other_shapes():
    late = datetime(2026, 9, 29, 15, 30, tzinfo=UTC)  # 日本時間では翌日の 0:30
    assert queries.parse_day(None, late, TZ) == date(2026, 9, 30)
    assert queries.parse_day("2026-09-01", late, TZ) == date(2026, 9, 1)
    with pytest.raises(ValueError, match="YYYY-MM-DD"):
        queries.parse_day("09/29", late, TZ)


@pytest.mark.parametrize(("seconds", "text"), [(None, "—"), (0, "0 秒"), (59, "59 秒"), (60, "1 分"), (3599, "59 分"),
                                               (3600, "1 時間"), (3660, "1 時間1 分"), (172800, "2 日")])
def test_durations_read_naturally(seconds, text):
    assert queries.duration_text(seconds) == text


def test_host_names_are_shortened_for_the_list():
    assert queries.short_host("app02-production") == "app02"
    assert queries.short_host("monitor01") == "monitor01"
    assert queries.short_host("") == ""


def test_rail_counts_every_state(populated):
    conn, ids = populated
    rail = queries.rail(conn, NOW, Config(), date(2026, 9, 29))
    assert rail["waiting"] == 4 and rail["running"] == 1 and rail["failed"] == 1 and rail["skipped"] == 2
    assert rail["done"] == 6 and rail["done_sub"] == "本日 · 未確認 2 件"
    assert rail["running_sub"].startswith("推論中") and "312 / 1200 tok" in rail["running_sub"]
    assert rail["running_percent"] == 26
    assert rail["waiting_sub"].startswith("次の開始見込")


def test_sections_group_the_rows_the_way_the_design_shows(populated):
    conn, ids = populated
    sections = {s.key: s for s in queries.sections(conn, NOW, Config(), date(2026, 9, 29))}
    active = [r["id"] for r in sections["active"].rows]
    assert active[0] == ids["running"], "解析中が先頭"
    assert set(active) == {ids["running"], ids["held"], ids["queued"], ids["queued_disk"], ids["retry_wait"]}
    assert all(r["id"] not in active for r in sections["done"].rows)
    done = [r["id"] for r in sections["done"].rows]
    assert done[0] == ids["done_today"] and ids["group"] in done and len(done) == 6
    assert [r["id"] for r in sections["failed"].rows] == [ids["failed"]]
    assert {r["id"] for r in sections["skipped"].rows} == {ids["skipped_manual"], ids["skipped_low"]}
    assert sections["skipped"].hidden is True and sections["active"].hidden is False
    grouped_member = ids["icmp1"]
    assert all(grouped_member not in [r["id"] for r in s.rows] for s in sections.values()), "束の構成要素は行にしない"


def test_row_texts_describe_the_state(populated):
    conn, ids = populated
    rows = {r["id"]: r for s in queries.sections(conn, NOW, Config(), date(2026, 9, 29)) for r in s.rows}
    running = rows[ids["running"]]
    assert running["state"] == "run" and running["progress"] == 26 and running["why"].startswith("推論中")
    assert running["live"] == "発生中 6 分" and running["time"] == "14:51" and running["icon"] == "pg-cpu"
    assert rows[ids["held"]]["why"] == "続報を束ね中"
    assert rows[ids["queued_disk"]]["why"].startswith("先行 ") and "開始見込" in rows[ids["queued_disk"]]["why"]
    assert rows[ids["retry_wait"]]["why"].startswith("再試行 ") and rows[ids["retry_wait"]]["why"].endswith("予定")
    assert rows[ids["failed"]]["why"] == "LLM の応答が制限時間を超えた"
    assert rows[ids["skipped_manual"]]["why"] == "対象外: 検証環境の作業"
    assert rows[ids["skipped_low"]]["why"] == "閾値未満のため対象外"
    today = rows[ids["done_today"]]
    assert today["u"] == "today" and today["urgency_label"] == "今日中" and today["unread"] is True
    assert rows[ids["done_watch"]]["healed"].startswith("復旧済み · ") and rows[ids["done_watch"]]["unread"] is False
    assert rows[ids["done_wazuh"]]["healed"] == "単発" and rows[ids["done_wazuh"]]["source_short"] == "Wazuh"
    group = rows[ids["group"]]
    assert group["members"] == 6 and group["u"] == "now" and group["source"] == "group"
    assert rows[ids["done_now_hostile"]]["title"] == HOSTILE, "文字列はそのまま。エスケープは描画で行う"


def test_state_filter_keeps_only_matching_rows(populated):
    conn, ids = populated
    for key, expected in (("wait", 4), ("run", 1), ("done", 6), ("fail", 1), ("skip", 2)):
        sections = queries.sections(conn, NOW, Config(), date(2026, 9, 29), state=key)
        assert sum(s.count for s in sections) == expected, key
        assert all(not s.hidden for s in sections)
    with pytest.raises(ValueError):
        queries.sections(conn, NOW, Config(), date(2026, 9, 29), state="all")


def test_host_filter_and_other_days(populated):
    conn, ids = populated
    sections = queries.sections(conn, NOW, Config(), date(2026, 9, 29), host="example-router01")
    assert all(r["host"] == "example-router01" for s in sections for r in s.rows)
    yesterday = queries.sections(conn, NOW, Config(), date(2026, 9, 28))
    assert {s.key: s.count for s in yesterday}["done"] == 0
    assert {s.key: s.count for s in yesterday}["active"] == 5, "進行中は日に関係なく出す"


def test_band_places_marks_by_local_time(populated):
    conn, ids = populated
    band = queries.band(conn, NOW, Config(), date(2026, 9, 29))
    assert band["now_x"] == pytest.approx(62.29, abs=0.01) and band["now_label"] == "現在 14:57"
    by_id = {m["id"]: m for m in band["marks"]}
    running = by_id[ids["running"]]
    assert running["cls"] == "ring" and running["color"] == "var(--brand)" and running["title"].endswith("解析中")
    assert running["x"] == pytest.approx(61.88, abs=0.02)
    assert by_id[ids["done_today"]]["color"] == "var(--today)"
    group = by_id[ids["group"]]
    assert "wide" in group["cls"] and group["title"].endswith("連鎖 6 件")
    assert ids["icmp1"] not in by_id, "束の構成要素は帯に出さない"
    assert all(0 <= m["x"] <= 100 for m in band["marks"])
    earlier = queries.band(conn, NOW, Config(), date(2026, 9, 28))
    assert earlier["now_x"] is None and earlier["now_label"] == "2026-09-28"


def test_detail_of_a_done_incident(populated):
    conn, ids = populated
    d = queries.detail(conn, ids["done_today"], NOW, Config())
    assert d["label"] == "I-0001" and d["kind_label"] == "性能" and d["urgency_label"] == "今日中"
    assert d["analysed"].startswith("解析 14:22 完了 · 所要 1 分")
    assert d["causes"][0]["confidence_label"] == "中" and len(d["checks"]) == 2
    assert d["checks"][0]["verified"] is True and d["checks"][1]["verified"] is False
    assert d["needs_human_decision"] is True and d["unknowns"] == ["過去 24 時間の推移"]
    assert d["context"]["knowledge_version"] == "20260929-abcdef012345" and d["context"]["selected"][0]["heading"] == "監視VMの状態"
    assert [e["label"] for e in d["events"]][:2] == ["検知", "順番待ちに入った"]
    assert d["events"][-1]["label"] == "解析完了" and d["events"][-1]["note"] == "今日中"
    assert d["actions"] == ["reanalyze", "feedback", "case"]
    assert d["alerts"][0]["external_id"] == "48150"


def test_detail_of_waiting_running_failed_and_skipped(populated):
    conn, ids = populated
    waiting = queries.detail(conn, ids["queued_disk"], NOW, Config())
    assert waiting["position"]["ahead"] == 2 and waiting["actions"] == ["prioritize", "skip"]
    running = queries.detail(conn, ids["running"], NOW, Config())
    assert running["running"].phase == "inference" and running["running"].tokens == 312 and running["actions"] == []
    failed = queries.detail(conn, ids["failed"], NOW, Config())
    assert failed["why"] == "LLM の応答が制限時間を超えた" and failed["actions"] == ["reanalyze"]
    assert [a["status"] for a in failed["analyses"]] == ["failed"] * 4
    skipped = queries.detail(conn, ids["skipped_manual"], NOW, Config())
    assert skipped["actions"] == ["reanalyze"] and skipped["events"][-1]["note"] == "検証環境の作業"


def test_detail_of_a_group_and_its_member(populated):
    conn, ids = populated
    group = queries.detail(conn, ids["group"], NOW, Config())
    assert group["members"] == 6 and len(group["member_rows"]) == 6 and group["member_rows"][0]["host_short"] == "example-router01"
    member = queries.detail(conn, ids["icmp1"], NOW, Config())
    assert member["parent"]["id"] == ids["group"] and member["actions"] == []


def test_detail_carries_case_and_feedback(populated):
    conn, ids = populated
    with_case = queries.detail(conn, ids["done_wazuh"], NOW, Config())
    assert with_case["case"]["verdict"] == "correct" and with_case["confirmed_verdict"] == "correct"
    with_feedback = queries.detail(conn, ids["done_watch"], NOW, Config())
    assert with_feedback["feedback"]["verdict"] == "helpful" and with_feedback["case"] is None


def test_detail_of_an_unknown_incident_is_none(populated):
    conn, ids = populated
    assert queries.detail(conn, 999, NOW, Config()) is None


def test_change_marks_name_the_incidents_that_changed(populated):
    conn, ids = populated
    before = queries.mark(conn)
    assert not before.changed(queries.mark(conn))
    stamp = queries.to_iso(NOW + timedelta(seconds=5))
    conn.execute("UPDATE incidents SET read_at = ?, updated_at = ? WHERE id = ?", (stamp, stamp, ids["done_today"]))
    after = queries.mark(conn)
    assert after.changed(before) and queries.changed_incidents(conn, before) == {ids["done_today"]}


def test_queue_summary_counts_the_wait_from_the_moment_it_became_due(populated):
    conn, ids = populated
    summary = queries.queue_summary(conn, NOW, Config())
    assert summary["depth"] == 4 and summary["stalled"] is False and summary["running"]["incident_id"] == ids["running"]
    assert summary["oldest_waiting_sec"] == 60
    later = queries.queue_summary(conn, NOW + timedelta(seconds=700), Config())
    assert later["stalled"] is True


def test_feedback_ratio(populated):
    conn, ids = populated
    ratio = queries.feedback_ratio(conn, NOW - timedelta(days=1))
    assert ratio == {"helpful": 1, "wrong": 0, "corrected": 0, "total": 1, "helpful_percent": 100}
    assert queries.feedback_ratio(conn, NOW)["helpful_percent"] is None


def test_waiting_time_is_not_reset_by_a_recurrence_or_a_prioritise(populated):
    """I-3: 待ちの起点は順番待ちに入った出来事。再発や先に解析する指定で戻らない。"""
    conn, ids = populated
    cfg = Config()
    qid = ids["queued"]
    conn.execute("UPDATE events SET at = ? WHERE incident_id = ? AND type = 'queued'", (to_iso(NOW - timedelta(minutes=20)), qid))
    summary = queries.queue_summary(conn, NOW, cfg)
    assert summary["oldest_waiting_sec"] == 1200 and summary["stalled"] is True
    # 再発と同じ更新: 回数と updated_at が進む
    conn.execute("UPDATE incidents SET occurrence_count = occurrence_count + 1, updated_at = ? WHERE id = ?",
                 (to_iso(NOW - timedelta(seconds=30)), qid))
    assert queries.queue_summary(conn, NOW, cfg)["oldest_waiting_sec"] == 1200
    queue.prioritize(conn, qid, NOW - timedelta(seconds=10))
    assert queries.queue_summary(conn, NOW, cfg)["oldest_waiting_sec"] == 1200
    # 再試行待ちは、再試行の時刻が来てから数える
    conn.execute("UPDATE incidents SET analysis_state = 'done' WHERE id IN (?, ?)", (qid, ids["queued_disk"]))
    conn.execute("UPDATE incidents SET next_retry_at = ? WHERE id = ?", (to_iso(NOW - timedelta(seconds=90)), ids["retry_wait"]))
    assert queries.queue_summary(conn, NOW, cfg)["oldest_waiting_sec"] == 90


def test_detail_shows_the_analysis_the_incident_points_to_not_a_later_replay(populated):
    """I-5: 再生の結果は別の版として並び、表示は incidents.latest_analysis_id の解析のまま。"""
    conn, ids = populated
    iid = ids["done_today"]
    replay = records.begin(conn, iid, "replay", MODEL, NOW - timedelta(seconds=60))
    records.finish(conn, replay, NOW - timedelta(seconds=30), status="done",
                   result=_result(classification={"kind": "noise", "urgency": "ignore"}, summary="再生の要約",
                                  probable_causes=[{"cause": "再生で出た原因", "confidence": "low", "evidence": ""}]),
                   prompt_tokens=100, completion_tokens=50, tokens_per_sec=7.0)
    pointed = conn.execute("SELECT latest_analysis_id FROM incidents WHERE id = ?", (iid,)).fetchone()[0]
    d = queries.detail(conn, iid, NOW, Config())
    assert d["shown_analysis_id"] == pointed and d["latest"]["id"] == pointed and d["latest"]["trigger"] == "initial"
    assert d["urgency_label"] == "今日中" and d["causes"][0]["cause"] != "再生で出た原因"
    assert len(d["analyses"]) == 2 and [a["trigger"] for a in d["analyses"]] == ["initial", "replay"]


def test_failed_incidents_stay_listed_and_counted_without_a_time_limit(populated):
    """I-6: 失敗は人が動かすまで残る。帯の数と一覧は同じものを数える。"""
    conn, ids = populated
    conn.execute("UPDATE incidents SET updated_at = ? WHERE id = ?", (to_iso(NOW - timedelta(days=10)), ids["failed"]))
    today = NOW.astimezone(TZ).date()
    rows = [r for s in queries.sections(conn, NOW, Config(), today, state="fail") for r in s.rows]
    assert [r["id"] for r in rows] == [ids["failed"]]
    assert queries.rail(conn, NOW, Config(), today)["failed"] == 1
