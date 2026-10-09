"""保持期間の整理。消すもの、残すもの、本文を落とすもの。"""
from contextlib import closing
from datetime import timedelta

import pytest
from web_helpers import NOW, make_db

from tia import db
from tia.analysis import records
from tia.config import Config
from tia.models import to_iso
from tia.ops import retention


def age(conn, incident_id, days, *, resolved=True):
    """インシデントを days 日前のものにする。resolved なら復旧済み、そうでなければ発生中にする。"""
    then = to_iso(NOW - timedelta(days=days))
    status = "resolved" if resolved else "open"
    conn.execute("UPDATE incidents SET started_at = ?, last_occurrence_at = ?, updated_at = ?, "
                 "resolved_at = CASE WHEN ? = 'resolved' THEN ? ELSE NULL END, problem_status = ? WHERE id = ?",
                 (then, then, then, status, then, status, incident_id))
    conn.execute("UPDATE events SET at = ? WHERE incident_id = ?", (then, incident_id))
    conn.execute("UPDATE analyses SET started_at = ?, updated_at = ? WHERE incident_id = ?", (then, then, incident_id))


def counts(conn):
    return {table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("incidents", "events", "alert_refs", "analyses", "cases")}


def members_of(ids):
    return [ids[key] for key in ("icmp", "icmp1", "icmp2", "icmp3", "icmp4", "icmp5")]


@pytest.fixture
def populated(tmp_path):
    path = tmp_path / "tia.sqlite"
    ids = make_db(path)
    with closing(db.connect(path)) as conn:
        yield conn, ids


def test_old_finished_incident_is_deleted_with_its_rows(populated):
    conn, ids = populated
    done = ids["done_watch"]
    age(conn, done, 200)
    before = counts(conn)
    conn.execute("INSERT INTO probes (incident_id, name, target, trigger, started_at, duration_ms, status, output) "
                 "VALUES (?, 'disk', 'h', 'initial', '2026-01-01T00:00:00+00:00', 1, 'ok', '')", (done,))
    report = retention.apply(conn, NOW, Config())
    assert report.incidents_deleted == 1 and report.analyses_deleted >= 1 and report.events_deleted >= 1
    assert conn.execute("SELECT COUNT(*) FROM incidents WHERE id = ?", (done,)).fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM probes WHERE incident_id = ?", (done,)).fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM events WHERE incident_id = ?", (done,)).fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM alert_refs WHERE incident_id = ?", (done,)).fetchone()[0] == 0
    assert counts(conn)["incidents"] == before["incidents"] - 1
    assert report.checkpointed


def test_recent_finished_incident_is_kept(populated):
    conn, ids = populated
    age(conn, ids["done_watch"], 179)
    assert retention.apply(conn, NOW, Config()).incidents_deleted == 0


def test_open_queued_and_running_incidents_are_never_deleted(populated):
    conn, ids = populated
    for key in ("queued", "running", "held", "retry_wait"):
        age(conn, key and ids[key], 400, resolved=False)
    age(conn, ids["done_today"], 400, resolved=False)
    report = retention.apply(conn, NOW, Config())
    assert report.incidents_deleted == 0
    assert conn.execute("SELECT COUNT(*) FROM incidents WHERE id IN (?, ?, ?, ?, ?)",
                        (ids["queued"], ids["running"], ids["held"], ids["retry_wait"],
                         ids["done_today"])).fetchone()[0] == 5


def test_resolved_but_still_queued_incident_is_kept(populated):
    conn, ids = populated
    age(conn, ids["queued"], 400)
    assert retention.apply(conn, NOW, Config()).incidents_deleted == 0


def test_incident_with_a_case_is_kept_and_counted(populated):
    conn, ids = populated
    age(conn, ids["done_wazuh"], 400)
    report = retention.apply(conn, NOW, Config())
    assert report.incidents_deleted == 0 and report.kept_for_cases == 1
    assert counts(conn)["cases"] == 1


def test_skipped_incident_is_deleted_after_its_own_shorter_period(populated):
    conn, ids = populated
    age(conn, ids["skipped_manual"], 15)
    age(conn, ids["skipped_low"], 13)
    report = retention.apply(conn, NOW, Config())
    assert report.incidents_deleted == 1
    assert conn.execute("SELECT COUNT(*) FROM incidents WHERE id = ?", (ids["skipped_manual"],)).fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM incidents WHERE id = ?", (ids["skipped_low"],)).fetchone()[0] == 1


def test_group_is_deleted_only_with_all_its_members(populated):
    conn, ids = populated
    group, members = ids["group"], members_of(ids)
    assert conn.execute("SELECT COUNT(*) FROM incidents WHERE group_id = ?", (group,)).fetchone()[0] == len(members)
    age(conn, group, 200)
    for member in members[:-1]:
        age(conn, member, 200)
    # 1 つの構成要素が新しい間は、群も構成要素も残る
    assert retention.apply(conn, NOW, Config()).incidents_deleted == 0
    age(conn, members[-1], 200)
    report = retention.apply(conn, NOW, Config())
    assert report.incidents_deleted == 1 + len(members)
    assert conn.execute("SELECT COUNT(*) FROM incidents WHERE id = ? OR group_id = ?", (group, group)).fetchone()[0] == 0


def test_payload_is_cleared_only_for_finished_incidents_and_never_for_groups(populated):
    conn, ids = populated
    age(conn, ids["done_watch"], 100)
    age(conn, ids["group"], 100)
    age(conn, ids["done_today"], 100, resolved=False)
    report = retention.apply(conn, NOW, Config())
    assert report.incidents_deleted == 0
    assert report.payloads_cleared == 1 and report.contexts_cleared >= 1
    raw = {row["id"]: row["raw_json"] for row in conn.execute("SELECT id, raw_json FROM incidents")}
    assert raw[ids["done_watch"]] == "{}"
    assert raw[ids["group"]] != "{}" and raw[ids["done_today"]] != "{}"
    assert conn.execute("SELECT context_json FROM analyses WHERE incident_id = ?",
                        (ids["done_watch"],)).fetchone()[0] is None
    assert records.latest_done(conn, ids["done_watch"]) is not None  # 結果は残る


def test_payload_of_an_incident_that_still_waits_for_analysis_is_kept(populated):
    """復旧して古くなっても、まだ解析していない（待ち）ものの本文は落とさない（I-5）。"""
    conn, ids = populated
    age(conn, ids["queued"], 100)
    age(conn, ids["queued_disk"], 100)
    report = retention.apply(conn, NOW, Config())
    assert report.incidents_deleted == 0 and report.payloads_cleared == 0
    raw = {row["id"]: (row["raw_json"], row["analysis_state"])
           for row in conn.execute("SELECT id, raw_json, analysis_state FROM incidents")}
    assert raw[ids["queued"]][1] == "queued" and raw[ids["queued"]][0] != "{}"
    assert raw[ids["queued_disk"]][0] != "{}"


def test_dry_run_changes_nothing(populated):
    conn, ids = populated
    age(conn, ids["done_watch"], 200)
    before = counts(conn)
    report = retention.apply(conn, NOW, Config(), dry_run=True)
    assert report.incidents_deleted == 1 and not report.checkpointed
    assert counts(conn) == before
    assert not conn.in_transaction


def test_apply_refuses_to_run_inside_another_transaction(populated):
    conn, _ = populated
    conn.execute("BEGIN")
    try:
        with pytest.raises(RuntimeError, match="まとまり"):
            retention.apply(conn, NOW, Config())
    finally:
        conn.execute("ROLLBACK")


def test_summary_names_every_count(populated):
    conn, ids = populated
    age(conn, ids["done_watch"], 200)
    text = retention.apply(conn, NOW, Config()).summary()
    assert "インシデント 1 件" in text and "事例" in text and "文脈" in text
