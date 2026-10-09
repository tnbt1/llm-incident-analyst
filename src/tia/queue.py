"""待ち行列と解析の状態遷移。"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta

from tia import db
from tia.config import Config
from tia.intake import add_event
from tia.models import AnalysisState, ProblemStatus, to_iso


class StateError(RuntimeError):
    """その状態からは行えない操作。"""


def _get(conn: sqlite3.Connection, incident_id: int) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    if row is None:
        raise StateError(f"インシデント {incident_id} がない")
    return row


def _expect(row: sqlite3.Row, *states: AnalysisState) -> None:
    if row["analysis_state"] not in states:
        raise StateError(f"インシデント {row['id']} は {row['analysis_state']}。"
                         f"この操作は {', '.join(states)} のときだけ行える")


def promote_held(conn: sqlite3.Connection, now: datetime) -> int:
    """束ね判定の待ちが明けたものを順番待ちに移し、移した数を返す。"""
    with db.transaction(conn):
        rows = conn.execute("SELECT id FROM incidents WHERE analysis_state = ? AND held_until <= ?",
                            (AnalysisState.HELD, to_iso(now))).fetchall()
        for row in rows:
            conn.execute("UPDATE incidents SET analysis_state = ?, held_until = NULL, updated_at = ? WHERE id = ?",
                         (AnalysisState.QUEUED, to_iso(now), row["id"]))
            add_event(conn, row["id"], now, "queued")
        return len(rows)


def next_candidate(conn: sqlite3.Connection, now: datetime, cfg: Config) -> sqlite3.Row | None:
    """次に解析する 1 件を返す。復旧から時間がたちすぎたものは対象外にして飛ばす。

    人が選んだもの（再解析、優先）は飛ばさない。
    """
    limit = to_iso(now - timedelta(seconds=cfg.intake_skip_resolved_after_sec))
    with db.transaction(conn):
        stale = conn.execute(
            "SELECT id FROM incidents WHERE analysis_state IN (?, ?) AND problem_status = ? AND resolved_at < ? "
            "AND queue_reason != 'manual' AND priority = 0",
            (AnalysisState.QUEUED, AnalysisState.RETRY_WAIT, ProblemStatus.RESOLVED, limit)).fetchall()
        for row in stale:
            conn.execute("UPDATE incidents SET analysis_state = ?, skip_reason = ?, next_retry_at = NULL, "
                         "updated_at = ? WHERE id = ?",
                         (AnalysisState.SKIPPED, "resolved_too_long", to_iso(now), row["id"]))
            add_event(conn, row["id"], now, "skipped", {"reason": "resolved_too_long"})
    return conn.execute(
        "SELECT * FROM incidents WHERE analysis_state = ? OR (analysis_state = ? AND next_retry_at <= ?) "
        "ORDER BY priority DESC, severity DESC, started_at ASC, id ASC LIMIT 1",
        (AnalysisState.QUEUED, AnalysisState.RETRY_WAIT, to_iso(now))).fetchone()


def start(conn: sqlite3.Connection, incident_id: int, now: datetime) -> None:
    with db.transaction(conn):
        row = _get(conn, incident_id)
        _expect(row, AnalysisState.QUEUED, AnalysisState.RETRY_WAIT)
        running = conn.execute("SELECT id FROM incidents WHERE analysis_state = ?",
                               (AnalysisState.RUNNING,)).fetchone()
        if running:
            raise StateError(f"インシデント {running['id']} を解析中。同時に解析するのは 1 件")
        try:
            conn.execute("UPDATE incidents SET analysis_state = ?, attempt_count = attempt_count + 1, "
                         "next_retry_at = NULL, updated_at = ? WHERE id = ?",
                         (AnalysisState.RUNNING, to_iso(now), incident_id))
        except sqlite3.IntegrityError as exc:
            # 別の接続が先に解析を始めた。索引が 2 件目を拒否する。
            raise StateError("別のインシデントを解析中。同時に解析するのは 1 件") from exc
        add_event(conn, incident_id, now, "analysis_started", {"attempt": row["attempt_count"] + 1})


def complete(conn: sqlite3.Connection, incident_id: int, now: datetime, *, urgency: str, kind: str,
             summary: str, analysis_id: int | None = None) -> None:
    with db.transaction(conn):
        _expect(_get(conn, incident_id), AnalysisState.RUNNING)
        conn.execute("UPDATE incidents SET analysis_state = ?, urgency = ?, kind = ?, summary = ?, "
                     "latest_analysis_id = ?, fail_reason = NULL, priority = 0, read_at = NULL, analyzed_at = ?, "
                     "updated_at = ? WHERE id = ?",
                     (AnalysisState.DONE, urgency, kind, summary, analysis_id, to_iso(now), to_iso(now),
                      incident_id))
        add_event(conn, incident_id, now, "analysis_done", {"urgency": urgency})


def fail(conn: sqlite3.Connection, incident_id: int, now: datetime, reason: str, cfg: Config, *,
         retry: bool = True) -> AnalysisState:
    """失敗を記録する。再試行の回数が残っていれば待ちに戻し、なければ失敗にする。

    retry が偽なら、回数が残っていても失敗にする。同じ入力でやり直しても直らない失敗（出力の検証、上限到達）に使う。
    理由は「種類: 説明」の形で、出来事には種類も残す。
    """
    kind = reason.split(":", 1)[0].strip() if ":" in reason else ""
    with db.transaction(conn):
        row = _get(conn, incident_id)
        _expect(row, AnalysisState.RUNNING)
        retries_used = row["attempt_count"] - 1
        if retry and retries_used < len(cfg.queue_retry_delays_sec):
            retry_at = now + timedelta(seconds=cfg.queue_retry_delays_sec[retries_used])
            conn.execute("UPDATE incidents SET analysis_state = ?, next_retry_at = ?, fail_reason = ?, "
                         "updated_at = ? WHERE id = ?",
                         (AnalysisState.RETRY_WAIT, to_iso(retry_at), reason, to_iso(now), incident_id))
            add_event(conn, incident_id, now, "retry_scheduled", {"reason": reason, "at": to_iso(retry_at)})
            return AnalysisState.RETRY_WAIT
        conn.execute("UPDATE incidents SET analysis_state = ?, fail_reason = ?, updated_at = ? WHERE id = ?",
                     (AnalysisState.FAILED, reason, to_iso(now), incident_id))
        add_event(conn, incident_id, now, "analysis_failed", {"reason": reason, "kind": kind, "retried": retry})
        return AnalysisState.FAILED


def release(conn: sqlite3.Connection, incident_id: int, now: datetime, reason: str) -> None:
    """解析中の 1 件を、試行を数えずに順番待ちへ戻す。

    LLM に届かない、司令塔が止まった、という中断は解析の失敗ではない。再試行の回数を使わない。
    """
    with db.transaction(conn):
        _expect(_get(conn, incident_id), AnalysisState.RUNNING)
        conn.execute("UPDATE incidents SET analysis_state = ?, attempt_count = MAX(attempt_count - 1, 0), "
                     "next_retry_at = NULL, updated_at = ? WHERE id = ?",
                     (AnalysisState.QUEUED, to_iso(now), incident_id))
        add_event(conn, incident_id, now, "released", {"reason": reason})


def recover_running(conn: sqlite3.Connection, now: datetime) -> int:
    """起動時に呼ぶ。前回の停止で解析中のまま残ったものを順番待ちへ戻し、戻した数を返す。"""
    with db.transaction(conn):
        rows = conn.execute("SELECT id FROM incidents WHERE analysis_state = ?",
                            (AnalysisState.RUNNING,)).fetchall()
        for row in rows:
            release(conn, row["id"], now, "restart")
        return len(rows)


def schedule_followups(conn: sqlite3.Connection, now: datetime, cfg: Config) -> int:
    """解析してから時間がたっても未解決のものを、追跡解析として 1 回だけ待ちに戻す。"""
    limit = to_iso(now - timedelta(seconds=cfg.intake_followup_after_sec))
    with db.transaction(conn):
        rows = conn.execute(
            "SELECT id FROM incidents WHERE analysis_state = ? AND problem_status = ? AND followup_done = 0 "
            "AND analyzed_at <= ?", (AnalysisState.DONE, ProblemStatus.OPEN, limit)).fetchall()
        for row in rows:
            conn.execute("UPDATE incidents SET analysis_state = ?, followup_done = 1, attempt_count = 0, "
                         "queue_reason = 'followup', updated_at = ? WHERE id = ?",
                         (AnalysisState.QUEUED, to_iso(now), row["id"]))
            add_event(conn, row["id"], now, "followup_queued", {"reason": "still_open"})
        return len(rows)


def prioritize(conn: sqlite3.Connection, incident_id: int, now: datetime) -> None:
    """待ちの 1 件を先頭へ移す。束ね判定の待ちも打ち切る。"""
    with db.transaction(conn):
        _expect(_get(conn, incident_id), AnalysisState.HELD, AnalysisState.QUEUED, AnalysisState.RETRY_WAIT)
        conn.execute("UPDATE incidents SET analysis_state = ?, priority = 1, held_until = NULL, "
                     "next_retry_at = NULL, updated_at = ? WHERE id = ?",
                     (AnalysisState.QUEUED, to_iso(now), incident_id))
        add_event(conn, incident_id, now, "prioritized")


def skip_manually(conn: sqlite3.Connection, incident_id: int, now: datetime, reason: str) -> None:
    with db.transaction(conn):
        _expect(_get(conn, incident_id), AnalysisState.HELD, AnalysisState.QUEUED, AnalysisState.RETRY_WAIT)
        conn.execute("UPDATE incidents SET analysis_state = ?, skip_reason = ?, held_until = NULL, "
                     "next_retry_at = NULL, updated_at = ? WHERE id = ?",
                     (AnalysisState.SKIPPED, f"manual: {reason}", to_iso(now), incident_id))
        add_event(conn, incident_id, now, "skipped", {"reason": "manual", "note": reason})


def requeue(conn: sqlite3.Connection, incident_id: int, now: datetime) -> None:
    """解析済み、失敗、対象外を、もう一度解析の待ちに入れる。復旧から時間がたっていても解析する。"""
    with db.transaction(conn):
        _expect(_get(conn, incident_id), AnalysisState.DONE, AnalysisState.FAILED, AnalysisState.SKIPPED)
        conn.execute("UPDATE incidents SET analysis_state = ?, attempt_count = 0, skip_reason = NULL, "
                     "fail_reason = NULL, next_retry_at = NULL, queue_reason = 'manual', updated_at = ? "
                     "WHERE id = ?",
                     (AnalysisState.QUEUED, to_iso(now), incident_id))
        add_event(conn, incident_id, now, "requeued")
