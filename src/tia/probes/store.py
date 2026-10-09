"""確認の結果の保存。`probes` 表（移行 4）。インシデントが消えるときに一緒に消える。"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta

from tia.models import from_iso, to_iso

STATUSES = ("ok", "timeout", "unreachable", "refused", "failed", "skipped")
TRIGGERS = ("initial", "operator", "replay")
COLUMNS = ("id, incident_id, analysis_id, name, target, command, trigger, started_at, duration_ms, status, output, "
           "error")


def insert(conn: sqlite3.Connection, incident_id: int, analysis_id: int | None, name: str, target: str, trigger: str,
           started_at: datetime, duration_ms: int, status: str, output: str, error: str | None, *,
           command: str | None = None) -> int:
    if status not in STATUSES:
        raise ValueError(f"確認の結果の状態 {status!r} は {'、'.join(STATUSES)} のどれか")
    if trigger not in TRIGGERS:
        raise ValueError(f"確認のきっかけ {trigger!r} は {'、'.join(TRIGGERS)} のどれか")
    cursor = conn.execute(
        "INSERT INTO probes (incident_id, analysis_id, name, target, command, trigger, started_at, duration_ms, status, "
        "output, error) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (incident_id, analysis_id, name, target, command, trigger, to_iso(started_at), int(duration_ms), status, output,
         error))
    return int(cursor.lastrowid)


def for_incident(conn: sqlite3.Connection, incident_id: int) -> list[sqlite3.Row]:
    return conn.execute(f"SELECT {COLUMNS} FROM probes WHERE incident_id = ? ORDER BY id", (incident_id,)).fetchall()


def for_analysis(conn: sqlite3.Connection, analysis_id: int) -> list[sqlite3.Row]:
    return conn.execute(f"SELECT {COLUMNS} FROM probes WHERE analysis_id = ? ORDER BY id", (analysis_id,)).fetchall()


def latest(conn: sqlite3.Connection, incident_id: int, limit: int) -> list[sqlite3.Row]:
    """新しい順に limit 件。再解析に添える結果を選ぶのに使う。"""
    return conn.execute(f"SELECT {COLUMNS} FROM probes WHERE incident_id = ? ORDER BY id DESC LIMIT ?",
                        (incident_id, limit)).fetchall()


def unattached(conn: sqlite3.Connection, incident_id: int) -> list[sqlite3.Row]:
    """運用者が画面から取り、まだどの解析にも添えていない結果。次の解析が拾う。"""
    return conn.execute(f"SELECT {COLUMNS} FROM probes WHERE incident_id = ? AND analysis_id IS NULL "
                        "AND trigger = 'operator' ORDER BY id", (incident_id,)).fetchall()


def attach(conn: sqlite3.Connection, ids: list[int], analysis_id: int) -> None:
    if ids:
        marks = ",".join("?" * len(ids))
        conn.execute(f"UPDATE probes SET analysis_id = ? WHERE id IN ({marks})", (analysis_id, *ids))


def recent_operator_run(conn: sqlite3.Connection, incident_id: int, name: str, now: datetime, within_sec: int) -> int | None:
    """運用者が同じ確認を within_sec 秒以内に実行していれば、その経過秒数。なければ None。"""
    row = conn.execute("SELECT started_at FROM probes WHERE incident_id = ? AND name = ? AND trigger = 'operator' "
                       "ORDER BY id DESC LIMIT 1", (incident_id, name)).fetchone()
    if row is None:
        return None
    age = now - from_iso(row["started_at"])
    if age < timedelta(0):
        return 0
    return int(age.total_seconds()) if age.total_seconds() < within_sec else None
