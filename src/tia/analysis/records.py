"""解析の記録。1 回の解析ごとに `analyses` の 1 行。"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime

from tia import db
from tia.models import from_iso, to_iso

PHASES = ("context", "inference", "validation", "finished")
STATUSES = ("running", "done", "failed", "released")
TRIGGERS = ("initial", "retry", "followup", "manual", "replay")
ERROR_LIMIT = 300


class RecordError(ValueError):
    """解析の記録に対する、できない操作。"""


def begin(conn: sqlite3.Connection, incident_id: int, trigger: str, model: str, now: datetime, *,
          attempt: int = 1) -> int:
    """解析の行を作り、その id を返す。段階は文脈収集から始まる。"""
    if trigger not in TRIGGERS:
        raise RecordError(f"きっかけ {trigger!r} は {', '.join(TRIGGERS)} のどれか")
    with db.transaction(conn):
        cursor = conn.execute(
            "INSERT INTO analyses (incident_id, trigger, status, phase, attempt, started_at, model, updated_at) "
            "VALUES (?, ?, 'running', 'context', ?, ?, ?, ?)",
            (incident_id, trigger, attempt, to_iso(now), model, to_iso(now)))
        return int(cursor.lastrowid)


def progress(conn: sqlite3.Connection, analysis_id: int, phase: str, now: datetime, *,
             tokens_so_far: int | None = None) -> None:
    """段階と、受け取ったトークン数を更新する。画面の「解析中」の表示の元になる。"""
    if phase not in PHASES:
        raise RecordError(f"段階 {phase!r} は {', '.join(PHASES)} のどれか")
    with db.transaction(conn):
        row = _get(conn, analysis_id)
        if row["status"] != "running":
            raise RecordError(f"解析 {analysis_id} は {row['status']}。進捗を更新できるのは running のときだけ")
        tokens = row["tokens_so_far"] if tokens_so_far is None else max(0, int(tokens_so_far))
        conn.execute("UPDATE analyses SET phase = ?, tokens_so_far = ?, updated_at = ? WHERE id = ?",
                     (phase, tokens, to_iso(now), analysis_id))


def finish(conn: sqlite3.Connection, analysis_id: int, now: datetime, *, status: str, result: dict | None = None,
           error_kind: str | None = None, error: str | None = None, prompt_tokens: int | None = None,
           completion_tokens: int | None = None, tokens_per_sec: float | None = None, context: dict | None = None,
           prompt_hash: str | None = None, knowledge_version: str | None = None) -> None:
    """解析を終える。done には結果が要り、failed と released には理由が要る。"""
    if status not in ("done", "failed", "released"):
        raise RecordError(f"終わり方 {status!r} は done、failed、released のどれか")
    if status == "done" and result is None:
        raise RecordError("done には結果が要る")
    # failed でも、LLM の出力があれば残す。何が拒まれたかを後から確かめるため
    if status != "done" and not error_kind:
        raise RecordError(f"{status} には理由の種類が要る")
    with db.transaction(conn):
        row = _get(conn, analysis_id)
        if row["status"] != "running":
            raise RecordError(f"解析 {analysis_id} は {row['status']}。終えられるのは running のときだけ")
        started = from_iso(row["started_at"])
        duration_ms = max(0, int((now - started).total_seconds() * 1000))
        conn.execute(
            "UPDATE analyses SET status = ?, phase = 'finished', finished_at = ?, duration_ms = ?, result_json = ?, "
            "error_kind = ?, error = ?, prompt_tokens = COALESCE(?, prompt_tokens), "
            "completion_tokens = COALESCE(?, completion_tokens), tokens_per_sec = ?, "
            "context_json = COALESCE(?, context_json), prompt_hash = COALESCE(?, prompt_hash), "
            "knowledge_version = COALESCE(?, knowledge_version), updated_at = ? WHERE id = ?",
            (status, to_iso(now), duration_ms, json.dumps(result, ensure_ascii=False) if result is not None else None,
             error_kind, (error or None) and str(error)[:ERROR_LIMIT], prompt_tokens, completion_tokens,
             tokens_per_sec, json.dumps(context, ensure_ascii=False) if context is not None else None,
             prompt_hash, knowledge_version, to_iso(now), analysis_id))


def attach_context(conn: sqlite3.Connection, analysis_id: int, now: datetime, *, context: dict, prompt_hash: str,
                   knowledge_version: str, prompt_tokens: int | None) -> None:
    """文脈ができた時点で保存する。推論の途中で止まっても、何を渡したかが残る。"""
    with db.transaction(conn):
        _get(conn, analysis_id)
        conn.execute("UPDATE analyses SET context_json = ?, prompt_hash = ?, knowledge_version = ?, "
                     "prompt_tokens = ?, phase = 'inference', updated_at = ? WHERE id = ?",
                     (json.dumps(context, ensure_ascii=False), prompt_hash, knowledge_version, prompt_tokens,
                      to_iso(now), analysis_id))


def _get(conn: sqlite3.Connection, analysis_id: int) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM analyses WHERE id = ?", (analysis_id,)).fetchone()
    if row is None:
        raise RecordError(f"解析 {analysis_id} がない")
    return row


def get(conn: sqlite3.Connection, analysis_id: int) -> sqlite3.Row:
    return _get(conn, analysis_id)


def for_incident(conn: sqlite3.Connection, incident_id: int) -> list[sqlite3.Row]:
    """インシデントの解析を古い順に。"""
    return conn.execute("SELECT * FROM analyses WHERE incident_id = ? ORDER BY id", (incident_id,)).fetchall()


def latest_done(conn: sqlite3.Connection, incident_id: int) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM analyses WHERE incident_id = ? AND status = 'done' ORDER BY id DESC LIMIT 1",
                        (incident_id,)).fetchone()


def result_of(row: sqlite3.Row) -> dict | None:
    """保存した結果を読む。壊れていれば None。"""
    try:
        data = json.loads(row["result_json"]) if row["result_json"] else None
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def failed_output(row: sqlite3.Row) -> dict | str | None:
    """失敗した解析に残した LLM の出力。JSON として読めたものは対応表、読めなかったものは文のまま。"""
    data = result_of(row)
    if data is None:
        return None
    if "failed_output" in data:
        return data["failed_output"]
    return data


def abandon_running(conn: sqlite3.Connection, now: datetime) -> int:
    """起動時に呼ぶ。前回の停止で running のまま残った解析の行を released で閉じ、閉じた数を返す。"""
    with db.transaction(conn):
        rows = conn.execute("SELECT id FROM analyses WHERE status = 'running'").fetchall()
        for row in rows:
            finish(conn, row["id"], now, status="released", error_kind="restart", error="司令塔の再起動で中断した")
        return len(rows)
