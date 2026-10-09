"""連鎖の束ね。同時多発と、経路の要のホストの停止を 1 件の群にまとめる。"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta

from tia import db
from tia.config import Config
from tia.intake import add_event
from tia.models import AnalysisState, IncidentType, ProblemStatus, Source, from_iso, to_iso

WAITING = (AnalysisState.HELD, AnalysisState.QUEUED)
# 構成員から決め直す群の項目。
DERIVED = ("occurrence_count", "severity", "started_at", "last_occurrence_at", "problem_status", "resolved_at",
           "title", "raw_json")


def evaluate(conn: sqlite3.Connection, now: datetime, cfg: Config) -> int | None:
    """群を構成員の今の状態に合わせ直し、束ねる対象があれば群を作るか既存の群に足す。

    束ねるかどうかは発生時刻で決める。届いた時刻では決めない。収集が止まった後にまとめて届いた
    古い問題を、同時多発と取り違えないため。作るか足した群の id を返す。なければ None。
    """
    window = timedelta(seconds=cfg.grouping_storm_window_sec)
    with db.transaction(conn):
        _refresh(conn, now, cfg)
        # 優先にしたインシデントは単独で解析する。束ねない。
        candidates = conn.execute(
            "SELECT id, started_at FROM incidents WHERE source != ? AND group_id IS NULL "
            "AND analysis_state IN (?, ?) AND priority = 0 ORDER BY started_at, id",
            (Source.GROUP, *WAITING)).fetchall()
        if not candidates:
            return None
        group_id = _join_waiting_group(conn, candidates, window, now)
        if group_id is None and not _has_waiting_group(conn):
            group_id = _create_from_storm(conn, candidates, window, now, cfg)
            if group_id is None:
                group_id = _create_from_root(conn, candidates, window, now, cfg)
        if group_id is not None:
            _refresh(conn, now, cfg, group_id)
        return group_id


def _has_waiting_group(conn: sqlite3.Connection) -> bool:
    return conn.execute("SELECT 1 FROM incidents WHERE source = ? AND analysis_state IN (?, ?) LIMIT 1",
                        (Source.GROUP, *WAITING)).fetchone() is not None


def _within(rows: list[sqlite3.Row], first: str, last: str, window: timedelta) -> list[sqlite3.Row]:
    """発生時刻が、first から last の範囲の前後 window 以内にあるもの。"""
    low, high = to_iso(from_iso(first) - window), to_iso(from_iso(last) + window)
    return [r for r in rows if low <= r["started_at"] <= high]


def _join_waiting_group(conn: sqlite3.Connection, candidates: list[sqlite3.Row], window: timedelta,
                        now: datetime) -> int | None:
    """解析を待っている群に、近い時刻に起きたものを足す。解析が始まった群には足さない。"""
    groups = conn.execute("SELECT id FROM incidents WHERE source = ? AND analysis_state IN (?, ?) "
                          "ORDER BY id DESC", (Source.GROUP, *WAITING)).fetchall()
    for group in groups:
        span = conn.execute("SELECT MIN(started_at) AS first, MAX(started_at) AS last FROM incidents "
                            "WHERE group_id = ?", (group["id"],)).fetchone()
        if span["first"] is None:
            continue
        members = _within(candidates, span["first"], span["last"], window)
        if members:
            _attach(conn, group["id"], members, now)
            return group["id"]
    return None


def _create_from_storm(conn: sqlite3.Connection, candidates: list[sqlite3.Row], window: timedelta,
                       now: datetime, cfg: Config) -> int | None:
    """1 つの時間幅に収まる最大の組を探し、件数が閾値以上なら群にする。"""
    times = [from_iso(c["started_at"]) for c in candidates]
    size, first, end = 0, 0, 0
    for start in range(len(times)):
        while end < len(times) and times[end] - times[start] <= window:
            end += 1
        if end - start > size:
            size, first = end - start, start
    if size < cfg.grouping_storm_count:
        return None
    members = candidates[first:first + size]
    roots = _within(_open_roots(conn, cfg), members[0]["started_at"], members[-1]["started_at"], window)
    return _create(conn, members, bool(roots), now, cfg)


def _create_from_root(conn: sqlite3.Connection, candidates: list[sqlite3.Row], window: timedelta,
                      now: datetime, cfg: Config) -> int | None:
    """経路の要のホストが止まっていれば、その前後に起きたものを 2 件から群にする。"""
    for root in _open_roots(conn, cfg):
        members = _within(candidates, root["started_at"], root["started_at"], window)
        if len(members) >= 2:
            return _create(conn, members, True, now, cfg)
    return None


def _open_roots(conn: sqlite3.Connection, cfg: Config) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT id, started_at FROM incidents WHERE source != ? AND host = ? AND availability = 1 "
        "AND problem_status = ? ORDER BY started_at DESC, id DESC",
        (Source.GROUP, cfg.grouping_root_host, ProblemStatus.OPEN)).fetchall()


def _title(count: int, root_down: bool, cfg: Config) -> str:
    if root_down:
        return f"{cfg.grouping_root_host} の停止に伴う連鎖（{count} 件）"
    return f"同時多発（{count} 件）"


def _create(conn: sqlite3.Connection, members: list[sqlite3.Row], root_down: bool, now: datetime,
            cfg: Config) -> int:
    """群を作って構成員を足す。件数、重大度、時刻、問題の状態は `_refresh` が構成員から決める。"""
    name = f"group-{min(m['id'] for m in members)}"
    started = members[0]["started_at"]
    held_until = to_iso(now + timedelta(seconds=cfg.zabbix_hold_sec))
    cursor = conn.execute(
        "INSERT INTO incidents (source, external_id, fingerprint, host, type, source_severity, severity, title, "
        "started_at, problem_status, last_occurrence_at, analysis_state, held_until, raw_json, created_at, "
        "updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (Source.GROUP, name, name, cfg.grouping_root_host if root_down else "複数", IncidentType.OTHER, "連鎖", 1,
         _title(len(members), root_down, cfg), started, ProblemStatus.OPEN, started, AnalysisState.HELD,
         held_until, json.dumps({"members": [], "root_down": root_down}), to_iso(now), to_iso(now)))
    group_id = int(cursor.lastrowid)
    add_event(conn, group_id, now, "group_created", {"root_down": root_down})
    _attach(conn, group_id, members, now)
    return group_id


def _attach(conn: sqlite3.Connection, group_id: int, members: list[sqlite3.Row], now: datetime) -> None:
    for member in members:
        conn.execute("UPDATE incidents SET analysis_state = ?, group_id = ?, held_until = NULL, updated_at = ? "
                     "WHERE id = ?", (AnalysisState.GROUPED, group_id, to_iso(now), member["id"]))
        add_event(conn, member["id"], now, "grouped", {"group_id": group_id})


def _refresh(conn: sqlite3.Connection, now: datetime, cfg: Config, group_id: int | None = None) -> None:
    """群の件数、重大度、時刻、問題の状態を、構成員から決め直す。group_id が None なら全部の群。

    構成員は束ねた後も復旧し、再発し、重大度が上がる。群に写さないと、復旧した群に追跡解析が走る。
    """
    only = "group_id = ?" if group_id is not None else "group_id IS NOT NULL"
    summaries = conn.execute(
        "SELECT group_id, COUNT(*) AS members, MAX(severity) AS severity, MIN(started_at) AS started_at, "
        "MAX(last_occurrence_at) AS last_occurrence_at, SUM(problem_status = ?) AS open_members, "
        "SUM(problem_status = ?) AS oneshot_members, MAX(resolved_at) AS resolved_at, GROUP_CONCAT(id) AS ids "
        f"FROM incidents WHERE {only} GROUP BY group_id",
        (ProblemStatus.OPEN, ProblemStatus.ONESHOT, *((group_id,) if group_id is not None else ()))).fetchall()
    for summary in summaries:
        _refresh_one(conn, summary, now, cfg)


def _refresh_one(conn: sqlite3.Connection, summary: sqlite3.Row, now: datetime, cfg: Config) -> None:
    group = conn.execute(f"SELECT id, analysis_state, {', '.join(DERIVED)} FROM incidents WHERE id = ?",
                         (summary["group_id"],)).fetchone()
    if summary["open_members"]:
        status, resolved_at = ProblemStatus.OPEN, None
    elif summary["oneshot_members"] == summary["members"]:
        status, resolved_at = ProblemStatus.ONESHOT, None
    else:
        status, resolved_at = ProblemStatus.RESOLVED, summary["resolved_at"] or to_iso(now)
    root_down = bool(json.loads(group["raw_json"]).get("root_down"))
    # 題名の件数を書き換えるのは解析を待つ間だけ。解析した後の題名は、解析した時点の記録。
    title = _title(summary["members"], root_down, cfg) if group["analysis_state"] in WAITING else group["title"]
    members = sorted(int(i) for i in summary["ids"].split(","))
    values = (summary["members"], summary["severity"], summary["started_at"], summary["last_occurrence_at"],
              str(status), resolved_at, title, json.dumps({"members": members, "root_down": root_down}))
    if values == tuple(group[column] for column in DERIVED):
        return
    conn.execute(f"UPDATE incidents SET {', '.join(f'{column} = ?' for column in DERIVED)}, updated_at = ? "
                 "WHERE id = ?", (*values, to_iso(now), group["id"]))
    if status == group["problem_status"]:
        return
    if status == ProblemStatus.RESOLVED:
        add_event(conn, group["id"], now, "resolved", {"resolved_at": resolved_at})
    elif status == ProblemStatus.OPEN:
        add_event(conn, group["id"], now, "reopened")
