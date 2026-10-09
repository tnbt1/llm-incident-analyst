"""正規化したアラートを保存する。重複、再発、閾値、復旧をここで扱う。"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta

from tia import db
from tia.config import Config
from tia.models import AnalysisState, NormalizedAlert, ProblemStatus, Source, from_iso, to_iso


@dataclass(frozen=True)
class IntakeResult:
    incident_id: int
    outcome: str  # created / skipped / recurred / duplicate


def add_event(conn: sqlite3.Connection, incident_id: int, at: datetime, kind: str,
              detail: dict | None = None) -> None:
    conn.execute("INSERT INTO events (incident_id, at, type, detail_json) VALUES (?, ?, ?, ?)",
                 (incident_id, to_iso(at), kind, json.dumps(detail or {}, ensure_ascii=False)))


def _recovery(alert: NormalizedAlert, now: datetime) -> str | None:
    """アラートの復旧時刻。復旧済みなのに時刻がなければ、知った時刻を使う。"""
    if alert.problem_status != ProblemStatus.RESOLVED:
        return None
    return to_iso(alert.resolved_at or now)


def _remember(conn: sqlite3.Connection, alert: NormalizedAlert, incident_id: int, now: datetime) -> None:
    conn.execute("INSERT INTO alert_refs (source, external_id, incident_id, seen_at, resolved_at) "
                 "VALUES (?, ?, ?, ?, ?)",
                 (alert.source, alert.external_id, incident_id, to_iso(now), _recovery(alert, now)))


def _mark_ref_resolved(conn: sqlite3.Connection, source: Source, external_id: str, resolved_at: str) -> bool:
    return bool(conn.execute(
        "UPDATE alert_refs SET resolved_at = ? WHERE source = ? AND external_id = ? AND resolved_at IS NULL",
        (resolved_at, source, external_id)).rowcount)


def _sync_status(conn: sqlite3.Connection, incident_id: int, now: datetime) -> None:
    """問題の状態を、まとめたアラートの復旧から決め直す。全部が復旧して初めて復旧とする。"""
    incident = conn.execute("SELECT problem_status, resolved_at FROM incidents WHERE id = ?",
                            (incident_id,)).fetchone()
    if incident["problem_status"] == ProblemStatus.ONESHOT:
        return
    refs = conn.execute("SELECT COUNT(*) AS total, COUNT(resolved_at) AS resolved, MAX(resolved_at) AS latest "
                        "FROM alert_refs WHERE incident_id = ?", (incident_id,)).fetchone()
    if refs["total"] and refs["total"] == refs["resolved"]:
        status, resolved_at = ProblemStatus.RESOLVED, refs["latest"]
    else:
        status, resolved_at = ProblemStatus.OPEN, None
    if (status, resolved_at) == (incident["problem_status"], incident["resolved_at"]):
        return
    conn.execute("UPDATE incidents SET problem_status = ?, resolved_at = ?, updated_at = ? WHERE id = ?",
                 (status, resolved_at, to_iso(now), incident_id))
    if status == incident["problem_status"]:
        return
    if status == ProblemStatus.RESOLVED:
        add_event(conn, incident_id, now, "resolved", {"resolved_at": resolved_at})
    else:
        add_event(conn, incident_id, now, "reopened")


def _find_previous(conn: sqlite3.Connection, alert: NormalizedAlert, cfg: Config) -> sqlite3.Row | None:
    """同じ発生源の直近のインシデントが、この発生を引き取るかを決める。

    比べるのは届いた時刻ではなく発生時刻。収集が止まった後にまとめて届いても、結果は変わらない。
    手動で見送ったインシデントも引き取る。見送ったものが新しい解析を生まないようにするため。
    """
    previous = conn.execute(
        "SELECT id, started_at, last_occurrence_at, resolved_at, problem_status, severity, analysis_state, "
        "followup_done FROM incidents WHERE source = ? AND fingerprint = ? "
        "AND (analysis_state != ? OR skip_reason LIKE 'manual:%') ORDER BY id DESC LIMIT 1",
        (alert.source, alert.fingerprint, AnalysisState.SKIPPED)).fetchone()
    if previous is None or previous["problem_status"] == ProblemStatus.OPEN:
        return previous
    window = timedelta(seconds=cfg.intake_recurrence_window_sec)
    last_seen = max(previous["last_occurrence_at"], previous["resolved_at"] or "")
    soon_after = to_iso(alert.started_at - window) <= last_seen
    not_far_before = alert.started_at >= from_iso(previous["started_at"]) - window
    return previous if soon_after and not_far_before else None


def apply(conn: sqlite3.Connection, alert: NormalizedAlert, now: datetime, cfg: Config) -> IntakeResult:
    """1 件を取り込む。同じアラートを何度渡しても結果は変わらない。"""
    with db.transaction(conn):
        seen = conn.execute("SELECT incident_id FROM alert_refs WHERE source = ? AND external_id = ?",
                            (alert.source, alert.external_id)).fetchone()
        if seen:
            recovery = _recovery(alert, now)
            if recovery and _mark_ref_resolved(conn, alert.source, alert.external_id, recovery):
                _sync_status(conn, seen["incident_id"], now)
            return IntakeResult(seen["incident_id"], "duplicate")
        if not alert.analyzable:
            incident_id = _insert(conn, alert, now, AnalysisState.SKIPPED, None, "below_threshold")
            _remember(conn, alert, incident_id, now)
            add_event(conn, incident_id, now, "skipped", {"reason": "below_threshold"})
            return IntakeResult(incident_id, "skipped")
        previous = _find_previous(conn, alert, cfg)
        if previous:
            _recur(conn, previous, alert, now)
            _remember(conn, alert, previous["id"], now)
            _sync_status(conn, previous["id"], now)
            return IntakeResult(previous["id"], "recurred")
        hold = cfg.wazuh_hold_sec if alert.source == Source.WAZUH else cfg.zabbix_hold_sec
        incident_id = _insert(conn, alert, now, AnalysisState.HELD, now + timedelta(seconds=hold), None)
        _remember(conn, alert, incident_id, now)
        add_event(conn, incident_id, now, "detected", {"held_sec": hold})
        return IntakeResult(incident_id, "created")


def _insert(conn: sqlite3.Connection, alert: NormalizedAlert, now: datetime, state: AnalysisState,
            held_until: datetime | None, skip_reason: str | None) -> int:
    cursor = conn.execute(
        "INSERT INTO incidents (source, external_id, fingerprint, host, type, source_severity, severity, title, "
        "started_at, resolved_at, problem_status, availability, last_occurrence_at, analysis_state, held_until, "
        "skip_reason, raw_json, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (alert.source, alert.external_id, alert.fingerprint, alert.host, alert.type, alert.source_severity,
         alert.severity, alert.title, to_iso(alert.started_at), _recovery(alert, now), alert.problem_status,
         int(alert.availability),
         to_iso(alert.started_at), state, to_iso(held_until) if held_until else None, skip_reason,
         json.dumps(alert.raw, ensure_ascii=False), to_iso(now), to_iso(now)))
    return int(cursor.lastrowid)


def _recur(conn: sqlite3.Connection, previous: sqlite3.Row, alert: NormalizedAlert, now: datetime) -> None:
    """再発は件数を積むだけ。重大度が上がったときだけ追跡解析を 1 回起こす。"""
    started = to_iso(alert.started_at)
    conn.execute("UPDATE incidents SET occurrence_count = occurrence_count + 1, started_at = ?, "
                 "last_occurrence_at = ?, updated_at = ? WHERE id = ?",
                 (min(previous["started_at"], started), max(previous["last_occurrence_at"], started),
                  to_iso(now), previous["id"]))
    add_event(conn, previous["id"], now, "recurred", {"external_id": alert.external_id})
    if alert.severity > previous["severity"]:
        conn.execute("UPDATE incidents SET severity = ?, source_severity = ? WHERE id = ?",
                     (alert.severity, alert.source_severity, previous["id"]))
        finished = previous["analysis_state"] in (AnalysisState.DONE, AnalysisState.FAILED)
        if finished and not previous["followup_done"]:
            conn.execute("UPDATE incidents SET analysis_state = ?, followup_done = 1, attempt_count = 0, "
                         "next_retry_at = NULL, queue_reason = 'followup' WHERE id = ?",
                         (AnalysisState.QUEUED, previous["id"]))
            add_event(conn, previous["id"], now, "followup_queued", {"reason": "severity_up"})


def reopen(conn: sqlite3.Connection, source: Source, external_id: str, now: datetime) -> bool:
    """復旧と記録したアラートが、未解決のまま戻ったときに、復旧を取り消す。

    知らないアラートと、未復旧のアラートは何もせず False を返す。
    """
    with db.transaction(conn):
        seen = conn.execute("SELECT incident_id, resolved_at FROM alert_refs WHERE source = ? AND external_id = ?",
                            (source, external_id)).fetchone()
        if not seen or seen["resolved_at"] is None:
            return False
        conn.execute("UPDATE alert_refs SET resolved_at = NULL WHERE source = ? AND external_id = ?",
                     (source, external_id))
        _sync_status(conn, seen["incident_id"], now)
        return True


def resolve(conn: sqlite3.Connection, source: Source, external_id: str, resolved_at: datetime,
            now: datetime) -> bool:
    """1 件のアラートの復旧を記録する。知らないアラートと、記録済みの復旧は何もせず False を返す。

    インシデントが復旧になるのは、まとめたアラートが全部復旧したとき。
    """
    with db.transaction(conn):
        seen = conn.execute("SELECT incident_id FROM alert_refs WHERE source = ? AND external_id = ?",
                            (source, external_id)).fetchone()
        if not seen or not _mark_ref_resolved(conn, source, external_id, to_iso(resolved_at)):
            return False
        _sync_status(conn, seen["incident_id"], now)
        return True
