"""事例カードと統計。人が確認した事例だけを本文として渡し、未確認の解析からは統計だけを渡す。"""
from __future__ import annotations

import sqlite3
import statistics as stat
from dataclasses import dataclass
from datetime import datetime, timedelta

from tia import db
from tia.analysis import records
from tia.intake import add_event
from tia.knowledge.safety import neutralise
from tia.knowledge.tokens import TokenCounter, estimate_tokens
from tia.models import from_iso, to_iso

VERDICTS = ("correct", "corrected")
STATUSES = ("approved", "stale")
CARD_TOKEN_LIMIT = 300
FIELD_LIMITS = {"symptoms": 200, "cause": 300, "confirmation": 300, "action": 300}
TITLE_LIMIT = 120
HOST_LIMIT = 120
DEFAULT_WINDOW_DAYS = 30


class CaseError(ValueError):
    """事例に対する、できない操作。"""


@dataclass(frozen=True)
class CaseDraft:
    """事例の下書き。LLM の最新の結果から作り、人が直して承認する。"""
    symptoms: str
    cause: str
    confirmation: str
    action: str


def _clean(text: object, limit: int) -> str:
    value = neutralise(str(text or ""))[0]
    value = " ".join(value.split())
    return value[:limit]


def _incident(conn: sqlite3.Connection, incident_id: int) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    if row is None:
        raise CaseError(f"インシデント {incident_id} がない")
    return row


def draft(conn: sqlite3.Connection, incident_id: int, analysis_id: int | None = None) -> CaseDraft:
    """解析から下書きを作る。analysis_id を指定すればその解析、なければ最後に完了した解析。

    解析がなければ、題名だけの下書き。生ログは入れない。
    """
    incident = _incident(conn, incident_id)
    latest = records.latest_done(conn, incident_id)
    if analysis_id is not None:
        chosen = records.get(conn, analysis_id)
        if chosen["incident_id"] == incident_id and chosen["status"] == "done":
            latest = chosen
    result = records.result_of(latest) if latest is not None else None
    if not result:
        return CaseDraft(symptoms=_clean(incident["title"], FIELD_LIMITS["symptoms"]), cause="", confirmation="",
                         action="")
    causes = result.get("probable_causes") or []
    checks = result.get("recommended_checks") or []
    cause = causes[0].get("cause", "") if causes and isinstance(causes[0], dict) else ""
    confirmation = "、".join(c.get("purpose", "") for c in checks[:3] if isinstance(c, dict))
    return CaseDraft(symptoms=_clean(result.get("summary") or incident["title"], FIELD_LIMITS["symptoms"]),
                     cause=_clean(cause, FIELD_LIMITS["cause"]),
                     confirmation=_clean(confirmation, FIELD_LIMITS["confirmation"]), action="")


def _time_to_recover(incident: sqlite3.Row) -> int | None:
    if not incident["resolved_at"]:
        return None
    seconds = (from_iso(incident["resolved_at"]) - from_iso(incident["started_at"])).total_seconds()
    return max(0, int(seconds))


def render_fields(host: str, kind: str, occurred_on: str, symptoms: str, cause: str, confirmation: str,
                  action: str, time_to_recover_sec: int | None) -> str:
    """事例カードの本文。LLM に渡す形。"""
    recover = f"{time_to_recover_sec // 60} 分" if time_to_recover_sec is not None else "記録なし"
    return (f"ホスト: {host}\n種類: {kind}\n日付: {occurred_on}\n症状: {symptoms}\n確定した原因: {cause}\n"
            f"確認の方法: {confirmation or '記録なし'}\n対処または判断: {action or '記録なし'}\n復旧までの時間: {recover}")


def confirm(conn: sqlite3.Connection, incident_id: int, verdict: str, note: str, now: datetime, *,
            draft_: CaseDraft | None = None, counter: TokenCounter = estimate_tokens) -> int:
    """人が原因を確認したインシデントから事例カードを作り、その id を返す。

    verdict は correct（LLM の原因が合っていた）か corrected（人が正しい原因を書いた）。
    corrected のときは note に原因を書く。カードは 300 トークン以内に切り詰める。
    """
    if verdict not in VERDICTS:
        raise CaseError(f"評価 {verdict!r} は {', '.join(VERDICTS)} のどちらか")
    base = draft_ or draft(conn, incident_id)
    cause = _clean(note, FIELD_LIMITS["cause"]) if verdict == "corrected" else (base.cause or _clean(note, 300))
    if not cause:
        raise CaseError("原因の記述が要る。corrected のときは note に、correct のときは解析の結果か note に")
    incident = _incident(conn, incident_id)
    fields = {"symptoms": base.symptoms, "cause": cause, "confirmation": base.confirmation, "action": base.action}
    fields = {name: _clean(value, FIELD_LIMITS[name]) for name, value in fields.items()}
    occurred_on = incident["started_at"][:10]
    recover = _time_to_recover(incident)
    # ホスト名もアラート由来の文なので、信頼しない
    host = _clean(incident["host"], HOST_LIMIT)
    text = render_fields(host, incident["type"], occurred_on, fields["symptoms"], fields["cause"],
                         fields["confirmation"], fields["action"], recover)
    tokens = counter(text)
    # 大きすぎれば、対処、確認、症状の順に短くして収める。原因は最後まで残す。
    for name in ("action", "confirmation", "symptoms"):
        while tokens > CARD_TOKEN_LIMIT and len(fields[name]) > 2:
            fields[name] = fields[name][: len(fields[name]) // 2].rstrip() + "…"
            text = render_fields(host, incident["type"], occurred_on, fields["symptoms"], fields["cause"],
                                 fields["confirmation"], fields["action"], recover)
            tokens = counter(text)
    with db.transaction(conn):
        conn.execute("DELETE FROM cases WHERE incident_id = ?", (incident_id,))
        cursor = conn.execute(
            "INSERT INTO cases (incident_id, fingerprint, host, type, title, symptoms, cause, confirmation, action, "
            "time_to_recover_sec, occurred_on, verdict, status, approved_at, tokens) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,'approved',?,?)",
            (incident_id, incident["fingerprint"], host, incident["type"],
             _clean(incident["title"], TITLE_LIMIT), fields["symptoms"], fields["cause"], fields["confirmation"],
             fields["action"], recover, occurred_on, verdict, to_iso(now), tokens))
        conn.execute("UPDATE incidents SET confirmed_at = ?, confirmed_verdict = ?, updated_at = ? WHERE id = ?",
                     (to_iso(now), verdict, to_iso(now), incident_id))
        add_event(conn, incident_id, now, "case_registered", {"verdict": verdict, "tokens": tokens})
        return int(cursor.lastrowid)


def render(case: sqlite3.Row) -> str:
    return render_fields(_clean(case["host"], HOST_LIMIT), _clean(case["type"], 40), case["occurred_on"],
                         case["symptoms"], case["cause"], case["confirmation"], case["action"],
                         case["time_to_recover_sec"])


def similar(conn: sqlite3.Connection, incident: sqlite3.Row, *, limit: int = 3) -> list[sqlite3.Row]:
    """似た事例を、同じ指紋、同じホストの同じ種類、他ホストの同じ種類の順に、新しいものから。

    劣化の印の付いたものは後ろに回す。自分自身から作った事例は除く。
    """
    if limit <= 0:
        return []
    return conn.execute(
        "SELECT * FROM cases WHERE type = ? AND incident_id != ? ORDER BY "
        "CASE WHEN fingerprint = ? THEN 0 WHEN host = ? THEN 1 ELSE 2 END, "
        "CASE status WHEN 'approved' THEN 0 ELSE 1 END, approved_at DESC, id DESC LIMIT ?",
        (incident["type"], incident["id"], incident["fingerprint"], incident["host"], limit)).fetchall()


def mark_stale(conn: sqlite3.Connection, reason: str, now: datetime, *, hosts: tuple[str, ...] | None = None) -> int:
    """構成が変わったときに、関係する事例に「参考度低」の印を付ける。hosts が None なら全部。"""
    with db.transaction(conn):
        if hosts is None:
            cursor = conn.execute("UPDATE cases SET status = 'stale', stale_reason = ? WHERE status = 'approved'",
                                  (_clean(reason, 200),))
        else:
            marks = ",".join("?" for _ in hosts)
            cursor = conn.execute(f"UPDATE cases SET status = 'stale', stale_reason = ? WHERE status = 'approved' "
                                  f"AND host IN ({marks})", (_clean(reason, 200), *hosts))
        return cursor.rowcount


@dataclass(frozen=True)
class Statistics:
    same_fingerprint: int
    same_host_type: int
    recovered: int
    median_recover_sec: int | None
    urgencies: dict[str, int]
    window_days: int

    def render(self) -> str:
        """統計の文。LLM に渡す形。"""
        recover = f"中央値 {self.median_recover_sec // 60} 分" if self.median_recover_sec is not None else "記録なし"
        verdicts = "、".join(f"{name} {count} 回" for name, count in sorted(self.urgencies.items())) or "なし"
        return (f"過去 {self.window_days} 日の統計（未確認の解析からは数だけ）\n"
                f"同じ指紋の発生: {self.same_fingerprint} 回\n同じホストの同じ種類: {self.same_host_type} 回\n"
                f"復旧した回数: {self.recovered} 回、復旧までの時間: {recover}\n過去の解析の緊急度: {verdicts}")


def statistics(conn: sqlite3.Connection, incident: sqlite3.Row, now: datetime, *,
               window_days: int = DEFAULT_WINDOW_DAYS) -> Statistics:
    """同じ指紋の過去の回数と復旧のしかた。本文は渡さず、数だけを渡す。"""
    since = to_iso(now - timedelta(days=window_days))
    rows = conn.execute(
        "SELECT id, host, type, started_at, resolved_at, urgency FROM incidents WHERE fingerprint = ? AND id != ? "
        "AND started_at >= ? AND source != 'group'", (incident["fingerprint"], incident["id"], since)).fetchall()
    same_host_type = conn.execute(
        "SELECT COUNT(*) FROM incidents WHERE host = ? AND type = ? AND id != ? AND started_at >= ? "
        "AND source != 'group'", (incident["host"], incident["type"], incident["id"], since)).fetchone()[0]
    recover = [int((from_iso(r["resolved_at"]) - from_iso(r["started_at"])).total_seconds())
               for r in rows if r["resolved_at"]]
    urgencies: dict[str, int] = {}
    for row in rows:
        if row["urgency"]:
            urgencies[row["urgency"]] = urgencies.get(row["urgency"], 0) + 1
    return Statistics(same_fingerprint=len(rows), same_host_type=int(same_host_type), recovered=len(recover),
                      median_recover_sec=int(stat.median(recover)) if recover else None, urgencies=urgencies,
                      window_days=window_days)


def to_json(case: sqlite3.Row) -> dict:
    """画面と再生で使う形。"""
    return {key: case[key] for key in case.keys()}


def dump(conn: sqlite3.Connection) -> str:
    """夜間の書き出し用。事例を Markdown で返す。保存先は呼び出し側が決める。"""
    rows = conn.execute("SELECT * FROM cases ORDER BY id").fetchall()
    blocks = [f"## 事例 {row['id']}（I-{row['incident_id']:04d}、{row['status']}）\n\n{render(row)}\n" for row in rows]
    return "# 事例カード\n\n" + "\n".join(blocks) if blocks else "# 事例カード\n\n事例はまだない。\n"
