"""画面からの操作。待ち行列と事例の関数を呼び、結果を 1 つの形で返す。

操作の名前は、ボタン、トースト、経過の表示で同じ言葉を使う。
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime

from tia import db, queue
from tia.analysis import cases, records
from tia.analysis.cases import CaseDraft, CaseError
from tia.intake import add_event
from tia.knowledge.safety import neutralise
from tia.models import AnalysisState, to_iso
from tia.queue import StateError
from tia.probes import store as probe_store
from tia.probes.runner import STATUS_LABELS as PROBE_STATUS_LABELS, store_results
from tia.web.queries import available_actions, probes_available, shown_analysis_id

ACTOR = "operator"
NAMES = {"read": "既読にする", "prioritize": "先に解析する", "skip": "対象外にする", "reanalyze": "再解析する",
         "feedback": "評価を記録する", "case": "事例として登録する", "probe": "確認を実行する",
         "reanalyze_with_probes": "結果を添えて再解析する"}
FEEDBACK_VERDICTS = ("helpful", "wrong", "corrected")
NOTE_LIMIT = 1000
FIELD_LIMIT = 600


@dataclass(frozen=True)
class Outcome:
    ok: bool
    message: str
    status: int = 200


class ActionError(ValueError):
    """入力の誤り。状態の誤りは `StateError` と `CaseError` のまま返す。"""


def _text(value: object, limit: int) -> str:
    cleaned = neutralise(str(value or ""))[0]
    return " ".join(cleaned.split())[:limit]


def _incident(conn: sqlite3.Connection, incident_id: int) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    if row is None:
        raise StateError(f"インシデント I-{incident_id:04d} がない")
    return row


def mark_read(conn: sqlite3.Connection, incident_id: int, now: datetime) -> bool:
    """未確認の印を消す。すでに既読なら何もしない（二重に送られても害がない）。"""
    with db.transaction(conn):
        row = _incident(conn, incident_id)
        if row["read_at"] is not None:
            return False
        conn.execute("UPDATE incidents SET read_at = ?, updated_at = ? WHERE id = ?",
                     (to_iso(now), to_iso(now), incident_id))
        return True


def record_feedback(conn: sqlite3.Connection, incident_id: int, verdict: str, note: str, now: datetime) -> None:
    """評価は経過に残す。表は増やさない。"""
    if verdict not in FEEDBACK_VERDICTS:
        raise ActionError("評価は、役に立った、外れていた、正しい原因を記入、のどれか")
    note = _text(note, NOTE_LIMIT)
    if verdict == "corrected" and not note:
        raise ActionError("正しい原因を記入する場合は、原因の文が要る")
    with db.transaction(conn):
        row = _incident(conn, incident_id)
        shown = shown_analysis_id(conn, incident_id)
        if shown is None:
            raise StateError(f"I-{incident_id:04d} はまだ解析されていない。評価は解析の後に記録できる")
        # 評価は画面に出ている解析（インシデントが指す解析）に付ける。後の再生には付けない
        add_event(conn, incident_id, now, "feedback",
                  {"verdict": verdict, "note": note, "analysis_id": shown, "actor": ACTOR})
        conn.execute("UPDATE incidents SET updated_at = ? WHERE id = ?", (to_iso(now), row["id"]))


def register_case(conn: sqlite3.Connection, incident_id: int, verdict: str, note: str, now: datetime, *,
                  symptoms: str = "", cause: str = "", confirmation: str = "", action: str = "") -> int:
    """人が直した内容で事例を登録する。空の欄は下書きの値を使う。"""
    if verdict not in cases.VERDICTS:
        raise ActionError("評価は correct（原因は正しかった）か corrected（原因を直す）のどちらか")
    base = cases.draft(conn, incident_id, analysis_id=shown_analysis_id(conn, incident_id))
    draft = CaseDraft(symptoms=_text(symptoms, FIELD_LIMIT) or base.symptoms,
                      cause=_text(cause, FIELD_LIMIT) or base.cause,
                      confirmation=_text(confirmation, FIELD_LIMIT) or base.confirmation,
                      action=_text(action, FIELD_LIMIT) or base.action)
    # corrected のとき、`cases.confirm` は note を原因にする。画面では原因の欄に書くので、それを渡す
    note_text = _text(note, NOTE_LIMIT) or (draft.cause if verdict == "corrected" else "")
    with db.transaction(conn):
        case_id = cases.confirm(conn, incident_id, verdict, note_text, now, draft_=draft)
        conn.execute("UPDATE incidents SET updated_at = ? WHERE id = ?", (to_iso(now), incident_id))
        return case_id


# 同じインシデントの同じ確認は、この秒数の間は 2 回目を受けない。「実行」の連打で対象の VM に ssh が飛び続けないため
PROBE_REPEAT_SEC = 60


def run_probe(conn: sqlite3.Connection, row: sqlite3.Row, name: str, now: datetime, runner) -> Outcome:
    """運用者が画面から選んだ確認を 1 つ動かし、結果を保存する（段階 2'）。次の解析が結果を拾う。"""
    catalog = getattr(runner, "catalog", None)
    probe = catalog.probes.get(name) if catalog is not None else None
    if probe is None:
        raise ActionError("カタログにない確認")
    if not catalog.runs_on(probe, row["host"]):
        raise ActionError(f"確認 {name} はこのホストには行えない")
    recent = probe_store.recent_operator_run(conn, row["id"], name, now, PROBE_REPEAT_SEC)
    if recent is not None:
        raise StateError(f"確認 {name} は実行したばかり（{recent} 秒前）。{PROBE_REPEAT_SEC} 秒おいてから")
    results = runner.run([probe], row)
    with db.transaction(conn):
        store_results(conn, row["id"], None, "operator", results)
        result = results[0]
        add_event(conn, row["id"], now, "probe_run",
                  {"name": name, "status": result.status, "duration_ms": result.duration_ms, "actor": ACTOR})
        conn.execute("UPDATE incidents SET updated_at = ? WHERE id = ?", (to_iso(now), row["id"]))
    label = PROBE_STATUS_LABELS.get(result.status, result.status)
    return Outcome(result.status == "ok", f"確認 {name} を実行した: {label}" + (f"（{result.error}）" if result.error else ""))


def perform(conn: sqlite3.Connection, name: str, incident_id: int, now: datetime, form: dict[str, str], *,
            runner=None) -> Outcome:
    """操作を行う。状態が合わない操作は 409、入力の誤りは 400、ないインシデントは 404。"""
    if name not in NAMES:
        return Outcome(False, "知らない操作", 404)
    label = NAMES[name]
    try:
        row = _incident(conn, incident_id)
        if name != "read":
            allowed = available_actions(row["analysis_state"],
                                        records.latest_done(conn, incident_id) is not None,
                                        probes=probes_available(runner, row["host"]),
                                        attachable=bool(probe_store.unattached(conn, incident_id)))
            if name not in allowed:
                raise StateError(f"{label}は、いまの状態（{_state_label(row['analysis_state'])}）では行えない")
        if name == "probe":
            return run_probe(conn, row, _text(form.get("name"), 40), now, runner)
        if name == "reanalyze_with_probes":
            queue.requeue(conn, incident_id, now)
            return Outcome(True, "結果を添えて再解析する。待ちに入れた")
        if name == "read":
            mark_read(conn, incident_id, now)
            return Outcome(True, "既読にした")
        if name == "prioritize":
            queue.prioritize(conn, incident_id, now)
            return Outcome(True, f"{NAMES[name]}。待ちの先頭に移した")
        if name == "skip":
            reason = _text(form.get("reason"), NOTE_LIMIT)
            if not reason:
                raise ActionError("対象外にする理由を書く")
            queue.skip_manually(conn, incident_id, now, reason)
            return Outcome(True, "対象外にした")
        if name == "reanalyze":
            queue.requeue(conn, incident_id, now)
            return Outcome(True, "再解析する。待ちに入れた")
        if name == "feedback":
            record_feedback(conn, incident_id, form.get("verdict", ""), form.get("note", ""), now)
            return Outcome(True, "評価を記録した")
        register_case(conn, incident_id, form.get("verdict", ""), form.get("note", ""), now,
                      symptoms=form.get("symptoms", ""), cause=form.get("cause", ""),
                      confirmation=form.get("confirmation", ""), action=form.get("action", ""))
        return Outcome(True, "事例として登録した")
    except ActionError as exc:
        return Outcome(False, str(exc), 400)
    except (StateError, CaseError) as exc:
        text = str(exc)
        return Outcome(False, text, 404 if text.endswith("がない") else 409)


def _state_label(state: str) -> str:
    return {AnalysisState.HELD: "束ね判定の待ち", AnalysisState.QUEUED: "処理待ち", AnalysisState.RETRY_WAIT: "再試行待ち",
            AnalysisState.RUNNING: "解析中", AnalysisState.DONE: "解析済み", AnalysisState.FAILED: "解析失敗",
            AnalysisState.SKIPPED: "対象外", AnalysisState.GROUPED: "束の一部"}.get(state, state)
