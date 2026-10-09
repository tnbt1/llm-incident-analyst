"""画面のための読み取り。書き込みはしない。

表の列の意味は各モジュールが決める。ここはそれを画面の形に直すだけで、
表が変わっても、直す場所がここ 1 つで済むようにする。
"""
from __future__ import annotations

import json
import sqlite3
import statistics
from dataclasses import dataclass, field
from datetime import date, datetime, time, timedelta
from zoneinfo import ZoneInfo

from tia.analysis import records
from tia.probes import store as probe_store
from tia.probes.runner import STATUS_LABELS as PROBE_STATUS_LABELS
from tia.analysis.schema import CONFIDENCE_LABELS, KIND_LABELS, URGENCY_LABELS
from tia.config import Config
from tia.models import AnalysisState, ProblemStatus, from_iso, to_iso

WAITING = (AnalysisState.HELD, AnalysisState.QUEUED, AnalysisState.RETRY_WAIT)
# パイプライン帯の絞り込みの名前と、解析の状態の対応
FILTERS = {"wait": WAITING, "run": (AnalysisState.RUNNING,), "done": (AnalysisState.DONE,),
           "fail": (AnalysisState.FAILED,), "skip": (AnalysisState.SKIPPED,)}
ICONS = {"cpu": "pg-cpu", "mem": "pg-mem", "swap": "pg-swap", "disk": "pg-disk", "io": "pg-io", "net": "pg-net",
         "container": "pg-box", "service": "pg-service", "auth": "pg-key", "user": "pg-user", "file": "pg-file",
         "pkg": "pg-pkg", "other": "pg-other"}
TYPE_LABELS = {"cpu": "CPU", "mem": "メモリ", "swap": "スワップ", "disk": "ディスク", "io": "I/O", "net": "ネットワーク",
               "container": "コンテナ", "service": "サービス", "auth": "認証", "user": "利用者", "file": "ファイル変更",
               "pkg": "パッケージ", "other": "その他"}
EVENT_LABELS = {
    "detected": "検知", "recurred": "再発", "resolved": "復旧", "reopened": "再開", "queued": "順番待ちに入った",
    "grouped": "束に入った", "group_created": "束を作った", "analysis_started": "解析開始", "analysis_done": "解析完了",
    "analysis_failed": "解析失敗", "retry_scheduled": "再試行を予約", "released": "待ちに戻した",
    "prioritized": "先に解析する", "skipped": "対象外にした", "requeued": "再解析する", "followup_queued": "追跡解析",
    "regenerated": "作り直した", "case_registered": "事例として登録した", "feedback": "評価を記録した", "read": "既読にした",
    "checks_excluded": "確認を規則により除外した", "probed": "状態を確認した", "probe_run": "確認を実行した",
}
PROBE_TRIGGER_LABELS = {"initial": "解析の前に", "operator": "運用者が", "replay": "再生で"}
PHASE_LABELS = {"context": "文脈収集", "inference": "推論中", "validation": "検証", "finished": "完了"}
FAIL_LABELS = {"timeout": "LLM の応答が制限時間を超えた", "validation": "出力の検証に失敗した",
               "truncated": "応答が途中で切れた", "context": "文脈を組み立てられなかった",
               "internal": "想定外の失敗", "length": "出力が上限で切れた", "invalid_response": "応答を読めなかった"}
SKIP_LABELS = {"below_threshold": "閾値未満のため対象外", "resolved_too_long": "復旧から時間がたったため対象外",
               "not_analyzable": "解析の対象外の種類"}
EMPTY_TITLES = {"active": "進行中のものはありません", "done": "この日に解析したものはありません",
                "failed": "解析できなかったものはありません", "skipped": "対象外にしたものはありません"}
SOURCE_SHORT = {"zabbix": "Zabbix", "wazuh": "Wazuh", "group": "束"}


def zone(cfg: Config) -> ZoneInfo:
    return ZoneInfo(cfg.web_timezone)


def local(value: str | datetime | None, tz: ZoneInfo) -> datetime | None:
    if value is None:
        return None
    moment = from_iso(value) if isinstance(value, str) else value
    return moment.astimezone(tz)


def clock_text(value: str | datetime | None, tz: ZoneInfo) -> str:
    moment = local(value, tz)
    return moment.strftime("%H:%M") if moment else "—"


def day_bounds(day: date, tz: ZoneInfo) -> tuple[str, str]:
    """その日の始まりと終わり（翌日の始まり）を、UTC の文字列で。"""
    start = datetime.combine(day, time.min, tzinfo=tz)
    return to_iso(start), to_iso(start + timedelta(days=1))


def parse_day(text: str | None, now: datetime, tz: ZoneInfo) -> date:
    """`day` の引数。空なら今日。形が違えば ValueError。"""
    if not text:
        return now.astimezone(tz).date()
    try:
        return date.fromisoformat(text.strip())
    except ValueError as exc:
        raise ValueError("day は YYYY-MM-DD の形で書く") from exc


def duration_text(seconds: int | float | None) -> str:
    if seconds is None:
        return "—"
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds} 秒"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes} 分"
    hours, minutes = divmod(minutes, 60)
    if hours < 48:
        return f"{hours} 時間{minutes} 分" if minutes else f"{hours} 時間"
    return f"{hours // 24} 日"


def short_host(host: str) -> str:
    """`app02-production` を `app02` に。表の列が長くならないように、環境を表す接尾辞を落とす。"""
    name = host or ""
    for suffix in ("-production", "-staging", "-development"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
    return name or host


def label_of(incident_id: int) -> str:
    return f"I-{incident_id:04d}"


def _json(text: str | None) -> dict:
    try:
        data = json.loads(text) if text else {}
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def filter_key(state: str) -> str:
    for key, states in FILTERS.items():
        if state in states:
            return key
    return "other"


@dataclass(frozen=True)
class Running:
    incident_id: int
    analysis_id: int
    phase: str
    phase_label: str
    tokens: int
    elapsed_sec: int
    percent: int

    def texts(self, max_tokens: int) -> dict:
        """進捗の文。帯、一覧の行、詳細で同じ作り方にし、SSE の progress もこれを送る。"""
        elapsed = duration_text(self.elapsed_sec)
        return {"id": self.incident_id, "percent": self.percent, "tokens": self.tokens,
                "rail": f"{self.phase_label} {elapsed} · {self.tokens} / {max_tokens} tok",
                "row": f"{self.phase_label} {elapsed}",
                "detail": f"{self.tokens} / {max_tokens} トークン · 経過 {elapsed}"}


def running(conn: sqlite3.Connection, now: datetime, cfg: Config) -> Running | None:
    """解析中の 1 件の進み具合。`analyses` の phase と tokens_so_far を読む。"""
    row = conn.execute("SELECT id, incident_id, phase, tokens_so_far, started_at FROM analyses "
                       "WHERE status = 'running' ORDER BY id DESC LIMIT 1").fetchone()
    if row is None:
        return None
    elapsed = max(0, int((now - from_iso(row["started_at"])).total_seconds()))
    percent = min(100, int(row["tokens_so_far"] * 100 / max(1, cfg.llm_max_tokens)))
    return Running(row["incident_id"], row["id"], row["phase"], PHASE_LABELS.get(row["phase"], row["phase"]),
                   row["tokens_so_far"], elapsed, percent)


def typical_duration_sec(conn: sqlite3.Connection) -> int | None:
    rows = conn.execute("SELECT duration_ms FROM analyses WHERE status = 'done' AND duration_ms IS NOT NULL "
                        "ORDER BY id DESC LIMIT 10").fetchall()
    if not rows:
        return None
    return int(statistics.median(r["duration_ms"] for r in rows) / 1000)


def _waiting_order(conn: sqlite3.Connection, now: datetime) -> list[int]:
    """待ちの順番。`queue.next_candidate` と同じ並べ方。"""
    return [r["id"] for r in conn.execute(
        "SELECT id FROM incidents WHERE analysis_state IN (?, ?, ?) "
        "ORDER BY priority DESC, severity DESC, started_at ASC, id ASC", tuple(WAITING))]


# 順番待ちに入った瞬間を示す出来事。先に解析する指定や再発は、待ちの起点を動かさない
QUEUED_EVENTS = ("queued", "requeued", "followup_queued")


def queue_summary(conn: sqlite3.Connection, now: datetime, cfg: Config) -> dict:
    """待ちの深さと最も古い待ち。`/healthz` と最上段の警告に使う。

    待ちの起点は、順番待ちに入った最後の出来事（なければ発生時刻）。updated_at は再発や操作でも進むので使わない。
    再試行待ちは、再試行の時刻が来てから数える。束ね判定の待ちは数えない。
    """
    depth = conn.execute("SELECT COUNT(*) FROM incidents WHERE analysis_state IN (?, ?, ?)", tuple(WAITING)).fetchone()[0]
    placeholders = ", ".join("?" for _ in QUEUED_EVENTS)
    oldest = conn.execute(
        f"SELECT MIN(t) FROM ("
        f"  SELECT COALESCE((SELECT MAX(e.at) FROM events e WHERE e.incident_id = i.id AND e.type IN ({placeholders})), "
        f"                  i.started_at) AS t FROM incidents i WHERE i.analysis_state = ?"
        f"  UNION ALL"
        f"  SELECT next_retry_at AS t FROM incidents WHERE analysis_state = ? AND next_retry_at <= ?)",
        (*QUEUED_EVENTS, AnalysisState.QUEUED, AnalysisState.RETRY_WAIT, to_iso(now))).fetchone()[0]
    oldest_sec = max(0, int((now - from_iso(oldest)).total_seconds())) if oldest else 0
    current = running(conn, now, cfg)
    return {"depth": int(depth), "oldest_waiting_sec": oldest_sec, "stalled": oldest_sec > cfg.web_stall_warn_sec,
            "running": None if current is None else {"incident_id": current.incident_id, "phase": current.phase,
                                                     "tokens": current.tokens, "elapsed_sec": current.elapsed_sec}}


def rail(conn: sqlite3.Connection, now: datetime, cfg: Config, day: date) -> dict:
    """パイプライン帯の数。"""
    tz = zone(cfg)
    start, end = day_bounds(day, tz)
    counts = {key: 0 for key in FILTERS}
    for row in conn.execute("SELECT analysis_state, COUNT(*) AS n FROM incidents GROUP BY analysis_state"):
        counts[filter_key(row["analysis_state"])] = counts.get(filter_key(row["analysis_state"]), 0) + row["n"]
    done_today, unread = conn.execute(
        "SELECT COUNT(*), SUM(CASE WHEN read_at IS NULL THEN 1 ELSE 0 END) FROM incidents "
        "WHERE analysis_state = ? AND analyzed_at >= ? AND analyzed_at < ?",
        (AnalysisState.DONE, start, end)).fetchone()
    skipped_today = conn.execute(
        "SELECT COUNT(*) FROM incidents WHERE analysis_state = ? AND updated_at >= ? AND updated_at < ?",
        (AnalysisState.SKIPPED, start, end)).fetchone()[0]
    current = running(conn, now, cfg)
    order = _waiting_order(conn, now)
    typical = typical_duration_sec(conn)
    if order:
        if typical is not None:
            eta = now + timedelta(seconds=(typical if current is None else max(0, typical - current.elapsed_sec)))
            waiting_sub = f"次の開始見込 {clock_text(eta, tz)}"
        else:
            waiting_sub = "次の開始見込は未定"
    else:
        waiting_sub = "待ちはない"
    if current is not None:
        running_sub = current.texts(cfg.llm_max_tokens)["rail"]
    else:
        running_sub = "いまは解析していない"
    return {"waiting": counts["wait"], "waiting_sub": waiting_sub, "running": counts["run"], "running_sub": running_sub,
            "running_percent": current.percent if current else 0, "running_id": current.incident_id if current else None,
            "done": int(done_today or 0),
            "done_sub": f"本日 · 未確認 {int(unread or 0)} 件", "failed": counts["fail"], "skipped": int(skipped_today),
            "day": day.isoformat()}


def _row_dict(row: sqlite3.Row, now: datetime, cfg: Config, tz: ZoneInfo, current: Running | None,
              order: list[int], typical: int | None) -> dict:
    state = row["analysis_state"]
    key = filter_key(state)
    urgency = row["urgency"] if state == AnalysisState.DONE else None
    raw = _json(row["raw_json"]) if row["source"] == "group" else {}
    members = len(raw.get("members") or []) if row["source"] == "group" else 0
    live = healed = why = None
    progress = None
    if row["problem_status"] == ProblemStatus.OPEN:
        live = f"発生中 {duration_text((now - from_iso(row['started_at'])).total_seconds())}"
    elif row["problem_status"] == ProblemStatus.RESOLVED and row["resolved_at"]:
        held = (from_iso(row["resolved_at"]) - from_iso(row["started_at"])).total_seconds()
        healed = f"復旧済み · {duration_text(held)}"
    else:
        healed = "単発"
    if state == AnalysisState.RUNNING and current is not None and current.incident_id == row["id"]:
        why = current.texts(cfg.llm_max_tokens)["row"]
        progress = current.percent
    elif state == AnalysisState.HELD:
        why = "続報を束ね中"
    elif state in (AnalysisState.QUEUED, AnalysisState.RETRY_WAIT):
        ahead = order.index(row["id"]) if row["id"] in order else 0
        if state == AnalysisState.RETRY_WAIT and row["next_retry_at"]:
            why = f"再試行 {clock_text(row['next_retry_at'], tz)} 予定"
        elif typical is not None:
            eta = now + timedelta(seconds=typical * (ahead + 1))
            why = f"先行 {ahead} 件 · 開始見込 {clock_text(eta, tz)}"
        else:
            why = f"先行 {ahead} 件"
    elif state == AnalysisState.FAILED:
        why = FAIL_LABELS.get(row["fail_reason"] or "", row["fail_reason"] or "解析に失敗した")
    elif state == AnalysisState.SKIPPED:
        reason = row["skip_reason"] or ""
        why = f"対象外: {reason[8:]}" if reason.startswith("manual: ") else SKIP_LABELS.get(reason, "対象外")
    return {
        "id": row["id"], "label": label_of(row["id"]), "state": key, "analysis_state": state,
        "problem_status": row["problem_status"], "urgency": urgency, "u": urgency or "none",
        "urgency_label": URGENCY_LABELS.get(urgency or "", ""), "type": row["type"],
        "icon": ICONS.get(row["type"], "pg-other"), "title": row["title"], "host": row["host"],
        "host_short": short_host(row["host"]), "source": row["source"], "source_label": row["source_severity"],
        "source_short": SOURCE_SHORT.get(row["source"], row["source"]), "time": clock_text(row["started_at"], tz),
        "unread": state == AnalysisState.DONE and row["read_at"] is None, "live": live, "healed": healed,
        "why": why, "progress": progress, "members": members, "count": row["occurrence_count"],
        "priority": bool(row["priority"]),
    }


@dataclass
class Section:
    key: str
    title: str
    rows: list[dict] = field(default_factory=list)
    hidden: bool = False

    @property
    def count(self) -> int:
        return len(self.rows)

    @property
    def empty_title(self) -> str:
        return EMPTY_TITLES.get(self.key, "該当するものはありません")


def sections(conn: sqlite3.Connection, now: datetime, cfg: Config, day: date, *, state: str | None = None,
             host: str | None = None) -> list[Section]:
    """一覧。進行中、その日の解析済み、解析できなかったもの、対象外の 4 つの節。

    state は wait、run、done、fail、skip のどれか。指定すると、その状態の行だけを返す。
    """
    tz = zone(cfg)
    start, end = day_bounds(day, tz)
    current = running(conn, now, cfg)
    order_ids = _waiting_order(conn, now)
    typical = typical_duration_sec(conn)
    limit = cfg.web_max_rows
    host_clause = " AND host = ?" if host else ""
    host_args: tuple = (host,) if host else ()

    def rows(where: str, order: str, args: tuple) -> list[dict]:
        sql = f"SELECT * FROM incidents WHERE {where}{host_clause} ORDER BY {order} LIMIT {int(limit)}"
        found = conn.execute(sql, args + host_args).fetchall()
        return [_row_dict(r, now, cfg, tz, current, order_ids, typical) for r in found]

    active = rows("analysis_state IN (?, ?, ?, ?) AND group_id IS NULL",
                  "CASE analysis_state WHEN 'running' THEN 0 ELSE 1 END, priority DESC, started_at DESC, id DESC",
                  (*WAITING, AnalysisState.RUNNING))
    done = rows("analysis_state = ? AND analyzed_at >= ? AND analyzed_at < ?", "analyzed_at DESC, id DESC",
                (AnalysisState.DONE, start, end))
    # 失敗は人が動かすまで残るので、日や期間で切らない。帯の数（rail）も同じ条件で数える
    failed = rows("analysis_state = ?", "updated_at DESC, id DESC", (AnalysisState.FAILED,))
    skipped = rows("analysis_state = ? AND updated_at >= ? AND updated_at < ?", "updated_at DESC, id DESC",
                   (AnalysisState.SKIPPED, start, end))
    result = [Section("active", "進行中", active), Section("done", "本日の解析済み", done),
              Section("failed", "解析できなかったもの", failed), Section("skipped", "対象外", skipped, hidden=True)]
    if state:
        if state not in FILTERS:
            raise ValueError("state は wait、run、done、fail、skip のどれかで書く")
        for section in result:
            section.rows = [r for r in section.rows if r["state"] == state]
            section.hidden = False
    return result


def band(conn: sqlite3.Connection, now: datetime, cfg: Config, day: date) -> dict:
    """24 時間の帯。その日に発生したインシデントの位置と色。"""
    tz = zone(cfg)
    start, end = day_bounds(day, tz)
    begin = datetime.combine(day, time.min, tzinfo=tz)
    marks = []
    for row in conn.execute("SELECT id, title, started_at, analysis_state, urgency, source, raw_json FROM incidents "
                            "WHERE started_at >= ? AND started_at < ? AND group_id IS NULL ORDER BY started_at",
                            (start, end)):
        moment = from_iso(row["started_at"]).astimezone(tz)
        x = round((moment - begin).total_seconds() / 864, 2)
        state = row["analysis_state"]
        cls = ""
        if state == AnalysisState.DONE and row["urgency"]:
            color, note = f"var(--{row['urgency']})", URGENCY_LABELS.get(row["urgency"], row["urgency"])
        elif state == AnalysisState.RUNNING:
            color, note, cls = "var(--brand)", "解析中", "ring"
        elif state == AnalysisState.FAILED:
            color, note, cls = "var(--now)", "解析失敗", "ring"
        elif state in WAITING:
            color, note, cls = "var(--ink-3)", "処理待ち", "ring"
        else:
            color, note, cls = "var(--ignore)", "対象外", "ring"
        if row["source"] == "group":
            count = len(_json(row["raw_json"]).get("members") or [])
            note = f"連鎖 {count} 件"
            cls = (cls + " wide").strip()
        marks.append({"x": x, "color": color, "cls": cls, "title": f"{moment.strftime('%H:%M')} {note}",
                      "id": row["id"]})
    local_now = now.astimezone(tz)
    today = local_now.date() == day
    now_x = round((local_now - begin).total_seconds() / 864, 2) if today else None
    return {"ticks": [(0, "00"), (25, "06"), (50, "12"), (75, "18")], "marks": marks, "now_x": now_x,
            "now_label": f"現在 {local_now.strftime('%H:%M')}" if today else day.isoformat(), "day": day.isoformat()}


def _events(conn: sqlite3.Connection, incident_id: int, tz: ZoneInfo) -> list[dict]:
    result = []
    for row in conn.execute("SELECT at, type, detail_json FROM events WHERE incident_id = ? ORDER BY id",
                            (incident_id,)):
        detail = _json(row["detail_json"])
        note = ""
        if row["type"] == "skipped":
            note = detail.get("note") or SKIP_LABELS.get(detail.get("reason", ""), detail.get("reason", ""))
        elif row["type"] in ("analysis_failed", "retry_scheduled", "released"):
            note = FAIL_LABELS.get(detail.get("reason", ""), detail.get("reason", ""))
        elif row["type"] == "feedback":
            note = {"helpful": "役に立った", "wrong": "外れていた", "corrected": "正しい原因を記入"}.get(
                detail.get("verdict", ""), "")
        elif row["type"] == "case_registered":
            note = {"correct": "原因は正しかった", "corrected": "原因を直して登録"}.get(detail.get("verdict", ""), "")
        elif row["type"] == "analysis_done":
            note = URGENCY_LABELS.get(detail.get("urgency", ""), "")
        elif row["type"] == "checks_excluded":
            reasons = "、".join(str(r) for r in (detail.get("reasons") or []))
            note = f"{detail.get('count', 0)} 件" + (f"（{reasons}）" if reasons else "")
        elif row["type"] == "probed":
            note = f"{detail.get('count', 0)} 件（成功 {detail.get('ok', 0)}）"
        elif row["type"] == "probe_run":
            note = f"{detail.get('name', '')}: {PROBE_STATUS_LABELS.get(detail.get('status', ''), detail.get('status', ''))}"
        result.append({"at": row["at"], "time": clock_text(row["at"], tz),
                       "day": local(row["at"], tz).strftime("%m/%d"), "type": row["type"],
                       "label": EVENT_LABELS.get(row["type"], row["type"]), "note": str(note or "")})
    return result


def _analyses(conn: sqlite3.Connection, incident_id: int, tz: ZoneInfo) -> list[dict]:
    result = []
    for row in records.for_incident(conn, incident_id):
        result.append({
            "id": row["id"], "trigger": row["trigger"], "status": row["status"], "phase": row["phase"],
            "started": clock_text(row["started_at"], tz), "started_at": row["started_at"],
            "finished": clock_text(row["finished_at"], tz), "duration": duration_text(
                row["duration_ms"] / 1000 if row["duration_ms"] is not None else None),
            "model": row["model"], "prompt_tokens": row["prompt_tokens"], "completion_tokens": row["completion_tokens"],
            "tokens_per_sec": row["tokens_per_sec"], "knowledge_version": row["knowledge_version"],
            "prompt_hash": row["prompt_hash"], "error_kind": row["error_kind"], "error": row["error"],
            "result": records.result_of(row), "context": _json(row["context_json"]),
        })
    return result


def shown_analysis(analyses: list[dict], pointed: int | None) -> dict | None:
    """画面に出す解析。インシデントが指す解析（状態を決めたもの）。なければ最後の完了したもの。

    再生（replay）はインシデントの状態を変えないので、指す先も変わらない。再生の結果は版の一覧に並ぶ。
    """
    if pointed is not None:
        for item in analyses:
            if item["id"] == pointed and item["status"] == "done":
                return item
    return next((a for a in reversed(analyses) if a["status"] == "done"), None)


def shown_analysis_id(conn: sqlite3.Connection, incident_id: int) -> int | None:
    """操作（評価、事例）が対象にする解析の番号。詳細に出ているものと同じ。"""
    row = conn.execute("SELECT latest_analysis_id FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    if row is None:
        return None
    if row["latest_analysis_id"] is not None:
        done = conn.execute("SELECT id FROM analyses WHERE id = ? AND status = 'done'", (row["latest_analysis_id"],)).fetchone()
        if done is not None:
            return int(done["id"])
    last = records.latest_done(conn, incident_id)
    return int(last["id"]) if last is not None else None


def _checks(result: dict | None) -> list[dict]:
    checks = []
    for item in (result or {}).get("recommended_checks") or []:
        if isinstance(item, dict):
            checks.append({"purpose": str(item.get("purpose", "")), "where": str(item.get("where", "")),
                           "command": str(item.get("command", "")), "verified": bool(item.get("verified"))})
    return checks


def _excluded(result: dict | None) -> list[dict]:
    """規則により推奨から外した確認。目的と理由だけを画面に出す。コマンドの文は渡さない。"""
    items = []
    for item in (result or {}).get("excluded_checks") or []:
        if isinstance(item, dict):
            items.append({"purpose": str(item.get("purpose", "")), "reason": str(item.get("reason", ""))})
    return items


def _causes(result: dict | None) -> list[dict]:
    causes = []
    for item in (result or {}).get("probable_causes") or []:
        if isinstance(item, dict):
            level = str(item.get("confidence", ""))
            causes.append({"cause": str(item.get("cause", "")), "confidence": level,
                           "confidence_label": CONFIDENCE_LABELS.get(level, level), "evidence": str(item.get("evidence", ""))})
    return causes


def _strings(value: object) -> list[str]:
    return [str(v) for v in value] if isinstance(value, list) else []


def _sub(result: dict | None, key: str) -> dict:
    value = (result or {}).get(key)
    return value if isinstance(value, dict) else {}


def available_actions(state: str, has_done: bool, *, probes: bool = False, attachable: bool = False) -> list[str]:
    """その状態で行える操作。画面のボタンと、操作の受け付けの両方がこれを見る。

    probes は確認の実行器があり、このホストに行える確認があるとき。attachable は運用者が取った結果で、
    まだ解析に添えていないものがあるとき。
    """
    actions: list[str] = []
    if state in WAITING:
        actions += ["prioritize", "skip"]
    if state in (AnalysisState.DONE, AnalysisState.FAILED, AnalysisState.SKIPPED):
        actions.append("reanalyze")
        if attachable:
            actions.append("reanalyze_with_probes")
    if state == AnalysisState.DONE or has_done:
        actions += ["feedback", "case"]
    if probes and state != AnalysisState.RUNNING:
        actions.append("probe")
    return actions


def _words(command: str) -> list[str]:
    words = command.split()
    while words and words[0] in ("sudo", "-n"):
        words.pop(0)
    return words


def probe_for_check(runner: object | None, host: str, command: str) -> str | None:
    """推奨の確認と同じことをするカタログの確認の名前。言葉単位で、推奨の先頭がカタログのコマンドと一致するとき。"""
    catalog = getattr(runner, "catalog", None)
    if catalog is None or host not in catalog.hosts:
        return None
    wanted = _words(command)
    if not wanted:
        return None
    for probe in catalog.probes.values():
        fixed = catalog.command_for(probe, host)
        if not fixed or not catalog.runs_on(probe, host):
            continue
        words = _words(fixed)
        if words and wanted[:len(words)] == words:
            return probe.name
    return None


def probes_available(runner: object | None, host: str) -> bool:
    catalog = getattr(runner, "catalog", None)
    return catalog is not None and any(catalog.runs_on(p, host) for p in catalog.probes.values())


def _probes(conn: sqlite3.Connection, incident_id: int, tz: ZoneInfo) -> list[dict]:
    rows = []
    for row in probe_store.for_incident(conn, incident_id):
        rows.append({"id": row["id"], "name": row["name"], "target": row["target"], "command": row["command"],
                     "trigger": row["trigger"], "trigger_label": PROBE_TRIGGER_LABELS.get(row["trigger"], row["trigger"]),
                     "status": row["status"], "status_label": PROBE_STATUS_LABELS.get(row["status"], row["status"]),
                     "time": clock_text(row["started_at"], tz), "duration": duration_text(row["duration_ms"] / 1000),
                     "output": row["output"], "error": row["error"], "analysis_id": row["analysis_id"]})
    return rows


def detail(conn: sqlite3.Connection, incident_id: int, now: datetime, cfg: Config, *,
           runner: object | None = None) -> dict | None:
    """1 件の詳細。なければ None。runner は確認の実行器（あれば「実行」のボタンと照合が出る）。"""
    row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    if row is None:
        return None
    tz = zone(cfg)
    current = running(conn, now, cfg)
    order = _waiting_order(conn, now)
    typical = typical_duration_sec(conn)
    base = _row_dict(row, now, cfg, tz, current, order, typical)
    analyses = _analyses(conn, incident_id, tz)
    latest = shown_analysis(analyses, row["latest_analysis_id"])
    result = latest["result"] if latest else None
    context = latest["context"] if latest else {}
    raw = _json(row["raw_json"])
    members = []
    if row["source"] == "group":
        for member in conn.execute("SELECT * FROM incidents WHERE group_id = ? ORDER BY started_at, id", (incident_id,)):
            members.append(_row_dict(member, now, cfg, tz, current, order, typical))
    parent = None
    if row["group_id"]:
        parent_row = conn.execute("SELECT id, title FROM incidents WHERE id = ?", (row["group_id"],)).fetchone()
        parent = {"id": parent_row["id"], "label": label_of(parent_row["id"]), "title": parent_row["title"]} if parent_row else None
    alerts = [{"source": a["source"], "external_id": a["external_id"], "seen": clock_text(a["seen_at"], tz),
               "resolved": clock_text(a["resolved_at"], tz) if a["resolved_at"] else None}
              for a in conn.execute("SELECT * FROM alert_refs WHERE incident_id = ? ORDER BY seen_at, external_id",
                                    (incident_id,))]
    case = conn.execute("SELECT * FROM cases WHERE incident_id = ?", (incident_id,)).fetchone()
    feedback = conn.execute("SELECT at, detail_json FROM events WHERE incident_id = ? AND type = 'feedback' "
                            "ORDER BY id DESC LIMIT 1", (incident_id,)).fetchone()
    feedback_detail = _json(feedback["detail_json"]) if feedback else None
    state = row["analysis_state"]
    analysed = None
    if row["analyzed_at"] and latest:
        analysed = f"解析 {clock_text(row['analyzed_at'], tz)} 完了 · 所要 {latest['duration']}"
    position = None
    if state in (AnalysisState.QUEUED, AnalysisState.RETRY_WAIT, AnalysisState.HELD) and row["id"] in order:
        ahead = order.index(row["id"])
        eta = clock_text(now + timedelta(seconds=typical * (ahead + 1)), tz) if typical is not None else None
        position = {"ahead": ahead, "eta": eta}
    selected = [s for s in context.get("selected", []) if isinstance(s, dict)]
    parts = [p for p in context.get("parts", []) if isinstance(p, dict)]
    can_probe = probes_available(runner, row["host"])
    checks = _checks(result)
    for check in checks:
        check["probe"] = probe_for_check(runner, row["host"], check["command"]) if can_probe else None
    return {
        **base, "started": clock_text(row["started_at"], tz), "started_day": local(row["started_at"], tz).strftime("%Y-%m-%d"),
        "resolved": clock_text(row["resolved_at"], tz) if row["resolved_at"] else None,
        "kind": row["kind"], "kind_label": KIND_LABELS.get(row["kind"] or "", ""), "summary": row["summary"],
        "analysed": analysed, "position": position, "fail_reason": row["fail_reason"], "skip_reason": row["skip_reason"],
        "attempt_count": row["attempt_count"], "queue_reason": row["queue_reason"],
        "result": result, "causes": _causes(result), "checks": checks, "excluded": _excluded(result),
        "impact": {"services": _strings(_sub(result, "impact").get("services")),
                   "scope": str(_sub(result, "impact").get("scope", ""))},
        "correlation": {"incidents": _strings(_sub(result, "correlation").get("incidents")),
                        "changes": _strings(_sub(result, "correlation").get("changes"))},
        "unknowns": _strings((result or {}).get("unknowns")), "needs_human_decision": bool((result or {}).get("needs_human_decision")),
        "events": _events(conn, incident_id, tz), "analyses": analyses, "latest": latest,
        "shown_analysis_id": latest["id"] if latest else None,
        "context": {"selected": selected, "parts": parts, "mode": context.get("mode"), "tokens": context.get("tokens"),
                    "prompt_hash": context.get("prompt_hash"), "knowledge_version": context.get("knowledge_version"),
                    "notes": _strings(context.get("notes"))},
        "running": current if current and current.incident_id == incident_id else None,
        "member_rows": members, "parent": parent, "alerts": alerts, "root_down": bool(raw.get("root_down")),
        "case": dict(case) if case else None, "confirmed_at": row["confirmed_at"], "confirmed_verdict": row["confirmed_verdict"],
        "feedback": feedback_detail,
        "actions": available_actions(state, latest is not None, probes=can_probe,
                                     attachable=bool(probe_store.unattached(conn, incident_id))),
        "type_label": TYPE_LABELS.get(row["type"], row["type"]),
        "probes": _probes(conn, incident_id, tz), "probes_enabled": can_probe,
    }


@dataclass(frozen=True)
class Mark:
    """変化を見つけるための印。インシデント、経過、解析の番号と状態をまとめる。

    解析の進捗（tokens_so_far、phase）は含めない。進捗は progress のイベントだけで届く。
    """
    incidents_updated: str
    incidents_count: int
    events_id: int
    analyses_id: int
    analyses_finished: str
    analyses_states: str

    def changed(self, other: "Mark") -> bool:
        return self != other


def mark(conn: sqlite3.Connection) -> Mark:
    i_updated, i_count = conn.execute("SELECT COALESCE(MAX(updated_at), ''), COUNT(*) FROM incidents").fetchone()
    e_id = conn.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0]
    a_id, a_finished, running, done, failed = conn.execute(
        "SELECT COALESCE(MAX(id), 0), COALESCE(MAX(finished_at), ''), "
        "COALESCE(SUM(status = 'running'), 0), COALESCE(SUM(status = 'done'), 0), COALESCE(SUM(status = 'failed'), 0) "
        "FROM analyses").fetchone()
    return Mark(i_updated, int(i_count), int(e_id), int(a_id), a_finished, f"{running}/{done}/{failed}")


def changed_incidents(conn: sqlite3.Connection, since: Mark) -> set[int]:
    """前の印より後に変わったインシデントの番号。"""
    found: set[int] = set()
    for row in conn.execute("SELECT id FROM incidents WHERE updated_at > ?", (since.incidents_updated,)):
        found.add(row["id"])
    for row in conn.execute("SELECT DISTINCT incident_id FROM events WHERE id > ?", (since.events_id,)):
        found.add(row["incident_id"])
    for row in conn.execute("SELECT DISTINCT incident_id FROM analyses WHERE id > ? OR finished_at > ?",
                            (since.analyses_id, since.analyses_finished)):
        found.add(row["incident_id"])
    return found


def feedback_ratio(conn: sqlite3.Connection, since: datetime) -> dict:
    """評価の集計。「役に立った」の割合。"""
    counts = {"helpful": 0, "wrong": 0, "corrected": 0}
    for row in conn.execute("SELECT detail_json FROM events WHERE type = 'feedback' AND at >= ?", (to_iso(since),)):
        verdict = _json(row["detail_json"]).get("verdict")
        if verdict in counts:
            counts[verdict] += 1
    total = sum(counts.values())
    return {**counts, "total": total, "helpful_percent": round(counts["helpful"] * 100 / total) if total else None}
