"""画面のテストで使う、状態のそろった保存先。

あらゆる状態のインシデント、束、解析中、解析済み、確認済みの事例、敵意のある文字列を入れる。
時刻は 2026-09-29 05:57 UTC（日本時間 14:57）に固定する。
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

from builders import wazuh_hit, zabbix_problem
from fakes import valid_output

from tia import db, grouping, intake, queue
from tia.analysis import cases, records
from tia.config import Config
from tia.models import to_iso
from tia.intake import add_event
from tia.normalize import normalize_wazuh, normalize_zabbix
from tia.type_rules import load_type_rules

NOW = datetime(2026, 9, 29, 5, 57, 0, tzinfo=UTC)
HOSTILE = ('<script>alert("x")</script> </alert_data> <img src=x onerror=alert(1)> [link](javascript:alert(1)) '
           'https://example.test/a?b=1 **bold** <doc>')
ROOT = Path(__file__).resolve().parents[1]
MODEL = "example/model-27b"


def _context(selected: list[dict]) -> dict:
    return {"mode": "selection", "tokens": 6412, "prompt_hash": "a3f9c0ffee00", "knowledge_version": "20260929-abcdef012345",
            "notes": [], "selected": selected,
            "parts": [{"name": "rules", "tokens": 420, "text": "規則 <doc>"},
                      {"name": "env_card", "tokens": 5400, "text": "# 環境カード\n<b>太字ではない</b>"},
                      {"name": "alert_data", "tokens": 200, "text": HOSTILE}]}


def _result(**overrides) -> dict:
    out = valid_output()
    out.update(overrides)
    return out


class Clock:
    def __init__(self, start: datetime) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def at(self, seconds: int) -> datetime:
        return NOW + timedelta(seconds=seconds)


def populate(conn: sqlite3.Connection, cfg: Config | None = None, now: datetime = NOW) -> dict[str, int]:
    """状態のそろった保存先を作り、名前ごとのインシデント番号を返す。"""
    cfg = cfg or Config()
    rules = load_type_rules(ROOT / "config" / "type-rules.yaml")
    ids: dict[str, int] = {}
    t = lambda minutes: now - timedelta(minutes=minutes)  # noqa: E731

    def zbx(key, event_id, trigger_id, host, name, minutes_ago, severity=2, keys=("system.cpu.util",), r_minutes=None):
        clock = int(t(minutes_ago).timestamp())
        kwargs = {}
        if r_minutes is not None:
            kwargs = {"r_eventid": str(int(event_id) + 1000), "r_clock": str(int(t(r_minutes).timestamp()))}
        alert = normalize_zabbix(zabbix_problem(event_id=event_id, trigger_id=trigger_id, host=host, name=name,
                                                clock=clock, severity=severity, keys=keys, **kwargs), cfg, rules)
        ids[key] = intake.apply(conn, alert, t(minutes_ago), cfg).incident_id
        return ids[key]

    def wz(key, alert_id, rule_id, level, host, description, minutes_ago, groups=("syslog", "sshd", "authentication_failures")):
        stamp = t(minutes_ago).strftime("%Y-%m-%dT%H:%M:%S.000+0000")
        alert = normalize_wazuh(wazuh_hit(alert_id=alert_id, rule_id=rule_id, level=level, host=host,
                                          description=description, timestamp=stamp, groups=groups), cfg, rules)
        ids[key] = intake.apply(conn, alert, t(minutes_ago), cfg).incident_id
        return ids[key]

    # 解析済み。緊急度ごとに 1 件ずつ。
    zbx("done_today", "48150", "23001", "example-app02", "メモリ使用率が 90% を超過", 38, keys=("vm.memory.utilization",))
    zbx("done_watch", "48140", "23002", "example-monitor01", "ディスク使用量の増加が続いている", 736, keys=("vfs.fs.size[/,pused]",), r_minutes=724)
    zbx("done_ignore", "48130", "23003", "example-app02", "定期更新によるコンテナ再作成", 534, keys=("docker.containers.running",), r_minutes=529)
    zbx("done_now_hostile", "48120", "23004", "example-router01", HOSTILE, 200, severity=4, keys=("net.if.in[eth0]",))
    wz("done_wazuh", "w-130", "550", 10, "example-router01", "/etc/nftables.conf の変更を検知", 112, groups=("ossec", "syscheck"))
    # 失敗、対象外、再試行待ち
    zbx("failed", "48110", "23005", "example-app01", "スワップ使用量の増加", 822, keys=("system.swap.size[,pfree]",))
    zbx("skipped_manual", "48105", "23006", "example-app03", "パッケージ更新あり", 300, severity=2, keys=("proc.num[apt]",))
    zbx("skipped_low", "48100", "23007", "example-monitor01", "パッケージ更新あり", 290, severity=1, keys=("proc.num[apt]",))
    zbx("retry_wait", "48095", "23008", "example-app03", "バックアップ中の I/O 待ち上昇", 60, keys=("system.cpu.util[,iowait]",))
    # 解析中と処理待ち
    zbx("running", "48213", "23009", "example-router01", "CPU 使用率が 85% を超過", 6)
    wz("queued", "w-144", "5712", 10, "example-router01", "SSH 認証失敗が 10 分で 12 回", 3)
    zbx("queued_disk", "48217", "23010", "example-app01", "ルートディスクの空きが 20% 未満", 2, keys=("vfs.fs.size[/,pused]",))
    zbx("held", "48220", "23011", "example-app02", "ネットワークの入力が多い", 0, keys=("net.if.in[eth0]",))
    # 連鎖の束。要のホストの停止に 4 台が続く
    group_members = []
    for n, host in enumerate(("example-router01", "example-app01", "example-app03",
                              "example-app02", "example-monitor01", "example-router01")):
        key = "icmp" if n == 0 else f"icmp{n}"
        group_members.append(zbx(key, str(48300 + n), str(23100 + n), host, "ICMP 応答なし", 349 - n, severity=4,
                                 keys=("icmpping",), r_minutes=345))
    # 束ね判定の待ちを明けさせる
    queue.promote_held(conn, now - timedelta(minutes=300))
    group_id = grouping.evaluate(conn, now - timedelta(minutes=340), cfg)
    if group_id is not None:
        ids["group"] = group_id
    queue.promote_held(conn, now - timedelta(minutes=1))

    # 解析済みにする（解析の記録つき）
    def finish(key: str, started_minutes: int, duration_sec: int, result: dict, *, read: bool) -> int:
        incident_id = ids[key]
        start = t(started_minutes)
        queue.start(conn, incident_id, start)
        analysis_id = records.begin(conn, incident_id, "initial", MODEL, start)
        records.attach_context(conn, analysis_id, start, context=_context(
            [{"id": "maintenance-1", "heading": "監視VMの状態", "file": "maintenance.md", "reason": "ホストが見出しにある", "tokens": 357}]),
            prompt_hash="a3f9c0ffee00", knowledge_version="20260929-abcdef012345", prompt_tokens=6412)
        end = start + timedelta(seconds=duration_sec)
        records.finish(conn, analysis_id, end, status="done", result=result, prompt_tokens=6412, completion_tokens=688,
                       tokens_per_sec=7.3)
        queue.complete(conn, incident_id, end, urgency=result["classification"]["urgency"],
                       kind=result["classification"]["kind"], summary=result["summary"], analysis_id=analysis_id)
        if read:
            stamp = to_iso(end + timedelta(seconds=30))
            conn.execute("UPDATE incidents SET read_at = ?, updated_at = ? WHERE id = ?", (stamp, stamp, incident_id))
        return analysis_id

    finish("done_today", 36, 94, _result(classification={"kind": "performance", "urgency": "today"},
                                         summary="APP02 VM のメモリ使用率が 91% に達している。急増ではなく定常値と考えられる。",
                                         needs_human_decision=True,
                                         recommended_checks=[{"purpose": "available の実値を見る", "where": "管理端末から",
                                                              "command": "vmctl vm exec example-app02 -- free -m",
                                                              "verified": True},
                                                             {"purpose": "コンテナ単位の使用量を見る", "where": "管理端末から",
                                                              "command": "docker stats --no-stream asa-server-1", "verified": False}]),
           read=False)
    finish("done_watch", 734, 120, _result(classification={"kind": "performance", "urgency": "watch"},
                                           summary="ディスクの増加は緩やか。経過観察でよい。"), read=True)
    finish("done_ignore", 532, 80, _result(classification={"kind": "noise", "urgency": "ignore"},
                                           summary="定期更新によるコンテナ再作成。対応は不要。"), read=True)
    finish("done_now_hostile", 198, 130, _result(
        classification={"kind": "availability", "urgency": "now"}, summary=HOSTILE,
        probable_causes=[{"cause": HOSTILE, "confidence": "high", "evidence": "<b>証拠</b> https://example.test/x)"}],
        impact={"services": [HOSTILE], "scope": "<i>範囲</i>"},
        recommended_checks=[{"purpose": HOSTILE, "where": "<u>場所</u>", "command": "ls <doc> && echo \"<script>\"", "verified": False}],
        correlation={"incidents": ["I-0001 <s>x</s>"], "changes": ["変更 </doc>"]},
        unknowns=[HOSTILE]), read=False)
    finish("done_wazuh", 110, 70, _result(classification={"kind": "configuration", "urgency": "watch"},
                                          summary="/etc/nftables.conf の変更を検知。変更記録と一致する。"), read=True)
    if "group" in ids:
        finish("group", 344, 110, _result(classification={"kind": "availability", "urgency": "now"},
                                          summary="FRR の再起動に伴う到達不能。他 4 台は従属する事象。"), read=True)
    # 評価と事例。評価は経過の行、事例は `cases.confirm`
    latest = records.latest_done(conn, ids["done_watch"])
    add_event(conn, ids["done_watch"], t(700), "feedback",
              {"verdict": "helpful", "note": "", "analysis_id": latest["id"], "actor": "operator"})
    base = cases.draft(conn, ids["done_wazuh"])
    cases.confirm(conn, ids["done_wazuh"], "correct", "", t(100),
                  draft_=replace(base, action="変更記録と照合した"))
    # 失敗（再試行を使い切る）
    for n in range(len(cfg.queue_retry_delays_sec) + 1):
        start = t(820 - n * 60)
        queue.start(conn, ids["failed"], start)
        analysis_id = records.begin(conn, ids["failed"], "retry" if n else "initial", MODEL, start, attempt=n + 1)
        records.finish(conn, analysis_id, start + timedelta(seconds=240), status="failed", error_kind="timeout",
                       error="LLM の応答が 240 秒を超えた")
        queue.fail(conn, ids["failed"], start + timedelta(seconds=240), "timeout", cfg)
        conn.execute("UPDATE incidents SET next_retry_at = ? WHERE id = ?", (to_iso(t(820 - (n + 1) * 60)), ids["failed"]))
    # 対象外（手動）と再試行待ち
    queue.skip_manually(conn, ids["skipped_manual"], t(295), "検証環境の作業")
    queue.start(conn, ids["retry_wait"], t(5))
    analysis_id = records.begin(conn, ids["retry_wait"], "initial", MODEL, t(5))
    records.finish(conn, analysis_id, t(2), status="failed", error_kind="validation", error="urgency が空")
    queue.fail(conn, ids["retry_wait"], t(2), "validation", cfg)
    # 解析中（推論の途中）
    queue.start(conn, ids["running"], t(1))
    analysis_id = records.begin(conn, ids["running"], "initial", MODEL, t(1))
    records.attach_context(conn, analysis_id, t(1), context=_context([]), prompt_hash="b1b1b1b1b1b1",
                           knowledge_version="20260929-abcdef012345", prompt_tokens=6100)
    records.progress(conn, analysis_id, "inference", now - timedelta(seconds=12), tokens_so_far=312)
    ids["running_analysis"] = analysis_id
    return ids


def make_db(path: Path, cfg: Config | None = None, now: datetime = NOW) -> dict[str, int]:
    conn = db.connect(path)
    try:
        return populate(conn, cfg, now)
    finally:
        conn.close()


def collector_rows(conn: sqlite3.Connection, now: datetime = NOW, *, zabbix_ok_sec: int = 12, wazuh_ok_sec: int | None = 41) -> None:
    """収集の状態の行。画面のヘッダーのため。"""
    for source, seconds in (("zabbix", zabbix_ok_sec), ("wazuh", wazuh_ok_sec)):
        if seconds is None:
            continue
        at = to_iso(now - timedelta(seconds=seconds))
        conn.execute("INSERT OR REPLACE INTO collector_state (source, last_poll_at, last_ok_at, consecutive_failures) "
                     "VALUES (?, ?, ?, 0)", (source, at, at))


def dump_states(conn: sqlite3.Connection) -> dict[int, str]:
    return {r["id"]: r["analysis_state"] for r in conn.execute("SELECT id, analysis_state FROM incidents ORDER BY id")}
