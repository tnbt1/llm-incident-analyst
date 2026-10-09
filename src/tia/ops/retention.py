"""保持期間の整理。古いものを消し、本文を落とす。発生中、待ち、解析中、事例のあるものは残す。"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta

from tia.config import Config
from tia.models import to_iso

EMPTY_PAYLOAD = "{}"
# 消してよいインシデントの条件。発生中でなく、終わっていて、事例がない。年齢は _AGED が足す。
# 表の別名は i。構成要素を調べるときは m に置き換える
_FINISHED = ("i.problem_status != 'open' AND i.analysis_state IN ('done', 'failed', 'skipped', 'grouped') "
             "AND NOT EXISTS (SELECT 1 FROM cases c WHERE c.incident_id = i.id)")
_AGED = ("((i.analysis_state = 'skipped' AND i.updated_at < :skipped) "
         "OR COALESCE(i.resolved_at, i.last_occurrence_at) < :incident)")


@dataclass(frozen=True)
class RetentionReport:
    incidents_deleted: int = 0
    events_deleted: int = 0
    alert_refs_deleted: int = 0
    analyses_deleted: int = 0
    payloads_cleared: int = 0
    contexts_cleared: int = 0
    kept_for_cases: int = 0
    checkpointed: bool = False

    def summary(self) -> str:
        return (f"保持期間の整理: インシデント {self.incidents_deleted} 件、経過 {self.events_deleted} 件、"
                f"アラートの参照 {self.alert_refs_deleted} 件、解析 {self.analyses_deleted} 件を消した。"
                f"本文を落とした: アラート {self.payloads_cleared} 件、文脈 {self.contexts_cleared} 件。"
                f"事例があるので残した: {self.kept_for_cases} 件")


def _limits(now: datetime, cfg: Config) -> dict[str, str]:
    return {"incident": to_iso(now - timedelta(days=cfg.retention_incident_days)),
            "skipped": to_iso(now - timedelta(days=cfg.retention_skipped_days)),
            "payload": to_iso(now - timedelta(days=cfg.retention_payload_days))}


def _for_member(clause: str) -> str:
    return clause.replace("i.", "m.")


def expired(conn: sqlite3.Connection, now: datetime, cfg: Config) -> tuple[list[int], list[int]]:
    """消してよい番号。(群でないもの, 群の構成要素と群) の順。群は構成要素が全部消せるときだけ。"""
    limits = _limits(now, cfg)
    plain = [row["id"] for row in conn.execute(
        f"SELECT i.id FROM incidents i WHERE i.group_id IS NULL AND i.source != 'group' AND {_FINISHED} AND {_AGED} "
        "ORDER BY i.id", limits)]
    groups = [row["id"] for row in conn.execute(
        f"SELECT i.id FROM incidents i WHERE i.source = 'group' AND {_FINISHED} AND {_AGED} "
        "AND NOT EXISTS (SELECT 1 FROM incidents m WHERE m.group_id = i.id "
        f"AND NOT ({_for_member(_FINISHED)} AND {_for_member(_AGED)})) ORDER BY i.id", limits)]
    members = [row["id"] for group in groups
               for row in conn.execute("SELECT id FROM incidents WHERE group_id = ? ORDER BY id", (group,))]
    return plain, members + groups


def _delete(conn: sqlite3.Connection, ids: list[int]) -> tuple[int, int, int, int]:
    """番号の列のインシデントと、その行を消す。構成要素は群より先に消す。"""
    if not ids:
        return 0, 0, 0, 0
    marks = ",".join("?" * len(ids))
    conn.execute(f"DELETE FROM probes WHERE incident_id IN ({marks})", ids)
    analyses = conn.execute(f"DELETE FROM analyses WHERE incident_id IN ({marks})", ids).rowcount
    events =conn.execute(f"DELETE FROM events WHERE incident_id IN ({marks})", ids).rowcount
    refs = conn.execute(f"DELETE FROM alert_refs WHERE incident_id IN ({marks})", ids).rowcount
    members = conn.execute(f"DELETE FROM incidents WHERE id IN ({marks}) AND group_id IS NOT NULL", ids).rowcount
    others = conn.execute(f"DELETE FROM incidents WHERE id IN ({marks})", ids).rowcount
    return members + others, events, refs, analyses


def apply(conn: sqlite3.Connection, now: datetime, cfg: Config, *, dry_run: bool = False) -> RetentionReport:
    """整理を 1 回行う。dry_run なら同じ処理を行って取り消し、数だけを返す。"""
    if conn.in_transaction:
        raise RuntimeError("保持期間の整理は、ほかのまとまりの中では行わない")
    limits = _limits(now, cfg)
    conn.execute("BEGIN IMMEDIATE")
    try:
        plain, grouped = expired(conn, now, cfg)
        kept = conn.execute(
            f"SELECT COUNT(*) FROM incidents i WHERE i.problem_status != 'open' AND {_AGED} "
            "AND EXISTS (SELECT 1 FROM cases c WHERE c.incident_id = i.id)", limits).fetchone()[0]
        deleted = [a + b for a, b in zip(_delete(conn, plain), _delete(conn, grouped), strict=True)]
        # 本文を落とすのは、解析が終わったものだけ。待ち（queued、held、retry_wait）の本文は解析に要る
        payloads = conn.execute(
            "UPDATE incidents SET raw_json = ? WHERE raw_json != ? AND source != 'group' AND problem_status != 'open' "
            "AND analysis_state IN ('done', 'failed', 'skipped', 'grouped') "
            "AND COALESCE(resolved_at, last_occurrence_at) < ?",
            (EMPTY_PAYLOAD, EMPTY_PAYLOAD, limits["payload"])).rowcount
        contexts = conn.execute(
            "UPDATE analyses SET context_json = NULL WHERE context_json IS NOT NULL AND started_at < ?",
            (limits["payload"],)).rowcount
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("ROLLBACK" if dry_run else "COMMIT")
    checkpointed = False
    if not dry_run:
        # 消した分の WAL を本体に写し、ファイルを縮める。VACUUM はしない
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        checkpointed = True
    return RetentionReport(deleted[0], deleted[1], deleted[2], deleted[3], payloads, contexts, kept, checkpointed)
