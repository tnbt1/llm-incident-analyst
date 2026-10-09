"""Zabbix の問題の収集。未解決と復旧直後の問題を一覧し、保存済みのものと突き合わせる。"""
from __future__ import annotations

import itertools
import json
import logging
import re
import sqlite3
from collections import Counter
from collections.abc import Callable, Iterator, Sequence
from datetime import UTC, datetime

from tia import db, intake
from tia.collectors import state
from tia.collectors.base import PollReport, SourceError, note_rejected, read_secret, scrub
from tia.collectors.endpoints import ZabbixEndpoint
from tia.collectors.http import Http, tls_context
from tia.config import Config
from tia.models import Source
from tia.normalize import EARLIEST, LATEST, NormalizationError, normalize_zabbix
from tia.type_rules import TypeRules

log = logging.getLogger("tia.collect.zabbix")

PROBLEM_FIELDS = ["eventid", "objectid", "clock", "severity", "name", "opdata", "r_eventid", "r_clock"]
# 認証や権限の誤りを示す文言。Zabbix は HTTP 200 で誤りを返すので、文言で見分ける。
NOT_AUTHORIZED = re.compile(r"not authori[sz]ed|no permissions|session terminated|re-?login|token.{0,20}expired",
                            re.IGNORECASE)
LOOKUP_CHUNK = 200
# 復旧の出来事も問題の行もないまま、読み切った一覧にこの回数続けてなければ、復旧にする。
# 1 回の変な応答で、発生中のインシデントを閉じないため。
MISSING_ROUNDS_TO_CLOSE = 3


def _chunks(values: Sequence[str], size: int) -> Iterator[list[str]]:
    for start in range(0, len(values), size):
        yield list(values[start:start + size])


def _digits(value: object) -> str | None:
    """Zabbix の番号。数字だけの文字列にして返す。番号でなければ None。"""
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return None
    text = str(value)
    return text if text.isascii() and text.isdigit() and len(text) <= 20 else None


def _event_id(row: object) -> str | None:
    return _digits(row.get("eventid")) if isinstance(row, dict) else None


def _recovery_id(row: dict) -> str | None:
    """復旧の出来事の番号。未復旧なら None。"""
    value = _digits(row.get("r_eventid"))
    return value if value and int(value) else None


def _moment(value: object, now: datetime) -> datetime:
    """復旧の時刻。読めない値と範囲外の値は、復旧を知った時刻で代える。"""
    try:
        moment = datetime.fromtimestamp(int(value), UTC)  # type: ignore[arg-type]
    except (TypeError, ValueError, OverflowError, OSError):
        return now
    return moment if EARLIEST <= moment < LATEST else now


class ZabbixClient:
    """JSON-RPC の呼び出し。読み取りの `*.get` だけを使う。"""

    def __init__(self, http: Http, url: str, token: str) -> None:
        self._http = http
        self._url = url
        self._token = token
        self._ids = itertools.count(1)

    def call(self, method: str, params: dict) -> list:
        request_id = next(self._ids)
        data = self._http.post_json(
            self._url, {"jsonrpc": "2.0", "method": method, "params": params, "id": request_id},
            content_type="application/json-rpc", headers={"Authorization": f"Bearer {self._token}"},
            secrets=(self._token,))
        if not isinstance(data, dict):
            raise SourceError("invalid_response", f"{method} の応答が JSON-RPC の形でない")
        if "error" in data:
            error = data["error"] if isinstance(data["error"], dict) else {}
            detail = scrub(f"{error.get('message', '')} {error.get('data', '')}".strip(), (self._token,))
            kind = "auth" if NOT_AUTHORIZED.search(detail) else "rpc"
            raise SourceError(kind, f"Zabbix が {method} を断った: {detail or '理由の記載なし'}")
        if data.get("id") != request_id:
            raise SourceError("invalid_response", f"{method} の応答の番号が要求と合わない")
        result = data.get("result")
        if not isinstance(result, list):
            raise SourceError("invalid_response", f"{method} の結果が配列でない")
        return result


def _resume_point(text: str | None) -> str | None:
    """保存した続きの番号。読めない値は None を返し、先頭から読み直す。"""
    try:
        value = json.loads(text or "null")
    except ValueError:
        return None
    return _digits(value.get("from")) if isinstance(value, dict) else None


def _list_problems(client: ZabbixClient, cfg: Config, should_stop: Callable[[], bool],
                   start: str | None) -> tuple[dict[str, dict], int, bool, str | None]:
    """未解決と復旧直後の問題を、番号の順にページで読む。start は、前の収集の読み残しの続き。

    戻り値は、番号ごとの問題、形の違う行の数、末尾まで読んだか、読み残しの続きの番号。
    1 回に読むのは page_size × max_pages 件まで。
    """
    listed: dict[str, dict] = {}
    malformed = 0
    for _ in range(cfg.zabbix_max_pages):
        if should_stop():
            return listed, malformed, False, start
        params: dict = {
            "output": PROBLEM_FIELDS, "selectTags": ["tag", "value"], "source": 0, "object": 0,
            "recent": True, "suppressed": False,
            "severities": list(range(cfg.zabbix_fetch_min_severity, 6)),
            "sortfield": ["eventid"], "sortorder": "ASC", "limit": cfg.zabbix_page_size,
        }
        if start is not None:
            params["eventid_from"] = start
        rows = client.call("problem.get", params)
        last = 0
        for row in rows[:cfg.zabbix_page_size]:
            event_id = _event_id(row)
            if event_id is None:
                malformed += 1
                continue
            listed[event_id] = row
            last = max(last, int(event_id))
        if len(rows) < cfg.zabbix_page_size:
            return listed, malformed, True, None
        if not last:
            raise SourceError("invalid_response", "problem.get の結果に番号がなく、続きを読めない")
        start = str(last + 1)
    return listed, malformed, False, start


def _known(conn: sqlite3.Connection, event_ids: Sequence[str]) -> dict[str, bool]:
    """保存済みの番号と、復旧を記録済みか。"""
    found: dict[str, bool] = {}
    for chunk in _chunks(event_ids, 500):
        marks = ",".join("?" * len(chunk))
        found.update((row["external_id"], row["resolved_at"] is not None) for row in conn.execute(
            f"SELECT external_id, resolved_at FROM alert_refs WHERE source = ? AND external_id IN ({marks})",
            (Source.ZABBIX, *chunk)))
    return found


def _triggers(client: ZabbixClient, rows: Sequence[dict]) -> dict[str, dict]:
    """問題を出したトリガーの、ホストと項目を引く。"""
    trigger_ids = sorted({t for t in (_digits(row.get("objectid")) for row in rows) if t})
    found: dict[str, dict] = {}
    for chunk in _chunks(trigger_ids, LOOKUP_CHUNK):
        for trigger in client.call("trigger.get", {
                "output": ["triggerid"], "triggerids": chunk,
                "selectHosts": ["hostid", "host", "name"], "selectItems": ["itemid", "key_", "name"]}):
            trigger_id = _digits(trigger.get("triggerid")) if isinstance(trigger, dict) else None
            if trigger_id:
                found[trigger_id] = trigger
    return found


def _mark_listed(conn: sqlite3.Connection, event_ids: Sequence[str], round_no: int) -> None:
    """この回の一覧にあったことを残す。一覧を何回かに分けて読んでも、消えた問題を取り違えないため。"""
    for chunk in _chunks(event_ids, 500):
        marks = ",".join("?" * len(chunk))
        conn.execute("UPDATE alert_refs SET listed_round = ?, missing_rounds = 0 "
                     f"WHERE source = ? AND external_id IN ({marks})", (round_no, Source.ZABBIX, *chunk))


def _count_missing(conn: sqlite3.Connection, event_id: str, rounds: int) -> None:
    conn.execute("UPDATE alert_refs SET missing_rounds = ? WHERE source = ? AND external_id = ? "
                 "AND missing_rounds != ?", (rounds, Source.ZABBIX, event_id, rounds))


def _settle_missing(conn: sqlite3.Connection, client: ZabbixClient, round_no: int, now: datetime,
                    cfg: Config, counts: Counter) -> None:
    """一覧を末尾まで読んだ後に、保存済みで未復旧なのに、この回の一覧になかったものを調べる。

    復旧の出来事があれば、その時刻で復旧にする。抑制中など、未解決のまま一覧から外れただけのものは
    そのままにする。どちらでもないもの（トリガーの無効化、出来事の削除、一時的に見えないだけ）は、
    読み切った一覧に MISSING_ROUNDS_TO_CLOSE 回続けてなかったときに、その時刻で復旧にする。
    最後に、この回を読み切ったことを記録する。
    """
    limit = cfg.zabbix_page_size * cfg.zabbix_max_pages
    absent = {row["external_id"]: row["missing_rounds"] for row in conn.execute(
        "SELECT external_id, missing_rounds FROM alert_refs WHERE source = ? AND resolved_at IS NULL "
        "AND (listed_round IS NULL OR listed_round < ?) ORDER BY seen_at, external_id LIMIT ?",
        (Source.ZABBIX, round_no, limit))}
    missing = list(absent)
    if not missing:
        state.finish_round(conn, Source.ZABBIX)
        return
    recovery_of: dict[str, str] = {}
    for chunk in _chunks(missing, LOOKUP_CHUNK):
        for event in client.call("event.get", {"output": ["eventid", "r_eventid"], "eventids": chunk,
                                               "source": 0, "object": 0}):
            event_id = _event_id(event)
            recovery = _recovery_id(event) if event_id else None
            if event_id in chunk and recovery:
                recovery_of[event_id] = recovery
    clocks: dict[str, object] = {}
    for chunk in _chunks(sorted(set(recovery_of.values())), LOOKUP_CHUNK):
        for event in client.call("event.get", {"output": ["eventid", "clock"], "eventids": chunk,
                                               "source": 0, "object": 0}):
            event_id = _event_id(event)
            if event_id:
                clocks[event_id] = event.get("clock")
    hidden: set[str] = set()
    for chunk in _chunks([m for m in missing if m not in recovery_of], LOOKUP_CHUNK):
        for problem in client.call("problem.get", {"output": ["eventid", "r_eventid"], "eventids": chunk,
                                                   "source": 0, "object": 0}):
            event_id = _event_id(problem)
            if event_id in chunk and not _recovery_id(problem):
                hidden.add(event_id)
    with db.transaction(conn):
        for event_id in missing:
            if event_id in hidden:
                counts["hidden"] += 1
                _count_missing(conn, event_id, 0)
                continue
            if event_id in recovery_of:
                resolved_at = _moment(clocks.get(recovery_of[event_id]), now)
            elif absent[event_id] + 1 < MISSING_ROUNDS_TO_CLOSE:
                counts["missing"] += 1
                _count_missing(conn, event_id, absent[event_id] + 1)
                continue
            else:
                resolved_at = now
            if intake.resolve(conn, Source.ZABBIX, event_id, resolved_at, now):
                counts["resolved"] += 1
        state.finish_round(conn, Source.ZABBIX)


def collect(conn: sqlite3.Connection, client: ZabbixClient, now: datetime, cfg: Config, rules: TypeRules,
            should_stop: Callable[[], bool] = lambda: False, rejected: set[str] | None = None) -> PollReport:
    """1 回の収集。通信を先に済ませ、保存は短いまとまりで行う。通信の間は保存先の鍵を持たない。

    一覧が 1 回に読む上限を超えたら、続きの番号を保存し、次の収集はそこから読む。
    消えた問題を調べるのは、末尾まで読み切った回だけ。
    """
    rejected = set() if rejected is None else rejected
    counts: Counter = Counter()
    before = state.get(conn, Source.ZABBIX)
    round_no = before.round + 1
    listed, malformed, reached_end, resume = _list_problems(client, cfg, should_stop,
                                                            _resume_point(before.cursor))
    counts["fetched"] = len(listed) + malformed
    counts["rejected"] = malformed
    known = _known(conn, list(listed))
    fresh = [row for event_id, row in listed.items() if event_id not in known]
    triggers = _triggers(client, fresh) if fresh else {}
    with db.transaction(conn):
        for row in fresh:
            trigger = triggers.get(_digits(row.get("objectid")) or "", {})
            try:
                alert = normalize_zabbix({**row, "hosts": trigger.get("hosts"), "items": trigger.get("items")},
                                         cfg, rules)
            except NormalizationError as exc:
                counts["rejected"] += 1
                note_rejected(rejected, log, "Zabbix の問題", _event_id(row) or "", exc)
                continue
            counts[intake.apply(conn, alert, now, cfg).outcome] += 1
        for event_id, row in listed.items():
            if event_id not in known:
                continue
            counts["known"] += 1
            if _recovery_id(row):
                if intake.resolve(conn, Source.ZABBIX, event_id, _moment(row.get("r_clock"), now), now):
                    counts["resolved"] += 1
            elif known[event_id] and intake.reopen(conn, Source.ZABBIX, event_id, now):
                # 復旧と記録したものが、未解決のまま一覧に戻った。
                counts["reopened"] += 1
        _mark_listed(conn, list(listed), round_no)
        if not reached_end:
            state.set_cursor(conn, Source.ZABBIX, json.dumps({"from": resume}))
    complete = reached_end and not should_stop()
    if complete:
        _settle_missing(conn, client, round_no, now, cfg, counts)
    newest = max((int(event_id) for event_id in listed), default=0)
    return PollReport(Source.ZABBIX, {name: count for name, count in counts.items() if count}, complete,
                      str(newest) if newest else None)


class ZabbixPoller:
    source = Source.ZABBIX

    def __init__(self, endpoint: ZabbixEndpoint) -> None:
        self._endpoint = endpoint
        self._rejected: set[str] = set()

    def poll(self, conn: sqlite3.Connection, now: datetime, cfg: Config, rules: TypeRules,
             should_stop: Callable[[], bool] = lambda: False) -> PollReport:
        """秘密は収集のたびに読む。入れ替えた秘密が、再起動なしで効く。"""
        token = read_secret(self._endpoint.token_file, "Zabbix の API トークン", header_safe=True)
        with Http(cfg, tls_context(None)) as http:
            client = ZabbixClient(http, self._endpoint.url, token)
            return collect(conn, client, now, cfg, rules, should_stop, self._rejected)
