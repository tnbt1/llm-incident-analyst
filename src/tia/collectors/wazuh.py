"""Wazuh のアラートの収集。インデクサーを時刻の順に照会し、前回位置から先を読む。"""
from __future__ import annotations

import base64
import json
import logging
import sqlite3
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta

from tia import db, intake
from tia.collectors import state
from tia.collectors.base import PollReport, SourceError, note_rejected, read_secret, scrub
from tia.collectors.endpoints import WazuhEndpoint
from tia.collectors.http import Http, tls_context
from tia.config import Config
from tia.models import Source
from tia.normalize import NormalizationError, normalize_wazuh
from tia.type_rules import TypeRules

log = logging.getLogger("tia.collect.wazuh")

SEARCH_PATH = "/wazuh-alerts-*/_search?ignore_unavailable=true&allow_no_indices=true"
SOURCE_FIELDS = ["timestamp", "agent.id", "agent.name", "rule.id", "rule.level", "rule.description",
                 "rule.groups", "data.srcip", "data.dstuser", "syscheck.path", "syscheck.event", "full_log"]


@dataclass(frozen=True)
class Position:
    """前回位置。ts は読み終えた最後の時刻（ミリ秒）。after は、読み残しがあるときの続きの位置。"""

    ts: int
    after: tuple[int, str] | None = None

    def dump(self) -> str:
        return json.dumps({"ts": self.ts, "after": list(self.after) if self.after else None})

    @staticmethod
    def load(text: str | None) -> Position | None:
        """保存した位置を読む。壊れていれば None を返し、初回と同じ扱いにする。"""
        try:
            data = json.loads(text or "")
            after = data["after"]
            if after is not None:
                after = (_millis(after[0]), _tie(after[1]))
                if len(data["after"]) != 2:
                    return None
            return Position(_millis(data["ts"]), after)
        except (ValueError, TypeError, KeyError, IndexError):
            return None


def _millis(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 2 ** 53:
        raise ValueError("時刻がミリ秒の整数でない")
    return value


def _tie(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 200:
        raise ValueError("順序を決める値が文字列でない")
    return value


def _ms(moment: datetime) -> int:
    return int(moment.timestamp() * 1000)


def build_query(cfg: Config, start_ms: int, end_ms: int, after: tuple[int, str] | None) -> dict:
    """前回位置より後で、閾値以上か名指しのルールに当たるものを、時刻の順に 1 ページ分。"""
    body: dict = {
        "size": cfg.wazuh_page_size,
        "track_total_hits": False,
        "_source": SOURCE_FIELDS,
        "sort": [{"timestamp": {"order": "asc"}}, {cfg.wazuh_tiebreak_field: {"order": "asc"}}],
        "query": {"bool": {"filter": [
            {"range": {"timestamp": {"gte": start_ms, "lte": end_ms, "format": "epoch_millis"}}},
            {"bool": {"minimum_should_match": 1, "should": [
                {"range": {"rule.level": {"gte": cfg.wazuh_min_level}}},
                {"terms": {"rule.id": sorted(cfg.wazuh_named_rules)}},
            ]}},
        ]}},
    }
    if after is not None:
        body["search_after"] = list(after)
    return body


class WazuhClient:
    def __init__(self, http: Http, url: str, user: str, password: str) -> None:
        self._http = http
        self._url = url + SEARCH_PATH
        self._auth = (user, password)
        # 記録から消す値。パスワードと、ヘッダーに載る形の両方。
        self._secrets = (password, base64.b64encode(f"{user}:{password}".encode()).decode())

    def search(self, body: dict) -> list[dict]:
        """1 ページ分の結果を返す。一部しか検索できなかった応答は失敗にする。取りこぼしを防ぐため。"""
        data = self._http.post_json(self._url, body, auth=self._auth, secrets=self._secrets)
        if not isinstance(data, dict):
            raise SourceError("invalid_response", "インデクサーの応答が対応表でない")
        if data.get("timed_out") is True:
            raise SourceError("partial", "インデクサーの検索が時間切れになった")
        shards = data.get("_shards")
        failed = shards.get("failed") if isinstance(shards, dict) else None
        if failed:
            raise SourceError("partial", f"インデクサーの検索の一部が失敗した（{scrub(failed)} 個）")
        outer = data.get("hits")
        hits = outer.get("hits") if isinstance(outer, dict) else None
        if not isinstance(hits, list):
            raise SourceError("invalid_response", "インデクサーの応答に結果の配列がない")
        return hits


# 順序を決める値を持たない文書の次から読むときに、順序を決める値の代わりに使う。どの値よりも前に並ぶ。
FIRST_TIE = " "


def _sort_values(hit: object) -> tuple[int, str | None]:
    """結果の 1 件に付いた並べ替えの値。続きを読む位置になる。

    順序を決める項目を持たない文書では、2 つ目が None になる。その 1 件だけを読み飛ばす。
    値の数や型が違う応答は、相手の振る舞いが想定と違うので、全体を失敗にする。
    """
    values = hit.get("sort") if isinstance(hit, dict) else None
    try:
        if not isinstance(values, list) or len(values) != 2:
            raise ValueError("並べ替えの値が 2 つでない")
        return _millis(values[0]), None if values[1] is None else _tie(values[1])
    except ValueError as exc:
        raise SourceError("invalid_response", f"インデクサーの結果の並べ替えの値を読めない: {exc}") from None


def _read_page(hits: list, cfg: Config, counts: Counter, rejected: set[str]
               ) -> tuple[list, list[int], tuple[int, str] | None]:
    """応答から 1 ページ分を取り出す。戻り値は、取り込む結果、それぞれの時刻、続きを読む位置。

    順序を決める値のない文書は、読み飛ばして数える。ページの最後がそれなら、続きは次の 1 ミリ秒から読む。
    同じ位置から読み直すと、同じ文書で止まり続けるため。
    """
    usable, times = [], []
    after: tuple[int, str] | None = None
    for hit in hits[:cfg.wazuh_page_size]:
        ts, tie = _sort_values(hit)
        if tie is None:
            counts["fetched"] += 1
            counts["rejected"] += 1
            key = scrub(hit.get("_id"))
            note_rejected(rejected, log, "Wazuh のアラート", key, f"{key} に順序を決める値がない")
            after = (ts + 1, FIRST_TIE)
            continue
        usable.append(hit)
        times.append(ts)
        after = (ts, tie)
    return usable, times, after if len(hits) >= cfg.wazuh_page_size else None


def _store_page(conn: sqlite3.Connection, page: list, now: datetime, cfg: Config, rules: TypeRules,
                counts: Counter, rejected: set[str], position: Position | None) -> None:
    """1 ページ分の取り込みと、前回位置の更新を、1 つのまとまりで保存する。"""
    with db.transaction(conn):
        for hit in page:
            counts["fetched"] += 1
            try:
                alert = normalize_wazuh(hit, cfg, rules)
            except NormalizationError as exc:
                counts["rejected"] += 1
                key = hit.get("_id") if isinstance(hit, dict) else None
                note_rejected(rejected, log, "Wazuh のアラート", scrub(key), exc)
                continue
            counts[intake.apply(conn, alert, now, cfg).outcome] += 1
        if position is not None:
            state.set_watermark(conn, Source.WAZUH, position.dump())


def _reread(conn: sqlite3.Connection, client: WazuhClient, now: datetime, cfg: Config, rules: TypeRules,
            mark: tuple[int, str], end_ms: int, counts: Counter, rejected: set[str],
            should_stop: Callable[[], bool]) -> None:
    """読み残しの続きを読む前に、続きの位置の手前を重ねて読む。

    位置を通り過ぎた後で検索に現れた文書を拾う。読むのは max_pages ページまで。前回位置は動かさない。
    """
    start_ms = max(mark[0] - cfg.collector_overlap_sec * 1000, 0)
    after: tuple[int, str] | None = None
    for _ in range(cfg.wazuh_max_pages):
        if should_stop():
            return
        hits = client.search(build_query(cfg, start_ms, min(mark[0], end_ms), after))
        page, _, after = _read_page(hits, cfg, counts, rejected)
        _store_page(conn, page, now, cfg, rules, counts, rejected, None)
        if after is None:
            return


def collect(conn: sqlite3.Connection, client: WazuhClient, now: datetime, cfg: Config, rules: TypeRules,
            should_stop: Callable[[], bool] = lambda: False, rejected: set[str] | None = None) -> PollReport:
    """1 回の収集。1 ページごとに、取り込みと前回位置の更新を 1 つのまとまりで保存する。

    失敗したページより先へ、前回位置は進まない。読み終えたページは、失敗しても読み直さない。
    """
    rejected = set() if rejected is None else rejected
    counts: Counter = Counter()
    stored = state.get(conn, Source.WAZUH).watermark
    position = Position.load(stored)
    if position is None:
        if stored:
            log.warning("Wazuh の前回位置を読めない。初回と同じ長さをさかのぼる")
        position = Position(_ms(now - timedelta(seconds=cfg.collector_first_lookback_sec)))
    end_ms = _ms(now)
    if position.after is not None:
        _reread(conn, client, now, cfg, rules, position.after, end_ms, counts, rejected, should_stop)
    # 読み残しがなければ、前回位置から重ねて読む。検索に遅れて現れたものを拾うため。
    start_ms = max(position.ts - cfg.collector_overlap_sec * 1000, 0)
    complete = False
    for _ in range(cfg.wazuh_max_pages):
        if should_stop():
            break
        hits = client.search(build_query(cfg, start_ms, end_ms, position.after))
        page, times, after = _read_page(hits, cfg, counts, rejected)
        newest = max([position.ts, *(min(ts, end_ms) for ts in times)])
        position = Position(newest, after)
        _store_page(conn, page, now, cfg, rules, counts, rejected, position)
        if after is None:
            complete = True
            break
    return PollReport(Source.WAZUH, {name: count for name, count in counts.items() if count}, complete,
                      position.dump())


class WazuhPoller:
    source = Source.WAZUH

    def __init__(self, endpoint: WazuhEndpoint) -> None:
        self._endpoint = endpoint
        self._rejected: set[str] = set()

    def poll(self, conn: sqlite3.Connection, now: datetime, cfg: Config, rules: TypeRules,
             should_stop: Callable[[], bool] = lambda: False) -> PollReport:
        password = read_secret(self._endpoint.password_file, "インデクサーの閲覧パスワード")
        with Http(cfg, tls_context(self._endpoint.ca_file)) as http:
            client = WazuhClient(http, self._endpoint.url, self._endpoint.user, password)
            return collect(conn, client, now, cfg, rules, should_stop, self._rejected)
