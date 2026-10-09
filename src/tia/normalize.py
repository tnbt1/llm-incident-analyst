"""Zabbix と Wazuh の生データを、共通の形に直す。"""
from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime

from tia.config import Config
from tia.models import IncidentType, NormalizedAlert, ProblemStatus, Source
from tia.type_rules import TypeRules, classify_wazuh, classify_zabbix

TITLE_LIMIT = 200
LOG_LIMIT = 2000
ID_LIMIT = 64
HOST_LIMIT = 120
OPDATA_LIMIT = 500
KEPT_TAGS = 30
KEPT_HOSTS = 5
KEPT_ITEMS = 20
# これより外の時刻は壊れた入力とみなす。時刻の計算があふれるのも防ぐ。
EARLIEST = datetime(2000, 1, 1, tzinfo=UTC)
LATEST = datetime(2100, 1, 1, tzinfo=UTC)
ZABBIX_SEVERITY_NAMES = {0: "Not classified", 1: "Information", 2: "Warning", 3: "Average", 4: "High", 5: "Disaster"}
AVAILABILITY_KEY_PREFIXES = ("icmpping", "agent.ping", "zabbix[host")
# 制御文字と、対になっていない代用符号。後者は UTF-8 にできず、保存で失敗する。
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\ud800-\udfff]")


class NormalizationError(ValueError):
    """生データに必須の項目がない、または形が違う。"""


def clean_text(value: object, limit: int) -> str:
    """制御文字と壊れた文字を除き、長さを切る。アラートの本文は信頼しない。"""
    text = _CONTROL.sub("", str(value if value is not None else "")).strip()
    return text[:limit]


def fingerprint(source: Source, host: str, key: str) -> str:
    return hashlib.sha256(f"{source}|{host}|{key}".encode()).hexdigest()[:16]


def _require(mapping: dict, key: str, where: str):
    if not isinstance(mapping, dict) or key not in mapping:
        raise NormalizationError(f"{where} に {key} がない")
    return mapping[key]


def _scalar(value: object, limit: int, where: str) -> str:
    """文字列か数値だけを受け取る。ない場合は空文字。"""
    if value is None:
        return ""
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        raise NormalizationError(f"{where} は文字列で書く")
    return clean_text(value, limit)


def _identifier(value: object, where: str) -> str:
    text = _scalar(value, ID_LIMIT, where)
    if not text:
        raise NormalizationError(f"{where} が空")
    return text


def _mapping(value: object, where: str) -> dict:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise NormalizationError(f"{where} は対応表で書く")
    return value


def _sequence(value: object, where: str) -> list:
    if value is None:
        return []
    if not isinstance(value, list):
        raise NormalizationError(f"{where} は配列で書く")
    return value


def _plausible(moment: datetime, where: str) -> datetime:
    if not EARLIEST <= moment < LATEST:
        raise NormalizationError(f"{where} の時刻 {moment.isoformat()} は範囲外")
    return moment


def normalize_zabbix(raw: dict, cfg: Config, rules: TypeRules) -> NormalizedAlert:
    """problem.get の 1 件に、trigger.get の hosts と items を足したものを受け取る。"""
    event_id = _identifier(_require(raw, "eventid", "Zabbix の問題"), "Zabbix の問題の eventid")
    where = f"Zabbix の問題 {event_id}"
    trigger_id = _identifier(_require(raw, "objectid", where), f"{where} の objectid")
    try:
        level = int(_require(raw, "severity", where))
        clock = int(_require(raw, "clock", where))
        started = datetime.fromtimestamp(clock, UTC)
        r_clock = int(raw.get("r_clock") or 0)
        recovered = datetime.fromtimestamp(r_clock, UTC) if r_clock else None
    except (TypeError, ValueError, OverflowError, OSError) as exc:
        raise NormalizationError(f"{where} の数値が読めない: {exc}") from exc
    if level not in ZABBIX_SEVERITY_NAMES:
        raise NormalizationError(f"{where} の重大度 {level} は範囲外")
    _plausible(started, where)
    if recovered is not None:
        _plausible(recovered, f"{where} の復旧")
    hosts = _sequence(raw.get("hosts"), f"{where} の hosts")
    if not all(isinstance(h, dict) for h in hosts):
        raise NormalizationError(f"{where} の hosts の要素は対応表で書く")
    host = (_scalar(hosts[0].get("host"), HOST_LIMIT, f"{where} の host") if hosts else "") or "unknown"
    tags = [{"tag": clean_text(t.get("tag"), 100), "value": clean_text(t.get("value"), TITLE_LIMIT)}
            for t in _sequence(raw.get("tags"), f"{where} の tags") if isinstance(t, dict)]
    items = [{"itemid": clean_text(i.get("itemid"), ID_LIMIT), "key_": clean_text(i.get("key_"), 255),
              "name": clean_text(i.get("name"), TITLE_LIMIT)}
             for i in _sequence(raw.get("items"), f"{where} の items") if isinstance(i, dict)]
    item_keys = [i["key_"] for i in items]
    r_event_id = _scalar(raw.get("r_eventid"), ID_LIMIT, f"{where} の r_eventid") or "0"
    resolved = r_event_id != "0"
    availability = any(k.startswith(AVAILABILITY_KEY_PREFIXES) for k in item_keys) or any(
        t["tag"] == "scope" and t["value"] == "availability" for t in tags)
    title = clean_text(raw.get("name"), TITLE_LIMIT)
    # 保存するのは解析に使う項目だけ。入力の残りは捨てる。
    kept = {
        "eventid": event_id, "objectid": trigger_id, "clock": str(clock), "severity": str(level),
        "name": title, "opdata": clean_text(raw.get("opdata"), OPDATA_LIMIT),
        "r_eventid": r_event_id, "r_clock": str(r_clock),
        "tags": tags[:KEPT_TAGS],
        "hosts": [{"hostid": clean_text(h.get("hostid"), ID_LIMIT), "host": clean_text(h.get("host"), HOST_LIMIT),
                   "name": clean_text(h.get("name"), HOST_LIMIT)} for h in hosts[:KEPT_HOSTS]],
        "items": items[:KEPT_ITEMS],
    }
    return NormalizedAlert(
        source=Source.ZABBIX,
        external_id=event_id,
        host=host,
        type=classify_zabbix(rules, tags, item_keys),
        source_severity=f"Zabbix {ZABBIX_SEVERITY_NAMES[level]}",
        severity=max(1, level),
        title=title or "(題名なし)",
        started_at=started,
        resolved_at=recovered if resolved else None,
        problem_status=ProblemStatus.RESOLVED if resolved else ProblemStatus.OPEN,
        fingerprint=fingerprint(Source.ZABBIX, host, trigger_id),
        analyzable=level >= cfg.zabbix_min_severity,
        availability=availability,
        raw=kept,
    )


def _wazuh_severity(level: int) -> int:
    if level >= 15:
        return 5
    if level >= 12:
        return 4
    if level >= 10:
        return 3
    if level >= 7:
        return 2
    return 1


def normalize_wazuh(hit: dict, cfg: Config, rules: TypeRules) -> NormalizedAlert:
    """インデクサーの検索結果の 1 件（`_id` と `_source`）を受け取る。"""
    alert_id = _identifier(_require(hit, "_id", "Wazuh のアラート"), "Wazuh のアラートの _id")
    where = f"Wazuh のアラート {alert_id}"
    source = _require(hit, "_source", where)
    rule = _require(source, "rule", where)
    rule_id = _identifier(_require(rule, "id", f"{where} の rule"), f"{where} の rule.id")
    try:
        level = int(_require(rule, "level", f"{where} の rule"))
        started = datetime.fromisoformat(str(_require(source, "timestamp", where)))
        if started.tzinfo is None:
            started = started.replace(tzinfo=UTC)
        started = started.astimezone(UTC)
    except (TypeError, ValueError, OverflowError) as exc:
        raise NormalizationError(f"{where} の値が読めない: {exc}") from exc
    _plausible(started, where)
    agent = _mapping(source.get("agent"), f"{where} の agent")
    host = _scalar(agent.get("name"), HOST_LIMIT, f"{where} の agent.name") or "unknown"
    data = _mapping(source.get("data"), f"{where} の data")
    srcip = _scalar(data.get("srcip"), 64, f"{where} の data.srcip")
    groups = [clean_text(g, 100) for g in _sequence(rule.get("groups"), f"{where} の rule.groups")]
    syscheck = _mapping(source.get("syscheck"), f"{where} の syscheck")
    kept = {
        "timestamp": clean_text(source.get("timestamp"), 40),
        "agent": {"id": clean_text(agent.get("id"), ID_LIMIT), "name": host},
        "rule": {"id": rule_id, "level": level, "description": clean_text(rule.get("description"), TITLE_LIMIT),
                 "groups": groups},
        "data": {"srcip": srcip, "dstuser": clean_text(data.get("dstuser"), 64)},
        "syscheck": {k: clean_text(v, 300) for k, v in syscheck.items() if k in ("path", "event")},
        "full_log": clean_text(source.get("full_log"), LOG_LIMIT),
    }
    return NormalizedAlert(
        source=Source.WAZUH,
        external_id=alert_id,
        host=host,
        type=classify_wazuh(rules, rule_id, groups),
        source_severity=f"Wazuh level {level}",
        severity=_wazuh_severity(level),
        title=kept["rule"]["description"] or f"Wazuh rule {rule_id}",
        started_at=started,
        resolved_at=None,
        problem_status=ProblemStatus.ONESHOT,
        fingerprint=fingerprint(Source.WAZUH, host, f"{rule_id}|{srcip}"),
        analyzable=level >= cfg.wazuh_min_level or rule_id in cfg.wazuh_named_rules,
        availability=False,
        raw={"_id": alert_id, "_source": kept},
    )
