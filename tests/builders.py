"""テスト用の生データを作る。"""
from datetime import datetime


def zabbix_problem(event_id="48213", trigger_id="23456", severity=2, host="example-router01",
                   name="High CPU utilization", clock=1790661060, keys=("system.cpu.util",), tags=None,
                   r_eventid="0", r_clock="0"):
    return {
        "eventid": event_id, "objectid": trigger_id, "clock": str(clock), "severity": str(severity),
        "name": name, "r_eventid": r_eventid, "r_clock": r_clock,
        "tags": tags if tags is not None else [],
        "hosts": [{"hostid": "10650", "host": host, "name": host}] if host else [],
        "items": [{"itemid": str(n), "key_": key} for n, key in enumerate(keys, 1)],
    }


def wazuh_hit(alert_id="w-1", rule_id="5712", level=10, host="example-router01",
              groups=("syslog", "sshd", "authentication_failures"), srcip="192.0.2.5",
              timestamp="2026-09-29T05:56:01.000+0000", description="sshd: brute force", full_log="log"):
    return {"_id": alert_id, "_source": {
        "timestamp": timestamp, "agent": {"id": "001", "name": host},
        "rule": {"id": rule_id, "level": level, "description": description, "groups": list(groups)},
        "data": {"srcip": srcip, "dstuser": "root"}, "full_log": full_log}}


def at(now: datetime, seconds: int) -> datetime:
    from datetime import timedelta
    return now + timedelta(seconds=seconds)
