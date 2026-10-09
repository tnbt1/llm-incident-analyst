from datetime import UTC, datetime

import pytest

from builders import wazuh_hit, zabbix_problem
from tia import intake
from tia.config import Config
from tia.models import IncidentType, ProblemStatus, Source
from tia.normalize import NormalizationError, clean_text, normalize_wazuh, normalize_zabbix


def test_zabbix_warning_is_analyzable(cfg, rules):
    alert = normalize_zabbix(zabbix_problem(), cfg, rules)
    assert alert.source == Source.ZABBIX
    assert alert.external_id == "48213"
    assert alert.host == "example-router01"
    assert alert.type == IncidentType.CPU
    assert alert.source_severity == "Zabbix Warning"
    assert alert.severity == 2
    assert alert.analyzable is True
    assert alert.problem_status == ProblemStatus.OPEN
    assert alert.started_at == datetime.fromtimestamp(1790661060, UTC)


def test_zabbix_information_is_not_analyzable(cfg, rules):
    alert = normalize_zabbix(zabbix_problem(severity=1), cfg, rules)
    assert alert.source_severity == "Zabbix Information"
    assert alert.analyzable is False


def test_zabbix_threshold_follows_config(rules):
    alert = normalize_zabbix(zabbix_problem(severity=2), Config(zabbix_min_severity=3), rules)
    assert alert.analyzable is False


def test_zabbix_resolved_problem_carries_the_recovery_time(cfg, rules):
    alert = normalize_zabbix(zabbix_problem(r_eventid="48300", r_clock="1790661360"), cfg, rules)
    assert alert.problem_status == ProblemStatus.RESOLVED
    assert alert.resolved_at == datetime.fromtimestamp(1790661360, UTC)


def test_zabbix_same_trigger_gives_same_fingerprint(cfg, rules):
    first = normalize_zabbix(zabbix_problem(event_id="1"), cfg, rules)
    second = normalize_zabbix(zabbix_problem(event_id="2"), cfg, rules)
    other = normalize_zabbix(zabbix_problem(event_id="3", trigger_id="999"), cfg, rules)
    assert first.fingerprint == second.fingerprint
    assert first.fingerprint != other.fingerprint


@pytest.mark.parametrize("keys, tags, expected", [
    (("icmpping",), [], True),
    (("agent.ping",), [], True),
    (("zabbix[host,agent,available]",), [], True),
    (("system.cpu.util",), [{"tag": "scope", "value": "availability"}], True),
    (("system.cpu.util",), [], False),
])
def test_zabbix_availability(cfg, rules, keys, tags, expected):
    assert normalize_zabbix(zabbix_problem(keys=keys, tags=tags), cfg, rules).availability is expected


def test_zabbix_problem_without_host_is_kept(cfg, rules):
    alert = normalize_zabbix(zabbix_problem(host=None), cfg, rules)
    assert alert.host == "unknown"


@pytest.mark.parametrize("broken", [
    {},
    {"eventid": "1"},
    {"eventid": "1", "objectid": "2", "severity": "abc", "clock": "1"},
    {"eventid": "1", "objectid": "2", "severity": "9", "clock": "1"},
    {"eventid": "1", "objectid": "2", "severity": "2", "clock": "yesterday"},
])
def test_zabbix_broken_input_is_rejected(cfg, rules, broken):
    with pytest.raises(NormalizationError):
        normalize_zabbix(broken, cfg, rules)


def test_wazuh_level_10_is_analyzable(cfg, rules):
    alert = normalize_wazuh(wazuh_hit(), cfg, rules)
    assert alert.source == Source.WAZUH
    assert alert.type == IncidentType.AUTH
    assert alert.source_severity == "Wazuh level 10"
    assert alert.severity == 3
    assert alert.analyzable is True
    assert alert.problem_status == ProblemStatus.ONESHOT
    assert alert.started_at == datetime(2026, 9, 29, 5, 56, 1, tzinfo=UTC)


def test_wazuh_named_rule_below_the_level_is_analyzable(cfg, rules):
    alert = normalize_wazuh(wazuh_hit(rule_id="550", level=7, groups=("ossec", "syscheck")), cfg, rules)
    assert alert.analyzable is True
    assert alert.severity == 2


def test_wazuh_low_level_is_not_analyzable(cfg, rules):
    assert normalize_wazuh(wazuh_hit(rule_id="5715", level=3), cfg, rules).analyzable is False


@pytest.mark.parametrize("level, expected", [(3, 1), (7, 2), (10, 3), (12, 4), (15, 5)])
def test_wazuh_severity_mapping(cfg, rules, level, expected):
    assert normalize_wazuh(wazuh_hit(level=level), cfg, rules).severity == expected


def test_wazuh_fingerprint_separates_source_addresses(cfg, rules):
    first = normalize_wazuh(wazuh_hit(alert_id="a", srcip="192.0.2.5"), cfg, rules)
    same = normalize_wazuh(wazuh_hit(alert_id="b", srcip="192.0.2.5"), cfg, rules)
    other = normalize_wazuh(wazuh_hit(alert_id="c", srcip="192.0.2.7"), cfg, rules)
    assert first.fingerprint == same.fingerprint
    assert first.fingerprint != other.fingerprint


@pytest.mark.parametrize("timestamp", [
    "2026-09-29T05:56:01.000+0000",
    "2026-09-29T05:56:01+00:00",
    "2026-09-29T14:56:01.000+0900",
    "2026-09-29T05:56:01",
])
def test_wazuh_timestamp_formats(cfg, rules, timestamp):
    alert = normalize_wazuh(wazuh_hit(timestamp=timestamp), cfg, rules)
    assert alert.started_at == datetime(2026, 9, 29, 5, 56, 1, tzinfo=UTC)


def test_wazuh_log_is_truncated_and_cleaned(cfg, rules):
    alert = normalize_wazuh(wazuh_hit(full_log="a\x00b\x1b[31m" + "x" * 5000, description="d\x07" + "y" * 500),
                            cfg, rules)
    log = alert.raw["_source"]["full_log"]
    assert len(log) == 2000
    assert "\x00" not in log and "\x1b" not in log
    assert len(alert.title) == 200
    assert "\x07" not in alert.title


def test_wazuh_keeps_only_the_listed_fields(cfg, rules):
    hit = wazuh_hit()
    hit["_source"]["decoder"] = {"name": "sshd"}
    hit["_source"]["syscheck"] = {"path": "/etc/nftables.conf", "event": "modified", "md5_after": "abc"}
    kept = normalize_wazuh(hit, cfg, rules).raw["_source"]
    assert "decoder" not in kept
    assert kept["syscheck"] == {"path": "/etc/nftables.conf", "event": "modified"}


@pytest.mark.parametrize("broken", [
    {},
    {"_id": "1"},
    {"_id": "1", "_source": {}},
    {"_id": "1", "_source": {"rule": {"id": "1", "level": "x"}, "timestamp": "2026-09-29T05:56:01+00:00"}},
    {"_id": "1", "_source": {"rule": {"id": "1", "level": 3}, "timestamp": "not a time"}},
])
def test_wazuh_broken_input_is_rejected(cfg, rules, broken):
    with pytest.raises(NormalizationError):
        normalize_wazuh(broken, cfg, rules)


def test_clean_text_handles_none_and_numbers():
    assert clean_text(None, 10) == ""
    assert clean_text(12345, 3) == "123"
    assert clean_text("  a\tb\n ", 10) == "a\tb"


@pytest.mark.parametrize("change", [
    {"hosts": [None]},
    {"hosts": "example-router01"},
    {"hosts": {"host": "example-router01"}},
    {"hosts": [{"host": ["example-router01"]}]},
    {"tags": 5},
    {"tags": {"tag": "scope", "value": "availability"}},
    {"items": "system.cpu.util"},
    {"clock": "9" * 30},
    {"r_eventid": "5", "r_clock": "9" * 30},
    {"eventid": None},
    {"eventid": {"id": 1}},
    {"objectid": ["23456"]},
    {"eventid": "\ud800"},
])
def test_zabbix_malformed_structure_is_rejected(cfg, rules, change):
    with pytest.raises(NormalizationError):
        normalize_zabbix(zabbix_problem() | change, cfg, rules)


@pytest.mark.parametrize("raw", [None, [], "problem", 5])
def test_zabbix_item_that_is_not_a_mapping_is_rejected(cfg, rules, raw):
    with pytest.raises(NormalizationError):
        normalize_zabbix(raw, cfg, rules)


def test_zabbix_keeps_only_the_listed_fields_cleaned_and_cut(cfg, rules):
    raw = zabbix_problem(name="n\x00" + "x" * 500,
                         tags=[{"tag": f"t{n}", "value": "v\x07", "extra": "e"} for n in range(40)],
                         keys=[f"key{n}" for n in range(30)])
    raw["opdata"] = "o" * 1000
    raw["acknowledges"] = [{"message": "m" * 100000}]
    raw["hosts"][0]["interfaces"] = [{"ip": "192.0.2.4"}]
    kept = normalize_zabbix(raw, cfg, rules).raw
    assert set(kept) == {"eventid", "objectid", "clock", "severity", "name", "opdata", "r_eventid", "r_clock",
                         "tags", "hosts", "items"}
    assert kept["name"] == "n" + "x" * 199
    assert kept["opdata"] == "o" * 500
    assert len(kept["tags"]) == 30
    assert kept["tags"][0] == {"tag": "t0", "value": "v"}
    assert kept["hosts"] == [{"hostid": "10650", "host": "example-router01", "name": "example-router01"}]
    assert len(kept["items"]) == 20
    assert kept["items"][0] == {"itemid": "1", "key_": "key0", "name": ""}
    assert (kept["eventid"], kept["objectid"], kept["clock"], kept["severity"]) == ("48213", "23456", "1790661060",
                                                                                     "2")


def test_zabbix_tags_beyond_the_kept_ones_still_decide_the_type(cfg, rules):
    tags = [{"tag": f"t{n}", "value": "v"} for n in range(35)]
    tags += [{"tag": "scope", "value": "availability"}, {"tag": "component", "value": "network"}]
    alert = normalize_zabbix(zabbix_problem(tags=tags, keys=()), cfg, rules)
    assert alert.availability is True
    assert alert.type is IncidentType.NET


def _wazuh_with(**changes):
    hit = wazuh_hit()
    hit["_source"].update(changes)
    return hit


@pytest.mark.parametrize("change", [
    {"agent": "example-router01"},
    {"agent": ["example-router01"]},
    {"agent": {"id": "001", "name": {"first": "frr"}}},
    {"data": "192.0.2.5"},
    {"data": {"srcip": ["192.0.2.5"]}},
    {"syscheck": "/etc/passwd"},
    {"timestamp": "9999-12-31T23:59:59-23:59"},
    {"timestamp": "0001-01-01T00:00:00+23:59"},
    {"rule": {"id": "5712", "level": 10, "groups": 5}},
    {"rule": {"id": "5712", "level": 10, "groups": "sshd"}},
    {"rule": {"id": None, "level": 10}},
    {"rule": {"id": ["5712"], "level": 10}},
])
def test_wazuh_malformed_structure_is_rejected(cfg, rules, change):
    with pytest.raises(NormalizationError):
        normalize_wazuh(_wazuh_with(**change), cfg, rules)


@pytest.mark.parametrize("hit", [None, [], "alert", {"_id": None, "_source": {}}, {"_id": "1", "_source": "x"}])
def test_wazuh_item_that_is_not_a_mapping_is_rejected(cfg, rules, hit):
    with pytest.raises(NormalizationError):
        normalize_wazuh(hit, cfg, rules)


def test_clean_text_drops_lone_surrogates():
    assert clean_text("CPU\ud800 high\udfff", 50) == "CPU high"
    assert clean_text("絵文字 \U0001f525 は残す", 50) == "絵文字 \U0001f525 は残す"


def test_zabbix_alert_with_lone_surrogates_can_be_saved(conn, cfg, rules, now):
    raw = zabbix_problem(event_id="48\ud800213", name="High\ud800 CPU", host="frr\udc00",
                         tags=[{"tag": "t\ud800", "value": "v\udfff"}], keys=("system.cpu\ud800.util",))
    raw["opdata"] = "\ud800"
    alert = normalize_zabbix(raw, cfg, rules)
    assert (alert.external_id, alert.host, alert.title) == ("48213", "frr", "High CPU")
    assert intake.apply(conn, alert, now, cfg).outcome == "created"


def test_wazuh_alert_with_lone_surrogates_can_be_saved(conn, cfg, rules, now):
    hit = wazuh_hit(alert_id="w\ud800-1", host="frr\udc00", description="sshd\ud800", full_log="log\udfff",
                    srcip="192.0.2.5\ud800", groups=("sshd\ud800",))
    hit["_source"]["agent"]["id"] = "001\ud800"
    hit["_source"]["syscheck"] = {"path": "/etc/\ud800passwd"}
    alert = normalize_wazuh(hit, cfg, rules)
    assert (alert.external_id, alert.host, alert.title) == ("w-1", "frr", "sshd")
    assert intake.apply(conn, alert, now, cfg).outcome == "created"


@pytest.mark.parametrize("change", [
    {"clock": "0"},
    {"clock": "946684799"},      # 1999-12-31T23:59:59Z
    {"clock": "4102444800"},     # 2100-01-01T00:00:00Z
    {"clock": "-1790661060"},
    {"r_eventid": "9", "r_clock": "5"},
])
def test_zabbix_time_outside_the_plausible_range_is_rejected(cfg, rules, change):
    with pytest.raises(NormalizationError, match="範囲外"):
        normalize_zabbix(zabbix_problem() | change, cfg, rules)


@pytest.mark.parametrize("timestamp", [
    "0001-01-01T00:10:00+00:00",
    "1999-12-31T23:59:59+00:00",
    "2100-01-01T00:00:00+00:00",
])
def test_wazuh_time_outside_the_plausible_range_is_rejected(cfg, rules, timestamp):
    with pytest.raises(NormalizationError, match="範囲外"):
        normalize_wazuh(wazuh_hit(timestamp=timestamp), cfg, rules)

