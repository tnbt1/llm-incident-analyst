import re
from pathlib import Path

import pytest

from tia.config import Config, load_config

ROOT = Path(__file__).resolve().parents[1]


def test_defaults_match_the_spec():
    cfg = load_config(None)
    assert cfg == Config()
    assert cfg.zabbix_min_severity == 2
    assert cfg.wazuh_min_level == 10
    assert "5712" in cfg.wazuh_named_rules
    assert cfg.queue_retry_delays_sec == (60, 300, 900)


def test_shipped_file_equals_defaults():
    assert load_config(ROOT / "config" / "analyzer.yaml") == Config()


def test_file_overrides_one_value(tmp_path):
    path = tmp_path / "analyzer.yaml"
    path.write_text("zabbix:\n  min_severity: 3\nwazuh:\n  named_rules: [550]\n", encoding="utf-8")
    cfg = load_config(path)
    assert cfg.zabbix_min_severity == 3
    assert cfg.wazuh_named_rules == frozenset({"550"})
    assert cfg.wazuh_min_level == 10


def test_unknown_key_is_rejected(tmp_path):
    path = tmp_path / "analyzer.yaml"
    path.write_text("zabbix:\n  min_severty: 3\n", encoding="utf-8")
    with pytest.raises(ValueError, match="zabbix.min_severty"):
        load_config(path)


def test_empty_file_gives_defaults(tmp_path):
    path = tmp_path / "analyzer.yaml"
    path.write_text("", encoding="utf-8")
    assert load_config(path) == Config()


@pytest.mark.parametrize(("text", "key"), [
    ("zabbix:\n  min_severity: high\n", "zabbix.min_severity"),
    ("zabbix:\n  min_severity: 9\n", "zabbix.min_severity"),
    ("zabbix:\n  min_severity: true\n", "zabbix.min_severity"),
    ("zabbix:\n  min_severity: '3'\n", "zabbix.min_severity"),
    ("zabbix:\n  hold_sec: -1\n", "zabbix.hold_sec"),
    ("zabbix:\n  hold_sec: 1.5\n", "zabbix.hold_sec"),
    ("wazuh:\n  min_level: 99\n", "wazuh.min_level"),
    ("wazuh:\n  hold_sec:\n", "wazuh.hold_sec"),
    ("wazuh:\n  named_rules: 550\n", "wazuh.named_rules"),
    ("wazuh:\n  named_rules: '550'\n", "wazuh.named_rules"),
    ("wazuh:\n  named_rules: [[550]]\n", "wazuh.named_rules"),
    ("wazuh:\n  named_rules: [true]\n", "wazuh.named_rules"),
    ("intake:\n  recurrence_window_sec: 0\n", "intake.recurrence_window_sec"),
    ("intake:\n  followup_after_sec: two hours\n", "intake.followup_after_sec"),
    ("intake:\n  skip_resolved_after_sec: -60\n", "intake.skip_resolved_after_sec"),
    ("grouping:\n  storm_count: 1\n", "grouping.storm_count"),
    ("grouping:\n  storm_window_sec: 0\n", "grouping.storm_window_sec"),
    ("grouping:\n  root_host: ''\n", "grouping.root_host"),
    ("grouping:\n  root_host: 5\n", "grouping.root_host"),
    ("queue:\n  retry_delays_sec: 60\n", "queue.retry_delays_sec"),
    ("queue:\n  retry_delays_sec: [60, soon]\n", "queue.retry_delays_sec"),
    ("queue:\n  retry_delays_sec: [60, -5]\n", "queue.retry_delays_sec"),
    ("queue:\n  retry_delays_sec: [60, 1.5]\n", "queue.retry_delays_sec"),
])
def test_wrong_type_or_range_is_rejected_with_the_key(tmp_path, text, key):
    path = tmp_path / "analyzer.yaml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ValueError, match=re.escape(key)):
        load_config(path)


@pytest.mark.parametrize("text", ["- zabbix\n", "zabbix\n", "5\n"])
def test_file_that_is_not_a_mapping_is_rejected(tmp_path, text):
    path = tmp_path / "analyzer.yaml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ValueError, match="対応表"):
        load_config(path)


def test_values_built_in_code_are_checked_too():
    with pytest.raises(ValueError, match="zabbix.min_severity"):
        Config(zabbix_min_severity=9)
    assert Config(queue_retry_delays_sec=()).queue_retry_delays_sec == ()



def test_collector_defaults_match_the_spec():
    cfg = Config()
    assert (cfg.zabbix_poll_interval_sec, cfg.wazuh_poll_interval_sec) == (30, 60)
    assert (cfg.zabbix_fetch_min_severity, cfg.zabbix_min_severity) == (1, 2)
    assert (cfg.zabbix_page_size, cfg.zabbix_max_pages) == (200, 10)
    assert (cfg.wazuh_page_size, cfg.wazuh_max_pages, cfg.wazuh_tiebreak_field) == (200, 10, "id")
    assert (cfg.collector_tick_sec, cfg.collector_overlap_sec, cfg.collector_first_lookback_sec) == (5, 120, 3600)
    assert (cfg.collector_connect_timeout_sec, cfg.collector_timeout_sec) == (5, 10)
    assert (cfg.collector_backoff_max_sec, cfg.collector_auth_backoff_sec) == (600, 900)
    assert cfg.collector_max_response_mb == 16


@pytest.mark.parametrize(("text", "key"), [
    ("zabbix:\n  poll_interval_sec: 1\n", "zabbix.poll_interval_sec"),
    ("zabbix:\n  page_size: 0\n", "zabbix.page_size"),
    ("zabbix:\n  max_pages: 101\n", "zabbix.max_pages"),
    ("zabbix:\n  fetch_min_severity: -1\n", "zabbix.fetch_min_severity"),
    ("zabbix:\n  fetch_min_severity: 3\n", "zabbix.fetch_min_severity"),
    ("wazuh:\n  poll_interval_sec: fast\n", "wazuh.poll_interval_sec"),
    ("wazuh:\n  page_size: 5000\n", "wazuh.page_size"),
    ("wazuh:\n  max_pages: 0\n", "wazuh.max_pages"),
    ("wazuh:\n  tiebreak_field: 'a b'\n", "wazuh.tiebreak_field"),
    ("wazuh:\n  tiebreak_field: 5\n", "wazuh.tiebreak_field"),
    ("wazuh:\n  tiebreak_field: ''\n", "wazuh.tiebreak_field"),
    ("collector:\n  tick_sec: 0\n", "collector.tick_sec"),
    ("collector:\n  first_lookback_sec: -1\n", "collector.first_lookback_sec"),
    ("collector:\n  overlap_sec: 1.5\n", "collector.overlap_sec"),
    ("collector:\n  overlap_sec: 9\n", "collector.overlap_sec"),
    ("collector:\n  connect_timeout_sec: 0\n", "collector.connect_timeout_sec"),
    ("collector:\n  timeout_sec: 500\n", "collector.timeout_sec"),
    ("collector:\n  backoff_max_sec: 1\n", "collector.backoff_max_sec"),
    ("collector:\n  auth_backoff_sec: true\n", "collector.auth_backoff_sec"),
    ("collector:\n  max_response_mb: 0\n", "collector.max_response_mb"),
])
def test_wrong_collector_setting_is_rejected_with_the_key(tmp_path, text, key):
    path = tmp_path / "analyzer.yaml"
    path.write_text(text, encoding="utf-8")
    # 「知らない設定」ではなく、値の誤りとして断ること。
    with pytest.raises(ValueError, match=re.escape(f"設定 {key} は")):
        load_config(path)


def test_fetch_threshold_may_equal_the_analysis_threshold():
    assert Config(zabbix_fetch_min_severity=2).zabbix_fetch_min_severity == 2
    assert Config(zabbix_min_severity=4, zabbix_fetch_min_severity=3).zabbix_fetch_min_severity == 3


@pytest.mark.parametrize(("analysed", "fetched"), [(0, 0), (1, 1), (2, 1), (5, 1)])
def test_fetch_threshold_follows_the_analysis_threshold_when_it_is_not_written(tmp_path, analysed, fetched):
    assert Config(zabbix_min_severity=analysed).zabbix_fetch_min_severity == fetched
    path = tmp_path / "analyzer.yaml"
    path.write_text(f"zabbix:\n  min_severity: {analysed}\n", encoding="utf-8")
    assert load_config(path).zabbix_fetch_min_severity == fetched


def test_fetch_threshold_above_the_analysis_threshold_names_both_settings(tmp_path):
    path = tmp_path / "analyzer.yaml"
    path.write_text("zabbix:\n  min_severity: 2\n  fetch_min_severity: 3\n", encoding="utf-8")
    with pytest.raises(ValueError) as caught:
        load_config(path)
    assert str(caught.value) == ("設定 zabbix.fetch_min_severity は zabbix.min_severity 以下で書く: "
                                 "zabbix.fetch_min_severity = 3、zabbix.min_severity = 2")


def test_wrong_analysis_threshold_is_named_even_when_the_fetch_threshold_is_not_written():
    with pytest.raises(ValueError, match=re.escape("設定 zabbix.min_severity は")):
        Config(zabbix_min_severity=9)
    with pytest.raises(ValueError, match=re.escape("設定 zabbix.min_severity は")):
        Config(zabbix_min_severity="2")


def test_probe_defaults_match_the_spec():
    cfg = Config()
    assert cfg.probes_enabled is True and cfg.probes_total_budget_sec == 30 and cfg.probes_timeout_sec == 10
    assert cfg.probes_output_cap_bytes == 4096 and cfg.probes_ssh_user == "analyst-probe"
    assert cfg.probes_catalog == "config/probes.yaml" and cfg.probes_known_hosts == "config/probes_known_hosts"
    assert cfg.probes_key_file == "/run/secrets/probe_ssh_key"


@pytest.mark.parametrize("text, key", [
    ("probes:\n  enabled: yes please\n", "probes.enabled"),
    ("probes:\n  total_budget_sec: 4\n", "probes.total_budget_sec"),
    ("probes:\n  total_budget_sec: 121\n", "probes.total_budget_sec"),
    ("probes:\n  timeout_sec: 31\n", "probes.timeout_sec"),
    ("probes:\n  timeout_sec: 20\n  total_budget_sec: 10\n", "probes.timeout_sec"),
    ("probes:\n  output_cap_bytes: 100\n", "probes.output_cap_bytes"),
    ("probes:\n  ssh_user: 'bad probe'\n", "probes.ssh_user"),
    ("web:\n  system_name: ''\n", "web.system_name"),
    ("web:\n  system_name: 3\n", "web.system_name"),
    ("probes:\n  ssh_user: Root\n", "probes.ssh_user"),
    ("probes:\n  catalog: ''\n", "probes.catalog"),
    ("probes:\n  key_file: 5\n", "probes.key_file"),
])
def test_wrong_probe_setting_is_rejected_with_the_key(tmp_path, text, key):
    path = tmp_path / "analyzer.yaml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ValueError, match=re.escape(key)):
        load_config(path)
