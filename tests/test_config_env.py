"""環境変数と `.env` による設定の上書き。優先は 環境変数 > .env > analyzer.yaml > 既定。"""
import re
from dataclasses import fields

import pytest

from tia.config import (EXTERNAL_VARIABLES, Config, coerce, env_name, format_value, inspect_config, load_config,
                        setting_name)


def _yaml(tmp_path, text=""):
    path = tmp_path / "analyzer.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_every_setting_has_an_upper_case_variable_name_and_back():
    for field in fields(Config):
        var = env_name(field.name)
        assert var == "TIA_" + field.name.upper() and var.isupper()
        assert setting_name(var) == field.name
    assert setting_name("TIA_NOT_A_SETTING") is None and setting_name("zabbix_min_severity") is None


@pytest.mark.parametrize("var, raw, name, expected", [
    ("TIA_ZABBIX_MIN_SEVERITY", "4", "zabbix_min_severity", 4),
    ("TIA_ZABBIX_MIN_SEVERITY", " 4 ", "zabbix_min_severity", 4),
    ("TIA_LLM_MODEL", "org/model-7b", "llm_model", "org/model-7b"),
    ("TIA_LLM_TEMPERATURE", "0.7", "llm_temperature", 0.7),
    ("TIA_LLM_RETRY_TEMPERATURE", "1", "llm_retry_temperature", 1.0),
    ("TIA_LLM_THINKING", "true", "llm_thinking", True),
    ("TIA_LLM_THINKING", "Yes", "llm_thinking", True),
    ("TIA_LLM_THINKING", "ON", "llm_thinking", True),
    ("TIA_LLM_THINKING", "1", "llm_thinking", True),
    ("TIA_WEB_COOKIE_SECURE", "false", "web_cookie_secure", False),
    ("TIA_WEB_COOKIE_SECURE", "No", "web_cookie_secure", False),
    ("TIA_WEB_COOKIE_SECURE", "off", "web_cookie_secure", False),
    ("TIA_WEB_COOKIE_SECURE", "0", "web_cookie_secure", False),
    ("TIA_ZABBIX_FETCH_MIN_SEVERITY", "0", "zabbix_fetch_min_severity", 0),
    ("TIA_QUEUE_RETRY_DELAYS_SEC", "30, 60,120", "queue_retry_delays_sec", (30, 60, 120)),
    ("TIA_QUEUE_RETRY_DELAYS_SEC", "", "queue_retry_delays_sec", ()),
    ("TIA_WAZUH_NAMED_RULES", " 550 ,5710", "wazuh_named_rules", frozenset({"550", "5710"})),
    ("TIA_WAZUH_NAMED_RULES", "", "wazuh_named_rules", frozenset()),
    ("TIA_BACKUP_AT", "05:15", "backup_at", "05:15"),
])
def test_each_type_is_read_from_the_environment(var, raw, name, expected):
    cfg = load_config(None, env={var: raw})
    assert getattr(cfg, name) == expected
    assert type(getattr(cfg, name)) is type(expected)


def test_empty_optional_int_means_not_written():
    cfg = load_config(None, env={"TIA_ZABBIX_FETCH_MIN_SEVERITY": "", "TIA_ZABBIX_MIN_SEVERITY": "0"})
    assert cfg.zabbix_fetch_min_severity == 0


@pytest.mark.parametrize("var, raw, expected", [
    ("TIA_ZABBIX_MIN_SEVERITY", "9", "TIA_ZABBIX_MIN_SEVERITY は 0 から 5 の整数で書く: 9"),
    ("TIA_ZABBIX_MIN_SEVERITY", "high", "TIA_ZABBIX_MIN_SEVERITY は 0 から 5 の整数で書く: 'high'"),
    ("TIA_ZABBIX_MIN_SEVERITY", "1.5", "TIA_ZABBIX_MIN_SEVERITY は 0 から 5 の整数で書く: '1.5'"),
    ("TIA_ZABBIX_MIN_SEVERITY", "", "TIA_ZABBIX_MIN_SEVERITY は 0 から 5 の整数で書く: ''"),
    ("TIA_LLM_THINKING", "maybe", "TIA_LLM_THINKING は true か false で書く: 'maybe'"),
    ("TIA_LLM_TEMPERATURE", "hot", "TIA_LLM_TEMPERATURE は 0.0 から 2.0 の数で書く: 'hot'"),
    ("TIA_LLM_TEMPERATURE", "3", "TIA_LLM_TEMPERATURE は 0.0 から 2.0 の数で書く: 3.0"),
    ("TIA_QUEUE_RETRY_DELAYS_SEC", "60,soon", "TIA_QUEUE_RETRY_DELAYS_SEC は 1 から 86400 の整数の配列で書く"),
    ("TIA_KNOWLEDGE_MODE", "partial", "TIA_KNOWLEDGE_MODE は selection か full で書く: 'partial'"),
    ("TIA_BACKUP_AT", "4:30", "TIA_BACKUP_AT は HH:MM で書く: '4:30'"),
    ("TIA_PROBES_SSH_USER", "Root", "TIA_PROBES_SSH_USER は利用者名で書く: 'Root'"),
])
def test_wrong_value_names_the_variable(var, raw, expected):
    with pytest.raises(ValueError) as caught:
        load_config(None, env={var: raw})
    assert str(caught.value).startswith(expected)
    assert "設定 " not in str(caught.value)


def test_cross_check_names_both_variables_when_both_come_from_the_environment():
    with pytest.raises(ValueError) as caught:
        load_config(None, env={"TIA_ZABBIX_MIN_SEVERITY": "2", "TIA_ZABBIX_FETCH_MIN_SEVERITY": "3"})
    assert str(caught.value) == ("TIA_ZABBIX_FETCH_MIN_SEVERITY は TIA_ZABBIX_MIN_SEVERITY 以下で書く: "
                                 "TIA_ZABBIX_FETCH_MIN_SEVERITY = 3、TIA_ZABBIX_MIN_SEVERITY = 2")


def test_yaml_error_keeps_the_dotted_name_when_the_value_came_from_the_file(tmp_path):
    path = _yaml(tmp_path, "zabbix:\n  min_severity: 9\n")
    with pytest.raises(ValueError, match=re.escape("設定 zabbix.min_severity は 0 から 5 の整数で書く: 9")):
        load_config(path, env={"TIA_ZABBIX_HOLD_SEC": "30"})


def test_precedence_runs_environment_then_dotenv_then_yaml_then_defaults(tmp_path):
    path = _yaml(tmp_path, "zabbix:\n  min_severity: 3\n  hold_sec: 30\nwazuh:\n  min_level: 11\n")
    (tmp_path / ".env").write_text("TIA_ZABBIX_MIN_SEVERITY=4\nTIA_ZABBIX_HOLD_SEC=40\nTIA_WAZUH_HOLD_SEC=140\n",
                                   encoding="utf-8")
    cfg = load_config(path, env={"TIA_ZABBIX_MIN_SEVERITY": "5"})
    assert cfg.zabbix_min_severity == 5          # 環境変数
    assert cfg.zabbix_hold_sec == 40             # .env
    assert cfg.wazuh_hold_sec == 140             # .env（YAML に書いていない）
    assert cfg.wazuh_min_level == 11             # analyzer.yaml
    assert cfg.wazuh_page_size == 200            # 既定
    loaded = inspect_config(path, env={"TIA_ZABBIX_MIN_SEVERITY": "5"})
    assert loaded.config == cfg
    assert loaded.sources["zabbix_min_severity"] == "env"
    assert loaded.sources["zabbix_hold_sec"] == ".env"
    assert loaded.sources["wazuh_hold_sec"] == ".env"
    assert loaded.sources["wazuh_min_level"] == "yaml"
    assert loaded.sources["wazuh_page_size"] == "default"
    assert loaded.env_file == tmp_path / ".env"
    assert set(loaded.sources) == {f.name for f in fields(Config)}


def test_dotenv_next_to_the_yaml_is_optional(tmp_path):
    path = _yaml(tmp_path, "zabbix:\n  min_severity: 3\n")
    loaded = inspect_config(path, env={})
    assert loaded.config.zabbix_min_severity == 3 and loaded.env_file is None


def test_without_a_yaml_no_dotenv_is_looked_for(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("TIA_ZABBIX_MIN_SEVERITY=4\n", encoding="utf-8")
    assert load_config(None, env={}).zabbix_min_severity == 2


def test_env_file_variable_points_at_the_dotenv(tmp_path):
    path = _yaml(tmp_path, "")
    (tmp_path / ".env").write_text("TIA_ZABBIX_MIN_SEVERITY=4\n", encoding="utf-8")
    other = tmp_path / "other.env"
    other.write_text("TIA_ZABBIX_MIN_SEVERITY=5\n", encoding="utf-8")
    loaded = inspect_config(path, env={"TIA_ENV_FILE": str(other)})
    assert loaded.config.zabbix_min_severity == 5 and loaded.env_file == other
    assert load_config(None, env={"TIA_ENV_FILE": str(other)}).zabbix_min_severity == 5
    # 空は書いていないのと同じ
    assert load_config(path, env={"TIA_ENV_FILE": ""}).zabbix_min_severity == 4


def test_missing_env_file_named_explicitly_is_an_error(tmp_path):
    with pytest.raises(ValueError, match=re.escape(f"TIA_ENV_FILE のファイルがない: {tmp_path / 'missing.env'}")):
        load_config(None, env={"TIA_ENV_FILE": str(tmp_path / "missing.env")})


def test_malformed_dotenv_is_refused_with_the_line(tmp_path):
    path = _yaml(tmp_path, "")
    (tmp_path / ".env").write_text("TIA_ZABBIX_MIN_SEVERITY=4\nbroken line\n", encoding="utf-8")
    with pytest.raises(ValueError, match=re.escape(f"{tmp_path / '.env'} の 2 行目")):
        load_config(path, env={})


def test_unknown_setting_in_the_dotenv_is_refused(tmp_path):
    path = _yaml(tmp_path, "")
    (tmp_path / ".env").write_text("TIA_ZABBIX_MIN_SEVERTY=4\n", encoding="utf-8")
    with pytest.raises(ValueError, match=re.escape("知らない設定: TIA_ZABBIX_MIN_SEVERTY")):
        load_config(path, env={})


def test_unknown_variable_in_the_process_environment_is_only_warned_about(caplog):
    with caplog.at_level("WARNING", logger="tia.config"):
        cfg = load_config(None, env={"TIA_ZABBIX_MIN_SEVERTY": "4", "TIA_IMAGE_TAG": "0.3.0", "TIA_LLM_URL": "x"})
    assert cfg == Config()
    assert "TIA_ZABBIX_MIN_SEVERTY" in caplog.text
    assert "TIA_IMAGE_TAG" not in caplog.text and "TIA_LLM_URL" not in caplog.text


def test_endpoint_variables_in_the_dotenv_reach_the_process_environment(tmp_path):
    """接続先と秘密の場所は従来の名前のまま。.env に書けば、環境変数にないときだけ写す。"""
    path = _yaml(tmp_path, "")
    (tmp_path / ".env").write_text("TIA_ZABBIX_URL=http://zabbix.example/api_jsonrpc.php\nTIA_WAZUH_USER=from-file\n"
                                   "TIA_IMAGE_TAG=0.3.0\nTIA_LLM_MODEL=org/from-file\n", encoding="utf-8")
    env = {"TIA_WAZUH_USER": "from-env"}
    cfg = load_config(path, env=env)
    assert env == {"TIA_WAZUH_USER": "from-env", "TIA_ZABBIX_URL": "http://zabbix.example/api_jsonrpc.php",
                   "TIA_IMAGE_TAG": "0.3.0"}
    # TIA_LLM_MODEL は規則どおりの名前なので、設定 llm.model として読む
    assert cfg.llm_model == "org/from-file"


def test_aliases_are_the_endpoint_and_secret_variables_already_in_use():
    names = {name for name, _meaning in EXTERNAL_VARIABLES}
    assert {"TIA_ZABBIX_URL", "TIA_ZABBIX_TOKEN_FILE", "TIA_WAZUH_URL", "TIA_WAZUH_USER", "TIA_WAZUH_PASSWORD_FILE",
            "TIA_WAZUH_CA_FILE", "TIA_LLM_URL", "TIA_LLM_API_KEY_FILE", "TIA_PROBE_SSH_BIN",
            "TIA_IMAGE_TAG", "TIA_ENV_FILE"} == names
    assert all(setting_name(name) is None for name in names)
    assert setting_name("TIA_LLM_MODEL") == "llm_model"


def test_process_environment_is_used_when_none_is_given(monkeypatch):
    monkeypatch.setenv("TIA_WEB_PORT", "8800")
    assert load_config(None).web_port == 8800


@pytest.mark.parametrize("value, text", [
    (3, "3"), (0.2, "0.2"), (True, "true"), (False, "false"), (None, ""), ("04:30", "04:30"),
    ((60, 300, 900), "60,300,900"), ((), ""), (frozenset({"5710", "550"}), "550,5710"),
])
def test_values_are_written_the_way_they_are_read(value, text):
    assert format_value(value) == text


def test_every_default_survives_a_round_trip_through_text():
    for field in fields(Config):
        default = field.default
        assert coerce(field, format_value(default)) == default, field.name
