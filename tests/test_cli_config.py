"""`tia config show` と `tia config env-template`。"""
import re
from dataclasses import fields
from pathlib import Path

import pytest

from tia.cli import main
from tia.config import Config, env_name, load_config
from tia.config_cli import mask_value, render_template

ROOT = Path(__file__).resolve().parents[1]
SHIPPED = ROOT / "config" / "analyzer.yaml"


def _lines(capsys):
    return capsys.readouterr().out.splitlines()


def test_show_lists_every_setting_with_its_value_and_source(tmp_path, monkeypatch, capsys):
    path = tmp_path / "analyzer.yaml"
    path.write_text("zabbix:\n  min_severity: 3\n", encoding="utf-8")
    (tmp_path / ".env").write_text("TIA_ZABBIX_HOLD_SEC=40\nTIA_ZABBIX_URL=http://zabbix.example/api_jsonrpc.php\n",
                                   encoding="utf-8")
    monkeypatch.delenv("TIA_ZABBIX_URL", raising=False)
    monkeypatch.setenv("TIA_WEB_PORT", "8800")
    monkeypatch.setenv("TIA_LLM_API_KEY_FILE", "/tmp/key")
    assert main(["config", "show", "--config", str(path)]) == 0
    lines = _lines(capsys)
    rows = {line.split("=", 1)[0]: line for line in lines if line.startswith("TIA_")}
    for field in fields(Config):
        assert env_name(field.name) in rows, field.name
    assert rows["TIA_ZABBIX_MIN_SEVERITY"] == "TIA_ZABBIX_MIN_SEVERITY=3  # zabbix.min_severity  yaml"
    assert rows["TIA_ZABBIX_HOLD_SEC"] == "TIA_ZABBIX_HOLD_SEC=40  # zabbix.hold_sec  .env"
    assert rows["TIA_WEB_PORT"] == "TIA_WEB_PORT=8800  # web.port  env"
    assert rows["TIA_WAZUH_MIN_LEVEL"] == "TIA_WAZUH_MIN_LEVEL=10  # wazuh.min_level  default"
    assert rows["TIA_ZABBIX_FETCH_MIN_SEVERITY"].startswith("TIA_ZABBIX_FETCH_MIN_SEVERITY=1  #")
    assert rows["TIA_QUEUE_RETRY_DELAYS_SEC"].startswith("TIA_QUEUE_RETRY_DELAYS_SEC=60,300,900  #")
    # 接続先と秘密のファイルの場所も、由来とともに出る。ファイルの場所は伏せない
    assert rows["TIA_ZABBIX_URL"] == "TIA_ZABBIX_URL=http://zabbix.example/api_jsonrpc.php  # .env"
    assert rows["TIA_LLM_API_KEY_FILE"] == "TIA_LLM_API_KEY_FILE=/tmp/key  # env"
    assert rows["TIA_WAZUH_URL"] == "TIA_WAZUH_URL=  # unset"
    assert rows["TIA_PROBES_KEY_FILE"].startswith("TIA_PROBES_KEY_FILE=/run/secrets/probe_ssh_key  #")
    assert lines[0].startswith("#") and str(path) in lines[0] and str(tmp_path / ".env") in lines[0]


def test_show_without_a_config_reports_defaults_and_no_dotenv(monkeypatch, capsys):
    for name in list(__import__("os").environ):
        if name.startswith("TIA_"):
            monkeypatch.delenv(name)
    assert main(["config", "show"]) == 0
    lines = _lines(capsys)
    assert "なし" in lines[0]
    assert all(line.endswith("default") or line.endswith("unset") for line in lines if line.startswith("TIA_"))


def test_show_fails_like_the_other_commands_on_a_wrong_value(monkeypatch, capsys):
    monkeypatch.setenv("TIA_ZABBIX_MIN_SEVERITY", "9")
    assert main(["config", "show"]) == 2
    assert "設定の誤り: TIA_ZABBIX_MIN_SEVERITY は 0 から 5 の整数で書く: 9" in capsys.readouterr().err


@pytest.mark.parametrize("name, value, shown", [
    ("TIA_LLM_API_KEY", "abc", "********"),
    ("TIA_ZABBIX_TOKEN", "abc", "********"),
    ("TIA_WAZUH_PASSWORD", "abc", "********"),
    ("TIA_SOME_SECRET", "abc", "********"),
    ("TIA_SOME_SECRET", "", ""),
    ("TIA_LLM_API_KEY_FILE", "/run/secrets/openwebui_api_key", "/run/secrets/openwebui_api_key"),
    ("TIA_PROBES_KEY_FILE", "/run/secrets/probe_ssh_key", "/run/secrets/probe_ssh_key"),
    ("TIA_WAZUH_PASSWORD_FILE", "/x", "/x"),
    ("TIA_WEB_PORT", "8000", "8000"),
])
def test_values_whose_name_says_secret_are_masked_unless_they_are_file_paths(name, value, shown):
    assert mask_value(name, value) == shown


def test_template_has_one_commented_entry_per_setting_with_meaning_type_and_default(capsys):
    assert main(["config", "env-template", "--config", str(SHIPPED)]) == 0
    text = capsys.readouterr().out
    for field in fields(Config):
        assert f"\n#{env_name(field.name)}=" in text, field.name
    assert text.count("\n#TIA_ZABBIX_MIN_SEVERITY=") == 1
    assert "# zabbix.min_severity: 2 = Warning（整数 0〜5、既定 2）\n#TIA_ZABBIX_MIN_SEVERITY=2\n" in text
    assert "# llm.thinking: 要求ごとに enable_thinking を指定する。サーバーの既定は変えない（真偽 true/false、既定 false）\n" in text
    assert "# queue.retry_delays_sec: queue.retry_delays_sec（整数の並び、コンマ区切り、各 1〜86400、既定 60,300,900）\n" in text
    assert "（整数 0〜5、空なら 1 と zabbix.min_severity の小さい方、既定 空）\n#TIA_ZABBIX_FETCH_MIN_SEVERITY=\n" in text
    assert "（数 0.0〜2.0、既定 0.2）" in text and "（selection か full、既定 selection）" in text
    assert "（HH:MM、既定 04:30）" in text and "（文字列の並び、コンマ区切り、既定 " in text
    assert "## knowledge\n" in text and "## probes\n" in text
    assert "#TIA_ZABBIX_URL=" in text and "#TIA_LLM_API_KEY_FILE=" in text and "#TIA_IMAGE_TAG=" in text
    assert "TIA_ENV_FILE" in text and "環境変数 > .env > analyzer.yaml > 既定" in text
    assert "Compose" in text


def test_template_meaning_falls_back_to_the_name_without_a_yaml(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert main(["config", "env-template"]) == 0
    text = capsys.readouterr().out
    assert "# zabbix.min_severity: zabbix.min_severity（整数 0〜5、既定 2）\n" in text


def test_template_loads_back_to_the_defaults_commented_or_not(tmp_path):
    text = render_template(SHIPPED)
    dotenv = tmp_path / ".env"
    dotenv.write_text(text, encoding="utf-8")
    assert load_config(None, env={"TIA_ENV_FILE": str(dotenv)}) == Config()
    uncommented = re.sub(r"^#(TIA_)", r"\1", text, flags=re.MULTILINE)
    dotenv.write_text(uncommented, encoding="utf-8")
    env = {"TIA_ENV_FILE": str(dotenv)}
    assert load_config(None, env=env) == Config()
    assert env["TIA_IMAGE_TAG"] == "" and env["TIA_ZABBIX_URL"] == ""


def test_committed_example_is_in_sync_with_the_config():
    """`.env.example` は `uv run tia config env-template > .env.example` で作り直す。"""
    assert (ROOT / ".env.example").read_text(encoding="utf-8") == render_template(SHIPPED)
