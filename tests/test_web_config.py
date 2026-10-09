"""画面の設定。既定値、型と範囲の確認。"""
from pathlib import Path

import pytest

from tia.config import Config, load_config

ROOT = Path(__file__).resolve().parents[1]


def test_web_defaults_match_the_design(cfg):
    assert cfg.web_host == "0.0.0.0"
    assert cfg.web_port == 8000
    assert cfg.web_timezone == "Asia/Tokyo"
    assert cfg.web_sse_poll_sec == 1
    assert cfg.web_sse_max_sec == 600
    assert cfg.web_health_interval_sec == 30
    assert cfg.web_stall_warn_sec == 600
    assert cfg.web_max_rows == 500
    assert cfg.web_min_free_mb == 200
    assert cfg.web_cookie_secure is True


def test_settings_file_holds_the_web_block():
    text = (ROOT / "config" / "analyzer.yaml").read_text(encoding="utf-8")
    assert "\nweb:\n" in text
    assert load_config(ROOT / "config" / "analyzer.yaml") == Config()


def test_settings_file_accepts_the_web_block(tmp_path):
    path = tmp_path / "analyzer.yaml"
    path.write_text("web:\n  port: 9000\n  timezone: UTC\n  cookie_secure: false\n  stall_warn_sec: 120\n", encoding="utf-8")
    cfg = load_config(path)
    assert (cfg.web_port, cfg.web_timezone, cfg.web_cookie_secure, cfg.web_stall_warn_sec) == (9000, "UTC", False, 120)


@pytest.mark.parametrize(("name", "value"), [
    ("web_port", 0), ("web_port", 70000), ("web_port", "8000"), ("web_port", True),
    ("web_sse_poll_sec", 0), ("web_sse_poll_sec", 31), ("web_sse_max_sec", 1),
    ("web_health_interval_sec", 4), ("web_stall_warn_sec", 59), ("web_max_rows", 9),
    ("web_min_free_mb", 0),
    ("web_host", ""), ("web_host", "a b"), ("web_host", 12),
    ("web_timezone", ""), ("web_timezone", "Mars/Olympus"), ("web_timezone", 9),
    ("web_cookie_secure", "yes"), ("web_cookie_secure", 1),
])
def test_wrong_web_value_names_the_key(name, value):
    with pytest.raises(ValueError, match=name.replace("_", ".", 1)):
        Config(**{name: value})
