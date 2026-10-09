"""常駐、保持期間、バックアップの設定。"""
from pathlib import Path

import pytest

from tia.config import Config, load_config


def test_defaults_follow_the_design():
    cfg = Config()
    assert (cfg.worker_enabled, cfg.retention_incident_days, cfg.retention_payload_days,
            cfg.retention_skipped_days) == (True, 180, 90, 14)
    assert (cfg.backup_dir, cfg.backup_keep, cfg.backup_at, cfg.housekeeping_retention_at) == (
        "backups", 7, "04:30", "04:40")
    assert cfg.knowledge_reload_check_sec == 60


def test_file_values_are_read(tmp_path):
    path = tmp_path / "analyzer.yaml"
    path.write_text('worker:\n  enabled: false\nretention:\n  incident_days: 30\n  payload_days: 10\n'
                    '  skipped_days: 3\nbackup:\n  dir: /backups\n  keep: 3\n  at: "01:15"\n'
                    'housekeeping:\n  retention_at: "01:30"\nknowledge:\n  reload_check_sec: 5\n',
                    encoding="utf-8")
    cfg = load_config(path)
    assert (cfg.worker_enabled, cfg.retention_incident_days, cfg.backup_dir, cfg.backup_keep,
            cfg.backup_at, cfg.housekeeping_retention_at, cfg.knowledge_reload_check_sec) == (
        False, 30, "/backups", 3, "01:15", "01:30", 5)


@pytest.mark.parametrize(("text", "name"), [
    ("worker:\n  enabled: yes please\n", "worker.enabled"),
    ("retention:\n  incident_days: 0\n", "retention.incident_days"),
    ("retention:\n  payload_days: 400\n", "retention.payload_days"),
    ("retention:\n  skipped_days: 200\n", "retention.skipped_days"),
    ("backup:\n  keep: 0\n", "backup.keep"),
    ("backup:\n  dir: ''\n", "backup.dir"),
    ("backup:\n  at: '24:00'\n", "backup.at"),
    ("housekeeping:\n  retention_at: '4:40'\n", "housekeeping.retention_at"),
    ("knowledge:\n  reload_check_sec: 1\n", "knowledge.reload_check_sec"),
])
def test_wrong_values_are_refused_with_the_name_of_the_setting(tmp_path, text, name):
    path = tmp_path / "analyzer.yaml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ValueError, match=name.replace(".", r"\.")):
        load_config(path)


def test_unquoted_clock_time_is_refused_with_the_name_of_the_setting(tmp_path):
    """YAML は 4:30 を 60 進の数 270 に読む（04:30 は文字列のまま）。引用符を促す。"""
    path = tmp_path / "analyzer.yaml"
    path.write_text("backup:\n  at: 4:30\n", encoding="utf-8")
    with pytest.raises(ValueError, match=r"backup\.at.*引用符"):
        load_config(path)


def test_shipped_settings_file_loads():
    cfg = load_config(Path(__file__).resolve().parents[1] / "config" / "analyzer.yaml")
    assert cfg.backup_at == "04:30" and cfg.worker_enabled is True
