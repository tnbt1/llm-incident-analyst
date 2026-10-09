from contextlib import closing
from pathlib import Path

from tia import db
from tia.cli import main

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
NOW = "2026-09-29T05:57:00+00:00"


def _ingest(path, source, name, now=NOW):
    return main(["ingest", "--db", str(path), "--source", source, "--file", str(FIXTURES / name), "--now", now,
                 "--type-rules", str(ROOT / "config" / "type-rules.yaml")])


def test_ingest_reports_counts_and_skips_broken_items(tmp_path, capsys):
    path = tmp_path / "tia.sqlite"
    assert _ingest(path, "zabbix", "zabbix_problems.json") == 0
    out = capsys.readouterr()
    assert out.out.strip() == "created=2 rejected=1 skipped=1"
    assert "読み飛ばし" in out.err


def test_ingesting_the_same_file_again_adds_nothing(tmp_path, capsys):
    path = tmp_path / "tia.sqlite"
    _ingest(path, "zabbix", "zabbix_problems.json")
    capsys.readouterr()
    assert _ingest(path, "zabbix", "zabbix_problems.json", now="2026-09-29T05:57:30+00:00") == 0
    assert capsys.readouterr().out.strip() == "duplicate=3 rejected=1"
    with closing(db.connect(path)) as conn:
        assert conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0] == 3


def test_wazuh_burst_is_counted_and_named_rule_is_kept(tmp_path, capsys):
    path = tmp_path / "tia.sqlite"
    assert _ingest(path, "wazuh", "wazuh_alerts.json") == 0
    assert capsys.readouterr().out.strip() == "created=2 recurred=1"
    with closing(db.connect(path)) as conn:
        rows = conn.execute("SELECT type, occurrence_count FROM incidents ORDER BY id").fetchall()
    assert [(r["type"], r["occurrence_count"]) for r in rows] == [("auth", 2), ("file", 1)]


def test_list_shows_one_line_per_incident(tmp_path, capsys):
    path = tmp_path / "tia.sqlite"
    _ingest(path, "zabbix", "zabbix_problems.json")
    capsys.readouterr()
    assert main(["list", "--db", str(path)]) == 0
    lines = capsys.readouterr().out.strip().splitlines()
    assert len(lines) == 3
    assert lines[0].startswith("I-0001 held")
    assert "High CPU utilization" in lines[0]
    assert lines[2].startswith("I-0003 skipped")


def test_input_that_is_not_a_list_is_refused(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text('{"eventid": "1"}', encoding="utf-8")
    code = main(["ingest", "--db", str(tmp_path / "tia.sqlite"), "--source", "zabbix", "--file", str(bad),
                 "--type-rules", str(ROOT / "config" / "type-rules.yaml")])
    assert code == 2
    assert "配列" in capsys.readouterr().err


def test_ingest_works_with_the_analysis_threshold_at_zero(tmp_path, capsys):
    # 以前から有効な設定。取得の閾値を書かなくても読めること。
    config = tmp_path / "analyzer.yaml"
    config.write_text("zabbix:\n  min_severity: 0\n", encoding="utf-8")
    path = tmp_path / "tia.sqlite"
    code = main(["ingest", "--db", str(path), "--source", "zabbix", "--file", str(FIXTURES / "zabbix_problems.json"),
                 "--now", NOW, "--config", str(config), "--type-rules", str(ROOT / "config" / "type-rules.yaml")])
    assert code == 0
    assert capsys.readouterr().out.strip() == "created=3 rejected=1"
