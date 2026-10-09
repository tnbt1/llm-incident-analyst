"""`tia web`。設定の誤り、--check、引数。"""
from pathlib import Path

from web_helpers import NOW, make_db

from tia.cli import main

ROOT = Path(__file__).resolve().parents[1]


def test_web_is_registered():
    import io
    from contextlib import redirect_stdout

    out = io.StringIO()
    try:
        with redirect_stdout(out):
            main(["--help"])
    except SystemExit:
        pass
    assert "web" in out.getvalue()


def test_check_renders_once_and_exits_zero(tmp_path, capsys):
    from knowledge_helpers import build_fixture

    path = tmp_path / "c.sqlite"
    make_db(path)
    bundle = build_fixture(tmp_path / "kb").path.parent
    code = main(["web", "--db", str(path), "--knowledge", str(bundle), "--check"])
    out = capsys.readouterr()
    assert code == 0, out.err
    assert out.out.startswith("一覧 ") and "/healthz 503 degraded" in out.out
    assert "zabbix" in out.out and "llm" not in out.out, "--check は LLM を確かめない"


def test_check_with_a_bad_setting_exits_two(tmp_path, capsys):
    path = tmp_path / "c.sqlite"
    make_db(path)
    settings = tmp_path / "analyzer.yaml"
    settings.write_text("web:\n  timezone: Nowhere/Town\n", encoding="utf-8")
    code = main(["web", "--db", str(path), "--config", str(settings), "--check"])
    assert code == 2 and "web.timezone" in capsys.readouterr().err


def test_check_without_a_bundle_still_reports(tmp_path, capsys):
    path = tmp_path / "c.sqlite"
    make_db(path)
    code = main(["web", "--db", str(path), "--knowledge", str(tmp_path / "none"), "--check"])
    out = capsys.readouterr().out
    assert code == 0 and "knowledge" in out


def test_web_refuses_a_database_that_does_not_exist(tmp_path, capsys):
    """M-6: 綴りを誤った --db で、空の保存先を黙って作らない。"""
    missing = tmp_path / "missing.sqlite"
    code = main(["web", "--db", str(missing), "--check"])
    err = capsys.readouterr().err
    assert code == 2 and "保存先がない" in err and not missing.exists()


def test_web_treats_a_broken_database_as_a_configuration_error(tmp_path, capsys):
    broken = tmp_path / "broken.sqlite"
    broken.write_bytes(b"not a database at all" * 100)
    code = main(["web", "--db", str(broken), "--check"])
    err = capsys.readouterr().err
    assert code == 2 and "設定の誤り" in err and "Traceback" not in err
