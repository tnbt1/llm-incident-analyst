"""秘密の検査の例外（許可の一覧）。値はテスト用に作ったもの。"""
import json
from dataclasses import replace
from pathlib import Path

import pytest
from knowledge_helpers import FIXTURES, TODAY, copy_source

from tia.cli import main
from tia.knowledge.build import build_bundle
from tia.knowledge.recipe import AllowedLine, RecipeError, load_recipe
from tia.knowledge.safety import SecretFound, line_digest

RECIPE = FIXTURES / "recipe.yaml"
FALSE_ALARM = "password: see-the-operators-handbook"
REASON = "手順書の名前であり、値ではない"


@pytest.fixture
def recipe():
    return load_recipe(RECIPE)


@pytest.fixture
def source(tmp_path):
    return copy_source(tmp_path)


def _replace(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    assert old in text
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def _allow(recipe, *entries):
    return replace(recipe, allow_secrets=tuple(AllowedLine(*entry) for entry in entries))


def _recipe_file(tmp_path, extra: str) -> Path:
    path = tmp_path / "recipe.yaml"
    path.write_text(RECIPE.read_text(encoding="utf-8") + extra, encoding="utf-8")
    return path


def test_allowed_line_does_not_stop_the_build(source, tmp_path, recipe):
    _replace(source / "maintenance.md", "sudo docker compose ps", FALSE_ALARM)
    with pytest.raises(SecretFound):
        build_bundle(source, tmp_path / "out", recipe, TODAY)
    allowed = _allow(recipe, ("maintenance.md", line_digest(FALSE_ALARM), REASON))
    result = build_bundle(source, tmp_path / "out", allowed, TODAY)
    assert result.allowed == 1 and result.stale_allowed == ()
    manifest = json.loads((result.path / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["allowed"] == [{"file": "maintenance.md", "line_sha256": line_digest(FALSE_ALARM),
                                    "reason": REASON}]
    assert manifest["counts"]["allowed"] == 1


def test_entry_allows_only_the_exact_line(source, tmp_path, recipe):
    _replace(source / "maintenance.md", "sudo docker compose ps", FALSE_ALARM + "2")
    allowed = _allow(recipe, ("maintenance.md", line_digest(FALSE_ALARM), REASON))
    with pytest.raises(SecretFound) as error:
        build_bundle(source, tmp_path / "out", allowed, TODAY)
    assert [(f.file, f.line) for f in error.value.findings] == [("maintenance.md", 19)]


def test_entry_allows_only_its_own_file(source, tmp_path, recipe):
    _replace(source / "maintenance.md", "sudo docker compose ps", FALSE_ALARM)
    allowed = _allow(recipe, ("README.md", line_digest(FALSE_ALARM), REASON))
    with pytest.raises(SecretFound):
        build_bundle(source, tmp_path / "out", allowed, TODAY)


def test_private_key_can_never_be_allowed(source, tmp_path, recipe):
    armour = "-----BEGIN OPENSSH PRIVATE KEY-----"
    _replace(source / "maintenance.md", "sudo docker compose ps", armour)
    allowed = _allow(recipe, ("maintenance.md", line_digest(armour), REASON))
    with pytest.raises(SecretFound) as error:
        build_bundle(source, tmp_path / "out", allowed, TODAY)
    assert [f.kind for f in error.value.findings] == ["private_key"]


def test_entry_that_matches_no_line_is_reported_as_stale(source, tmp_path, recipe):
    allowed = _allow(recipe, ("maintenance.md", line_digest(FALSE_ALARM), REASON))
    result = build_bundle(source, tmp_path / "out", allowed, TODAY)
    assert result.allowed == 0
    assert result.stale_allowed == (AllowedLine("maintenance.md", line_digest(FALSE_ALARM), REASON),)


def test_entry_for_a_line_that_is_no_longer_a_finding_is_not_stale(source, tmp_path, recipe):
    line = "sudo docker compose ps"
    allowed = _allow(recipe, ("maintenance.md", line_digest(line), REASON))
    result = build_bundle(source, tmp_path / "out", allowed, TODAY)
    assert result.allowed == 0 and result.stale_allowed == ()


def test_allowing_does_not_change_the_content_or_the_version(source, tmp_path, recipe):
    plain = build_bundle(source, tmp_path / "plain", recipe, TODAY)
    allowed = _allow(recipe, ("maintenance.md", line_digest(FALSE_ALARM), REASON))
    other = build_bundle(source, tmp_path / "allowed", allowed, TODAY)
    assert other.version == plain.version


@pytest.mark.parametrize(("extra", "message"), [
    ("allow_secrets: yes\n", "allow_secrets"),
    ("allow_secrets:\n  - maintenance.md\n", "allow_secrets"),
    ("allow_secrets:\n  - {file: maintenance.md, line_sha256: abc, reason: 手順書の名前であり、値ではない}\n", "line_sha256"),
    ("allow_secrets:\n  - {file: other.md, line_sha256: '" + "0" * 64 + "', reason: 手順書の名前であり、値ではない}\n", "files"),
    ("allow_secrets:\n  - {file: maintenance.md, line_sha256: '" + "0" * 64 + "'}\n", "reason"),
    ("allow_secrets:\n  - {file: maintenance.md, line_sha256: '" + "0" * 64 + "', reason: ''}\n", "reason"),
    ("allow_secrets:\n  - {file: maintenance.md, line_sha256: '" + "0" * 64 + "', reason: ok}\n", "reason"),
    ("allow_secrets:\n  - {file: maintenance.md, line_sha256: '" + "A" * 64 + "', reason: 手順書の名前であり、値ではない}\n",
     "line_sha256"),
    ("allow_secrets:\n  - {file: maintenance.md, pattern: 'pass.*', reason: 手順書の名前であり、値ではない}\n", "pattern"),
    ("allow_secrets:\n  - {file: maintenance.md, line_sha256: '" + "0" * 64 + "', reason: 手順書の名前であり、値ではない}\n"
     "  - {file: maintenance.md, line_sha256: '" + "0" * 64 + "', reason: 同じ行をもう一度書いた項目}\n", "重複"),
])
def test_entry_of_the_wrong_shape_is_refused(tmp_path, extra, message):
    with pytest.raises(RecipeError, match=message):
        load_recipe(_recipe_file(tmp_path, extra))


def test_entries_are_read_from_the_recipe(tmp_path):
    digest = line_digest(FALSE_ALARM)
    recipe = load_recipe(_recipe_file(
        tmp_path, f"allow_secrets:\n  - {{file: maintenance.md, line_sha256: '{digest}', reason: {REASON}}}\n"))
    assert recipe.allow_secrets == (AllowedLine("maintenance.md", digest, REASON),)
    assert load_recipe(RECIPE).allow_secrets == ()


def _command(tmp_path, recipe_path, *extra):
    return main(["knowledge", "build", "--source", str(tmp_path / "source"), "--out", str(tmp_path / "bundles"),
                 "--recipe", str(recipe_path), "--today", "2026-09-29", *extra])


def test_command_shows_the_digest_only_when_asked(source, tmp_path, capsys):
    _replace(source / "maintenance.md", "sudo docker compose ps", FALSE_ALARM)
    assert _command(tmp_path, RECIPE) == 3
    err = capsys.readouterr().err
    assert line_digest(FALSE_ALARM) not in err and "handbook" not in err
    assert "--line-hashes" in err
    assert _command(tmp_path, RECIPE, "--line-hashes") == 3
    err = capsys.readouterr().err
    assert f"maintenance.md:19 パスワードや鍵の値（名前と値の組） 行のハッシュ {line_digest(FALSE_ALARM)}" in err
    assert "handbook" not in err


def test_command_reports_allowed_and_stale_entries(source, tmp_path, capsys):
    _replace(source / "maintenance.md", "sudo docker compose ps", FALSE_ALARM)
    recipe_path = _recipe_file(
        tmp_path, "allow_secrets:\n"
        f"  - {{file: maintenance.md, line_sha256: '{line_digest(FALSE_ALARM)}', reason: {REASON}}}\n"
        f"  - {{file: README.md, line_sha256: '{'1' * 64}', reason: 前に許可した行で、今はもうない}}\n")
    for _ in range(2):   # 古い項目は、作るたびに知らせる
        assert _command(tmp_path, recipe_path) == 0
        out = capsys.readouterr()
        assert "秘密の検査で許可した行 1" in out.out
        assert "注意: 許可の一覧の項目が、どの行にも当たらない: README.md（理由: 前に許可した行で、今はもうない）" in out.err


def test_real_recipe_allows_nothing():
    root = Path(__file__).resolve().parents[1]
    assert load_recipe(root / "config" / "knowledge.yaml").allow_secrets == ()
