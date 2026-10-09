from pathlib import Path

import pytest

from tia.knowledge.recipe import CardSection, RecentChanges, RecipeError, is_safe_name, load_recipe
from tia.models import IncidentType

ROOT = Path(__file__).resolve().parents[1]

MINIMAL = "files: [a.md]\n"


def _write(tmp_path, body):
    path = tmp_path / "knowledge.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def test_shipped_recipe_follows_the_spec():
    recipe = load_recipe(ROOT / "config" / "knowledge.yaml")
    assert recipe.files == ("README.md", "architecture.md", "registers.md", "maintenance.md")
    assert CardSection("architecture.md", "構成の要点") in recipe.card_sections
    assert len(recipe.card_sections) == 6
    assert recipe.recent_changes is None  # 変更履歴の節はカードに入れない（文書の即時更新を前提にしない）
    assert "FRR" in recipe.hosts["example-router01"]
    assert recipe.types[IncidentType.MEM] == ("メモリ", "OOM")
    assert "切り分け" in recipe.prefer_headings


def test_minimal_recipe_has_empty_defaults(tmp_path):
    recipe = load_recipe(_write(tmp_path, MINIMAL))
    assert recipe.files == ("a.md",)
    assert recipe.card_sections == ()
    assert recipe.recent_changes is None
    assert recipe.hosts == {}
    assert recipe.types == {}
    assert recipe.prefer_headings == ()


def test_host_name_is_always_one_of_its_own_aliases(tmp_path):
    recipe = load_recipe(_write(tmp_path, MINIMAL + "hosts:\n  vm-a: [VM-A, vm-a]\n"))
    assert recipe.hosts["vm-a"] == ("vm-a", "VM-A")


@pytest.mark.parametrize(("body", "message"), [
    ("", "対応表"),
    ("- a.md\n", "対応表"),
    ("files: []\n", "files"),
    ("files: a.md\n", "files"),
    ("files: [a.md, a.md]\n", "重複"),
    ("files: [a.txt]\n", r"a\.txt"),
    ("files: [../a.md]\n", r"\.\./a\.md"),
    ("files: [/etc/a.md]\n", "/etc/a.md"),
    ("files: ['a\\\\b.md']\n", "files"),
    ("files: [.hidden.md]\n", "hidden"),
    ("files: [3]\n", "files"),
    (MINIMAL + "extra: 1\n", "extra"),
    (MINIMAL + "card: []\n", "card"),
    (MINIMAL + "card:\n  other: 1\n", r"card\.other"),
    (MINIMAL + "card:\n  sections: [{file: b.md, heading: x}]\n", r"b\.md"),
    (MINIMAL + "card:\n  sections: [{file: a.md}]\n", "heading"),
    (MINIMAL + "card:\n  sections: [{file: a.md, heading: ''}]\n", "heading"),
    (MINIMAL + "card:\n  sections: [{file: a.md, heading: x, more: 1}]\n", "more"),
    (MINIMAL + "card:\n  sections: [x]\n", "sections"),
    (MINIMAL + "card:\n  recent_changes: {file: a.md, heading: x, days: 0}\n", "days"),
    (MINIMAL + "card:\n  recent_changes: {file: a.md, heading: x, days: '14'}\n", "days"),
    (MINIMAL + "card:\n  recent_changes: {file: b.md, heading: x, days: 14}\n", r"b\.md"),
    (MINIMAL + "card:\n  recent_changes: {file: a.md, days: 14}\n", "heading"),
    (MINIMAL + "hosts: [a]\n", "hosts"),
    (MINIMAL + "hosts:\n  vm-a: FRR\n", "vm-a"),
    (MINIMAL + "hosts:\n  vm-a: ['']\n", "vm-a"),
    (MINIMAL + "hosts:\n  vm-a: [x]\n", "2 文字"),
    (MINIMAL + "hosts:\n  '': [FRR]\n", "hosts"),
    (MINIMAL + "types:\n  memory: [x]\n", "memory"),
    (MINIMAL + "types:\n  mem: []\n", "mem"),
    (MINIMAL + "types:\n  mem: [3]\n", "mem"),
    (MINIMAL + "prefer_headings: 確認\n", "prefer_headings"),
    (MINIMAL + "prefer_headings: ['']\n", "prefer_headings"),
])
def test_wrong_recipe_is_rejected_with_the_place(tmp_path, body, message):
    with pytest.raises(RecipeError, match=message):
        load_recipe(_write(tmp_path, body))


@pytest.mark.parametrize(("name", "safe"), [
    ("README.md", True),
    ("templates/change-record.md", True),
    ("a/b/c.md", True),
    ("../a.md", False),
    ("a/../b.md", False),
    ("/etc/passwd.md", False),
    ("a//b.md", False),
    (".hidden.md", False),
    ("a.txt", False),
    ("a\\b.md", False),
    ("", False),
    (None, False),
    (3, False),
])
def test_safe_names(name, safe):
    assert is_safe_name(name) is safe


def test_recipe_that_is_not_yaml_is_rejected(tmp_path):
    with pytest.raises(RecipeError, match="読めない"):
        load_recipe(_write(tmp_path, "files: [a.md\n"))


def test_missing_recipe_is_rejected(tmp_path):
    with pytest.raises(RecipeError, match="読めない"):
        load_recipe(tmp_path / "none.yaml")
