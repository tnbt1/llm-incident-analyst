from pathlib import Path

import pytest

from tia.config import Config, load_config

ROOT = Path(__file__).resolve().parents[1]


def test_knowledge_defaults_match_the_spec():
    cfg = Config()
    assert cfg.knowledge_mode == "selection"
    assert cfg.knowledge_card_budget_tokens == 6000
    assert cfg.knowledge_section_budget_tokens == 3000
    assert cfg.knowledge_max_sections == 3
    assert cfg.knowledge_stale_after_days == 30
    assert cfg.knowledge_bundle_dir == "config/knowledge"
    assert cfg.knowledge_recipe == "config/knowledge.yaml"


def test_shipped_file_has_the_knowledge_block_and_equals_defaults():
    text = (ROOT / "config" / "analyzer.yaml").read_text(encoding="utf-8")
    assert "\nknowledge:\n" in text
    assert load_config(ROOT / "config" / "analyzer.yaml") == Config()


def test_file_overrides_knowledge_values(tmp_path):
    path = tmp_path / "analyzer.yaml"
    path.write_text("knowledge:\n  mode: full\n  section_budget_tokens: 2000\n  bundle_dir: /config/knowledge\n",
                    encoding="utf-8")
    cfg = load_config(path)
    assert cfg.knowledge_mode == "full"
    assert cfg.knowledge_section_budget_tokens == 2000
    assert cfg.knowledge_bundle_dir == "/config/knowledge"
    assert cfg.knowledge_max_sections == 3


@pytest.mark.parametrize(("body", "key"), [
    ("knowledge:\n  mode: all\n", "knowledge.mode"),
    ("knowledge:\n  mode: 1\n", "knowledge.mode"),
    ("knowledge:\n  source_dir: ''\n", "knowledge.source_dir"),
    ("knowledge:\n  bundle_dir: 3\n", "knowledge.bundle_dir"),
    ("knowledge:\n  recipe: [a]\n", "knowledge.recipe"),
    ("knowledge:\n  card_budget_tokens: 0\n", "knowledge.card_budget_tokens"),
    ("knowledge:\n  card_budget_tokens: '6000'\n", "knowledge.card_budget_tokens"),
    ("knowledge:\n  section_budget_tokens: -1\n", "knowledge.section_budget_tokens"),
    ("knowledge:\n  section_budget_tokens: true\n", "knowledge.section_budget_tokens"),
    ("knowledge:\n  max_sections: 21\n", "knowledge.max_sections"),
    ("knowledge:\n  stale_after_days: 0\n", "knowledge.stale_after_days"),
])
def test_wrong_knowledge_value_is_rejected_with_the_key(tmp_path, body, key):
    path = tmp_path / "analyzer.yaml"
    path.write_text(body, encoding="utf-8")
    with pytest.raises(ValueError, match="設定 " + key.replace(".", r"\.") + " は"):
        load_config(path)


def test_unknown_knowledge_key_is_rejected(tmp_path):
    """守りのテスト。実装の前から成功する。"""
    path = tmp_path / "analyzer.yaml"
    path.write_text("knowledge:\n  budget: 1\n", encoding="utf-8")
    with pytest.raises(ValueError, match=r"knowledge\.budget"):
        load_config(path)


def test_section_budget_zero_is_allowed():
    assert Config(knowledge_section_budget_tokens=0, knowledge_max_sections=0).knowledge_max_sections == 0
