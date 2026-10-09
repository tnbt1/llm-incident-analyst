import time

import pytest

from tia.knowledge.split import MAX_HEADING_LENGTH, SplitError, split_sections

DOC = """# 保守手順

冒頭の説明。

## 日常点検

点検の本文。

### FRRの状態

```bash
# これは見出しではない
sudo vtysh -c 'show ip route'
```

#### 細かい補足

補足の本文。

## ログを読む場所

ログの本文。
"""


def _headings(text, file="maintenance.md"):
    return [section.heading for section in split_sections(file, text)]


def test_splits_at_levels_1_to_3():
    sections = split_sections("maintenance.md", DOC)
    assert [(s.level, s.heading) for s in sections] == [
        (1, "保守手順"), (2, "日常点検"), (3, "FRRの状態"), (2, "ログを読む場所")]
    assert [s.order for s in sections] == [0, 1, 2, 3]
    assert sections[0].text == "# 保守手順\n\n冒頭の説明。"
    assert sections[1].text == "## 日常点検\n\n点検の本文。"


def test_level_4_heading_stays_inside_its_section():
    section = split_sections("maintenance.md", DOC)[2]
    assert "#### 細かい補足" in section.text
    assert section.text.endswith("補足の本文。")


def test_hash_inside_a_code_block_is_not_a_heading():
    section = split_sections("maintenance.md", DOC)[2]
    assert "# これは見出しではない" in section.text


@pytest.mark.parametrize("text", [
    "## 節\n\n~~~\n## 中\n~~~\n\n後\n",
    "## 節\n\n````\n```\n## 中\n```\n````\n\n後\n",
    "## 節\n\n   ```text\n## 中\n   ```\n\n後\n",
    "## 節\n\n```\n## 中\n~~~\n## まだ中\n```\n\n後\n",
])
def test_fences_of_other_shapes_also_hide_headings(text):
    sections = split_sections("a.md", text)
    assert [s.heading for s in sections] == ["節"]
    assert sections[0].text.endswith("後")


@pytest.mark.parametrize("opening", ["```mermaid", "```Mermaid", "``` mermaid", "~~~mermaid", "```mermaid {init: 1}"])
def test_mermaid_block_is_dropped(opening):
    closing = "~~~" if opening.startswith("~") else "```"
    text = f"## 図\n\n前\n\n{opening}\nflowchart LR\n  A --> B\n{closing}\n\n後\n"
    section = split_sections("a.md", text)[0]
    assert section.text == "## 図\n\n前\n\n後"


def test_other_code_blocks_are_kept_as_written():
    text = "## 節\n\n```yaml\nkey:   value\n\n\n\nnext: 1\n```\n"
    assert split_sections("a.md", text)[0].text == "## 節\n\n```yaml\nkey:   value\n\n\n\nnext: 1\n```"


def test_code_block_that_is_not_closed_is_an_error():
    with pytest.raises(SplitError, match=r"a\.md:3") as info:
        split_sections("a.md", "## 節\n\n```bash\nls\n")
    assert "閉じていない" in str(info.value)


def test_text_before_the_first_heading_is_kept():
    sections = split_sections("notes/intro.md", "最初の文。\n\n## 節\n\n本文\n")
    assert [(s.level, s.heading) for s in sections] == [(0, "intro"), (2, "節")]
    assert sections[0].text == "最初の文。"


def test_document_without_text_has_no_sections():
    assert split_sections("a.md", "") == []
    assert split_sections("a.md", "\n\n  \n") == []


def test_blank_lines_are_collapsed_outside_code_blocks():
    section = split_sections("a.md", "## 節\n\n\n\n前\n\n\n\n\n後\n\n\n")[0]
    assert section.text == "## 節\n\n前\n\n後"


def test_trailing_spaces_are_removed_outside_code_blocks():
    section = split_sections("a.md", "## 節   \n本文  \n")[0]
    assert section.heading == "節"
    assert section.text == "## 節\n本文"


@pytest.mark.parametrize(("line", "heading"), [
    ("## 題名 ##", "題名"),
    ("##   題名", "題名"),
    ("## C#", "C#"),
    ("## `code` の設定", "`code` の設定"),
])
def test_heading_text_is_taken_without_decoration(line, heading):
    assert _headings(line + "\n\n本文\n") == [heading]


@pytest.mark.parametrize("line", ["#題名", "##", "## ", "#### 深い", "    ## 字下げ", "題名\n===", "題名\n---"])
def test_lines_that_are_not_split_points(line):
    sections = split_sections("a.md", "## 節\n\n" + line + "\n\n本文\n")
    assert [s.heading for s in sections] == ["節"]


def test_parent_of_a_level_3_section_is_the_level_2_heading():
    sections = split_sections("maintenance.md", DOC)
    assert [s.parent for s in sections] == ["", "", "日常点検", ""]


def test_level_3_section_directly_under_the_title_has_no_parent():
    sections = split_sections("a.md", "# 題\n\n### 小\n\n本文\n")
    assert sections[1].parent == ""


def test_line_is_the_line_of_the_heading():
    assert [s.line for s in split_sections("maintenance.md", DOC)] == [1, 5, 9, 20]


def test_id_does_not_change_when_the_body_changes():
    before = split_sections("maintenance.md", DOC)
    after = split_sections("maintenance.md", DOC.replace("点検の本文。", "書き直した本文。\n\n段落を足した。"))
    assert [s.id for s in before] == [s.id for s in after]


def test_id_changes_when_the_heading_changes():
    before = split_sections("maintenance.md", DOC)
    after = split_sections("maintenance.md", DOC.replace("## ログを読む場所", "## ログの場所"))
    assert before[3].id != after[3].id
    assert [s.id for s in before[:3]] == [s.id for s in after[:3]]


def test_id_names_the_file_and_is_unique():
    ids = [s.id for s in split_sections("maintenance.md", DOC)]
    assert all(value.startswith("maintenance-") and len(value) == len("maintenance-") + 10 for value in ids)
    assert len(set(ids)) == len(ids)
    other = [s.id for s in split_sections("templates/change-record.md", DOC)]
    assert all(value.startswith("templates-change-record-") for value in other)
    assert not set(ids) & set(other)


def test_same_heading_twice_gets_two_ids():
    sections = split_sections("a.md", "## 確認\n\n1\n\n## 確認\n\n2\n")
    assert sections[0].id != sections[1].id


def test_same_heading_under_different_parents_gets_two_ids():
    sections = split_sections("a.md", "## A\n\n### 確認\n\n1\n\n## B\n\n### 確認\n\n2\n")
    assert sections[1].id != sections[3].id


def test_line_longer_than_a_heading_can_be_is_not_a_heading():
    long_line = "## " + "あ" * MAX_HEADING_LENGTH
    sections = split_sections("a.md", "## 節\n\n" + long_line + "\n\n本文\n")
    assert [s.heading for s in sections] == ["節"]
    assert long_line in sections[0].text
    assert _headings("## " + "あ" * (MAX_HEADING_LENGTH - 3) + "\n") == ["あ" * (MAX_HEADING_LENGTH - 3)]


@pytest.mark.parametrize("line", [
    "## a" + " " * 40000 + "b",
    "## " + " #" * 20000,
    "##" + " " * 40000,
    "#" * 40000,
    "`" * 40000,
    "   ```" + " " * 40000 + "x",
])
def test_very_long_line_is_handled_quickly(line):
    started = time.monotonic()
    try:
        split_sections("a.md", "## 節\n\n" + line + "\n")
    except SplitError:
        pass
    assert time.monotonic() - started < 2.0
