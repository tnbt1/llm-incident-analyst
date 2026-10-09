"""`.env` の読み方。KEY=値、export、# のコメント、引用符。展開はしない。"""
import pytest

from tia.dotenv import DotenvError, parse_dotenv, read_dotenv


def test_plain_lines_comments_and_blanks():
    text = "# コメント\n\nTIA_A=1\n  TIA_B = two words  \nexport TIA_C=3\nTIA_D=\n"
    assert parse_dotenv(text) == {"TIA_A": "1", "TIA_B": "two words", "TIA_C": "3", "TIA_D": ""}


def test_trailing_comment_after_a_bare_value_is_dropped():
    assert parse_dotenv("TIA_A=1 # one\nTIA_B=a#b\n") == {"TIA_A": "1", "TIA_B": "a#b"}


def test_quotes_keep_spaces_and_hashes_and_are_not_expanded():
    text = "A='x # y'\nB=\"p q\"  # note\nC=\"say \\\"hi\\\" \\\\ $HOME\"\nD='$HOME'\nE=\"\"\n"
    assert parse_dotenv(text) == {"A": "x # y", "B": "p q", "C": 'say "hi" \\ $HOME', "D": "$HOME", "E": ""}


def test_later_line_wins():
    assert parse_dotenv("A=1\nA=2\n") == {"A": "2"}


@pytest.mark.parametrize("text, line", [
    ("A=1\nno equals sign\n", 2),
    ("A=1\n\n=3\n", 3),
    ("1A=3\n", 1),
    ("A-B=3\n", 1),
    ("A='open\n", 1),
    ("A=\"open\n", 1),
    ("A='x' trailing\n", 1),
    ("export\n", 1),
    ("A=1\n;B=2\n", 2),
])
def test_malformed_line_is_refused_with_its_number(text, line):
    with pytest.raises(DotenvError) as caught:
        parse_dotenv(text, source="here.env")
    message = str(caught.value)
    assert f"here.env の {line} 行目" in message
    # 値が秘密でも、誤りの表示に行の中身は出さない
    assert "open" not in message and "trailing" not in message


def test_read_dotenv_uses_the_file_name_in_errors(tmp_path):
    path = tmp_path / ".env"
    path.write_text("TIA_A=1\n", encoding="utf-8")
    assert read_dotenv(path) == {"TIA_A": "1"}
    path.write_text("TIA_A=1\nbroken\n", encoding="utf-8")
    with pytest.raises(DotenvError, match=f"{path} の 2 行目"):
        read_dotenv(path)


def test_bom_and_crlf_are_tolerated():
    assert parse_dotenv("﻿A=1\r\nB=2\r\n") == {"A": "1", "B": "2"}
