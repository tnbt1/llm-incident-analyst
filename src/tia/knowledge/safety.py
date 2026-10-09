"""文書の中身の検査と無害化。束は LLM に渡り、画面にも出る。文書は規則より低く信頼する。

- 鍵、トークン、パスワードの形をした文字列を見つける。見つけた値そのものは、どこにも出さない。
- 制御文字、見えない文字、チャットの区切りに見える文字列を無害にする。
- 指示を上書きしようとする言い回しを、注意として記録する。
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

from tia.knowledge.scan import (HINTS, KIND_LABELS, MAX_SCANNED_LINE, Finding, SecretFound, line_digest,
                                scan_secrets)

__all__ = ["HINTS", "KIND_LABELS", "RESERVED_TAGS", "Finding", "Notice", "SecretFound", "find_instruction_phrases",
           "line_digest", "neutralise", "reserved_tag_pattern", "scan_secrets"]

# 文脈の組み立てが区切りに使う名前。文書の中の同じ形のタグは無害にする。
RESERVED_TAGS = ("alert_data", "probe_data", "env_card", "doc", "case", "stats", "rules", "think", "tool_call",
                 "tool_response")

PHRASE_LIMIT = 60


def _character_class(ranges: tuple[tuple[int, int], ...]) -> str:
    """文字の範囲を、正規表現の文字クラスにする。見えない文字をソースに直接書かないため、番号から作る。"""
    return "".join(f"\\U{low:08x}" if low == high else f"\\U{low:08x}-\\U{high:08x}" for low, high in ranges)


# 取り除く文字。Unicode 15.1 の制御（Cc）と書式（Cf）の全部から、タブと改行を除いたもの。
# 機械や Python の版で結果が変わらないよう、範囲を固定で持つ。tests が、実行中の Python の表と照らし合わせる。
INVISIBLE_RANGES = (
    (0x0000, 0x0008), (0x000B, 0x000C), (0x000E, 0x001F), (0x007F, 0x009F),
    (0x00AD, 0x00AD), (0x0600, 0x0605), (0x061C, 0x061C), (0x06DD, 0x06DD), (0x070F, 0x070F),
    (0x0890, 0x0891), (0x08E2, 0x08E2), (0x180E, 0x180E), (0x200B, 0x200F), (0x202A, 0x202E),
    (0x2060, 0x206F), (0xFEFF, 0xFEFF), (0xFFF9, 0xFFFB), (0x110BD, 0x110BD), (0x110CD, 0x110CD),
    (0x13430, 0x1343F), (0x1BCA0, 0x1BCA3), (0x1D173, 0x1D17A), (0xE0000, 0xE007F),
    # 書式ではないが、見えないか、前の文字の見え方だけを変える文字
    (0x034F, 0x034F),                      # 結合書記素の結合子
    (0x115F, 0x1160), (0x3164, 0x3164), (0xFFA0, 0xFFA0),  # ハングルの埋め字
    (0xFE00, 0xFE0F), (0xE0100, 0xE01EF),  # 異体字セレクタ
)
LINE_BREAK_RANGES = ((0x2028, 0x2029),)
_LEFT = "<\\uff1c"    # 半角と全角の「<」
_RIGHT = ">\\uff1e"
_BAR = "|\\uff5c"

_DROP = re.compile("[" + _character_class(INVISIBLE_RANGES) + "]")
_LINE_BREAKS = re.compile("[" + _character_class(LINE_BREAK_RANGES) + "]")
_TEMPLATE_TOKEN = re.compile(f"[{_LEFT}](?=[{_BAR}][^{_BAR}\\n{_RIGHT}]{{1,40}}[{_BAR}][{_RIGHT}])")
_NAMES = "(?:" + "|".join(RESERVED_TAGS) + ")"
# タグの中の空白。全角と幅のある空白も含む
_BLANK = "[ \\t\\u00a0\\u1680\\u2000-\\u200a\\u202f\\u205f\\u3000]"
_SPACE = f"{_BLANK}{{0,8}}"
_WS = f"{_BLANK}{{1,8}}"
_ATTRS = f"[^{_LEFT}{_RIGHT}\\n]{{0,200}}"
# 区切りになるのは、閉じた形のタグだけ。`wc -l <doc` や `cat <<think`、`sort <stats >out` のような、コマンドの一部は変えない。
# 閉じるタグは、属性やスラッシュ、幅のある空白が付いていても区切りとみなす。
_RESERVED = re.compile(
    f"[{_LEFT}](?=(?:"
    f"{_SPACE}/{_SPACE}{_NAMES}(?:{_WS}{_ATTRS})?{_SPACE}/?{_SPACE}"
    f"|{_SPACE}{_NAMES}(?:{_SPACE}/{_SPACE}|{_WS}[^{_LEFT}{_RIGHT}\\n \\t\\u3000]{_ATTRS}/?{_SPACE})?"
    f")[{_RIGHT}])", re.IGNORECASE)


def reserved_tag_pattern() -> re.Pattern[str]:
    """閉じた形の区切りのタグを見つける正規表現。入力の無害化と、出力の検証が同じ定義を使う。"""
    return _RESERVED

_PHRASES = tuple(re.compile(pattern, re.IGNORECASE) for pattern in (
    r"ignore (?:all |any |the )?(?:previous|prior|above) instructions",
    r"disregard (?:all |any |the )?(?:previous|prior|above)",
    r"(?:以前|これまで|上記|前)の指示[をは]無視",
    r"system prompt",
    r"システムプロンプト",
))


@dataclass(frozen=True)
class Notice:
    file: str
    line: int
    phrase: str


def neutralise(text: str) -> tuple[str, int]:
    """無害にした文と、取り除いたり置き換えたりした数を返す。改行の統一は数えない。"""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    count = 0
    for pattern, replacement in ((_LINE_BREAKS, "\n"), (_DROP, ""), (_TEMPLATE_TOKEN, "&lt;"), (_RESERVED, "&lt;")):
        text, changed = pattern.subn(replacement, text)
        count += changed
    return text, count


def find_instruction_phrases(file: str, text: str) -> list[Notice]:
    """指示を上書きしようとする言い回し。文は変えず、場所だけを記録する。"""
    notices: list[Notice] = []
    for number, line in enumerate(text.split("\n"), start=1):
        # 全角や幅のある空白で書いた言い回しも見つけるため、互換の形にそろえてから探す
        line = " ".join(unicodedata.normalize("NFKC", line[:MAX_SCANNED_LINE]).split())
        for pattern in _PHRASES:
            match = pattern.search(line)
            if match is not None:
                notices.append(Notice(file, number, match.group(0)[:PHRASE_LIMIT]))
                break
    return notices
