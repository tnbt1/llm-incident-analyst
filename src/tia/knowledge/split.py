"""文書を見出しで節に分ける。

分けるのは `#`、`##`、`###` の見出し。コードブロックの中の `#` は見出しにしない。mermaid のブロックは除く。
下線で書く見出し（`===`、`---`）は使わない前提で、分ける位置にしない。
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import PurePosixPath

_FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")
_HEADING = re.compile(r"^(#{1,3})[ \t]+([^ \t].*)$")
ID_HASH_LENGTH = 10
MAX_HEADING_LENGTH = 200


class SplitError(ValueError):
    """文書の形が壊れていて、節に分けられない。"""


@dataclass(frozen=True)
class RawSection:
    id: str
    file: str
    heading: str
    level: int
    parent: str
    order: int
    line: int
    text: str


def section_id(file: str, parent: str, heading: str, occurrence: int) -> str:
    """ファイル、上位の見出し、見出しから決める。本文を書き換えても変わらない。"""
    slug = str(PurePosixPath(file).with_suffix("")).replace("/", "-").lower()
    digest = hashlib.sha256(f"{file}\n{parent}\n{heading}\n{occurrence}".encode()).hexdigest()
    return f"{slug}-{digest[:ID_HASH_LENGTH]}"


def _heading(line: str) -> tuple[int, str] | None:
    """見出しの行なら (レベル, 見出しの文)。長すぎる行は見出しにしない。"""
    if len(line) > MAX_HEADING_LENGTH:
        return None
    match = _HEADING.match(line)
    if match is None:
        return None
    text = match.group(2).rstrip()
    bare = text.rstrip("#")
    if bare != text and bare.endswith((" ", "\t")):
        text = bare.rstrip()  # `## 題名 ##` の後ろの `#`
    return (len(match.group(1)), text) if text else None


def _clean_lines(file: str, text: str) -> list[tuple[int, str, bool]]:
    """(元の行番号, 行, コードブロックの中か) の並び。mermaid を除き、外側の空行と行末の空白を整える。"""
    out: list[tuple[int, str, bool]] = []
    fence: tuple[str, int, int, bool] | None = None  # 記号、長さ、開始行、mermaid か
    blank = False
    for number, line in enumerate(text.split("\n"), start=1):
        match = _FENCE.match(line)
        if fence is not None:
            char, length, _, mermaid = fence
            closes = (match is not None and match.group(1)[0] == char and len(match.group(1)) >= length
                      and not match.group(2).strip())
            if not mermaid:
                out.append((number, line, True))
            if closes:
                fence = None
            continue
        if match is not None:
            info = match.group(2).strip().split(" ")[0].lower()
            mermaid = info == "mermaid" or info.startswith("mermaid{")
            fence = (match.group(1)[0], len(match.group(1)), number, mermaid)
            if not mermaid:
                out.append((number, line, True))
                blank = False
            continue
        line = line.rstrip()
        if not line:
            if blank:
                continue
            blank = True
        else:
            blank = False
        out.append((number, line, False))
    if fence is not None:
        raise SplitError(f"{file}:{fence[2]} コードブロックが閉じていない")
    return out


def split_sections(file: str, text: str) -> list[RawSection]:
    sections: list[dict] = []
    current: dict | None = None
    level_2 = ""
    seen: dict[tuple[str, str], int] = {}
    for number, line, in_code in _clean_lines(file, text):
        found = None if in_code else _heading(line)
        if found is not None:
            level, heading = found
            if level == 1:
                level_2 = ""
            parent = level_2 if level == 3 else ""
            if level == 2:
                level_2 = heading
            current = {"heading": heading, "level": level, "parent": parent, "line": number, "lines": [line]}
            sections.append(current)
        elif current is None:
            if not line:
                continue
            current = {"heading": PurePosixPath(file).stem, "level": 0, "parent": "", "line": number,
                       "lines": [line]}
            sections.append(current)
        else:
            current["lines"].append(line)
    result = []
    for order, item in enumerate(sections):
        key = (item["parent"], item["heading"])
        occurrence = seen.get(key, 0)
        seen[key] = occurrence + 1
        body = "\n".join(item["lines"]).strip("\n")
        result.append(RawSection(
            id=section_id(file, item["parent"], item["heading"], occurrence), file=file, heading=item["heading"],
            level=item["level"], parent=item["parent"], order=order, line=item["line"], text=body))
    return result
