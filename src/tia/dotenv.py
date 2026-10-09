"""`.env` の読み込み。KEY=値、先頭の export、# のコメント、引用符だけを受け付ける。展開はしない。

python-dotenv は入れない。形の違う行は、行番号を付けて断る。誤りの表示に行の中身は出さない（秘密が混ざるため）。
"""
from __future__ import annotations

import re
from pathlib import Path

NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


class DotenvError(ValueError):
    """`.env` の行の形の誤り。"""


def _unquote(rest: str) -> str | None:
    """引用符で始まる値を読む。閉じていない、閉じた後に字が続く、は None。"""
    quote = rest[0]
    out: list[str] = []
    i = 1
    while i < len(rest):
        char = rest[i]
        if quote == '"' and char == "\\" and i + 1 < len(rest) and rest[i + 1] in '"\\':
            out.append(rest[i + 1])
            i += 2
            continue
        if char == quote:
            tail = rest[i + 1:].strip()
            if tail and not tail.startswith("#"):
                return None
            return "".join(out)
        out.append(char)
        i += 1
    return None


def parse_dotenv(text: str, *, source: str = ".env") -> dict[str, str]:
    """本文を読む。同じ名前は後の行が勝つ。"""
    values: dict[str, str] = {}
    for number, raw in enumerate(text.lstrip("﻿").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export ") or line.startswith("export\t"):
            line = line[len("export"):].strip()
        name, separator, rest = line.partition("=")
        name = name.strip()
        if not separator or not NAME.fullmatch(name):
            raise DotenvError(f"{source} の {number} 行目は KEY=値 の形で書く")
        rest = rest.strip()
        if rest[:1] in ("'", '"'):
            value = _unquote(rest)
            if value is None:
                raise DotenvError(f"{source} の {number} 行目は引用符を閉じて書く")
        else:
            # 引用符なしの値は、空白に続く # から後をコメントとみなす
            value = re.split(r"\s+#", rest, maxsplit=1)[0].strip()
        values[name] = value
    return values


def read_dotenv(path: Path) -> dict[str, str]:
    return parse_dotenv(Path(path).read_text(encoding="utf-8"), source=str(path))
