"""トークン数の見積もり。実行時に通信もモデルの取得もしない。

係数は、日本語と英語が混ざった運用文書（約 90 節）を利用するモデルのトークナイザーで数えた値に、最小二乗で合わせたもの。
節ごとの誤差はおおむね 1 割以内、文書全体ではほぼ一致する。モデルが違えば係数を合わせ直す。
呼び出し側は `llama-server` の `/tokenize` を使う関数に差し替えられる。
"""
from __future__ import annotations

import re
from collections.abc import Callable

TokenCounter = Callable[[str], int]

ESTIMATOR = "tia-chars-v1"

# 1,000 分の 1 トークン単位。浮動小数を使わず、どの環境でも同じ値にする。
_KANJI = 1042
_KANA = 355
_WIDE = 2233
_WORD = 693
_LETTER = 41
_DIGIT = 1262
_PUNCT = 506
_SPACE = 654
_OTHER = 1000

_RE_KANJI = re.compile(r"[一-鿿々]")
_RE_KANA = re.compile(r"[぀-ゟ゠-ヿ]")
_RE_WIDE = re.compile(r"[　-〄〆-〿＀-￯]")
_RE_WORD = re.compile(r"[A-Za-z]+")
_RE_DIGIT = re.compile(r"[0-9]")
_RE_PUNCT = re.compile(r"[!-/:-@\[-`{-~]")
_RE_SPACE = re.compile(r"\n| +|\t+")
_RE_KNOWN = re.compile(r"[一-鿿々぀-ゟ゠-ヿ　-〄〆-〿＀-￯"
                       r"A-Za-z0-9!-/:-@\[-`{-~\n \t]")


def estimate_tokens(text: str) -> int:
    """文字の種類ごとの数から見積もる。空の文は 0、それ以外は 1 以上。"""
    if not text:
        return 0
    words = _RE_WORD.findall(text)
    milli = (
        _KANJI * len(_RE_KANJI.findall(text))
        + _KANA * len(_RE_KANA.findall(text))
        + _WIDE * len(_RE_WIDE.findall(text))
        + _WORD * len(words)
        + _LETTER * sum(len(word) for word in words)
        + _DIGIT * len(_RE_DIGIT.findall(text))
        + _PUNCT * len(_RE_PUNCT.findall(text))
        + _SPACE * len(_RE_SPACE.findall(text))
        + _OTHER * len(_RE_KNOWN.sub("", text))
    )
    return max(1, (milli + 999) // 1000)
