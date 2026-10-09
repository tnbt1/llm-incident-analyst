"""節の属性と索引。構造（ホスト、種類）と言葉の両方で節を探せるようにする。

関係の強さは 2 段階。見出しに出ていれば 2、本文に 2 回以上出ていれば 1。
種類の言葉は、コードブロックの外だけで数える。コマンドに出る `sudo` や `docker` は、節の主題を表さないため。
言葉は、英数字の並び（3 文字以上。数字だけの番号も含む）と、漢字・カタカナの隣り合う 2 文字。ひらがなは手がかりにしない。
"""
from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping, Sequence
from datetime import date

from tia.knowledge.recipe import Recipe

STRONG = 2
WEAK = 1
BODY_MENTIONS_FOR_WEAK = 2

_ISO_DATE = re.compile(r"(?<![0-9])(20[0-9]{2})-([0-9]{2})-([0-9]{2})(?![0-9])")
_WORD = re.compile(r"[A-Za-z0-9]{3,}")
_FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
_CJK_RUN = re.compile(r"[一-鿿々ァ-ヺー]{2,}")
STOPWORDS = frozenset({
    "the", "and", "for", "with", "from", "that", "this", "not", "are", "was", "has", "have", "over", "under",
    "into", "than", "too", "high", "low", "more", "less", "last", "min", "max", "avg", "per",
})


def _pattern(word: str) -> re.Pattern[str]:
    """英数字の言葉は、前後が英数字でないときだけ一致させる。`FRR` が `OFFRRAMP` に当たらないようにする。"""
    if word.isascii():
        return re.compile(r"(?<![A-Za-z0-9])" + re.escape(word) + r"(?![A-Za-z0-9])", re.IGNORECASE)
    return re.compile(re.escape(word))


def _strength(words: tuple[str, ...], heading: str, text: str) -> int:
    patterns = [_pattern(word) for word in words]
    if any(pattern.search(heading) for pattern in patterns):
        return STRONG
    body = text.split("\n", 1)[1] if "\n" in text else ""
    # 長い言葉から数え、数えた部分を消す。`APP01` を `APP` としても数えないため
    mentions = 0
    for word, pattern in sorted(zip(words, patterns), key=lambda pair: (-len(pair[0]), pair[0])):
        body, count = pattern.subn(" ", body)
        mentions += count
    return WEAK if mentions >= BODY_MENTIONS_FOR_WEAK else 0


def detect_hosts(recipe: Recipe, heading: str, text: str) -> dict[str, int]:
    found = {host: _strength(aliases, heading, text) for host, aliases in recipe.hosts.items()}
    return {host: found[host] for host in sorted(found) if found[host]}


def without_code(text: str) -> str:
    """コードブロックを除いた文。囲みの行も除く。"""
    kept: list[str] = []
    fence = ""
    for line in text.split("\n"):
        match = _FENCE.match(line)
        if fence:
            if match is not None and match.group(1)[0] == fence[0] and len(match.group(1)) >= len(fence):
                fence = ""
        elif match is not None:
            fence = match.group(1)
        else:
            kept.append(line)
    return "\n".join(kept)


def fold(name: str) -> str:
    """名前を比べるための形。前後の空白を除き、全角と半角、大文字と小文字をそろえる。"""
    return unicodedata.normalize("NFKC", name).strip().casefold()


def detect_types(recipe: Recipe, heading: str, text: str) -> dict[str, int]:
    prose = without_code(text)
    found = {str(kind): _strength(words, heading, prose) for kind, words in recipe.types.items()}
    return {kind: found[kind] for kind in sorted(found) if found[kind]}


def confirmed_on(text: str, today: date) -> str | None:
    """節に書かれた日付（年-月-日）のうち、生成日以前で最も新しいもの。なければ None。"""
    latest: date | None = None
    for year, month, day in _ISO_DATE.findall(text):
        try:
            found = date(int(year), int(month), int(day))
        except ValueError:
            continue
        if found <= today and (latest is None or found > latest):
            latest = found
    return latest.isoformat() if latest else None


def extract_terms(text: str) -> set[str]:
    terms = {word.lower() for word in _WORD.findall(text)} - STOPWORDS
    for run in _CJK_RUN.findall(text):
        terms.update(run[i:i + 2] for i in range(len(run) - 1))
    return terms


def _weight(frequency: int, total: int) -> int:
    """珍しい言葉ほど重い。半分を超える節に出る言葉は 0 で、索引に入れない。"""
    if frequency <= max(1, total // 20):
        return 3
    if frequency <= max(2, total // 5):
        return 2
    if frequency <= max(3, total // 2):
        return 1
    return 0


def _aliases(hosts: Mapping[str, Sequence[str]] | None) -> dict[str, list[str]]:
    """ホストの呼び方から、正式な名前を引く表。1 つの呼び方が複数のホストを指すことがある。"""
    found: dict[str, set[str]] = {}
    for host, names in (hosts or {}).items():
        for name in (host, *names):
            if fold(name):
                found.setdefault(fold(name), set()).add(host)
    return {name: sorted(found[name]) for name in sorted(found)}


def build_index(sections: list[dict], names: Mapping[str, Sequence[str]] | None = None) -> dict:
    """`id`、`heading`、`text`、`hosts`、`types` を持つ節の並びから索引を作る。キーは名前の順。"""
    hosts: dict[str, dict[str, int]] = {}
    types: dict[str, dict[str, int]] = {}
    in_heading: dict[str, set[str]] = {}
    in_body: dict[str, set[str]] = {}
    for section in sections:
        for host, strength in section["hosts"].items():
            hosts.setdefault(host, {})[section["id"]] = strength
        for kind, strength in section["types"].items():
            types.setdefault(kind, {})[section["id"]] = strength
        heading_terms = extract_terms(section["heading"])
        body = section["text"].split("\n", 1)[1] if "\n" in section["text"] else ""
        for term in heading_terms:
            in_heading.setdefault(term, set()).add(section["id"])
        for term in extract_terms(body) - heading_terms:
            in_body.setdefault(term, set()).add(section["id"])
    terms: dict[str, dict] = {}
    for term in sorted(set(in_heading) | set(in_body)):
        heading_ids = in_heading.get(term, set())
        body_ids = in_body.get(term, set()) - heading_ids
        weight = _weight(len(heading_ids | body_ids), len(sections))
        if weight:
            terms[term] = {"weight": weight, "heading": sorted(heading_ids), "body": sorted(body_ids)}
    return {
        "aliases": _aliases(names),
        "hosts": {host: dict(sorted(hosts[host].items())) for host in sorted(hosts)},
        "types": {kind: dict(sorted(types[kind].items())) for kind in sorted(types)},
        "terms": terms,
    }
