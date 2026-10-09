"""解析に渡す節の選択。

点数は整数で、同じ入力からはいつも同じ結果になる。

| 手がかり | 点 |
|---|---|
| ホストが見出しにある / 本文にある | 100 / 30。複数のホストは、最も強い 1 つだけを数える。同じ強さなら名前の順で先のもの |
| 種類の言葉が見出しにある / 本文にある | 60 / 20。コードブロックの中の言葉は数えない |
| 題名とタグの言葉が一致 | 言葉の重み（1〜3）× 5。見出しでの一致は 2 倍。合計 80 まで |
| 解析に向く見出し | 20。ほかの点があるときだけ。ホストが見出しにある節（そのホストの状態を見る節）は 40 |

選ぶ条件と順序。

1. 50 点以上で、種類か言葉の一致がある節だけを選ぶ。ホストが合うだけの節（バックアップの手順など）は選ばない。
   ホストが見出しにあり、見出しが解析に向く節は、そのホストの状態を見る節として、種類や言葉が合わなくても選ぶ。
2. 見出しにホストの名前があり、そのどれもがインシデントのホストでない節は、別のホストの節として除く。
3. 並びは点の高い順。同点は束の順（レシピの files の順、その中では文書の上から）。
4. 1 節は予算の半分まで。半分に収まる節が 1 つもないときだけ、予算に収まる大きい節を選ぶ。
5. 上から、予算と個数に収まるものを取る。

題名の中のホストの名前と、場所（`/var/lib/docker` など）は、言葉として数えない。
環境カードに入れた節は、既に文脈にあるので選ばない。見出しだけの節（30 トークン未満）も選ばない。
ホストの名前は、前後の空白、大文字と小文字、全角と半角の違いを除いて比べ、束が持つ呼び方から正式な名前を引く。
"""
from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from tia.knowledge.bundle import Bundle, Section
from tia.knowledge.index import STRONG, extract_terms, fold

HOST_POINTS = {STRONG: 100, 1: 30}
TYPE_POINTS = {STRONG: 60, 1: 20}
TERM_UNIT = 5
TERM_CAP = 80
PREFERRED_POINTS = 20
OWN_STATUS_POINTS = 40
MIN_SCORE = 50
MIN_SECTION_TOKENS = 30
TITLE_LIMIT = 200
TERMS_IN_REASON = 5
MIN_NAME_PART = 3
PLACE = {STRONG: "見出し", 1: "本文"}

_PATH = re.compile(r"(?:~|\.{1,2})?(?:/[A-Za-z0-9._@%+-]{1,80}){1,40}/?")
_NAME_PART = re.compile(r"[a-z0-9]+")


@dataclass(frozen=True)
class Selected:
    section: Section
    score: int
    reasons: tuple[str, ...]


def _texts(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if not isinstance(value, Sequence):
        return []
    return [item for item in value if isinstance(item, str)]


def _tag_words(tags: object) -> list[str]:
    if isinstance(tags, str):
        return [tags]
    if not isinstance(tags, Sequence):
        return []
    words = []
    for tag in tags:
        value = tag.get("value") if isinstance(tag, dict) else tag
        if isinstance(value, str):
            words.append(value)
    return words


def resolve_hosts(bundle: Bundle, hosts: object) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """インシデントのホストを、束の正式な名前にする。(正式な名前を名前の順で, 束にない名前を渡された順で) を返す。"""
    known: dict[str, list[str]] = {fold(host): [host] for host in bundle.index.get("hosts", {})}
    for section in bundle.sections:
        for host in section.hosts:
            known.setdefault(fold(host), [host])
    known.update(bundle.index.get("aliases", {}))
    resolved: set[str] = set()
    unknown: list[str] = []
    for host in _texts(hosts):
        name = fold(host)
        if not name:
            continue
        found = known.get(name) or known.get(name.split(".")[0])
        if found:
            resolved.update(found)
        elif host.strip() not in unknown:
            unknown.append(host.strip())
    return tuple(sorted(resolved)), tuple(unknown)


def _terms(words: str, names: Sequence[str]) -> list[str]:
    """題名とタグの言葉。場所とホストの名前は、言葉にしない。"""
    text = _PATH.sub(" ", words)
    parts: set[str] = set()
    for name in names:
        text = re.sub(re.escape(name), " ", text, flags=re.IGNORECASE)
        parts.update(part for part in _NAME_PART.findall(fold(name)) if len(part) >= MIN_NAME_PART)
    return sorted(extract_terms(text) - parts)


def _score(section: Section, hosts: Sequence[str], kind: str, terms: list[str], index: dict) -> tuple[Selected, bool]:
    """点と理由。2 つ目の値は、種類か言葉の一致があるか。"""
    score = 0
    reasons: list[str] = []
    own = False
    # hosts は名前の順。max は最初に見つけた最大を返すので、同じ強さなら名前の順で先のものになる
    strength, host = max(((section.hosts.get(h, 0), h) for h in hosts), key=lambda pair: pair[0], default=(0, ""))
    if strength:
        score += HOST_POINTS[strength]
        reasons.append(f"ホスト {host} が{PLACE[strength]}にある")
        own = strength == STRONG and section.preferred
    supported = own
    strength = section.types.get(kind, 0)
    if strength:
        supported = True
        score += TYPE_POINTS[strength]
        reasons.append(f"種類 {kind} の言葉が{PLACE[strength]}にある")
    points = 0
    matched: list[str] = []
    for term in terms:
        entry = index["terms"].get(term)
        if entry is None:
            continue
        if section.id in entry["heading"]:
            points += entry["weight"] * TERM_UNIT * 2
        elif section.id in entry["body"]:
            points += entry["weight"] * TERM_UNIT
        else:
            continue
        matched.append(term)
    if matched:
        supported = True
        score += min(points, TERM_CAP)
        shown = "、".join(matched[:TERMS_IN_REASON])
        rest = len(matched) - TERMS_IN_REASON
        reasons.append(f"題名の言葉が一致: {shown}" + (f" ほか {rest} 語" if rest > 0 else ""))
    if own:
        score += OWN_STATUS_POINTS
        reasons.append("ホストの状態を見る節")
    elif score and section.preferred:
        score += PREFERRED_POINTS
        reasons.append("解析に向く見出し")
    return Selected(section, score, tuple(reasons)), supported


def _about_others(section: Section, hosts: Sequence[str]) -> bool:
    """見出しにホストの名前があり、そのどれもがインシデントのホストでない節か。"""
    named = [host for host, strength in section.hosts.items() if strength == STRONG]
    return bool(hosts) and bool(named) and not set(named) & set(hosts)


def select_sections(bundle: Bundle, *, hosts: object, incident_type: object, title: object, tags: object = (),
                    budget: int = 3000, max_sections: int = 3) -> tuple[Selected, ...]:
    """インシデントに合う節を、点の高い順に返す。合うものがなければ空。"""
    if budget <= 0 or max_sections <= 0:
        return ()
    resolved, unknown = resolve_hosts(bundle, hosts)
    kind = str(incident_type) if isinstance(incident_type, str) else ""
    words = " ".join([title[:TITLE_LIMIT] if isinstance(title, str) else "", *_tag_words(tags)])
    terms = _terms(words, [*_texts(hosts), *resolved])
    ranked: list[Selected] = []
    for section in bundle.sections:
        if section.in_card or not MIN_SECTION_TOKENS <= section.tokens <= budget or _about_others(section, resolved):
            continue
        item, supported = _score(section, resolved, kind, terms, bundle.index)
        if supported and item.score >= MIN_SCORE:
            ranked.append(item)
    ranked.sort(key=lambda item: -item.score)  # 同点は束の順のまま（安定な並べ替え）
    within = [item for item in ranked if item.section.tokens <= budget // 2]
    notes = tuple(f"ホスト {name} は束のホストに当たらない" for name in unknown)
    chosen: list[Selected] = []
    remaining = budget
    for item in within or ranked:
        if len(chosen) == max_sections:
            break
        if item.section.tokens <= remaining:
            chosen.append(Selected(item.section, item.score, item.reasons + notes))
            remaining -= item.section.tokens
    return tuple(chosen)
