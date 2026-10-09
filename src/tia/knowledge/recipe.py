"""知識の束の作り方(レシピ)の読み込み。知らないキーと形の違う値は誤記とみなして失敗させる。"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from tia.models import IncidentType

MAX_DAYS = 365
MIN_ALIAS_LENGTH = 2
MIN_REASON_LENGTH = 5
_NAME_PART = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_SHA256 = re.compile(r"[0-9a-f]{64}")


class RecipeError(ValueError):
    """レシピが読めない、または形が違う。"""


@dataclass(frozen=True)
class CardSection:
    file: str
    heading: str


@dataclass(frozen=True)
class RecentChanges:
    file: str
    heading: str
    days: int


@dataclass(frozen=True)
class AllowedLine:
    """秘密の検査で、確かめた上で許可する 1 行。行は、文の SHA-256 で指す。形や言葉では指せない。"""
    file: str
    line_sha256: str
    reason: str


@dataclass(frozen=True)
class Recipe:
    files: tuple[str, ...]
    card_sections: tuple[CardSection, ...] = ()
    recent_changes: RecentChanges | None = None
    hosts: dict[str, tuple[str, ...]] | None = None
    types: dict[IncidentType, tuple[str, ...]] | None = None
    prefer_headings: tuple[str, ...] = ()
    allow_secrets: tuple[AllowedLine, ...] = ()

    def __post_init__(self) -> None:
        if self.hosts is None:
            object.__setattr__(self, "hosts", {})
        if self.types is None:
            object.__setattr__(self, "types", {})


def _text(value: object, where: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RecipeError(f"レシピの {where} は空でない文字列で書く: {value!r}")
    return value.strip()


def _mapping(value: object, where: str, allowed: set[str] | None = None) -> dict:
    if not isinstance(value, dict):
        raise RecipeError(f"レシピの {where} は対応表で書く")
    if allowed is not None:
        for key in value:
            if key not in allowed:
                raise RecipeError(f"レシピの知らないキー: {where}.{key}" if where else f"レシピの知らないキー: {key}")
    return value


def _words(value: object, where: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise RecipeError(f"レシピの {where} は空でない配列で書く: {value!r}")
    words = tuple(_text(item, where) for item in value)
    for word in words:
        if len(word) < MIN_ALIAS_LENGTH:
            raise RecipeError(f"レシピの {where} の言葉は {MIN_ALIAS_LENGTH} 文字以上で書く: {word!r}")
    return words


def is_safe_name(value: object) -> bool:
    """出典の場所の中の Markdown を指す名前か。`..`、絶対の場所、隠しファイルは受け付けない。"""
    return (isinstance(value, str) and value.endswith(".md")
            and all(_NAME_PART.fullmatch(part) for part in value.split("/")))


def _file_name(value: object) -> str:
    if not isinstance(value, str):
        raise RecipeError(f"レシピの files はファイル名の配列で書く: {value!r}")
    if not is_safe_name(value):
        raise RecipeError(f"レシピの files に使えない名前: {value}")
    return value


def _known_file(value: object, files: tuple[str, ...], where: str) -> str:
    name = _text(value, f"{where}.file")
    if name not in files:
        raise RecipeError(f"レシピの {where}.file が files にない: {name}")
    return name


def _card(value: object, files: tuple[str, ...]) -> tuple[tuple[CardSection, ...], RecentChanges | None]:
    card = _mapping(value, "card", {"sections", "recent_changes"})
    raw_sections = card.get("sections", [])
    if not isinstance(raw_sections, list):
        raise RecipeError("レシピの card.sections は配列で書く")
    sections = []
    for item in raw_sections:
        if not isinstance(item, dict):
            raise RecipeError(f"レシピの card.sections の要素は対応表で書く: {item!r}")
        entry = _mapping(item, "card.sections", {"file", "heading"})
        sections.append(CardSection(_known_file(entry.get("file"), files, "card.sections"),
                                    _text(entry.get("heading"), "card.sections.heading")))
    recent = None
    if "recent_changes" in card:
        entry = _mapping(card["recent_changes"], "card.recent_changes", {"file", "heading", "days"})
        days = entry.get("days")
        if isinstance(days, bool) or not isinstance(days, int) or not 1 <= days <= MAX_DAYS:
            raise RecipeError(f"レシピの card.recent_changes.days は 1 から {MAX_DAYS} の整数で書く: {days!r}")
        recent = RecentChanges(_known_file(entry.get("file"), files, "card.recent_changes"),
                               _text(entry.get("heading"), "card.recent_changes.heading"), days)
    return tuple(sections), recent


def _hosts(value: object) -> dict[str, tuple[str, ...]]:
    hosts: dict[str, tuple[str, ...]] = {}
    for name, aliases in _mapping(value, "hosts").items():
        host = _text(name, "hosts のホスト名")
        words = _words(aliases, f"hosts.{host}")
        hosts[host] = (host, *(word for word in words if word != host))
    return hosts


def _types(value: object) -> dict[IncidentType, tuple[str, ...]]:
    types: dict[IncidentType, tuple[str, ...]] = {}
    for name, words in _mapping(value, "types").items():
        try:
            incident_type = IncidentType(name)
        except ValueError:
            raise RecipeError(f"レシピの types に知らない種類: {name}") from None
        types[incident_type] = _words(words, f"types.{name}")
    return types


def _allowed(value: object, files: tuple[str, ...]) -> tuple[AllowedLine, ...]:
    if not isinstance(value, list):
        raise RecipeError("レシピの allow_secrets は配列で書く")
    entries: list[AllowedLine] = []
    for item in value:
        if not isinstance(item, dict):
            raise RecipeError(f"レシピの allow_secrets の要素は対応表で書く: {item!r}")
        entry = _mapping(item, "allow_secrets", {"file", "line_sha256", "reason"})
        file = _known_file(entry.get("file"), files, "allow_secrets")
        digest = entry.get("line_sha256")
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            raise RecipeError("レシピの allow_secrets.line_sha256 は、行の SHA-256（小文字の 16 進で 64 桁）で書く")
        reason = entry.get("reason")
        if not isinstance(reason, str) or len(reason.strip()) < MIN_REASON_LENGTH:
            raise RecipeError(f"レシピの allow_secrets.reason は、許可する理由を {MIN_REASON_LENGTH} 文字以上で書く")
        if any((e.file, e.line_sha256) == (file, digest) for e in entries):
            raise RecipeError(f"レシピの allow_secrets に重複がある: {file}")
        entries.append(AllowedLine(file, digest, reason.strip()))
    return tuple(entries)


def load_recipe(path: Path) -> Recipe:
    try:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise RecipeError(f"レシピが読めない: {path}: {type(exc).__name__}") from None
    if not isinstance(data, dict):
        raise RecipeError("レシピは対応表で書く")
    root = _mapping(data, "", {"files", "card", "hosts", "types", "prefer_headings", "allow_secrets"})
    raw_files = root.get("files")
    if not isinstance(raw_files, list) or not raw_files:
        raise RecipeError(f"レシピの files は空でない配列で書く: {raw_files!r}")
    files = tuple(_file_name(name) for name in raw_files)
    if len(set(files)) != len(files):
        raise RecipeError("レシピの files に重複がある")
    card_sections, recent = _card(root["card"], files) if "card" in root else ((), None)
    prefer = root.get("prefer_headings", [])
    if not isinstance(prefer, list):
        raise RecipeError("レシピの prefer_headings は配列で書く")
    return Recipe(
        files=files,
        card_sections=card_sections,
        recent_changes=recent,
        hosts=_hosts(root["hosts"]) if "hosts" in root else {},
        types=_types(root["types"]) if "types" in root else {},
        prefer_headings=tuple(_text(word, "prefer_headings") for word in prefer),
        allow_secrets=_allowed(root["allow_secrets"], files) if "allow_secrets" in root else (),
    )
