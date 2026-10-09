"""知識の束の読み込み、鮮度、全文。

束は読み取り専用で置かれる。読み込みのたびにハッシュと形を確かめ、合わないものは使わない。
ハッシュが守るのは、写し損ないや書きかけである。置き場所へ書ける相手による書き換えは守れない。
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from tia.knowledge.build import CONTENT_FILES, FORMAT, HASH_LENGTH, content_hash
from tia.knowledge.recipe import is_safe_name

MAX_BUNDLE_FILE_BYTES = 32 * 1024 * 1024
STALE_AFTER_DAYS = 30

_VERSION = re.compile(r"([0-9]{8})-([0-9a-f]{%d})" % HASH_LENGTH)
_SECTION_ID = re.compile(r"[a-z0-9][a-z0-9._-]*-[0-9a-f]{10}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_SECTION_KEYS = {"id", "file", "heading", "level", "parent", "order", "line", "text", "hosts", "types",
                 "confirmed_on", "tokens", "sha256", "in_card", "preferred"}


class BundleError(ValueError):
    """束がない、壊れている、または書き換わっている。"""


@dataclass(frozen=True)
class Section:
    id: str
    file: str
    heading: str
    level: int
    parent: str
    order: int
    line: int
    text: str
    hosts: dict[str, int]
    types: dict[str, int]
    confirmed_on: str | None
    tokens: int
    sha256: str
    in_card: bool
    preferred: bool


@dataclass(frozen=True)
class Bundle:
    version: str
    built_on: date
    path: Path
    sections: tuple[Section, ...]
    card: str
    card_tokens: int
    tokens: int
    index: dict
    source_hashes: dict[str, str]
    notices: tuple[dict, ...]
    estimator: str

    def section(self, identifier: str) -> Section:
        for section in self.sections:
            if section.id == identifier:
                return section
        raise KeyError(identifier)


@dataclass(frozen=True)
class Freshness:
    age_days: int
    stale: bool
    source_changed: bool | None
    changed_files: tuple[str, ...]


def _is_int(value: object, low: int, high: int | None = None) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= low and (high is None or value <= high)


def _is_date(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return date.fromisoformat(value).isoformat() == value
    except ValueError:
        return False


def _strengths(value: object) -> bool:
    return isinstance(value, dict) and all(isinstance(k, str) and _is_int(v, 1, 2) for k, v in value.items())


def resolve_bundle_dir(path: Path) -> Path:
    """束そのもののフォルダか、`current` を持つ置き場所を受け取り、束のフォルダを返す。"""
    path = Path(path)
    try:
        if (path / "manifest.json").is_file():
            return path
        pointer = path / "current"
        if not pointer.is_file():
            raise BundleError(f"束がない: {path}")
    except OSError as exc:
        raise BundleError(f"束の置き場所が読めない: {path}: {type(exc).__name__}") from None
    try:
        content = pointer.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        raise BundleError(f"current が読めない: {pointer}") from None
    version = content[:-1] if content.endswith("\n") else content
    if not _VERSION.fullmatch(version):
        raise BundleError(f"current の中身が版の形ではない: {pointer}")
    try:
        if not (path / version / "manifest.json").is_file():
            raise BundleError(f"束がない: {path / version}")
    except OSError as exc:
        raise BundleError(f"束が読めない: {path / version}: {type(exc).__name__}") from None
    return path / version


def _read(directory: Path, name: str) -> bytes:
    path = directory / name
    try:
        if not path.is_file():
            raise BundleError(f"束のファイルがない: {name}")
        if path.stat().st_size > MAX_BUNDLE_FILE_BYTES:
            raise BundleError(f"束のファイルが大きすぎる: {name}")
        return path.read_bytes()
    except OSError as exc:
        raise BundleError(f"束のファイルが読めない: {name}: {type(exc).__name__}") from None


def _parse(name: str, data: bytes, kind: type) -> object:
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise BundleError(f"{name} が読めない") from None
    if not isinstance(value, kind):
        raise BundleError(f"{name} の形が違う")
    return value


def _section(item: object) -> Section:
    if not isinstance(item, dict):
        raise BundleError("sections.json に節ではない要素がある")
    for key in item.keys() ^ _SECTION_KEYS:
        raise BundleError(f"節の項目が合わない: {key}")
    checks = {
        "id": isinstance(item["id"], str) and bool(_SECTION_ID.fullmatch(item["id"])),
        "file": is_safe_name(item["file"]),
        "heading": isinstance(item["heading"], str),
        "parent": isinstance(item["parent"], str),
        "text": isinstance(item["text"], str),
        "level": _is_int(item["level"], 0, 3),
        "order": _is_int(item["order"], 0),
        "line": _is_int(item["line"], 1),
        "tokens": _is_int(item["tokens"], 0),
        "hosts": _strengths(item["hosts"]),
        "types": _strengths(item["types"]),
        "confirmed_on": item["confirmed_on"] is None or _is_date(item["confirmed_on"]),
        "in_card": isinstance(item["in_card"], bool),
        "preferred": isinstance(item["preferred"], bool),
    }
    for key, ok in checks.items():
        if not ok:
            raise BundleError(f"節の {key} の値が違う")
    if item["sha256"] != hashlib.sha256(item["text"].encode("utf-8")).hexdigest():
        raise BundleError(f"節の sha256 が本文と合わない: {item['id']}")
    return Section(**item)


def _check_index(index: dict, known: set[str]) -> None:
    if set(index) != {"aliases", "hosts", "types", "terms"} or not all(isinstance(v, dict) for v in index.values()):
        raise BundleError("索引の形が違う")
    for name, hosts in index["aliases"].items():
        if not name or not isinstance(hosts, list) or not hosts or not all(isinstance(h, str) and h for h in hosts):
            raise BundleError("索引の aliases の形が違う")
    referenced: set[str] = set()
    for group in ("hosts", "types"):
        for entries in index[group].values():
            if not _strengths(entries):
                raise BundleError(f"索引の {group} の形が違う")
            referenced.update(entries)
    for entry in index["terms"].values():
        if (not isinstance(entry, dict) or set(entry) != {"weight", "heading", "body"}
                or not _is_int(entry["weight"], 1, 3)
                or not all(isinstance(entry[k], list) and all(isinstance(i, str) for i in entry[k])
                           for k in ("heading", "body"))):
            raise BundleError("索引の terms の形が違う")
        referenced.update(entry["heading"])
        referenced.update(entry["body"])
    if referenced - known:
        raise BundleError("索引が、束にない節を指している")


def _check_manifest(manifest: dict, digest: str) -> None:
    if manifest.get("format") != FORMAT or isinstance(manifest.get("format"), bool):
        raise BundleError(f"束の形式が違う。読めるのは形式 {FORMAT}")
    if not isinstance(manifest.get("content_hash"), str) or manifest["content_hash"] != digest:
        raise BundleError("束のハッシュが合わない。中身が書き換わったか、写しが途中で止まった")
    version = manifest.get("version")
    match = _VERSION.fullmatch(version) if isinstance(version, str) else None
    if match is None or match.group(2) != digest[:HASH_LENGTH]:
        raise BundleError("束の版がハッシュと合わない")
    built_on = manifest.get("built_on")
    if not _is_date(built_on) or built_on.replace("-", "") != match.group(1):
        raise BundleError("束の生成日が版と合わない")
    counts = manifest.get("counts")
    if not isinstance(counts, dict) or not all(_is_int(counts.get(k), 0) for k in
                                               ("sections", "tokens", "card_tokens", "neutralised")):
        raise BundleError("manifest.json の counts の形が違う")
    source = manifest.get("source")
    files = source.get("files") if isinstance(source, dict) else None
    if not isinstance(files, dict) or not all(is_safe_name(name) and isinstance(value, str)
                                              and _SHA256.fullmatch(value) for name, value in files.items()):
        raise BundleError("manifest.json の source の形が違う")
    notices = manifest.get("notices")
    if not isinstance(notices, list) or not all(isinstance(n, dict) for n in notices):
        raise BundleError("manifest.json の notices の形が違う")
    if not isinstance(manifest.get("estimator"), str):
        raise BundleError("manifest.json の estimator の形が違う")


def load_bundle(path: Path) -> Bundle:
    directory = resolve_bundle_dir(Path(path))
    manifest = _parse("manifest.json", _read(directory, "manifest.json"), dict)
    files = {name: _read(directory, name) for name in CONTENT_FILES}
    _check_manifest(manifest, content_hash(files))
    sections = tuple(_section(item) for item in _parse("sections.json", files["sections.json"], list))
    identifiers = {section.id for section in sections}
    if len(identifiers) != len(sections):
        raise BundleError("節の ID が重なっている")
    counts = manifest["counts"]
    if counts["sections"] != len(sections):
        raise BundleError("節の数が manifest.json と合わない")
    tokens = sum(section.tokens for section in sections)
    if counts["tokens"] != tokens:
        raise BundleError("トークンの合計が manifest.json と合わない")
    index = _parse("index.json", files["index.json"], dict)
    _check_index(index, identifiers)
    try:
        card = files["card.md"].decode("utf-8")
    except UnicodeDecodeError:
        raise BundleError("card.md が読めない") from None
    return Bundle(
        version=manifest["version"], built_on=date.fromisoformat(manifest["built_on"]), path=directory,
        sections=sections, card=card, card_tokens=counts["card_tokens"], tokens=tokens, index=index,
        source_hashes=dict(manifest["source"]["files"]), notices=tuple(manifest["notices"]),
        estimator=manifest["estimator"])


def full_document(bundle: Bundle) -> tuple[str, int]:
    """全文方式で先頭に置く文と、そのトークン数。順序は束の順で、いつも同じ。"""
    return "\n\n".join(section.text for section in bundle.sections) + "\n", bundle.tokens


def _changed(source: Path, root: Path, name: str, expected: str) -> bool:
    path = source / name
    try:
        if not path.resolve().is_relative_to(root) or not path.is_file():
            return True
        return hashlib.sha256(path.read_bytes()).hexdigest() != expected
    except OSError:
        return True


def freshness(bundle: Bundle, today: date, *, stale_after_days: int = STALE_AFTER_DAYS,
              source_dir: Path | None = None) -> Freshness:
    """生成からの日数と、出典が生成の後に変わったか。出典を見られないときは None。"""
    age = max(0, (today - bundle.built_on).days)
    changed: tuple[str, ...] = ()
    source_changed: bool | None = None
    if source_dir is not None and Path(source_dir).is_dir():
        source = Path(source_dir)
        root = source.resolve()
        changed = tuple(name for name, expected in sorted(bundle.source_hashes.items())
                        if _changed(source, root, name, expected))
        source_changed = bool(changed)
    return Freshness(age_days=age, stale=age > stale_after_days, source_changed=source_changed,
                     changed_files=changed)
