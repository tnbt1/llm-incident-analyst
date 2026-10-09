"""知識の束の生成。

出典の文書を読み、検査し、節に分け、環境カードと索引を作って、版の付いたフォルダに書く。
同じ入力（文書、レシピ、生成日）からは、1 バイトも違わない束ができる。出典の場所には何も書かない。
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import unicodedata
from dataclasses import dataclass
from datetime import date, timedelta
from pathlib import Path

from tia.knowledge.index import build_index, confirmed_on, detect_hosts, detect_types
from tia.knowledge.recipe import AllowedLine, Recipe
from tia.knowledge.safety import (Finding, Notice, SecretFound, find_instruction_phrases, line_digest, neutralise,
                                  scan_secrets)
from tia.knowledge.split import RawSection, SplitError, split_sections
from tia.knowledge.tokens import ESTIMATOR, TokenCounter, estimate_tokens

FORMAT = 2   # 2: 索引にホストの呼び方（aliases）を持つ
MAX_FILE_BYTES = 5 * 1024 * 1024
HASH_LENGTH = 12
CONTENT_FILES = ("card.md", "index.json", "sections.json")

# 変更履歴の行の日付。年-月-日、年/月/日、年.月.日、年 月 日（漢字）。行の中で最初に出るものを使う
_ROW_DATE = re.compile(r"(?<![0-9])(20[0-9]{2})(?:[-/.]([0-9]{1,2})[-/.]([0-9]{1,2})"
                       r"|年[ \t]{0,2}([0-9]{1,2})月[ \t]{0,2}([0-9]{1,2})日?)(?![0-9])")
_ROW_RULE = re.compile(r"^[ \t]{0,8}\|?[ \t:|-]{0,2000}-[ \t:|-]{0,2000}$")


class BuildError(ValueError):
    """束を作れない。原因は文書かレシピにある。"""


@dataclass(frozen=True)
class History:
    """変更履歴の表から読めた行。"""
    rows: int = 0          # 表の行
    inside: int = 0        # 日付が期間に入る行
    outside: int = 0       # 日付が期間の外の行
    unreadable: int = 0    # 日付を読めない行


@dataclass(frozen=True)
class BuildResult:
    version: str
    path: Path
    sections: int
    tokens: int
    card_tokens: int
    neutralised: int
    notices: tuple[Notice, ...]
    # 無害化した数の内訳。文書の名前と数。0 の文書は入れない
    neutralised_files: tuple[tuple[str, int], ...] = ()
    # 秘密の検査で、許可の一覧によって通した行の数と、どの行にも当たらなくなった項目
    allowed: int = 0
    stale_allowed: tuple[AllowedLine, ...] = ()
    history: History = History()
    # 環境カードの節の下にあり、カードに含めた節。文書の名前と見出し
    card_children: tuple[tuple[str, str], ...] = ()


def _read(source: Path, root: Path, name: str) -> bytes:
    path = source / name
    try:
        if not path.resolve().is_relative_to(root):
            raise BuildError(f"文書が出典の場所の外を指している: {name}")
        if path.stat().st_size > MAX_FILE_BYTES:
            raise BuildError(f"文書が大きすぎる（上限 {MAX_FILE_BYTES:,} バイト）: {name}")
        return path.read_bytes()
    except OSError as exc:
        raise BuildError(f"文書が読めない: {name}: {type(exc).__name__}") from None


def _find(sections: list[RawSection], file: str, heading: str, what: str) -> RawSection:
    """見出しが同じ節を探す。なければ、見出しの先頭が同じ節を探す。1 つに決まらなければ失敗させる。"""
    in_file = [s for s in sections if s.file == file]
    hits = [s for s in in_file if s.heading == heading] or [s for s in in_file if s.heading.startswith(heading)]
    if not hits:
        raise BuildError(f"{what}が見つからない: {file}「{heading}」")
    if len(hits) > 1:
        raise BuildError(f"{what}に当たる見出しが {len(hits)} つある: {file}「{heading}」")
    return hits[0]


def _children(sections: list[RawSection], parent: RawSection) -> list[RawSection]:
    """節の下にある節。同じ文書で、次に同じか上の段の見出しが出るまで。"""
    found: list[RawSection] = []
    started = False
    for section in sections:
        if section is parent:
            started = True
        elif started:
            if section.file != parent.file or section.level <= parent.level:
                break
            found.append(section)
    return found


def _row_date(line: str) -> date | None:
    match = _ROW_DATE.search(unicodedata.normalize("NFKC", line))
    if match is None:
        return None
    month, day = (match.group(2), match.group(3)) if match.group(2) else (match.group(4), match.group(5))
    try:
        return date(int(match.group(1)), int(month), int(day))
    except ValueError:
        return None


def _recent_rows(section: RawSection, today: date, days: int) -> tuple[list[str], History]:
    """表の行のうち、日付が期間に入るもの。表の見出しの行を先頭に付ける。"""
    header: list[str] = []
    rows: list[str] = []
    counts = {"rows": 0, "inside": 0, "outside": 0, "unreadable": 0}
    in_table = False
    previous = ""
    for line in section.text.split("\n"):
        if "|" not in line:
            in_table = False
        elif _ROW_RULE.match(line):
            if not in_table and "|" in previous and not header:
                header = [previous, line]
            in_table = True
        elif in_table:
            counts["rows"] += 1
            when = _row_date(line)
            if when is None:
                counts["unreadable"] += 1
            elif today - timedelta(days=days) <= when <= today:
                counts["inside"] += 1
                rows.append(line)
            else:
                counts["outside"] += 1
        previous = line
    history = History(**counts)
    if history.rows and history.unreadable == history.rows:
        raise BuildError(f"変更履歴の表に行が {history.rows} あるが、日付を読めない: {section.file}「{section.heading}」。"
                         "日付は 年-月-日 で書く")
    return (header + rows if rows else []), history


def _card(recipe: Recipe, sections: list[RawSection],
          today: date) -> tuple[str, list[tuple[str, str]], set[str], History, list[tuple[str, str]]]:
    """環境カードの文、部品（名前と文）の並び、カードに入れた節の ID、変更履歴の数、含めた下位の節。"""
    parts: list[tuple[str, str]] = []
    used: set[str] = set()
    children: list[tuple[str, str]] = []
    listed = {_find(sections, e.file, e.heading, "環境カードの節").id for e in recipe.card_sections}
    for entry in recipe.card_sections:
        section = _find(sections, entry.file, entry.heading, "環境カードの節")
        for member in (section, *_children(sections, section)):
            if member.id in used:
                continue
            used.add(member.id)
            parts.append((f"{member.file}「{member.heading}」", member.text))
            if member is not section and member.id not in listed:
                children.append((member.file, member.heading))
    history = History()
    if recipe.recent_changes is not None:
        entry = recipe.recent_changes
        section = _find(sections, entry.file, entry.heading, "変更履歴の節")
        rows, history = _recent_rows(section, today, entry.days)
        if rows:
            body = "\n".join(rows)
        elif history.rows:
            body = f"直近 {entry.days} 日の変更はない。"
        else:
            body = "変更履歴に行がない。"
        parts.append((f"変更履歴の直近 {entry.days} 日", f"## 変更履歴の直近 {entry.days} 日\n\n{body}"))
    if not parts:
        return "", parts, used, history, children
    return "# 環境カード\n\n" + "\n\n".join(text for _, text in parts) + "\n", parts, used, history, children


def _json(value: object, *, compact: bool = False) -> bytes:
    if compact:
        text = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    else:
        text = json.dumps(value, ensure_ascii=False, sort_keys=True, indent=1)
    return (text + "\n").encode("utf-8")


def content_hash(files: dict[str, bytes]) -> str:
    digest = hashlib.sha256()
    for name in CONTENT_FILES:
        digest.update(name.encode() + b"\0" + files[name] + b"\0")
    return digest.hexdigest()


def _write(out_dir: Path, version: str, files: dict[str, bytes]) -> Path:
    try:
        return _write_files(out_dir, version, files)
    except OSError as exc:
        raise BuildError(f"束を書けない: {out_dir}: {type(exc).__name__}") from None


def _write_files(out_dir: Path, version: str, files: dict[str, bytes]) -> Path:
    """一時フォルダに書いてから名前を変える。途中で止まっても、前の束は壊れない。"""
    final = out_dir / version
    out_dir.mkdir(parents=True, exist_ok=True)
    if final.is_dir():
        # 版は中身（CONTENT_FILES）で決まる。出典のハッシュだけが変わった作り直しは、manifest.json を置き換える
        if not all((final / name).is_file() and (final / name).read_bytes() == files[name] for name in CONTENT_FILES):
            raise BuildError(f"同じ版の束が既にあり、中身が違う: {final}")
        manifest = final / "manifest.json"
        if not manifest.is_file() or manifest.read_bytes() != files["manifest.json"]:
            temporary = final / f".manifest-{os.getpid()}"
            try:
                temporary.write_bytes(files["manifest.json"])
                os.replace(temporary, manifest)
            finally:
                temporary.unlink(missing_ok=True)
    else:
        temporary = out_dir / f".tmp-{version}-{os.getpid()}"
        shutil.rmtree(temporary, ignore_errors=True)
        temporary.mkdir()
        try:
            for name, data in files.items():
                (temporary / name).write_bytes(data)
            os.replace(temporary, final)
        finally:
            shutil.rmtree(temporary, ignore_errors=True)
    pointer = out_dir / f".current-{os.getpid()}"
    try:
        pointer.write_text(version + "\n", encoding="utf-8")
        os.replace(pointer, out_dir / "current")
    finally:
        pointer.unlink(missing_ok=True)
    return final


def build_bundle(source_dir: Path, out_dir: Path, recipe: Recipe, today: date, *, card_budget: int = 6000,
                 counter: TokenCounter = estimate_tokens) -> BuildResult:
    source, out = Path(source_dir), Path(out_dir)
    if not source.is_dir():
        raise BuildError(f"出典の場所がない: {source}")
    root = source.resolve()
    if out.resolve().is_relative_to(root):
        raise BuildError(f"出典の場所の中には書かない: {out}")

    raw_sections: list[RawSection] = []
    findings: list[Finding] = []
    notices: list[Notice] = []
    hashes: dict[str, str] = {}
    neutralised = 0
    cleaned: list[tuple[str, int]] = []
    stale: list[AllowedLine] = []
    allowed = 0
    for name in recipe.files:
        data = _read(source, root, name)
        hashes[name] = hashlib.sha256(data).hexdigest()
        try:
            raw = data.decode("utf-8")
        except UnicodeDecodeError:
            raise BuildError(f"文書が UTF-8 で読めない: {name}") from None
        text, changed = neutralise(raw)
        neutralised += changed
        if changed:
            cleaned.append((name, changed))
        # 見えない文字で切られた秘密も見つけるため、無害にした後の文を検査する
        entries = [entry for entry in recipe.allow_secrets if entry.file == name]
        present = {line_digest(line) for line in text.split("\n")} if entries else set()
        stale.extend(entry for entry in entries if entry.line_sha256 not in present)
        permitted = {entry.line_sha256 for entry in entries}
        for finding in scan_secrets(name, text):
            # 秘密鍵のブロックは、許可の一覧があっても通さない
            if finding.kind != "private_key" and finding.digest in permitted:
                allowed += 1
            else:
                findings.append(finding)
        notices.extend(find_instruction_phrases(name, text))
        try:
            raw_sections.extend(split_sections(name, text))
        except SplitError as exc:
            raise BuildError(str(exc)) from None
    if findings:
        raise SecretFound(findings)

    card, parts, in_card, history, card_children = _card(recipe, raw_sections, today)
    card_tokens = counter(card) if card else 0
    if card_tokens > card_budget:
        detail = "、".join(f"{name} {counter(text):,}" for name, text in parts)
        raise BuildError(f"環境カードが上限を超えた: {card_tokens:,} > {card_budget:,}。内訳: {detail}")

    sections = [{
        "id": s.id, "file": s.file, "heading": s.heading, "level": s.level, "parent": s.parent, "order": s.order,
        "line": s.line, "text": s.text,
        "hosts": detect_hosts(recipe, s.heading, s.text),
        "types": detect_types(recipe, s.heading, s.text),
        "confirmed_on": confirmed_on(s.text, today),
        "tokens": counter(s.text),
        "sha256": hashlib.sha256(s.text.encode("utf-8")).hexdigest(),
        "in_card": s.id in in_card,
        "preferred": any(word in s.heading for word in recipe.prefer_headings),
    } for s in raw_sections]
    if len({s["id"] for s in sections}) != len(sections):
        raise BuildError("節の ID が重なった。見出しを見直す")

    files = {
        "card.md": card.encode("utf-8"),
        "index.json": _json(build_index(sections, recipe.hosts), compact=True),
        "sections.json": _json(sections),
    }
    digest = content_hash(files)
    version = f"{today:%Y%m%d}-{digest[:HASH_LENGTH]}"
    tokens = sum(s["tokens"] for s in sections)
    files["manifest.json"] = _json({
        "format": FORMAT,
        "version": version,
        "built_on": today.isoformat(),
        "content_hash": digest,
        "estimator": ESTIMATOR if counter is estimate_tokens else getattr(counter, "__name__", "custom"),
        "source": {"files": hashes},
        "counts": {"sections": len(sections), "tokens": tokens, "card_tokens": card_tokens,
                   "neutralised": neutralised, "allowed": allowed},
        "allowed": [{"file": e.file, "line_sha256": e.line_sha256, "reason": e.reason}
                    for e in recipe.allow_secrets if e not in stale],
        "notices": [{"file": n.file, "line": n.line, "phrase": n.phrase} for n in notices],
    })
    path = _write(out, version, files)
    return BuildResult(version=version, path=path, sections=len(sections), tokens=tokens, card_tokens=card_tokens,
                       neutralised=neutralised, notices=tuple(notices), neutralised_files=tuple(cleaned),
                       allowed=allowed, stale_allowed=tuple(stale), history=history,
                       card_children=tuple(card_children))
