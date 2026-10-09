"""ナレッジのテストで共有する部品。"""
from __future__ import annotations

import json
import shutil
from datetime import date
from pathlib import Path

from tia.knowledge.build import BuildResult, build_bundle, content_hash
from tia.knowledge.recipe import load_recipe

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "knowledge"
TODAY = date(2026, 9, 29)


def copy_source(tmp_path: Path) -> Path:
    """書き換えてよい出典の写し。"""
    target = tmp_path / "source"
    shutil.copytree(FIXTURES / "source", target)
    return target


def build_fixture(tmp_path: Path, today: date = TODAY) -> BuildResult:
    """テスト用の出典から束を作る。置き場所は tmp_path / "bundles"。"""
    source = tmp_path / "source"
    if not source.exists():
        copy_source(tmp_path)
    return build_bundle(source, tmp_path / "bundles", load_recipe(FIXTURES / "recipe.yaml"), today)


def rewrite(path: Path, change) -> None:
    """JSON のファイルを読み、change で書き換えて保存する。"""
    data = json.loads(path.read_text(encoding="utf-8"))
    change(data)
    path.write_text(json.dumps(data, ensure_ascii=False, sort_keys=True, indent=1) + "\n", encoding="utf-8")


def reseal(bundle_dir: Path) -> None:
    """中身を書き換えた後で、ハッシュと数を合わせ直す。ハッシュの確認より先の確認を試すために使う。"""
    files = {name: (bundle_dir / name).read_bytes() for name in ("card.md", "index.json", "sections.json")}
    digest = content_hash(files)
    sections = json.loads(files["sections.json"])

    def change(manifest: dict) -> None:
        manifest["content_hash"] = digest
        manifest["version"] = manifest["version"].split("-")[0] + "-" + digest[:12]
        if isinstance(sections, list) and all(isinstance(s, dict) for s in sections):
            manifest["counts"]["sections"] = len(sections)
            manifest["counts"]["tokens"] = sum(s.get("tokens", 0) for s in sections
                                               if isinstance(s.get("tokens"), int))

    rewrite(bundle_dir / "manifest.json", change)
