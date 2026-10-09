#!/usr/bin/env python3
"""画面の見本を撮る。テスト用の状態をそろえた保存先で画面を起動し、明るい表示と暗い表示を PNG にする。

    uv run tools/web-screenshot.py [--out screenshots] [--incident 1]

headless の Chromium を使う。
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))


def chromium() -> str:
    found = shutil.which("chromium") or shutil.which("google-chrome") or shutil.which("chromium-browser")
    if not found:
        raise SystemExit("Chromium が見つからない")
    return found


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, default=ROOT / "screenshots")
    parser.add_argument("--incident", type=int, default=1)
    parser.add_argument("--width", type=int, default=1440)
    parser.add_argument("--height", type=int, default=1100)
    args = parser.parse_args()

    from knowledge_helpers import build_fixture
    from web_fixtures import serve
    from web_helpers import NOW, collector_rows, make_db

    from tia import db
    from tia.analysis.llm import LlmHealth
    from tia.config import Config
    from tia.web.app import create_app

    args.out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "screenshot.sqlite"
        make_db(path)
        conn = db.connect(path)
        collector_rows(conn)
        conn.close()
        bundle_dir = build_fixture(Path(tmp) / "kb").path.parent
        app = create_app(path, Config(web_cookie_secure=False), bundle_dir=bundle_dir,
                         llm_probe=lambda: LlmHealth(True, "モデル example/model-27b に届く"), clock=lambda: NOW)
        app.state.tia.monitor.refresh()
        with serve(app) as base:
            for theme in ("light", "dark"):
                target = args.out / f"inbox-{theme}.png"
                subprocess.run([chromium(), "--headless", "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage",
                                "--hide-scrollbars", f"--window-size={args.width},{args.height}",
                                f"--screenshot={target}", f"{base}/incidents/{args.incident}?theme={theme}"],
                               check=True, capture_output=True, timeout=120)
                print(f"{target.relative_to(ROOT) if target.is_relative_to(ROOT) else target}: {target.stat().st_size:,} バイト")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
